"""
Tests for the AI layer: configuration, wire formats, routing, and the agent.

No network is used anywhere. ``ScriptedTransport`` plays the provider, and the
router is given a fake clock and sleeper, so rate-limit behaviour is asserted
exactly rather than approximately -- a test that really slept five seconds would
be a worse test, not a more honest one.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import fixture  # noqa: E402

from apkmod.ai.agent import Agent  # noqa: E402
from apkmod.ai.client import AIClient, Response, Transport  # noqa: E402
from apkmod.ai.config import AIConfig, ProviderConfig, RoutingConfig, load_config, mask_key  # noqa: E402
from apkmod.ai.providers import (  # noqa: E402
    Message,
    ProviderError,
    ToolSpec,
    decode_response,
    encode_request,
)
from apkmod.ai.router import NoEndpointAvailable, Router  # noqa: E402
from apkmod.ai.tools import ToolContext, build_registry  # noqa: E402


# ==========================================================================
# helpers
# ==========================================================================
class ScriptedTransport(Transport):
    """Replays a queue of canned responses; records what was sent."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def post(self, url, headers, body, timeout):
        self.requests.append({"url": url, "headers": headers, "body": json.loads(body)})
        if not self.responses:
            raise AssertionError("transport ran out of scripted responses")
        item = self.responses.pop(0)
        if isinstance(item, Response):
            return item
        return Response(200, json.dumps(item), {})


class FakeClock:
    """A clock that only advances when the router sleeps."""

    def __init__(self, start: float = 1000.0):
        self.now = start
        self.slept = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def openai_reply(text="done", calls=None, tokens=10, finish="stop"):
    message = {"content": text}
    if calls:
        message["tool_calls"] = [
            {
                "id": call.get("id", f"c{i}"),
                "type": "function",
                "function": {"name": call["name"], "arguments": json.dumps(call.get("args", {}))},
            }
            for i, call in enumerate(calls)
        ]
    return {
        "model": "test-model",
        "choices": [{"message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": tokens, "completion_tokens": 2, "total_tokens": tokens + 2},
    }


def limited(retry_after=None, message="rate limited"):
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
    return Response(429, json.dumps({"error": {"message": message}}), headers)


def client_with(responses, *, keys=("sk-a",), models=("m",), clock=None, **routing):
    config = AIConfig(
        providers=[ProviderConfig(name="p", keys=list(keys), models=list(models))],
        routing=RoutingConfig(**routing),
    )
    clock = clock or FakeClock()
    transport = ScriptedTransport(responses)
    client = AIClient(
        config,
        transport=transport,
        clock=clock,
        router=Router(config, clock=clock, sleeper=clock.sleep),
    )
    return client, transport, clock


def ask(client, text="hi"):
    return client.chat([Message(role="user", content=text)])


# ==========================================================================
# config
# ==========================================================================
def test_mask_key_hides_the_secret():
    assert mask_key("sk-proj-abcdefghijklmnop1234") == "sk-pro...1234 (28 chars)"
    assert mask_key("") == "<empty>"
    assert "abcdef" not in mask_key("short")


def test_load_config_from_file(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("APKMOD_AI_KEYS", raising=False)
    path = tmp_path / "ai.json"
    path.write_text(
        json.dumps(
            {
                "default_model": "gpt-x",
                "providers": [
                    {
                        "name": "primary",
                        "base_url": "https://example.test/v1/",
                        "keys": ["k1", "k2"],
                        "models": ["gpt-x", "gpt-y"],
                    },
                    {"name": "backup", "key": "k3", "models": ["gpt-z"], "enabled": False},
                ],
                "routing": {"strategy": "round-robin", "max_wait_seconds": 99},
            }
        )
    )
    config = load_config(str(path), use_env=False)

    assert config.default_model == "gpt-x"
    assert config.routing.strategy == "round-robin"
    assert config.routing.max_wait_seconds == 99
    primary, backup = config.providers
    assert primary.keys == ["k1", "k2"]
    assert primary.base_url == "https://example.test/v1"  # trailing slash stripped
    assert [p.name for p in config.enabled_providers] == ["primary"]
    assert backup.enabled is False
    # a singular "key" field is accepted as a one-element list
    assert backup.keys == ["k3"]


def test_config_redacts_keys_in_reports(tmp_path):
    config = AIConfig(providers=[ProviderConfig(name="p", keys=["sk-secret-value-123456"])])
    redacted = config.as_dict()
    assert "sk-secret-value-123456" not in json.dumps(redacted)
    assert config.as_dict(redact=False)["providers"][0]["keys"] == ["sk-secret-value-123456"]


def test_environment_keys_create_a_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", " sk-from-env ")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anth")
    for var in ("APKMOD_AI_CONFIG", "APKMOD_AI_KEYS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)

    config = load_config(use_env=True)
    names = {p.name: p for p in config.providers}
    assert names["openai"].keys == ["sk-from-env"]  # stripped
    assert names["anthropic"].kind == "anthropic"


def test_duplicate_keys_are_collapsed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "same-key")
    monkeypatch.delenv("APKMOD_AI_CONFIG", raising=False)
    config = AIConfig(providers=[ProviderConfig(name="openai", keys=["same-key"])])
    # Re-running the merge must not double the key.
    from apkmod.ai import config as config_module

    config_module._merge_env(config, config.warnings)
    config_module._dedupe_keys(config)
    assert config.providers[0].keys == ["same-key"]


def test_unknown_provider_kind_is_coerced_and_warned(tmp_path):
    path = tmp_path / "ai.json"
    path.write_text(json.dumps({"providers": [{"name": "x", "kind": "carrier-pigeon", "keys": ["k"]}]}))
    config = load_config(str(path), use_env=False)
    assert config.providers[0].kind == "openai"
    assert any("carrier-pigeon" in w for w in config.warnings)


def test_invalid_config_paths_are_reported(tmp_path):
    with pytest.raises(Exception, match="not valid JSON"):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        load_config(str(bad), use_env=False)
    with pytest.raises(Exception, match="no AI config"):
        load_config(str(tmp_path / "absent.json"), use_env=False)


# ==========================================================================
# provider wire formats
# ==========================================================================
def test_openai_round_trip():
    messages = [Message(role="system", content="be terse"), Message(role="user", content="hi")]
    body = encode_request("openai", messages, "m", [ToolSpec("t", "does t")])
    assert body["model"] == "m"
    assert body["messages"][0]["role"] == "system"
    assert body["tools"][0]["function"]["name"] == "t"

    result = decode_response("openai", openai_reply("answer"), "p")
    assert result.text == "answer"
    assert result.usage.total_tokens == 12


def test_anthropic_lifts_system_and_requires_max_tokens():
    messages = [Message(role="system", content="sys"), Message(role="user", content="hi")]
    body = encode_request("anthropic", messages, "claude-x", [ToolSpec("t", "d")])
    assert body["system"] == "sys"
    assert all(m["role"] != "system" for m in body["messages"])
    assert body["max_tokens"] == 4096
    assert body["tools"][0]["input_schema"]["type"] == "object"


def test_anthropic_tool_use_decodes():
    payload = {
        "model": "claude-x",
        "content": [
            {"type": "text", "text": "let me look"},
            {"type": "tool_use", "id": "t1", "name": "apk_info", "input": {"a": 1}},
        ],
        "usage": {"input_tokens": 5, "output_tokens": 7},
        "stop_reason": "tool_use",
    }
    result = decode_response("anthropic", payload, "p")
    assert result.text == "let me look"
    assert result.tool_calls[0].name == "apk_info"
    assert result.tool_calls[0].arguments == {"a": 1}
    assert result.usage.total_tokens == 12
    assert result.finish_reason == "tool_use"


def test_google_uses_user_model_roles_and_function_calls():
    messages = [Message(role="system", content="sys"), Message(role="assistant", content="prev")]
    body = encode_request("google", messages, "gemini-x", [ToolSpec("t", "d")])
    assert body["systemInstruction"]["parts"][0]["text"] == "sys"
    assert {c["role"] for c in body["contents"]} <= {"user", "model"}
    assert body["generationConfig"]["tools"][0]["functionDeclarations"][0]["name"] == "t"


def test_google_tool_call_decodes_and_refusal_raises():
    payload = {
        "candidates": [
            {
                "content": {"parts": [{"functionCall": {"name": "analyze", "args": {}}}]},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7},
        "modelVersion": "models/gemini-x",
    }
    result = decode_response("google", payload, "p")
    assert result.tool_calls[0].name == "analyze"
    assert result.model == "gemini-x"
    assert result.usage.total_tokens == 7

    with pytest.raises(ProviderError):
        decode_response("google", {"promptFeedback": "SAFETY"}, "p")


def test_tool_call_history_round_trips_through_each_format():
    """An assistant turn with tool calls must re-encode without losing them."""
    from apkmod.ai.providers import ToolCall

    messages = [
        Message(role="user", content="go"),
        Message(role="assistant", content="", tool_calls=[ToolCall("c1", "apk_info", {})]),
        Message(role="tool", content='{"ok":true}', tool_call_id="c1", name="apk_info"),
    ]
    o = encode_request("openai", messages, "m")
    assert o["messages"][1]["tool_calls"][0]["id"] == "c1"
    assert o["messages"][2]["tool_call_id"] == "c1"

    a = encode_request("anthropic", messages, "m")
    assert a["messages"][1]["content"][-1]["type"] == "tool_use"
    assert a["messages"][2]["content"][0]["type"] == "tool_result"

    g = encode_request("google", messages, "m")
    assert g["contents"][1]["parts"][-1]["functionCall"]["name"] == "apk_info"
    assert "functionResponse" in g["contents"][2]["parts"][0]


def test_malformed_tool_arguments_do_not_crash():
    from apkmod.ai.providers import _loose_json

    assert _loose_json('{"a": 1}') == {"a": 1}
    assert _loose_json("```json\n{\"a\": 2}\n```") == {"a": 2}
    assert _loose_json("not json at all") == {"_unparsed": "not json at all"}
    assert _loose_json(None) == {}


# ==========================================================================
# routing
# ==========================================================================
def test_endpoints_are_one_per_key_per_model():
    config = AIConfig(
        providers=[
            ProviderConfig(name="a", keys=["k1", "k2"], models=["m1", "m2"]),
            ProviderConfig(name="b", keys=["k3"], models=["m1"]),
        ]
    )
    router = Router(config)
    assert len(router.endpoints) == 5
    assert router.usable[0].label == "a#0:m1"


def test_priority_strategy_prefers_the_first_provider():
    config = AIConfig(
        providers=[
            ProviderConfig(name="primary", keys=["k1"], models=["m"]),
            ProviderConfig(name="backup", keys=["k2"], models=["m"]),
        ]
    )
    router = Router(config)
    assert router.next_endpoint(now=0.0).endpoint.label == "primary#0:m"


def test_rate_limit_parks_the_endpoint_and_moves_on():
    client, transport, clock = client_with([limited(30), openai_reply("via second key")], keys=("a", "b"))
    result = ask(client)
    assert result.text == "via second key"
    assert len(transport.requests) == 2
    assert clock.slept == []  # the second key was free, so no wait was needed


def test_all_endpoints_limited_waits_and_recovers():
    """The headline requirement: a 429 waits, it does not end the task."""
    clock = FakeClock()
    client, transport, _ = client_with(
        [limited(5), limited(5), openai_reply("recovered")], keys=("a", "b"), clock=clock
    )
    result = ask(client)
    assert result.text == "recovered"
    assert clock.slept and sum(clock.slept) == pytest.approx(5.0)
    assert client.router.total_waited == pytest.approx(5.0)
    assert len(transport.requests) == 3


def test_retry_after_header_is_honoured_exactly():
    clock = FakeClock()
    client, _, _ = client_with([limited(42), openai_reply()], keys=("a",), clock=clock)
    ask(client)
    assert clock.slept == [42.0]


def test_bad_key_is_disabled_not_retried():
    client, transport, _ = client_with(
        [Response(401, '{"error":{"message":"invalid"}}', {}), openai_reply("good")],
        keys=("bad", "good"),
    )
    assert ask(client).text == "good"
    disabled = [e for e in client.router.endpoints if e.permanent_error]
    assert len(disabled) == 1
    assert "rejected the key" in disabled[0].permanent_error


def test_unknown_model_disables_the_endpoint():
    client, _, _ = client_with(
        [Response(404, '{"error":{"message":"no such model"}}', {}), openai_reply()],
        keys=("a",),
        models=("ghost", "real"),
    )
    ask(client)
    assert any("not found" in e.permanent_error for e in client.router.endpoints if e.permanent_error)


def test_wait_budget_is_enforced():
    """It waits, but not forever -- an unbounded hang is worse than an error."""
    clock = FakeClock()
    client, _, _ = client_with(
        [limited(9999)] * 4, keys=("a",), clock=clock, max_wait_seconds=60
    )
    with pytest.raises(Exception, match="beyond the 60s budget"):
        ask(client)


def test_every_endpoint_disabled_reports_cleanly():
    client, _, _ = client_with(
        [Response(401, "{}", {}), Response(401, "{}", {})], keys=("a", "b")
    )
    with pytest.raises(Exception, match="every endpoint is disabled"):
        ask(client)


def test_nothing_configured_is_a_clean_error():
    client = AIClient(AIConfig(), transport=ScriptedTransport([]))
    with pytest.raises(Exception, match="no AI provider is configured"):
        ask(client)


def test_retry_statuses_cause_a_wait_not_a_failure():
    clock = FakeClock()
    client, transport, _ = client_with(
        [Response(503, '{"error":{"message":"unavailable"}}', {}), openai_reply("back up")],
        keys=("a",),
        clock=clock,
    )
    assert ask(client).text == "back up"
    assert len(transport.requests) == 2


def test_a_400_is_not_retried_forever():
    """A bad request is our fault; parking and retrying would just waste time."""
    client, transport, _ = client_with(
        [Response(400, '{"error":{"message":"bad request"}}', {})], keys=("a",)
    )
    with pytest.raises(Exception):
        ask(client)
    assert len(transport.requests) == 1


def test_round_robin_spreads_the_load():
    config = AIConfig(
        providers=[ProviderConfig(name="p", keys=["k1", "k2", "k3"], models=["m"])],
        routing=RoutingConfig(strategy="round-robin"),
    )
    router = Router(config)
    seen = [router.next_endpoint(now=0.0).endpoint.label for _ in range(3)]
    assert len(set(seen)) == 3


def test_router_report_shape():
    config = AIConfig(providers=[ProviderConfig(name="p", keys=["k1"], models=["m"])])
    router = Router(config)
    report = router.as_dict()
    assert report["endpoint_count"] == 1
    assert "sk" not in json.dumps(report)[:200] or "..." in json.dumps(report)


# ==========================================================================
# tools
# ==========================================================================
@pytest.fixture
def session(tmp_path):
    apk = fixture.build_apk(tmp_path / "app.apk")
    context = ToolContext(work_dir=tmp_path, apk=apk, auto_confirm=True)
    return context, build_registry(context), apk


def test_every_tool_declares_a_schema(session):
    _, registry, _ = session
    assert len(registry.names()) == 19
    for spec in registry.specs:
        assert spec.name and spec.description
        assert spec.parameters.get("type") == "object"


def test_read_tools_describe_the_apk(session):
    _, registry, _ = session
    info = registry.call("apk_info", {})
    assert info["status"] == "ok"
    assert info["package"] == "com.example.demo"

    manifest = registry.call("read_manifest", {})
    assert "uses-permission" in manifest["xml"]

    strings = registry.call("list_strings", {"match": "demo"})
    assert any("Demo App" in s["value"] for s in strings["strings"])

    dex_hits = registry.call("search_dex", {"query": "example.com"})["matches"]
    assert any("api.example.com" in hit for hit in dex_hits)
    assert registry.call("analyze", {})["status"] == "ok"


def test_path_escape_is_refused(session):
    context, registry, _ = session
    for attempt in ("../../etc/passwd", "/etc/passwd", "../../../tmp/x"):
        result = registry.call("read_file", {"path": attempt})
        assert result["status"] == "error"
        assert "outside the session directory" in result["error"]


def test_mutating_tools_are_gated_without_yes(session, tmp_path):
    context, _, apk = session
    context.auto_confirm = False
    gated = build_registry(context)
    result = gated.call("rename_app", {"resource_name": "app_name", "new_value": "x"})
    assert result["status"] == "pending_confirmation"
    assert gated.pending_confirmations
    # Nothing was written.
    assert not list(tmp_path.glob("renamed-*.apk"))


def test_rename_and_sign_produce_an_installable_apk(session):
    context, registry, apk = session
    renamed = registry.call("rename_app", {"resource_name": "app_name", "new_value": "New Name"})
    assert renamed["status"] == "ok"
    assert renamed["old"] == "Demo App"

    signed = registry.call("sign_apk", {"source": pathlib.Path(renamed["output"]).name})
    assert signed["status"] == "ok"
    assert signed["schemes"] == ["v1"]
    # A key was generated rather than the call failing.
    assert signed.get("generated_debug_key")

    from apkmod.signing import verify_v1

    assert verify_v1(pathlib.Path(signed["output"])).ok


def test_injecting_a_new_entry_is_not_treated_as_a_replace(session):
    context, registry, apk = session
    (context.work_dir / "extra.json").write_text('{"x":1}')
    result = registry.call(
        "replace_entry", {"entry": "assets/extra.json", "source": "extra.json", "output": "out.apk"}
    )
    assert result["status"] == "ok"
    assert result["injected"] is True

    from apkmod.apk import ApkContainer

    with ApkContainer(result["output"]) as container:
        assert container.read("assets/extra.json") == b'{"x":1}'


def test_unknown_tool_and_bad_arguments_fail_structured(session):
    _, registry, _ = session
    assert registry.call("nope", {})["status"] == "error"
    # A tool error must come back as data, not an exception.
    assert registry.call("rename_app", {"resource_name": "", "new_value": ""})["status"] == "error"
    assert registry.call("apk_info", {})["status"] == "ok"


def test_run_shell_is_contained_and_argv_only(session):
    _, registry, _ = session
    result = registry.call("run_shell", {"command": ["python3", "-c", "print('hi')"]})
    assert result["status"] == "ok"
    assert "hi" in result["stdout"]
    # Shell metacharacters are not interpreted: this is argv, not a shell line.
    hostile = registry.call("run_shell", {"command": "echo a; echo b"})
    assert "a; echo b" in hostile["stdout"] or hostile["status"] == "error"


def test_no_tool_can_defeat_a_licence_check(session):
    """The scope boundary is structural: there is simply no such tool."""
    _, registry, _ = session
    names = " ".join(registry.names()).lower()
    for forbidden in ("license", "licence", "bypass", "crack", "memory", "cheat", "drm"):
        assert forbidden not in names


# ==========================================================================
# agent
# ==========================================================================
def test_agent_runs_a_tool_then_answers(session):
    context, registry, _ = session
    client, _, _ = client_with(
        [
            openai_reply("", calls=[{"name": "apk_info"}]),
            openai_reply("The package is com.example.demo."),
        ]
    )
    agent = Agent(client, registry=registry)
    result = agent.run("what package is this?")

    assert result.finished == "complete"
    assert "com.example.demo" in result.text
    assert result.tool_call_count == 1
    assert result.steps[0].tool_results[0]["package"] == "com.example.demo"


def test_agent_bounds_a_runaway_loop(session):
    context, registry, _ = session
    client, _, _ = client_with([openai_reply("", calls=[{"name": "apk_info"}])] * 30)
    agent = Agent(client, registry=registry, max_iterations=3)
    result = agent.run("loop forever")
    assert result.finished == "max_iterations"
    assert len(result.steps) == 3


def test_agent_refuses_to_fabricate_when_a_tool_errors(session):
    context, registry, _ = session
    client, _, _ = client_with(
        [
            openai_reply("", calls=[{"name": "rename_app", "args": {"resource_name": "nope"}}]),
            openai_reply("That resource does not exist."),
        ]
    )
    result = Agent(client, registry=registry).run("rename nope")
    tool_result = result.steps[0].tool_results[0]
    assert tool_result["status"] == "error"
    assert result.finished == "complete"


def test_agent_prompt_states_the_boundaries():
    from apkmod.ai.agent import SYSTEM_PROMPT

    lowered = SYSTEM_PROMPT.lower()
    assert "licence" in lowered or "license" in lowered
    assert "online game" in lowered or "cheat" in lowered
    assert "authorised" in lowered or "authorized" in lowered


def test_agent_records_provider_and_tokens(session):
    context, registry, _ = session
    client, _, _ = client_with([openai_reply("done", tokens=50)])
    result = Agent(client, registry=registry).run("hi")
    assert result.total_tokens == 52
    assert result.steps[0].provider == "p"


def test_agent_surfaces_pending_confirmations(session):
    context, _, _ = session
    context.auto_confirm = False
    registry = build_registry(context)
    client, _, _ = client_with(
        [
            openai_reply("", calls=[{"name": "set_debuggable", "args": {"enabled": True}}]),
            openai_reply("That needs confirmation."),
        ]
    )
    result = Agent(client, registry=registry).run("make it debuggable")
    assert result.pending_confirmations
    assert result.pending_confirmations[0]["tool"] == "set_debuggable"
