"""
Wire-format adapters for the three API families this toolkit talks to.

OpenAI-compatible is the lingua franca -- OpenRouter, Groq, DeepSeek, Mistral,
Together, Fireworks, xAI, vLLM, llama.cpp and Ollama all speak it, which is why
``kind="openai"`` plus a custom ``base_url`` covers most self-hosted setups.
Anthropic and Google need genuine translation, not just a different URL.

Two things matter here:

* A tool call must round-trip identically whichever family answers, so the
  agent loop never has to care which provider it landed on.
* Usage numbers come back in different shapes, and cost/rate-limit decisions
  depend on them, so they are normalised too.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "ToolCall",
    "ToolSpec",
    "Message",
    "Usage",
    "ChatResult",
    "ProviderError",
    "encode_request",
    "decode_response",
]


class ProviderError(Exception):
    """A provider said no. ``status`` drives the retry/wait decision."""

    def __init__(self, message: str, *, status: int = 0, retry_after: Optional[float] = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


@dataclass
class ToolSpec:
    """A capability the model may ask for."""

    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


@dataclass
class ToolCall:
    """A normalised tool invocation. ``arguments`` is always a dict."""

    id: str
    name: str
    arguments: Dict[str, Any]
    raw: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}


@dataclass
class Message:
    role: str  # system | user | assistant | tool
    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

    def as_dict(self) -> dict:
        out: dict = {"role": self.role, "content": self.content}
        if self.tool_calls:
            out["tool_calls"] = [c.as_dict() for c in self.tool_calls]
        if self.tool_call_id:
            out["tool_call_id"] = self.tool_call_id
        if self.name:
            out["name"] = self.name
        return out


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = ""

    def as_dict(self) -> dict:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "model": self.model,
        }


@dataclass
class ChatResult:
    """The single shape every provider collapses into."""

    text: str
    tool_calls: List[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    provider: str = ""
    model: str = ""
    finish_reason: str = ""
    raw: Any = None

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)

    def as_dict(self) -> dict:
        return {
            "text": self.text,
            "tool_calls": [c.as_dict() for c in self.tool_calls],
            "usage": self.usage.as_dict(),
            "provider": self.provider,
            "model": self.model,
            "finish_reason": self.finish_reason,
        }


# ==========================================================================
# OpenAI-compatible
# ==========================================================================
def _openai_messages(messages: List[Message]) -> List[dict]:
    out: List[dict] = []
    for message in messages:
        if message.role == "tool":
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": message.tool_call_id or "",
                    "content": message.content,
                }
            )
        elif message.role == "assistant" and message.tool_calls:
            out.append(
                {
                    "role": "assistant",
                    "content": message.content or None,
                    "tool_calls": [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.name,
                                "arguments": json.dumps(call.arguments, ensure_ascii=False),
                            },
                        }
                        for call in message.tool_calls
                    ],
                }
            )
        else:
            out.append({"role": message.role, "content": message.content})
    return out


def _encode_openai(
    messages: List[Message],
    model: str,
    tools: List[ToolSpec],
    *,
    temperature: Optional[float],
    max_tokens: Optional[int],
    extra: Optional[dict],
) -> dict:
    body: Dict[str, Any] = {"model": model, "messages": _openai_messages(messages)}
    if tools:
        body["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]
        body["tool_choice"] = "auto"
    if temperature is not None:
        body["temperature"] = temperature
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if extra:
        body.update(extra)
    return body


def _decode_openai(payload: dict, provider: str) -> ChatResult:
    choices = payload.get("choices") or []
    if not choices:
        raise ProviderError(f"{provider}: response had no choices", status=502)
    choice = choices[0]
    message = choice.get("message") or {}
    calls: List[ToolCall] = []
    for raw in message.get("tool_calls") or []:
        function = raw.get("function") or {}
        calls.append(
            ToolCall(
                id=raw.get("id") or f"call_{len(calls)}",
                name=function.get("name") or "",
                arguments=_loose_json(function.get("arguments")),
                raw=function.get("arguments") or "",
            )
        )
    usage_raw = payload.get("usage") or {}
    return ChatResult(
        text=message.get("content") or "",
        tool_calls=calls,
        usage=Usage(
            prompt_tokens=int(usage_raw.get("prompt_tokens") or 0),
            completion_tokens=int(usage_raw.get("completion_tokens") or 0),
            total_tokens=int(usage_raw.get("total_tokens") or 0),
            model=payload.get("model") or "",
        ),
        provider=provider,
        model=payload.get("model") or "",
        finish_reason=choice.get("finish_reason") or "",
        raw=payload,
    )


# ==========================================================================
# Anthropic
# ==========================================================================
def _encode_anthropic(
    messages: List[Message],
    model: str,
    tools: List[ToolSpec],
    *,
    temperature: Optional[float],
    max_tokens: Optional[int],
    extra: Optional[dict],
) -> dict:
    """Anthropic wants the system prompt lifted out and tool results as blocks."""
    system_parts: List[str] = []
    converted: List[dict] = []
    for message in messages:
        if message.role == "system":
            system_parts.append(message.content)
        elif message.role == "tool":
            converted.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": message.tool_call_id or "",
                            "content": message.content,
                        }
                    ],
                }
            )
        elif message.role == "assistant" and message.tool_calls:
            blocks: List[dict] = []
            if message.content:
                blocks.append({"type": "text", "text": message.content})
            for call in message.tool_calls:
                blocks.append(
                    {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
                )
            converted.append({"role": "assistant", "content": blocks})
        else:
            converted.append({"role": message.role, "content": message.content})

    body: Dict[str, Any] = {
        "model": model,
        "messages": converted,
        # Anthropic requires max_tokens; 4096 is a sane default.
        "max_tokens": max_tokens or 4096,
    }
    if system_parts:
        body["system"] = "\n\n".join(system_parts)
    if tools:
        body["tools"] = [
            {"name": t.name, "description": t.description, "input_schema": t.parameters}
            for t in tools
        ]
    if temperature is not None:
        body["temperature"] = temperature
    if extra:
        body.update(extra)
    return body


def _decode_anthropic(payload: dict, provider: str) -> ChatResult:
    blocks = payload.get("content") or []
    text_parts: List[str] = []
    calls: List[ToolCall] = []
    for block in blocks:
        if block.get("type") == "text":
            text_parts.append(block.get("text") or "")
        elif block.get("type") == "tool_use":
            raw = block.get("input")
            calls.append(
                ToolCall(
                    id=block.get("id") or f"toolu_{len(calls)}",
                    name=block.get("name") or "",
                    arguments=raw if isinstance(raw, dict) else _loose_json(raw),
                    raw=json.dumps(raw, ensure_ascii=False) if raw is not None else "",
                )
            )
    usage_raw = payload.get("usage") or {}
    prompt = int(usage_raw.get("input_tokens") or 0)
    completion = int(usage_raw.get("output_tokens") or 0)
    return ChatResult(
        text="".join(text_parts),
        tool_calls=calls,
        usage=Usage(
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=prompt + completion,
            model=payload.get("model") or "",
        ),
        provider=provider,
        model=payload.get("model") or "",
        finish_reason=payload.get("stop_reason") or "",
        raw=payload,
    )


# ==========================================================================
# Google Gemini
# ==========================================================================
def _encode_google(
    messages: List[Message],
    model: str,
    tools: List[ToolSpec],
    *,
    temperature: Optional[float],
    max_tokens: Optional[int],
    extra: Optional[dict],
) -> dict:
    system_parts: List[str] = []
    contents: List[dict] = []
    for message in messages:
        if message.role == "system":
            system_parts.append(message.content)
        elif message.role == "tool":
            contents.append(
                {
                    "role": "user",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": message.name or "tool",
                                "response": {"result": message.content},
                            }
                        }
                    ],
                }
            )
        elif message.role == "assistant" and message.tool_calls:
            parts: List[dict] = []
            if message.content:
                parts.append({"text": message.content})
            for call in message.tool_calls:
                parts.append({"functionCall": {"name": call.name, "args": call.arguments}})
            contents.append({"role": "model", "parts": parts})
        else:
            # Gemini only knows user/model; fold stray roles into user.
            role = "model" if message.role == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": message.content}]})

    generation: Dict[str, Any] = {}
    if temperature is not None:
        generation["temperature"] = temperature
    if max_tokens is not None:
        generation["maxOutputTokens"] = max_tokens
    if tools:
        generation.setdefault("tools", []).append(
            {
                "functionDeclarations": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                    for t in tools
                ]
            }
        )

    body: Dict[str, Any] = {"contents": contents}
    if system_parts:
        body["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
    if generation:
        body["generationConfig"] = generation
    if extra:
        body.update(extra)
    return body


def _decode_google(payload: dict, provider: str) -> ChatResult:
    candidates = payload.get("candidates") or []
    if not candidates:
        # Gemini reports refusals/safety with no candidates at all.
        raise ProviderError(
            f"{provider}: {payload.get('promptFeedback') or 'no candidates returned'}",
            status=502,
        )
    candidate = candidates[0]
    parts = (candidate.get("content") or {}).get("parts") or []
    text_parts: List[str] = []
    calls: List[ToolCall] = []
    for part in parts:
        if "text" in part:
            text_parts.append(part["text"])
        if "functionCall" in part:
            call = part["functionCall"]
            args = call.get("args")
            calls.append(
                ToolCall(
                    id=f"fc_{len(calls)}",
                    name=call.get("name") or "",
                    arguments=args if isinstance(args, dict) else _loose_json(args),
                    raw=json.dumps(args, ensure_ascii=False) if args is not None else "",
                )
            )
    usage_raw = payload.get("usageMetadata") or {}
    model_name = (payload.get("modelVersion") or "").replace("models/", "")
    return ChatResult(
        text="".join(text_parts),
        tool_calls=calls,
        usage=Usage(
            prompt_tokens=int(usage_raw.get("promptTokenCount") or 0),
            completion_tokens=int(usage_raw.get("candidatesTokenCount") or 0),
            total_tokens=int(usage_raw.get("totalTokenCount") or 0),
            model=model_name,
        ),
        provider=provider,
        model=model_name,
        finish_reason=candidate.get("finishReason") or "",
        raw=payload,
    )


# ==========================================================================
# dispatch
# ==========================================================================
DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "google": "https://generativelanguage.googleapis.com",
}

ENCODERS = {"openai": _encode_openai, "anthropic": _encode_anthropic, "google": _encode_google}
DECODERS = {"openai": _decode_openai, "anthropic": _decode_anthropic, "google": _decode_google}


def encode_request(
    kind: str,
    messages: List[Message],
    model: str,
    tools: Optional[List[ToolSpec]] = None,
    *,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    extra: Optional[dict] = None,
) -> dict:
    encoder = ENCODERS.get(kind, _encode_openai)
    return encoder(
        messages, model, tools or [], temperature=temperature, max_tokens=max_tokens, extra=extra
    )


def decode_response(kind: str, payload: dict, provider: str) -> ChatResult:
    decoder = DECODERS.get(kind, _decode_openai)
    return decoder(payload, provider)


def request_path(kind: str, model: str) -> str:
    """The URL suffix + whether the key goes in a header or a query string."""
    if kind == "anthropic":
        return "/v1/messages"
    if kind == "google":
        return f"/v1beta/models/{model}:generateContent"
    return "/chat/completions"


def auth_headers(kind: str, api_key: str) -> Dict[str, str]:
    if kind == "anthropic":
        return {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
    if kind == "google":
        # Gemini takes the key as a query parameter; see auth_query().
        return {}
    return {"Authorization": f"Bearer {api_key}"}


def auth_query(kind: str, api_key: str) -> str:
    return f"?key={api_key}" if kind == "google" else ""


def _loose_json(raw: Any) -> Dict[str, Any]:
    """Models sometimes emit tool arguments that are not quite JSON."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    if isinstance(raw, str):
        text = raw.strip()
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            # Strip the ```json fences models like to wrap arguments in.
            if text.startswith("```"):
                text = text.strip("`")
                if text.startswith("json"):
                    text = text[4:]
                try:
                    parsed = json.loads(text.strip())
                    return parsed if isinstance(parsed, dict) else {"value": parsed}
                except json.JSONDecodeError:
                    pass
            return {"_unparsed": raw}
    return {"value": raw}
