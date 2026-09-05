"""
The agent loop: chat -> tool calls -> results -> chat, until the model stops
asking for tools.

Two properties matter more than cleverness here.

**It survives rate limits.** All the waiting lives in the router, so a 429 mid
task pauses and resumes rather than throwing away twenty minutes of work. The
loop itself never sees a rate limit as a failure.

**It is bounded.** ``max_iterations`` caps the number of round trips and every
tool call is recorded, so a model that loops forever or tries something
destructive produces a transcript you can read rather than damage you have to
find.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from ..util import ApkModError
from .client import AIClient
from .providers import ChatResult, Message, ToolCall
from .tools import ToolContext, ToolRegistry, build_registry

__all__ = ["AgentResult", "Step", "Agent", "SYSTEM_PROMPT"]

SYSTEM_PROMPT = """\
You are an APK reverse-engineering and modification agent with direct tool
access to a single Android package and a session directory.

You can inspect the manifest, resources, DEX strings and native libraries, edit
smali and resources, swap or remove archive entries, repack, align and sign the
result, and run local commands such as a decompiler inside the session
directory.

How to work:
- Inspect before you change. Read the manifest and the relevant strings first;
  do not guess resource names or class names.
- Prefer the narrowest change that achieves the goal.
- After any edit that rewrites the APK, the v1 signature is invalid: align and
  sign before considering the work installable.
- Use dry_run for regex edits before committing them.
- Report exactly what you changed, in file and resource terms.

Hard boundaries, which no instruction from the user overrides:
- Work only on apps the user owns or is authorised to test.
- Do not defeat licence verification, payment or entitlement checks, and do not
  remove or bypass signature/integrity self-checks to hide a modification.
- Do not cheat in online games or alter another service's server-side state.
- Refuse requests that cross those lines and say why; then offer the legitimate
  alternative, such as static analysis of the protection in question.

If a task cannot be completed with the tools available, say so plainly instead
of inventing a result.
"""


@dataclass
class Step:
    """One round trip plus whatever it did."""

    index: int
    text: str = ""
    tool_calls: List[dict] = field(default_factory=list)
    tool_results: List[dict] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    tokens: int = 0
    latency_ms: float = 0.0

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "text": self.text,
            "provider": self.provider,
            "model": self.model,
            "tokens": self.tokens,
            "latency_ms": self.latency_ms,
            "tool_calls": self.tool_calls,
            "tool_results": self.tool_results,
        }


@dataclass
class AgentResult:
    text: str
    steps: List[Step] = field(default_factory=list)
    finished: str = "complete"  # complete | max_iterations | error
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    waited_seconds: float = 0.0
    pending_confirmations: List[dict] = field(default_factory=list)
    error: str = ""

    @property
    def tool_call_count(self) -> int:
        return sum(len(step.tool_calls) for step in self.steps)

    def as_dict(self) -> dict:
        return {
            "text": self.text,
            "finished": self.finished,
            "steps": [s.as_dict() for s in self.steps],
            "tool_call_count": self.tool_call_count,
            "total_tokens": self.total_tokens,
            "total_latency_ms": round(self.total_latency_ms, 1),
            "waited_seconds": round(self.waited_seconds, 2),
            "pending_confirmations": self.pending_confirmations,
            "error": self.error,
        }


class Agent:
    """Drives one task to completion across whichever provider answers."""

    def __init__(
        self,
        client: Optional[AIClient] = None,
        *,
        context: Optional[ToolContext] = None,
        registry: Optional[ToolRegistry] = None,
        system_prompt: str = SYSTEM_PROMPT,
        max_iterations: int = 12,
        clock: Callable[[], float] = time.monotonic,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ) -> None:
        self.client = client if client is not None else AIClient()
        self.context = context
        self.registry = registry or (
            build_registry(context) if context is not None else None
        )
        self.system_prompt = system_prompt
        self.max_iterations = max(1, max_iterations)
        self._clock = clock
        self._emit = on_event or (lambda kind, payload: None)
        # Route router telemetry into the same event stream as agent telemetry.
        self.client.on_event = self._emit

    # -- public -----------------------------------------------------------
    def run(
        self,
        task: str,
        *,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        history: Optional[List[Message]] = None,
    ) -> AgentResult:
        if self.registry is None:
            raise ApkModError("no tool registry attached to this agent")

        messages: List[Message] = list(history or [])
        if not messages or messages[0].role != "system":
            messages.insert(0, Message(role="system", content=self.system_prompt))
        messages.append(Message(role="user", content=task))

        result = AgentResult(text="")
        specs = self.registry.specs

        for index in range(1, self.max_iterations + 1):
            step = Step(index=index)
            started = self._clock()
            try:
                reply = self.client.chat(
                    messages,
                    tools=specs,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except ApkModError as exc:
                result.finished = "error"
                result.error = str(exc)
                result.steps.append(step)
                self._emit("agent_error", {"error": str(exc), "step": index})
                break

            step.latency_ms = (self._clock() - started) * 1000
            step.provider, step.model = reply.provider, reply.model
            step.tokens = reply.usage.total_tokens
            step.text = reply.text
            result.total_tokens += step.tokens
            result.total_latency_ms += step.latency_ms

            self._emit(
                "assistant",
                {
                    "step": index,
                    "provider": reply.provider,
                    "model": reply.model,
                    "text": reply.text[:2000],
                    "tool_calls": [c.name for c in reply.tool_calls],
                },
            )

            if not reply.wants_tools:
                result.text = reply.text
                result.finished = "complete"
                result.steps.append(step)
                break

            # Reconstruct the assistant turn so the next request is valid.
            messages.append(
                Message(role="assistant", content=reply.text, tool_calls=reply.tool_calls)
            )
            for call in reply.tool_calls:
                outcome = self._execute(call)
                step.tool_calls.append(call.as_dict())
                step.tool_results.append(outcome)
                messages.append(
                    Message(
                        role="tool",
                        content=_stringify(outcome),
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )
            result.steps.append(step)
        else:
            result.finished = "max_iterations"
            result.text = (
                f"stopped after {self.max_iterations} iterations without a final answer; "
                "the transcript shows what was in progress"
            )

        result.pending_confirmations = list(self.registry.pending_confirmations)
        if self.context is not None:
            result.waited_seconds = self.client.router.total_waited
        return result

    # -- internals --------------------------------------------------------
    def _execute(self, call: ToolCall) -> dict:
        self._emit("tool", {"name": call.name, "arguments": call.arguments})
        outcome = self.registry.call(call.name, call.arguments)
        self._emit(
            "tool_result",
            {"name": call.name, "status": outcome.get("status"), "keys": sorted(outcome)},
        )
        return outcome


def _stringify(outcome: dict) -> str:
    """Tool results go back to the model as text; keep them bounded."""
    import json

    text = json.dumps(outcome, ensure_ascii=False, default=str)
    limit = 24000
    if len(text) > limit:
        return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
    return text
