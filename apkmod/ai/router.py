"""
Endpoint routing with patient rate-limit handling.

The requirement this module exists to satisfy: when a provider answers 429, the
task must *wait*, not die. So every key of every enabled provider becomes an
:class:`Endpoint`, the router picks the best healthy one, and a rate-limited
endpoint is parked with a resume time rather than discarded. When every endpoint
is parked the router sleeps until the soonest one frees up and carries on --
up to ``routing.max_wait_seconds``, after which it raises rather than hanging
forever.

Time is injected as a callable so the waiting is testable without sleeping.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .config import AIConfig, ProviderConfig, RoutingConfig, mask_key
from .providers import ProviderError

__all__ = ["Endpoint", "EndpointStats", "Router", "RoutingDecision", "NoEndpointAvailable"]


class NoEndpointAvailable(Exception):
    """Every endpoint is exhausted or permanently parked."""


@dataclass
class EndpointStats:
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    rate_limits: int = 0
    last_latency: float = 0.0
    total_latency: float = 0.0
    last_error: str = ""
    tokens_in: int = 0
    tokens_out: int = 0

    @property
    def average_latency(self) -> float:
        return self.total_latency / self.successes if self.successes else 0.0

    def as_dict(self) -> dict:
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "rate_limits": self.rate_limits,
            "average_latency_ms": round(self.average_latency * 1000, 1),
            "last_error": self.last_error,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
        }


@dataclass
class Endpoint:
    """One (provider, key, model) triple -- the unit the router schedules."""

    provider: ProviderConfig
    key_index: int
    model: str
    stats: EndpointStats = field(default_factory=EndpointStats)
    parked_until: float = 0.0
    permanent_error: str = ""
    priority: int = 0

    @property
    def label(self) -> str:
        return f"{self.provider.name}#{self.key_index}:{self.model}"

    @property
    def masked_key(self) -> str:
        keys = self.provider.usable_keys
        return mask_key(keys[self.key_index]) if self.key_index < len(keys) else "<none>"

    def as_dict(self, now: float) -> dict:
        return {
            "endpoint": self.label,
            "provider": self.provider.name,
            "kind": self.provider.kind,
            "model": self.model,
            "key": self.masked_key,
            "priority": self.priority,
            "disabled": bool(self.permanent_error),
            "permanent_error": self.permanent_error,
            "parked_seconds": max(0.0, round(self.parked_until - now, 1)),
            "stats": self.stats.as_dict(),
        }


@dataclass
class RoutingDecision:
    """What the router chose, and what it had to wait through to choose it."""

    endpoint: Endpoint
    waited_seconds: float
    parked_skipped: List[str] = field(default_factory=list)


class Router:
    """Schedules requests across every configured key of every provider."""

    def __init__(
        self,
        config: AIConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Optional[Callable[[float], None]] = None,
        rng: Optional[random.Random] = None,
    ) -> None:
        self.config = config
        self.routing: RoutingConfig = config.routing
        self._clock = clock
        self._sleep = sleeper or time.sleep
        self._rng = rng or random.Random()
        self.endpoints = self._build_endpoints()
        self._cursor = 0
        self.total_waited = 0.0

    # -- construction -----------------------------------------------------
    def _build_endpoints(self) -> List[Endpoint]:
        """One endpoint per usable key, per model (or one with the default)."""
        out: List[Endpoint] = []
        priority = 0
        for provider in self.config.enabled_providers:
            keys = provider.usable_keys
            models = provider.models or [self.config.default_model or ""]
            models = [m for m in models if m]
            if not models:
                self.config.warnings.append(
                    f"provider '{provider.name}' has keys but no model; "
                    "pass --model or set default_model"
                )
                continue
            for key_index in range(len(keys)):
                for model in models:
                    out.append(
                        Endpoint(
                            provider=provider,
                            key_index=key_index,
                            model=model,
                            priority=priority,
                        )
                    )
            priority += 1
        return out

    # -- selection --------------------------------------------------------
    @property
    def usable(self) -> List[Endpoint]:
        return [e for e in self.endpoints if not e.permanent_error]

    def _rank(self, candidates: List[Endpoint]) -> List[Endpoint]:
        strategy = (self.routing.strategy or "priority").lower()
        if strategy == "lowest-latency":
            # Never-tried endpoints first, then fastest known.
            return sorted(
                candidates,
                key=lambda e: (e.stats.average_latency if e.stats.successes else -1.0)
                if e.stats.successes
                else -1.0,
            )
        if strategy == "round-robin":
            if not candidates:
                return []
            start = self._cursor % len(candidates)
            self._cursor += 1
            return candidates[start:] + candidates[:start]
        # priority: file order, tie-broken by fewest attempts so keys share load
        return sorted(
            candidates,
            key=lambda e: (e.priority, -e.provider.weight, e.stats.attempts, e.label),
        )

    def next_endpoint(self, *, now: Optional[float] = None) -> RoutingDecision:
        """
        Pick the next endpoint, waiting out any that are parked for rate limits.

        Raises :class:`NoEndpointAvailable` only when every endpoint is
        permanently disabled, or the wait budget is exhausted.
        """
        now = self._clock() if now is None else now
        deadline = now + max(0, self.routing.max_wait_seconds)
        waited = 0.0
        skipped: List[str] = []

        while True:
            live = self.usable
            if not live:
                raise NoEndpointAvailable(self._describe_disabled())

            ready = [e for e in live if e.parked_until <= now]
            if ready:
                ranked = self._rank(ready)
                return RoutingDecision(endpoint=ranked[0], waited_seconds=waited, parked_skipped=skipped)

            soonest = min(live, key=lambda e: e.parked_until)
            for endpoint in live:
                if endpoint.parked_until > now:
                    skipped.append(
                        f"{endpoint.label} parked {soonest.parked_until - now:.0f}s more"
                    )
            wake_at = soonest.parked_until
            if wake_at > deadline:
                raise NoEndpointAvailable(
                    f"every endpoint is rate-limited and the earliest is free in "
                    f"{wake_at - now:.0f}s, beyond the {self.routing.max_wait_seconds}s budget"
                )

            pause = max(0.05, wake_at - now)
            self._sleep(pause)
            waited += pause
            self.total_waited += pause
            now = wake_at

    def _describe_disabled(self) -> str:
        if not self.endpoints:
            return "no AI provider is configured (see `apkmod ai doctor`)"
        reasons = "; ".join(
            f"{e.label}: {e.permanent_error}" for e in self.endpoints if e.permanent_error
        )
        return f"every endpoint is disabled ({reasons})" if reasons else "no usable endpoint"

    # -- feedback ---------------------------------------------------------
    def report_success(self, endpoint: Endpoint, latency: float, tokens_in: int = 0, tokens_out: int = 0) -> None:
        stats = endpoint.stats
        stats.attempts += 1
        stats.successes += 1
        stats.last_latency = latency
        stats.total_latency += latency
        stats.tokens_in += tokens_in
        stats.tokens_out += tokens_out
        stats.last_error = ""
        endpoint.parked_until = 0.0

    def report_failure(self, endpoint: Endpoint, error: ProviderError, *, now: Optional[float] = None) -> float:
        """
        Park an endpoint appropriately and return how long it is parked for.

        A 429 with a ``Retry-After`` is honoured exactly. Other retryable
        statuses get exponential backoff with jitter. Auth failures disable the
        endpoint permanently -- retrying a bad key is never going to work.
        """
        now = self._clock() if now is None else now
        stats = endpoint.stats
        stats.attempts += 1
        stats.failures += 1
        stats.last_error = f"{error.status} {error}"

        if error.status in (401, 403):
            endpoint.permanent_error = f"rejected the key ({error.status})"
            return 0.0

        if error.status == 404:
            endpoint.permanent_error = f"model '{endpoint.model}' not found on this provider"
            return 0.0

        if error.status == 429:
            stats.rate_limits += 1
            pause = error.retry_after
            if pause is None:
                pause = self._backoff(stats.rate_limits)
            endpoint.parked_until = now + max(0.5, pause)
            return endpoint.parked_until - now

        if error.status in self.routing.retry_statuses or error.status == 0:
            pause = self._backoff(stats.failures)
            endpoint.parked_until = now + pause
            return pause

        # 400 and friends are our fault, not a transient condition.
        endpoint.permanent_error = f"request rejected ({error.status})"
        return 0.0

    def _backoff(self, attempt: int) -> float:
        base = self.routing.backoff_base_seconds * (2 ** max(0, attempt - 1))
        capped = min(base, self.routing.backoff_max_seconds)
        # Full jitter: avoids every key in the pool retrying in lockstep.
        return self._rng.uniform(capped / 2, capped) if capped > 0 else 0.0

    # -- reporting --------------------------------------------------------
    def as_dict(self) -> dict:
        now = self._clock()
        return {
            "endpoint_count": len(self.endpoints),
            "usable": len(self.usable),
            "strategy": self.routing.strategy,
            "total_waited_seconds": round(self.total_waited, 2),
            "endpoints": [e.as_dict(now) for e in self.endpoints],
        }

    def format(self) -> str:
        now = self._clock()
        if not self.endpoints:
            return "no AI endpoint is configured -- see `apkmod ai doctor`"
        lines = [
            f"{len(self.endpoints)} endpoint(s), strategy={self.routing.strategy}, "
            f"waited {self.total_waited:.1f}s total"
        ]
        for endpoint in self.endpoints:
            stats = endpoint.stats
            parked = endpoint.parked_until - now
            flag = "off  " if endpoint.permanent_error else ("wait " if parked > 0 else "ready")
            lines.append(f"[{flag}] {endpoint.label}  ok={stats.successes} fail={stats.failures} 429={stats.rate_limits}")
            if endpoint.permanent_error:
                lines.append(f"        disabled: {endpoint.permanent_error}")
            elif parked > 0:
                lines.append(f"        parked for {parked:.0f}s (rate limit)")
            if stats.last_error:
                lines.append(f"        last error: {stats.last_error}")
        return "\n".join(lines)
