"""
The HTTP layer and the retry loop that sits on top of the router.

``Transport`` is an injection point: the default does real HTTPS with the
standard library (this package has no hard dependencies), and the tests swap in
a scripted transport so rate-limit behaviour is verified without a network or a
real sleep.

The loop's contract, which is the whole point of the module: a 429 parks the
endpoint and the request moves on or waits. It does not surface as an error to
the caller unless every endpoint is gone or the wait budget runs out.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..util import ApkModError
from .config import AIConfig, load_config
from .providers import (
    ChatResult,
    DEFAULT_BASE_URLS,
    Message,
    ProviderError,
    ToolSpec,
    auth_headers,
    auth_query,
    decode_response,
    encode_request,
    request_path,
)
from .router import NoEndpointAvailable, Router

__all__ = ["Response", "Transport", "HttpTransport", "AIClient", "default_base_url"]


@dataclass
class Response:
    status: int
    body: str
    headers: dict


class Transport:
    """Swap this out in tests to script provider behaviour."""

    def post(self, url: str, headers: dict, body: bytes, timeout: int) -> Response:
        raise NotImplementedError


class HttpTransport(Transport):
    def post(self, url: str, headers: dict, body: bytes, timeout: int) -> Response:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as handle:
                return Response(
                    status=handle.status,
                    body=handle.read().decode("utf-8", "replace"),
                    headers=dict(handle.headers.items()),
                )
        except urllib.error.HTTPError as exc:
            # A 429 is not an exception for our purposes -- it is data.
            payload = exc.read().decode("utf-8", "replace") if exc.fp else ""
            return Response(status=exc.code, body=payload, headers=dict(exc.headers.items() or {}))
        except urllib.error.URLError as exc:
            # Network-level failure: status 0 so the router treats it as retryable.
            return Response(status=0, body=f"network error: {exc.reason}", headers={})
        except TimeoutError:
            return Response(status=0, body="request timed out", headers={})


def default_base_url(kind: str, explicit: str = "") -> str:
    if explicit:
        return explicit.rstrip("/")
    return DEFAULT_BASE_URLS.get(kind, DEFAULT_BASE_URLS["openai"])


def _retry_after(headers: dict) -> Optional[float]:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        # HTTP-date form; treat as "wait a minute" rather than parsing dates.
        return 60.0


class AIClient:
    """Send one chat request, transparently across every configured endpoint."""

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        *,
        transport: Optional[Transport] = None,
        router: Optional[Router] = None,
        clock: Callable[[], float] = time.monotonic,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ) -> None:
        self.config = config if config is not None else load_config()
        self.transport = transport or HttpTransport()
        self._clock = clock
        self.router = router or Router(self.config, clock=clock)
        self.on_event = on_event or (lambda kind, payload: None)

    # -- public -----------------------------------------------------------
    def chat(
        self,
        messages: List[Message],
        *,
        tools: Optional[List[ToolSpec]] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        extra: Optional[dict] = None,
    ) -> ChatResult:
        """
        Return one completion, waiting out rate limits rather than failing.

        Raises :class:`ApkModError` only when nothing is configured, every
        endpoint is permanently disabled, or the wait budget is spent.
        """
        if not self.router.endpoints:
            raise ApkModError(
                "no AI provider is configured -- set an API key or write ~/.apkmod/ai.json "
                "(see `apkmod ai doctor`)"
            )

        routing = self.config.routing
        total = 0
        last_error: Optional[ProviderError] = None

        while total < routing.max_total_attempts:
            total += 1
            try:
                decision = self.router.next_endpoint()
            except NoEndpointAvailable as exc:
                raise ApkModError(str(exc)) from None

            endpoint = decision.endpoint
            if decision.waited_seconds:
                self.on_event(
                    "waited",
                    {
                        "endpoint": endpoint.label,
                        "waited_seconds": round(decision.waited_seconds, 2),
                        "reason": "rate limited",
                    },
                )
            if decision.parked_skipped:
                self.on_event("parked", {"endpoints": decision.parked_skipped})

            wanted = model or endpoint.model
            self.on_event("request", {"endpoint": endpoint.label, "model": wanted, "attempt": total})

            started = self._clock()
            try:
                result = self._one_request(
                    endpoint, wanted, messages, tools, temperature, max_tokens, extra
                )
            except ProviderError as exc:
                parked = self.router.report_failure(endpoint, exc, now=self._clock())
                last_error = exc
                self.on_event(
                    "error",
                    {
                        "endpoint": endpoint.label,
                        "status": exc.status,
                        "message": str(exc)[:200],
                        "parked_seconds": round(parked, 1),
                    },
                )
                continue

            latency = self._clock() - started
            self.router.report_success(
                endpoint,
                latency,
                tokens_in=result.usage.prompt_tokens,
                tokens_out=result.usage.completion_tokens,
            )
            self.on_event(
                "response",
                {
                    "endpoint": endpoint.label,
                    "model": result.model,
                    "latency_ms": round(latency * 1000, 1),
                    "tokens": result.usage.total_tokens,
                },
            )
            result.provider = endpoint.provider.name
            return result

        raise ApkModError(
            f"gave up after {total} attempts across "
            f"{len(self.router.usable)} endpoint(s); last error: {last_error}"
        )

    # -- internals --------------------------------------------------------
    def _one_request(
        self,
        endpoint,
        model: str,
        messages: List[Message],
        tools: Optional[List[ToolSpec]],
        temperature: Optional[float],
        max_tokens: Optional[int],
        extra: Optional[dict],
    ) -> ChatResult:
        provider = endpoint.provider
        body = encode_request(
            provider.kind,
            messages,
            model,
            tools,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra,
        )
        keys = provider.usable_keys
        api_key = keys[endpoint.key_index] if endpoint.key_index < len(keys) else ""
        base = default_base_url(provider.kind, provider.base_url)
        url = base + request_path(provider.kind, model) + auth_query(provider.kind, api_key)

        headers = {"Content-Type": "application/json"}
        headers.update(auth_headers(provider.kind, api_key))
        headers.update(provider.extra_headers)

        response = self.transport.post(
            url, headers, json.dumps(body, ensure_ascii=False).encode("utf-8"), provider.timeout
        )

        if response.status == 200:
            try:
                payload = json.loads(response.body)
            except json.JSONDecodeError as exc:
                # A 200 that is not JSON is a gateway or proxy misbehaving.
                raise ProviderError(f"non-JSON body: {exc}", status=502) from None
            return decode_response(provider.kind, payload, provider.name)

        raise self._error_from(response, provider.name)

    @staticmethod
    def _error_from(response: Response, provider: str) -> ProviderError:
        detail = response.body[:400].strip()
        # Providers put the useful sentence in different places.
        try:
            parsed = json.loads(response.body)
            for path in (("error", "message"), ("error",), ("message",)):
                node = parsed
                for key in path:
                    node = node.get(key) if isinstance(node, dict) else None
                    if node is None:
                        break
                if isinstance(node, str) and node.strip():
                    detail = node.strip()
                    break
        except (json.JSONDecodeError, AttributeError):
            pass
        return ProviderError(
            f"{provider}: {detail or response.body[:200]}",
            status=response.status,
            retry_after=_retry_after(response.headers),
        )

    # -- reporting --------------------------------------------------------
    def describe(self) -> str:
        return self.router.format()

    def as_dict(self) -> dict:
        return self.router.as_dict()
