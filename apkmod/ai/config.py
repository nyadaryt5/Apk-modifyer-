"""
Configuration for the AI layer.

Everything is optional. Nothing here makes a network call, so a machine with no
keys at all still gets a usable, accurate answer from ``apkmod ai doctor`` --
it simply reports that there is nothing configured.

Precedence, highest first:

1. an explicit config file passed with ``--config``
2. ``$APKMOD_AI_CONFIG``
3. ``~/.apkmod/ai.json``
4. environment variables, which are always merged in so a single exported key
   works with no file at all

Keys are never logged and never echoed back by ``ai doctor``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..util import ApkModError

__all__ = ["ProviderConfig", "RoutingConfig", "AIConfig", "load_config", "mask_key"]

# Environment variables that, when set, imply a provider even with no file.
ENV_PROVIDERS = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY", "CLAUDE_API_KEY"),
    "google": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "openrouter": ("OPENROUTER_API_KEY",),
    "groq": ("GROQ_API_KEY",),
    "deepseek": ("DEEPSEEK_API_KEY",),
    "mistral": ("MISTRAL_API_KEY",),
    "xai": ("XAI_API_KEY",),
    "together": ("TOGETHER_API_KEY",),
    "fireworks": ("FIREWORKS_API_KEY",),
}

# A comma/space separated list that applies to every configured provider.
ENV_ANY_KEY = ("APKMOD_AI_KEYS", "AI_API_KEYS")

DEFAULT_CONFIG_PATH = "~/.apkmod/ai.json"


def mask_key(key: str) -> str:
    """Enough of a key to recognise it, nowhere near enough to use it."""
    if not key:
        return "<empty>"
    if len(key) <= 12:
        return key[:2] + "*" * 6
    return f"{key[:6]}...{key[-4:]} ({len(key)} chars)"


@dataclass
class ProviderConfig:
    """One upstream AI service, possibly with several keys behind it."""

    name: str
    kind: str = "openai"  # openai | anthropic | google
    base_url: str = ""
    keys: List[str] = field(default_factory=list)
    models: List[str] = field(default_factory=list)
    enabled: bool = True
    weight: int = 1
    timeout: int = 120
    extra_headers: Dict[str, str] = field(default_factory=dict)

    @property
    def usable_keys(self) -> List[str]:
        return [k for k in self.keys if k]

    def as_dict(self, *, redact: bool = True) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "base_url": self.base_url,
            "keys": [mask_key(k) if redact else k for k in self.keys],
            "key_count": len(self.usable_keys),
            "models": self.models,
            "enabled": self.enabled,
            "weight": self.weight,
            "timeout": self.timeout,
        }


@dataclass
class RoutingConfig:
    """How the router picks between endpoints and how hard it waits."""

    strategy: str = "priority"  # priority | round-robin | lowest-latency
    max_wait_seconds: int = 1800
    max_attempts_per_endpoint: int = 4
    max_total_attempts: int = 24
    backoff_base_seconds: float = 1.0
    backoff_max_seconds: float = 60.0
    retry_statuses: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])
    cooldown_seconds: int = 60

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "max_wait_seconds": self.max_wait_seconds,
            "max_attempts_per_endpoint": self.max_attempts_per_endpoint,
            "max_total_attempts": self.max_total_attempts,
            "backoff_base_seconds": self.backoff_base_seconds,
            "backoff_max_seconds": self.backoff_max_seconds,
            "retry_statuses": self.retry_statuses,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass
class AIConfig:
    providers: List[ProviderConfig] = field(default_factory=list)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    default_model: Optional[str] = None
    path: Optional[Path] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def enabled_providers(self) -> List[ProviderConfig]:
        return [p for p in self.providers if p.enabled and p.usable_keys]

    def as_dict(self, *, redact: bool = True) -> dict:
        return {
            "path": str(self.path) if self.path else None,
            "default_model": self.default_model,
            "providers": [p.as_dict(redact=redact) for p in self.providers],
            "routing": self.routing.as_dict(),
            "warnings": self.warnings,
        }


def _resolve_path(explicit: Optional[str]) -> Optional[Path]:
    raw = explicit or os.environ.get("APKMOD_AI_CONFIG")
    if raw:
        return Path(raw).expanduser()
    default = Path(DEFAULT_CONFIG_PATH).expanduser()
    return default if default.is_file() else None


def _from_env_keys(provider: str) -> List[str]:
    keys: List[str] = []
    for var in ENV_PROVIDERS.get(provider, ()):
        value = os.environ.get(var)
        if value:
            keys.append(value.strip())
    return keys


def _shared_keys() -> List[str]:
    out: List[str] = []
    for var in ENV_ANY_KEY:
        value = os.environ.get(var)
        if value:
            out.extend(part.strip() for part in value.replace(",", " ").split() if part.strip())
    return out


def _coerce_provider(raw: dict, index: int, warnings: List[str]) -> ProviderConfig:
    if not isinstance(raw, dict):
        warnings.append(f"providers[{index}] is not an object; ignored")
        return ProviderConfig(name=f"provider-{index}")
    name = str(raw.get("name") or raw.get("id") or f"provider-{index}")
    keys: List[str] = []
    raw_keys = raw.get("keys") or []
    if isinstance(raw_keys, str):
        keys.append(raw_keys)
    elif isinstance(raw_keys, list):
        keys.extend(str(k) for k in raw_keys if k)
    # A single "key"/"api_key" field is friendlier than a one-element list.
    for alias in ("key", "api_key", "apiKey"):
        if raw.get(alias):
            keys.append(str(raw[alias]))
    for var in raw.get("env", []) or []:
        value = os.environ.get(str(var))
        if value:
            keys.append(value.strip())
    provider = ProviderConfig(
        name=name,
        kind=str(raw.get("kind") or raw.get("type") or "openai").lower(),
        base_url=str(raw.get("base_url") or raw.get("baseUrl") or "").rstrip("/"),
        keys=keys,
        models=[str(m) for m in (raw.get("models") or [])],
        enabled=bool(raw.get("enabled", True)),
        weight=int(raw.get("weight", 1)),
        timeout=int(raw.get("timeout", 120)),
        extra_headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
    )
    if provider.kind not in ("openai", "anthropic", "google"):
        warnings.append(
            f"provider '{name}' has kind '{provider.kind}'; "
            "expected openai, anthropic or google -- treating as openai-compatible"
        )
        provider.kind = "openai"
    return provider


def load_config(explicit: Optional[str] = None, *, use_env: bool = True) -> AIConfig:
    """Read the config file, then merge in anything the environment supplies."""
    warnings: List[str] = []
    config = AIConfig(path=_resolve_path(explicit))

    if config.path is not None:
        if not config.path.is_file():
            raise ApkModError(f"no AI config at {config.path}")
        try:
            raw = json.loads(config.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ApkModError(f"{config.path} is not valid JSON: {exc}") from None
        if not isinstance(raw, dict):
            raise ApkModError(f"{config.path} must contain a JSON object")

        providers = raw.get("providers") or []
        if isinstance(providers, dict):
            providers = [dict(v, name=k) for k, v in providers.items()]
        for index, entry in enumerate(providers):
            config.providers.append(_coerce_provider(entry, index, warnings))

        routing = raw.get("routing") or {}
        if isinstance(routing, dict):
            known = {f for f in RoutingConfig.__dataclass_fields__}
            for key, value in routing.items():
                if key in known:
                    setattr(config.routing, key, value)
                else:
                    warnings.append(f"routing.{key} is not a known setting; ignored")
        config.default_model = raw.get("default_model") or raw.get("defaultModel")

    if use_env:
        _merge_env(config, warnings)

    _dedupe_keys(config)
    # The warnings were collected into a local list; without this line they are
    # silently dropped and a malformed config looks fine.
    config.warnings = warnings
    return config


def _merge_env(config: AIConfig, warnings: List[str]) -> None:
    """Environment keys fill in existing providers, or create one per family."""
    shared = _shared_keys()
    by_name = {p.name.lower(): p for p in config.providers}

    for family, variables in ENV_PROVIDERS.items():
        found = [os.environ[v].strip() for v in variables if os.environ.get(v)]
        provider = by_name.get(family)
        if provider is None and found:
            provider = ProviderConfig(name=family, kind=_kind_for(family))
            config.providers.append(provider)
            by_name[family] = provider
        if provider is not None:
            provider.keys.extend(found)

    if shared:
        targets = [p for p in config.providers if not p.usable_keys] or config.providers
        for provider in targets:
            provider.keys.extend(shared)
        if not config.providers:
            warnings.append("APKMOD_AI_KEYS is set but no provider is configured to use it")


def _kind_for(family: str) -> str:
    if family == "anthropic":
        return "anthropic"
    if family == "google":
        return "google"
    return "openai"


def _dedupe_keys(config: AIConfig) -> None:
    """Keep key order but drop repeats, so a key in both file and env is one key."""
    for provider in config.providers:
        seen = set()
        unique = []
        for key in provider.keys:
            key = key.strip()
            if key and key not in seen:
                seen.add(key)
                unique.append(key)
        provider.keys = unique
