"""
The AI layer: one agent, many cloud providers, automatic routing.

Layout
------
``config``      providers, keys and routing settings (file + environment)
``providers``   OpenAI-compatible / Anthropic / Gemini wire formats, normalised
``router``      picks an endpoint; parks and waits on rate limits
``client``      HTTP plus the retry loop that never abandons a task on a 429
``tools``       the capabilities the model may drive, contained to a work dir
``agent``       chat -> tool calls -> results -> chat, until it finishes

Nothing here is imported by the rest of the package at import time, so a user
who never configures a key pays nothing for it.
"""

from __future__ import annotations

from .agent import SYSTEM_PROMPT, Agent, AgentResult, Step
from .client import AIClient, HttpTransport, Response, Transport
from .config import AIConfig, ProviderConfig, RoutingConfig, load_config, mask_key
from .providers import ChatResult, Message, ProviderError, ToolCall, ToolSpec, Usage
from .router import Endpoint, NoEndpointAvailable, Router
from .tools import ToolContext, ToolRegistry, build_registry

__all__ = [
    "SYSTEM_PROMPT",
    "Agent",
    "AgentResult",
    "Step",
    "AIClient",
    "HttpTransport",
    "Response",
    "Transport",
    "AIConfig",
    "ProviderConfig",
    "RoutingConfig",
    "load_config",
    "mask_key",
    "ChatResult",
    "Message",
    "ProviderError",
    "ToolCall",
    "ToolSpec",
    "Usage",
    "Endpoint",
    "NoEndpointAvailable",
    "Router",
    "ToolContext",
    "ToolRegistry",
    "build_registry",
]
