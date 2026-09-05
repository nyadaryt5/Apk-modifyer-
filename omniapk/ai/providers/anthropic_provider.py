"""
Anthropic Claude Cloud Provider Adapter (Claude 3.5 Sonnet / Haiku / Opus).
"""

import json
import aiohttp
from typing import List, Dict, Any, Optional, AsyncGenerator
from omniapk.ai.providers.base import BaseAIProvider

class AnthropicProvider(BaseAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "claude-3-5-sonnet-20241022"):
        super().__init__("anthropic", api_keys, base_url or "https://api.anthropic.com/v1", default_model)

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        key = api_key or self.get_current_key()
        if not key:
            raise ValueError("No Anthropic API key provided.")

        url = f"{self.base_url.rstrip('/')}/messages"
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }

        # Separate system message if present
        system_prompt = ""
        anthropic_msgs = []
        for m in messages:
            if m["role"] == "system":
                system_prompt = m["content"]
            else:
                anthropic_msgs.append({"role": m["role"], "content": m["content"]})

        payload = {
            "model": model or self.default_model,
            "messages": anthropic_msgs,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=90)) as resp:
                if resp.status == 429:
                    raise PermissionError(f"RateLimitError: 429 Rate limit exceeded on Anthropic key")
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"Anthropic API error {resp.status}: {text}")
                data = await resp.json()
                content = data["content"][0]["text"]
                return {
                    "provider": "anthropic",
                    "model": model or self.default_model,
                    "content": content,
                    "usage": data.get("usage", {})
                }

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        api_key: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        # For simplicity, fallback to non-streaming chat yields
        res = await self.chat(messages, model, temperature, max_tokens, api_key)
        yield res["content"]
