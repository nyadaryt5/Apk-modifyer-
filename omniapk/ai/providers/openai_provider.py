"""
OpenAI Cloud Provider Adapter (GPT-4o, GPT-4o-mini, o1, o3).
Supports HTTP REST and async streaming with rate-limit error detection.
"""

import json
import aiohttp
from typing import List, Dict, Any, Optional, AsyncGenerator
from omniapk.ai.providers.base import BaseAIProvider

class OpenAIProvider(BaseAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "gpt-4o"):
        super().__init__("openai", api_keys, base_url or "https://api.openai.com/v1", default_model)

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
            raise ValueError("No OpenAI API key provided.")

        url = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model or self.default_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=90)) as resp:
                status = resp.status
                if status == 429:
                    raise PermissionError(f"RateLimitError: 429 Too Many Requests on OpenAI key ...{key[-4:] if len(key)>4 else key}")
                if status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"OpenAI API error {status}: {text}")
                data = await resp.json()
                content = data["choices"][0]["message"]["content"]
                return {
                    "provider": "openai",
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
        key = api_key or self.get_current_key()
        if not key:
            raise ValueError("No OpenAI API key provided.")

        url = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model or self.default_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                if resp.status == 429:
                    raise PermissionError(f"RateLimitError: 429 Too Many Requests on OpenAI key")
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"OpenAI Stream error {resp.status}: {text}")
                
                async for line in resp.content:
                    line_str = line.decode("utf-8").strip()
                    if line_str.startswith("data: "):
                        data_str = line_str[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta and delta["content"]:
                                yield delta["content"]
                        except Exception:
                            continue
