"""
Google Gemini Cloud Provider Adapter (Gemini 1.5 Pro / Flash / 2.0).
"""

import json
import aiohttp
from typing import List, Dict, Any, Optional, AsyncGenerator
from omniapk.ai.providers.base import BaseAIProvider

class GeminiProvider(BaseAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "gemini-1.5-flash"):
        super().__init__("gemini", api_keys, base_url or "https://generativelanguage.googleapis.com/v1beta", default_model)

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
            raise ValueError("No Gemini API key provided.")

        m_name = model or self.default_model
        url = f"{self.base_url.rstrip('/')}/models/{m_name}:generateContent?key={key}"
        
        # Convert standard OpenAI-style messages to Gemini format
        contents = []
        for m in messages:
            role = "user" if m["role"] in ("user", "system") else "model"
            contents.append({
                "role": role,
                "parts": [{"text": m["content"]}]
            })

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens
            }
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=90)) as resp:
                if resp.status == 429:
                    raise PermissionError(f"RateLimitError: 429 Quota exhausted on Google Gemini key")
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"Gemini API error {resp.status}: {text}")
                data = await resp.json()
                content = data["candidates"][0]["content"]["parts"][0]["text"]
                return {
                    "provider": "gemini",
                    "model": m_name,
                    "content": content,
                    "usage": data.get("usageMetadata", {})
                }

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        api_key: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        res = await self.chat(messages, model, temperature, max_tokens, api_key)
        yield res["content"]
