"""
Groq & DeepSeek & Mistral & OpenRouter & Custom OpenAI-Compatible Adapters.
"""

from typing import List, Optional
from omniapk.ai.providers.openai_provider import OpenAIProvider

class GroqProvider(OpenAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "llama-3.3-70b-versatile"):
        super().__init__(api_keys, base_url or "https://api.groq.com/openai/v1", default_model)
        self.provider_name = "groq"

class DeepSeekProvider(OpenAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "deepseek-chat"):
        super().__init__(api_keys, base_url or "https://api.deepseek.com/v1", default_model)
        self.provider_name = "deepseek"

class MistralProvider(OpenAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "mistral-large-latest"):
        super().__init__(api_keys, base_url or "https://api.mistral.ai/v1", default_model)
        self.provider_name = "mistral"

class OpenRouterProvider(OpenAIProvider):
    def __init__(self, api_keys: List[str], base_url: Optional[str] = None, default_model: str = "auto"):
        super().__init__(api_keys, base_url or "https://openrouter.ai/api/v1", default_model)
        self.provider_name = "openrouter"

class CustomAIProvider(OpenAIProvider):
    def __init__(self, api_keys: List[str], base_url: str, default_model: str = "custom-model"):
        super().__init__(api_keys, base_url, default_model)
        self.provider_name = "custom"
