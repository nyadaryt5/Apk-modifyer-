"""
Base AI Provider Interface.
Defines standard chat, completion, and tool-calling protocols for all AI Cloud adapters.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, AsyncGenerator

class BaseAIProvider(ABC):
    """Abstract interface for multi-cloud AI providers."""
    
    def __init__(self, provider_name: str, api_keys: List[str], base_url: Optional[str] = None, default_model: Optional[str] = None):
        self.provider_name = provider_name
        self.api_keys = [k.strip() for k in api_keys if k and k.strip()]
        self.current_key_idx = 0
        self.base_url = base_url
        self.default_model = default_model

    def get_current_key(self) -> Optional[str]:
        if not self.api_keys:
            return None
        return self.api_keys[self.current_key_idx % len(self.api_keys)]

    def rotate_key(self) -> Optional[str]:
        if not self.api_keys:
            return None
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
        return self.get_current_key()

    @abstractmethod
    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute chat completion request."""
        pass

    @abstractmethod
    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        api_key: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        """Stream chat tokens."""
        pass
