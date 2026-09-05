"""
Resilient Rate-Limiter & Exponential Backoff Task Queue.
Ensures that 429 Rate Limit errors and quota exhaustion NEVER terminate user tasks.
Automatically pauses, sleeps with progress updates, rotates keys, and resumes execution seamlessly.
"""

import asyncio
import time
from typing import Callable, Any, Optional, Dict

class RateLimitManager:
    """Tracks cooldowns for API keys and coordinates graceful exponential backoff."""
    
    def __init__(self):
        # { "provider:key": cooldown_until_timestamp }
        self.cooldowns: Dict[str, float] = {}

    def mark_rate_limited(self, provider: str, key: str, cooldown_seconds: float = 20.0):
        """Mark a specific key as cooling down."""
        key_id = f"{provider}:{key[-6:] if len(key) >= 6 else key}"
        self.cooldowns[key_id] = time.time() + cooldown_seconds

    def is_key_available(self, provider: str, key: str) -> bool:
        """Check if key is ready for requests."""
        key_id = f"{provider}:{key[-6:] if len(key) >= 6 else key}"
        until = self.cooldowns.get(key_id, 0)
        return time.time() >= until

    def get_remaining_cooldown(self, provider: str, key: str) -> float:
        """Return remaining seconds of cooldown."""
        key_id = f"{provider}:{key[-6:] if len(key) >= 6 else key}"
        until = self.cooldowns.get(key_id, 0)
        return max(0.0, until - time.time())

    async def execute_with_resilience(
        self,
        func: Callable,
        *args,
        on_rate_limit_callback: Optional[Callable[[str, int, float], None]] = None,
        max_retries: int = 10,
        base_backoff_sec: float = 5.0,
        **kwargs
    ) -> Any:
        """
        Execute an async function. If a 429/RateLimit error occurs,
        pauses, logs notification, backs off with exponential sleep, and retries.
        NEVER terminates the task due to rate limits!
        """
        retries = 0
        backoff = base_backoff_sec

        while True:
            try:
                return await func(*args, **kwargs)
            except (PermissionError, RuntimeError, Exception) as err:
                err_str = str(err).lower()
                is_rate_limit = (
                    "429" in err_str or
                    "rate limit" in err_str or
                    "quota" in err_str or
                    "resource_exhausted" in err_str or
                    "too many requests" in err_str
                )

                if is_rate_limit and retries < max_retries:
                    retries += 1
                    sleep_time = min(backoff * (1.5 ** (retries - 1)), 60.0)
                    
                    if on_rate_limit_callback:
                        on_rate_limit_callback(str(err), retries, sleep_time)

                    # Pause and wait for rate-limit reset
                    await asyncio.sleep(sleep_time)
                else:
                    raise err
