"""
Automated Test Suite for Cloud AI Router, Rate Limiter & Autonomous Mod Agent.
"""

import unittest
import asyncio
from pathlib import Path

from omniapk.ai.router import AIRouter
from omniapk.ai.rate_limiter import RateLimitManager
from omniapk.ai.agent import OmniAgent
from samples.make_sample_apk import generate_sample_apk

class TestAIRouterAndAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_apk = Path("samples/sample_target.apk")
        if not cls.sample_apk.exists():
            generate_sample_apk(cls.sample_apk)

    def test_rate_limiter_exponential_backoff_resilience(self):
        """Verify that 429 RateLimit errors NEVER terminate tasks, but wait and retry."""
        limiter = RateLimitManager()
        attempt_counter = 0
        backoff_events = []

        async def flaky_api_call():
            nonlocal attempt_counter
            attempt_counter += 1
            if attempt_counter < 3:
                raise PermissionError("RateLimitError: 429 Too Many Requests on API key")
            return {"status": "success", "attempts": attempt_counter}

        def on_limit(err, retry_num, sleep_time):
            backoff_events.append((retry_num, sleep_time))

        result = asyncio.run(limiter.execute_with_resilience(
            flaky_api_call,
            on_rate_limit_callback=on_limit,
            base_backoff_sec=0.01 # Fast backoff for unit tests
        ))

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(len(backoff_events), 2)

    def test_ai_router_chat_and_fallback(self):
        router = AIRouter()
        # Test routing with local heuristic fallback
        res = asyncio.run(router.chat(
            messages=[
                {"role": "user", "content": "Analyze APK: Strip AdMob ads and unlock VIP features"}
            ]
        ))

        self.assertIn("content", res)
        self.assertIn("Ad", res["content"])

    def test_autonomous_ai_agent_task(self):
        agent = OmniAgent()
        events = []

        def on_event(ev):
            events.append(ev)

        result = asyncio.run(agent.run_autonomous_mod_task(
            apk_path=self.sample_apk,
            user_prompt="Unlock VIP premium, remove ads, bypass root detection, and sign the APK",
            on_event_callback=on_event
        ))

        self.assertTrue(result["success"])
        self.assertTrue(Path(result["output_apk"]).exists())
        self.assertGreater(len(result["actions_taken"]), 0)
        self.assertGreater(len(events), 3)

if __name__ == "__main__":
    unittest.main()
