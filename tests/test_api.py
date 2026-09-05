"""
Automated Test Suite for FastAPI Endpoints.
"""

import unittest
from pathlib import Path
from starlette.testclient import TestClient

from omniapk.server.app import app
from samples.make_sample_apk import generate_sample_apk

class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.sample_apk = Path("samples/sample_target.apk")
        if not cls.sample_apk.exists():
            generate_sample_apk(cls.sample_apk)

    def test_system_info_endpoint(self):
        res = self.client.get("/api/system/info")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("platform", data)
        self.assertIn("arch", data)

    def test_apk_list_endpoint(self):
        res = self.client.get("/api/apk/list")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("apks", data)

    def test_inspect_endpoint(self):
        res = self.client.post("/api/apk/inspect", json={"apk_path": str(self.sample_apk)})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["filename"], "sample_target.apk")

    def test_lucky_patch_endpoint(self):
        res = self.client.post("/api/apk/lucky_patch", json={
            "apk_path": str(self.sample_apk),
            "remove_ads": True,
            "bypass_billing": True,
            "bypass_license": True,
            "bypass_root": True,
            "sign": True
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])

    def test_frida_generate_endpoint(self):
        res = self.client.post("/api/frida/generate", json={
            "package_name": "com.target.sampleapp",
            "class_name": "com.target.app.MainActivity",
            "method_name": "isPremium",
            "return_value": "true"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("ssl_unpinning", data)
        self.assertIn("custom_hook", data)

    def test_game_guardian_search_endpoint(self):
        res = self.client.post("/api/game_guardian/search", json={
            "value": 100,
            "value_type": "DWORD",
            "is_refine": False
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreater(data["matches_count"], 0)

if __name__ == "__main__":
    unittest.main()
