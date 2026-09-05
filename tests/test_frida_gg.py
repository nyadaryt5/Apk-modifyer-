"""
Automated Test Suite for Frida Dynamic Instrumentation & Game Guardian Engines.
"""

import unittest
from omniapk.modules.frida import FridaScriptGenerator
from omniapk.modules.game_guardian import MemoryScanner, GameGuardianScriptBuilder

class TestFridaAndGameGuardian(unittest.TestCase):
    def test_frida_ssl_unpinning_generator(self):
        script = FridaScriptGenerator.get_universal_ssl_unpinning()
        self.assertIn("CertificatePinner", script)
        self.assertIn("X509TrustManager", script)
        self.assertIn("Java.perform", script)

    def test_frida_root_bypass_generator(self):
        script = FridaScriptGenerator.get_universal_root_bypass()
        self.assertIn("Superuser.apk", script)
        self.assertIn("File.exists", script)
        self.assertIn("Runtime.exec", script)

    def test_frida_custom_hook_generator(self):
        hook = FridaScriptGenerator.generate_method_hook("com.target.app.MainActivity", "isPremium", "true")
        self.assertIn("com.target.app.MainActivity", hook)
        self.assertIn("isPremium", hook)
        self.assertIn("return true", hook)

    def test_game_guardian_memory_scanner(self):
        scanner = MemoryScanner()
        scanner.load_simulated_state({
            0x100: 100,
            0x200: 50,
            0x300: 100,
            0x400: 100
        }, "DWORD")

        matches = scanner.search_exact(100, "DWORD")
        self.assertIn(0x100, matches)
        self.assertIn(0x300, matches)
        self.assertIn(0x400, matches)
        self.assertNotIn(0x200, matches)

        # Refine search after simulated change at 0x300 to 120
        scanner.write_memory(0x300, 120, "DWORD")
        refined = scanner.refine_search(100)
        self.assertIn(0x100, refined)
        self.assertNotIn(0x300, refined)

        # Batch edit
        edited_count = scanner.batch_edit_matches(999999)
        self.assertEqual(edited_count, len(refined))
        self.assertEqual(scanner.read_memory(0x100, "DWORD"), 999999)

    def test_game_guardian_lua_script_builder(self):
        searches = [{"name": "Gold", "target_val": 100, "new_val": 999999, "type": "DWORD"}]
        lua = GameGuardianScriptBuilder.generate_lua_script("TestGame", searches, speedhack_speed=2.5)
        self.assertIn("gg.searchNumber", lua)
        self.assertIn("999999", lua)
        self.assertIn("gg.setSpeed(2.5)", lua)

if __name__ == "__main__":
    unittest.main()
