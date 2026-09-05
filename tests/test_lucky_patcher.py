"""
Automated Test Suite for Lucky Patcher Engine.
"""

import unittest
from pathlib import Path

from omniapk.modules.lucky_patcher import LuckyPatcherEngine, AdRemover, BillingBypass, LicenseBypass
from omniapk.core.dex_parser import DexParser
from samples.make_sample_apk import generate_sample_apk
import zipfile

class TestLuckyPatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_apk = Path("samples/sample_target.apk")
        if not cls.sample_apk.exists():
            generate_sample_apk(cls.sample_apk)

    def test_ad_remover(self):
        out_apk = Path("samples/test_noads.apk")
        res = AdRemover.patch_apk(self.sample_apk, out_apk)
        self.assertTrue(res["success"])
        self.assertTrue(out_apk.exists())

        # Verify Manifest has no AdMob
        with zipfile.ZipFile(out_apk, "r") as zf:
            manifest = zf.read("AndroidManifest.xml").decode("utf-8")
            self.assertNotIn("com.google.android.gms.permission.AD_ID", manifest)
            self.assertNotIn("AdActivity", manifest)

        if out_apk.exists():
            out_apk.unlink()

    def test_billing_bypass(self):
        out_apk = Path("samples/test_billing.apk")
        res = BillingBypass.patch_apk(self.sample_apk, out_apk)
        self.assertTrue(res["success"])
        self.assertGreater(res["methods_patched_count"], 0)

        # Verify isPremium bytecode in DEX
        with zipfile.ZipFile(out_apk, "r") as zf:
            parser = DexParser(zf.read("classes.dex"))
            prem_method = parser.classes[0]["virtual_methods"][0]
            dis = parser.disassemble_method(prem_method["code_off"])
            self.assertIn("const/4 v0, 0x1", dis["smali"])

        if out_apk.exists():
            out_apk.unlink()

    def test_full_lucky_patcher_pipeline(self):
        out_apk = Path("samples/test_full_lp.apk")
        res = LuckyPatcherEngine.apply_auto_patch(
            apk_path=self.sample_apk,
            output_apk=out_apk,
            remove_ads=True,
            bypass_billing=True,
            bypass_license=True,
            bypass_root_checks=True,
            sign=True
        )
        self.assertTrue(res["success"])
        self.assertTrue(out_apk.exists())
        self.assertTrue(res["signed"])

        if out_apk.exists():
            out_apk.unlink()

if __name__ == "__main__":
    unittest.main()
