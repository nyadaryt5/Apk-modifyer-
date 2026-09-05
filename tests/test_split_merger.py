"""
Automated Test Suite for MT Manager Anti-Split Merger, Batch Regex & Diff.
"""

import unittest
import zipfile
from pathlib import Path

from omniapk.modules.mt_manager import AntiSplitMerger, BatchRegexPatcher, ApkDiffer
from samples.make_sample_apk import generate_minimal_dex, generate_sample_apk

class TestSplitMergerAndMtManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path("samples/split_test")
        cls.test_dir.mkdir(parents=True, exist_ok=True)
        
        # Create base.apk
        cls.base_apk = cls.test_dir / "base.apk"
        generate_sample_apk(cls.base_apk)

        # Create split_config.arm64_v8a.apk
        cls.split_config = cls.test_dir / "split_config.arm64_v8a.apk"
        with zipfile.ZipFile(cls.split_config, "w") as zf:
            zf.writestr("lib/arm64-v8a/libgamecore.so", b"\x7fELFfake_arm64_lib_data")
            zf.writestr("classes.dex", generate_minimal_dex())

    def test_anti_split_merger(self):
        merged_out = self.test_dir / "merged_output.apk"
        res = AntiSplitMerger.merge_split_apks(
            [self.base_apk, self.split_config],
            merged_out,
            sign=True
        )

        self.assertTrue(res["success"])
        self.assertTrue(merged_out.exists())
        self.assertGreaterEqual(res["total_dex_count"], 2)

        # Verify merged APK contains both base files and split so files
        with zipfile.ZipFile(merged_out, "r") as zf:
            names = zf.namelist()
            self.assertIn("classes.dex", names)
            self.assertIn("classes2.dex", names)
            self.assertIn("lib/arm64-v8a/libgamecore.so", names)
            self.assertIn("AndroidManifest.xml", names)

    def test_batch_regex_patcher(self):
        matches = BatchRegexPatcher.search_all_dex(self.base_apk, "isPremium")
        self.assertGreater(len(matches), 0)

    def test_apk_differ(self):
        diff = ApkDiffer.compare_apks(self.base_apk, self.split_config)
        self.assertGreater(diff["total_diff_count"], 0)
        self.assertIn("lib/arm64-v8a/libgamecore.so", diff["added_files"])

    @classmethod
    def tearDownClass(cls):
        import shutil
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
