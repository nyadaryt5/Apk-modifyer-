"""
Automated Test Suite for Core Binary & File Format Parsers.
"""

import unittest
import zipfile
from pathlib import Path

from omniapk.core.dex_parser import DexParser
from omniapk.core.dex_editor import DexEditor
from omniapk.core.axml_parser import AxmlParser
from omniapk.core.axml_editor import AxmlEditor
from omniapk.core.apk_packager import ApkPackager
from omniapk.core.apk_signer import ApkSigner
from samples.make_sample_apk import generate_minimal_dex, generate_sample_apk

class TestCoreParsers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_apk = Path("samples/sample_target.apk")
        if not cls.sample_apk.exists():
            generate_sample_apk(cls.sample_apk)

    def test_dex_parser_and_disassembler(self):
        dex_bytes = generate_minimal_dex()
        parser = DexParser(dex_bytes)
        self.assertGreater(len(parser.strings), 0)
        self.assertGreater(len(parser.classes), 0)
        
        main_cls = parser.classes[0]
        self.assertIn("MainActivity", main_cls["name"])
        
        # Test disassembly of methods
        methods = main_cls["virtual_methods"]
        self.assertEqual(len(methods), 4)
        
        dis_prem = parser.disassemble_method(methods[0]["code_off"])
        self.assertIn("return", dis_prem["smali"])

    def test_dex_editor_patching(self):
        dex_bytes = generate_minimal_dex()
        editor = DexEditor(dex_bytes)
        
        # Patch isPremium -> True
        ok = editor.patch_method_return_true("Lcom/target/app/MainActivity;", "isPremium")
        self.assertTrue(ok)
        
        # Re-parse modified DEX to verify bytecode
        mod_dex = editor.get_bytes()
        re_parser = DexParser(mod_dex)
        prem_method = re_parser.classes[0]["virtual_methods"][0]
        dis = re_parser.disassemble_method(prem_method["code_off"])
        self.assertIn("const/4 v0, 0x1", dis["smali"])

    def test_axml_editor(self):
        raw_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.target.test">
    <uses-permission android:name="com.google.android.gms.permission.AD_ID" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="App" />
</manifest>"""
        editor = AxmlEditor(raw_xml)
        editor.set_debuggable(True)
        removed = editor.remove_ad_permissions()
        
        self.assertIn("com.google.android.gms.permission.AD_ID", removed)
        self.assertIn('android:debuggable="true"', editor.get_xml())

    def test_apk_packaging_and_signing(self):
        info = ApkPackager.inspect(self.sample_apk)
        self.assertTrue(info["has_manifest"])
        self.assertGreater(len(info["dex_files"]), 0)

        out_signed = Path("samples/test_signed_output.apk")
        signed_apk = ApkSigner.sign_apk(self.sample_apk, out_signed)
        self.assertTrue(signed_apk.exists())
        self.assertGreater(signed_apk.stat().st_size, 0)

        # Inspect signed archive
        with zipfile.ZipFile(signed_apk, "r") as zf:
            self.assertIn("META-INF/MANIFEST.MF", zf.namelist())
            self.assertIn("META-INF/CERT.SF", zf.namelist())
            self.assertIn("META-INF/CERT.RSA", zf.namelist())

        if out_signed.exists():
            out_signed.unlink()

if __name__ == "__main__":
    unittest.main()
