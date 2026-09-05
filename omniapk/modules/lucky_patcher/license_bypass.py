"""
Module 4: Lucky Patcher - License Verification Bypass & Signature Spoofing Engine.
Bypasses Android LVL (License Verification Library) and kills anti-tamper signature checks.
"""

import zipfile
import re
from pathlib import Path
from typing import Dict, Any, List

from omniapk.core.dex_editor import DexEditor

LVL_CLASSES = [
    "com/android/vending/licensing/LicenseChecker",
    "com/android/vending/licensing/LicenseValidator",
    "com/android/vending/licensing/Policy",
]

ROOT_DETECTION_METHODS = [
    "isRooted",
    "isDeviceRooted",
    "checkRoot",
    "isRootAvailable",
    "checkRootMethod",
    "isEmulator",
    "isRunningOnEmulator",
    "isXposedInstalled",
    "isMagiskInstalled",
    "checkSuBinary",
    "detectDebugger"
]

class LicenseBypass:
    """Bypasses LVL and root/emulator detection checks."""

    @staticmethod
    def patch_apk(apk_path: str | Path, output_apk: str | Path) -> Dict[str, Any]:
        """Neutralize license checks and force root/emulator detection to return False."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".lvl.tmp.apk")

        lvl_patched = []
        root_patched = []

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue

                if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    dex_data = src.read(item.filename)
                    editor = DexEditor(dex_data)
                    parser = editor.parser

                    for cls in parser.classes:
                        # 1. LVL checks
                        if any(lvl in cls["name"] for lvl in LVL_CLASSES):
                            for m in cls.get("virtual_methods", []) + cls.get("direct_methods", []):
                                if "checkAccess" in m["name"] or "verify" in m["name"]:
                                    if editor.patch_method_return_void(cls["name"], m["name"]):
                                        lvl_patched.append(f"{cls['name']}->{m['name']}()")

                        # 2. Root / Emulator detection checks -> return false
                        for m in cls.get("virtual_methods", []) + cls.get("direct_methods", []):
                            m_name = m["name"]
                            if any(rm.lower() == m_name.lower() or (rm.lower() in m_name.lower() and len(m_name) < 25) for rm in ROOT_DETECTION_METHODS):
                                if editor.patch_method_return_false(cls["name"], m_name):
                                    root_patched.append(f"{cls['name']}->{m_name}()")

                    editor.recalculate_checksums()
                    dst.writestr(item, editor.get_bytes())
                else:
                    dst.writestr(item, src.read(item.filename))

        if output_apk.exists():
            output_apk.unlink()
        temp_apk.rename(output_apk)

        return {
            "success": True,
            "lvl_methods_patched": lvl_patched,
            "root_methods_neutralized": root_patched,
            "output_apk": str(output_apk)
        }
