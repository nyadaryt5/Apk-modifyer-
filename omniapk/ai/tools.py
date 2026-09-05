"""
Autonomous Tool Registry for OmniAPK AI Agent.
Gives the Cloud AI Agent complete programmatic control to inspect, decompile,
edit smali/java, strip permissions, apply Lucky Patcher mods, merge split APKs,
generate Frida / Game Guardian scripts, and rebuild + sign APKs.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from omniapk.core.apk_packager import ApkPackager
from omniapk.core.apk_signer import ApkSigner
from omniapk.core.dex_editor import DexEditor
from omniapk.core.axml_editor import AxmlEditor
from omniapk.modules.apktool import ApktoolEngine
from omniapk.modules.apktool_m import ApktoolMEngine
from omniapk.modules.apk_editor import ApkResourceManager, PackageCloner
from omniapk.modules.lucky_patcher import LuckyPatcherEngine, AdRemover, BillingBypass, LicenseBypass
from omniapk.modules.jadx import JadxEngine
from omniapk.modules.frida import FridaScriptGenerator
from omniapk.modules.mt_manager import AntiSplitMerger, BatchRegexPatcher, ApkDiffer
from omniapk.modules.game_guardian import MemoryScanner, GameGuardianScriptBuilder
from omniapk.config import WORKSPACE_DIR, OUTPUT_DIR

class AIAgentTools:
    """Complete tool suite exposed to the autonomous AI modding agent."""

    @staticmethod
    def inspect_apk(apk_path: str) -> Dict[str, Any]:
        """Inspect APK manifest, dex files, native libraries, and metadata."""
        return ApkPackager.inspect(apk_path)

    @staticmethod
    def decompile_apk(apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Decompile APK into smali classes and resources."""
        out = output_dir or str(WORKSPACE_DIR / "decompiled" / Path(apk_path).stem)
        return ApktoolEngine.decompile(apk_path, out)

    @staticmethod
    def decompile_to_java(apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Decompile APK DEX bytecode into Java source files (JADX Engine)."""
        out = output_dir or str(WORKSPACE_DIR / "decompiled_java" / Path(apk_path).stem)
        return JadxEngine.decompile_apk_to_java(apk_path, out)

    @staticmethod
    def find_methods_and_strings(apk_path: str, query: str) -> List[Dict[str, Any]]:
        """Find cross-reference occurrences of methods and strings across all DEX files."""
        return JadxEngine.find_cross_references(apk_path, query)

    @staticmethod
    def patch_method_return_value(
        apk_path: str,
        class_name: str,
        method_name: str,
        return_value: str, # 'true', 'false', 'void'
        output_apk: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Directly patch method bytecode in DEX to return true, false, or void.
        Smali level modification.
        """
        import zipfile
        out_apk = Path(output_apk or (OUTPUT_DIR / f"{Path(apk_path).stem}_patched.apk"))
        temp_apk = out_apk.with_suffix(".tmp.apk")
        patched = False

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue
                data = src.read(item.filename)
                if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    editor = DexEditor(data)
                    ret_val_lower = return_value.lower()
                    if ret_val_lower in ("true", "1", "boolean_true"):
                        if editor.patch_method_return_true(class_name, method_name):
                            patched = True
                    elif ret_val_lower in ("false", "0", "boolean_false"):
                        if editor.patch_method_return_false(class_name, method_name):
                            patched = True
                    elif ret_val_lower in ("void", "return_void"):
                        if editor.patch_method_return_void(class_name, method_name):
                            patched = True
                    editor.recalculate_checksums()
                    data = editor.get_bytes()
                dst.writestr(item, data)

        ApkSigner.sign_apk(temp_apk, out_apk)
        if temp_apk.exists():
            temp_apk.unlink()

        return {
            "success": patched,
            "class": class_name,
            "method": method_name,
            "forced_return": return_value,
            "output_apk": str(out_apk)
        }

    @staticmethod
    def modify_manifest(
        apk_path: str,
        package_name: Optional[str] = None,
        debuggable: Optional[bool] = None,
        remove_permissions: Optional[List[str]] = None,
        add_permissions: Optional[List[str]] = None,
        output_apk: Optional[str] = None
    ) -> Dict[str, Any]:
        """Modify permissions, package name, or debuggable flag in AndroidManifest.xml."""
        out_apk = Path(output_apk or (OUTPUT_DIR / f"{Path(apk_path).stem}_manifest_mod.apk"))
        return ApktoolMEngine.quick_edit_manifest(
            apk_path=apk_path,
            output_apk=out_apk,
            package_name=package_name,
            debuggable=debuggable,
            remove_permissions=remove_permissions,
            add_permissions=add_permissions,
            sign=True
        )

    @staticmethod
    def apply_lucky_patch(
        apk_path: str,
        remove_ads: bool = True,
        bypass_billing: bool = True,
        bypass_license: bool = True,
        bypass_root: bool = True,
        output_apk: Optional[str] = None
    ) -> Dict[str, Any]:
        """Apply comprehensive Lucky Patcher automated mods (Ads, Billing, LVL, Root)."""
        out_apk = Path(output_apk or (OUTPUT_DIR / f"{Path(apk_path).stem}_modded.apk"))
        return LuckyPatcherEngine.apply_auto_patch(
            apk_path=apk_path,
            output_apk=out_apk,
            remove_ads=remove_ads,
            bypass_billing=bypass_billing,
            bypass_license=bypass_license,
            bypass_root_checks=bypass_root,
            sign=True
        )

    @staticmethod
    def merge_split_apks(split_apk_paths: List[str], output_apk: Optional[str] = None) -> Dict[str, Any]:
        """Merge split APK files (.apks, .xapk, or split configs) into single standalone APK."""
        out_apk = Path(output_apk or (OUTPUT_DIR / "merged_standalone.apk"))
        return AntiSplitMerger.merge_split_apks(split_apk_paths, out_apk, sign=True)

    @staticmethod
    def generate_frida_suite(target_package: str) -> Dict[str, str]:
        """Generate full Frida dynamic injection scripts (SSL bypass, Root bypass, Billing hook)."""
        return {
            "ssl_unpinning_script": FridaScriptGenerator.get_universal_ssl_unpinning(),
            "root_bypass_script": FridaScriptGenerator.get_universal_root_bypass(),
            "billing_bypass_script": FridaScriptGenerator.get_in_app_billing_bypass()
        }

    @staticmethod
    def generate_game_cheat_script(game_name: str, searches: List[Dict[str, Any]], speedhack: float = 1.0) -> Dict[str, str]:
        """Generate Game Guardian Lua script and Frida speedhack script."""
        return {
            "game_guardian_lua": GameGuardianScriptBuilder.generate_lua_script(game_name, searches, speedhack),
            "frida_speedhack_js": GameGuardianScriptBuilder.generate_speedhack_frida_script(speedhack)
        }

    @staticmethod
    def sign_apk_file(input_apk: str, output_apk: Optional[str] = None) -> Dict[str, Any]:
        """Sign APK using V1+V2 scheme."""
        out = ApkSigner.sign_apk(input_apk, output_apk)
        return {"success": True, "signed_apk": str(out), "size_bytes": out.stat().st_size}
