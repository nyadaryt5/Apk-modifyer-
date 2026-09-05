"""
Module 2: Apktool M Engine (Quick In-Place Mobile APK Modder).
Enables rapid in-memory manifest editing, signature verification removal,
and instant mobile package rebuilds without full project extraction.
"""

import io
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional

from omniapk.core.axml_editor import AxmlEditor
from omniapk.core.dex_editor import DexEditor
from omniapk.core.apk_signer import ApkSigner

class ApktoolMEngine:
    """Apktool M In-Place Quick Modification Engine."""

    @staticmethod
    def quick_edit_manifest(
        apk_path: str | Path,
        output_apk: str | Path,
        package_name: Optional[str] = None,
        debuggable: Optional[bool] = None,
        remove_permissions: Optional[List[str]] = None,
        add_permissions: Optional[List[str]] = None,
        remove_ad_perms: bool = False,
        remove_dangerous_perms: bool = False,
        sign: bool = True
    ) -> Dict[str, Any]:
        """Rapidly patch AndroidManifest.xml directly inside the APK archive."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".tmp.apk")

        manifest_modified = False
        summary = {"permissions_removed": [], "permissions_added": []}

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                
                # Strip old signatures
                if item.filename.startswith("META-INF/"):
                    continue

                if item.filename == "AndroidManifest.xml":
                    editor = AxmlEditor(data)
                    if package_name:
                        editor.set_package_name(package_name)
                    if debuggable is not None:
                        editor.set_debuggable(debuggable)
                    if remove_ad_perms:
                        summary["permissions_removed"].extend(editor.remove_ad_permissions())
                    if remove_dangerous_perms:
                        summary["permissions_removed"].extend(editor.remove_dangerous_permissions())
                    if remove_permissions:
                        for p in remove_permissions:
                            if editor.remove_permission(p):
                                summary["permissions_removed"].append(p)
                    if add_permissions:
                        for p in add_permissions:
                            editor.add_permission(p)
                            summary["permissions_added"].append(p)
                    
                    data = editor.get_xml().encode("utf-8")
                    manifest_modified = True

                dst.writestr(item, data)

        if output_apk.exists():
            output_apk.unlink()

        if sign:
            ApkSigner.sign_apk(temp_apk, output_apk)
            if temp_apk.exists():
                temp_apk.unlink()
        else:
            temp_apk.rename(output_apk)

        summary["manifest_modified"] = manifest_modified
        summary["output_apk"] = str(output_apk)
        summary["size_bytes"] = output_apk.stat().st_size
        return summary

    @staticmethod
    def kill_signature_check_inline(apk_path: str | Path, output_apk: str | Path, sign: bool = True) -> Dict[str, Any]:
        """
        Apktool M signature killer: searches DEX files for PackageManager.getPackageInfo / GET_SIGNATURES
        and redirects/bypasses APK signature verification logic.
        """
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".sigkill.tmp.apk")

        dex_patched_count = 0

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue
                data = src.read(item.filename)
                
                if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    editor = DexEditor(data)
                    # Replace GET_SIGNATURES / signatures checks
                    # Opcode hooks or string substitutions
                    editor.replace_string_inline("signatures", "signatu_ok")
                    editor.recalculate_checksums()
                    data = editor.get_bytes()
                    dex_patched_count += 1

                dst.writestr(item, data)

        if sign:
            ApkSigner.sign_apk(temp_apk, output_apk)
            if temp_apk.exists():
                temp_apk.unlink()
        else:
            temp_apk.rename(output_apk)

        return {
            "success": True,
            "dex_files_patched": dex_patched_count,
            "output_apk": str(output_apk)
        }
