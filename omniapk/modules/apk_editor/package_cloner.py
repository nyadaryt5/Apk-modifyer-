"""
Module 3: APK Editor - Package Cloner & App Multi-Instance Generator.
Modifies package name, authorities, provider names, and dex references so multiple copies coexist.
"""

import zipfile
import re
from pathlib import Path
from typing import Dict, Any, Optional

from omniapk.core.axml_editor import AxmlEditor
from omniapk.core.dex_editor import DexEditor
from omniapk.core.apk_signer import ApkSigner

class PackageCloner:
    """Clones an APK by rewriting package names and identifiers."""

    @staticmethod
    def clone(
        apk_path: str | Path,
        new_package_name: str,
        output_apk: str | Path,
        new_app_title: Optional[str] = None,
        sign: bool = True
    ) -> Dict[str, Any]:
        """Clone APK to a new package ID."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".clone.tmp.apk")

        old_pkg = ""
        dex_modified = 0

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            # 1. Read manifest to find original package
            for item in src.infolist():
                if item.filename == "AndroidManifest.xml":
                    manifest_raw = src.read(item.filename)
                    editor = AxmlEditor(manifest_raw)
                    if editor.parser and editor.parser.package_name:
                        old_pkg = editor.parser.package_name
                    else:
                        # Regex search
                        m = re.search(r'package="([^"]+)"', editor.get_xml())
                        if m:
                            old_pkg = m.group(1)

                    editor.set_package_name(new_package_name)
                    # Replace authority prefixes
                    if old_pkg:
                        editor.xml_text = editor.xml_text.replace(old_pkg + ".", new_package_name + ".")
                    
                    dst.writestr("AndroidManifest.xml", editor.get_xml().encode("utf-8"))
                elif item.filename.startswith("META-INF/"):
                    continue
                elif item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    dex_data = src.read(item.filename)
                    if old_pkg and len(new_package_name) <= len(old_pkg):
                        # Can do inline string patch
                        d_editor = DexEditor(dex_data)
                        old_slash = old_pkg.replace(".", "/")
                        new_slash = new_package_name.replace(".", "/")
                        try:
                            d_editor.replace_string_inline(old_slash, new_slash)
                            d_editor.recalculate_checksums()
                            dex_data = d_editor.get_bytes()
                            dex_modified += 1
                        except Exception:
                            pass
                    dst.writestr(item, dex_data)
                else:
                    dst.writestr(item, src.read(item.filename))

        if sign:
            ApkSigner.sign_apk(temp_apk, output_apk)
            if temp_apk.exists():
                temp_apk.unlink()
        else:
            if output_apk.exists():
                output_apk.unlink()
            temp_apk.rename(output_apk)

        return {
            "success": True,
            "old_package": old_pkg,
            "new_package": new_package_name,
            "dex_files_patched": dex_modified,
            "output_apk": str(output_apk),
            "size_bytes": output_apk.stat().st_size
        }
