"""
Module 3: APK Editor - Resource Manager & Asset Replacer.
Enables browsing, viewing, replacing, adding, and removing resources, drawables, audio, and assets.
"""

import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional

from omniapk.core.apk_signer import ApkSigner

class ApkResourceManager:
    """Manages files and resource assets directly inside an APK."""

    @staticmethod
    def list_resources(apk_path: str | Path, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all resources filtered by category (drawables, layouts, assets, audio, json, xml, native)."""
        apk_path = Path(apk_path)
        items = []

        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                name = info.filename
                cat = "other"
                if name.startswith("res/drawable") or name.startswith("res/mipmap") or name.endswith((".png", ".jpg", ".webp", ".svg")):
                    cat = "drawables"
                elif name.startswith("res/layout") or name.startswith("res/xml"):
                    cat = "layouts"
                elif name.startswith("res/values") or name.endswith("strings.xml"):
                    cat = "values"
                elif name.startswith("assets/"):
                    cat = "assets"
                elif name.endswith((".mp3", ".ogg", ".wav", ".aac")):
                    cat = "audio"
                elif name.endswith((".json", ".toml", ".yaml")):
                    cat = "configs"
                elif name.startswith("lib/"):
                    cat = "native"
                elif name.endswith(".dex"):
                    cat = "code"

                if category and category != "all" and cat != category:
                    continue

                items.append({
                    "path": name,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "category": cat
                })

        return sorted(items, key=lambda x: (x["category"], x["path"]))

    @staticmethod
    def read_file(apk_path: str | Path, file_inside_apk: str) -> bytes:
        """Read bytes of a file inside APK."""
        with zipfile.ZipFile(apk_path, "r") as zf:
            return zf.read(file_inside_apk)

    @staticmethod
    def replace_resource(
        apk_path: str | Path,
        file_inside_apk: str,
        new_content_bytes: bytes,
        output_apk: str | Path,
        sign: bool = True
    ) -> Path:
        """Replace or add a file in the APK archive and re-sign."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".resedit.tmp.apk")

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue
                if item.filename == file_inside_apk:
                    continue
                dst.writestr(item, src.read(item.filename))
            
            # Write new file
            dst.writestr(file_inside_apk, new_content_bytes)

        if sign:
            ApkSigner.sign_apk(temp_apk, output_apk)
            if temp_apk.exists():
                temp_apk.unlink()
        else:
            if output_apk.exists():
                output_apk.unlink()
            temp_apk.rename(output_apk)

        return output_apk

    @staticmethod
    def batch_replace_resources(
        apk_path: str | Path,
        replacements: Dict[str, bytes],
        output_apk: str | Path,
        sign: bool = True
    ) -> Path:
        """Replace multiple files at once."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".batchres.tmp.apk")

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue
                if item.filename in replacements:
                    continue
                dst.writestr(item, src.read(item.filename))

            for path_in_apk, data in replacements.items():
                dst.writestr(path_in_apk, data)

        if sign:
            ApkSigner.sign_apk(temp_apk, output_apk)
            if temp_apk.exists():
                temp_apk.unlink()
        else:
            if output_apk.exists():
                output_apk.unlink()
            temp_apk.rename(output_apk)

        return output_apk
