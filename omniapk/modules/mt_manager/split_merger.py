"""
Module 7: MT Manager - Anti-Split APK Merger Engine.
Merges Split APK sets (.apks, .xapk, .apkm, or loose split APK files)
into a single standalone unified APK ready for installation on any device.
"""

import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from omniapk.core.axml_editor import AxmlEditor
from omniapk.core.apk_signer import ApkSigner
from omniapk.core.apk_packager import ApkPackager

class AntiSplitMerger:
    """Merges split Android packages into a standalone single APK."""

    @staticmethod
    def merge_split_apks(
        split_apk_paths: List[str | Path],
        output_apk: str | Path,
        sign: bool = True
    ) -> Dict[str, Any]:
        """
        Merge multiple split APKs (base.apk + split_config.*.apk) into one unified APK.
        """
        output_apk = Path(output_apk)
        temp_dir = output_apk.parent / f"merge_tmp_{output_apk.stem}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        merged_dex_count = 0
        merged_files_count = 0
        base_manifest_found = False

        try:
            # 1. Sort APKs to ensure base.apk is processed first
            sorted_apks = sorted(
                [Path(p) for p in split_apk_paths],
                key=lambda p: 0 if "base" in p.name.lower() or "standalone" in p.name.lower() else 1
            )

            current_dex_idx = 1

            for apk in sorted_apks:
                with zipfile.ZipFile(apk, "r") as zf:
                    for item in zf.infolist():
                        filename = item.filename
                        if filename.startswith("META-INF/"):
                            continue

                        # Handle DEX files: ensure no collisions by sequentially renaming
                        if filename.startswith("classes") and filename.endswith(".dex"):
                            dex_name = "classes.dex" if current_dex_idx == 1 else f"classes{current_dex_idx}.dex"
                            target_file = temp_dir / dex_name
                            target_file.write_bytes(zf.read(filename))
                            current_dex_idx += 1
                            merged_dex_count += 1
                            continue

                        # Handle AndroidManifest.xml (keep only from base.apk, and clean split attributes)
                        if filename == "AndroidManifest.xml":
                            if not base_manifest_found:
                                manifest_data = zf.read(filename)
                                editor = AxmlEditor(manifest_data)
                                
                                # Strip split-related attributes from manifest
                                editor.xml_text = re.sub(r'\s+split="[^"]*"', '', editor.xml_text)
                                editor.xml_text = re.sub(r'\s+android:isSplitRequired="[^"]*"', '', editor.xml_text)
                                editor.xml_text = re.sub(r'<meta-data[^>]*android:name="com\.android\.vending\.splits"[^>]*/>\s*', '', editor.xml_text)
                                editor.xml_text = re.sub(r'<meta-data[^>]*android:name="com\.android\.dynamic\.apk\.fused\.modules"[^>]*/>\s*', '', editor.xml_text)

                                (temp_dir / "AndroidManifest.xml").write_text(editor.get_xml(), encoding="utf-8")
                                base_manifest_found = True
                            continue

                        # Extract other files (assets, libs, resources)
                        target_file = temp_dir / filename
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        if not target_file.exists():
                            target_file.write_bytes(zf.read(filename))
                            merged_files_count += 1

            # 2. Pack merged directory into final APK
            temp_packed = output_apk.with_suffix(".unaligned.apk")
            ApkPackager.repack(temp_dir, temp_packed, zipalign=True)

            # 3. Sign APK
            if sign:
                ApkSigner.sign_apk(temp_packed, output_apk)
                if temp_packed.exists():
                    temp_packed.unlink()
            else:
                if output_apk.exists():
                    output_apk.unlink()
                temp_packed.rename(output_apk)

        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

        return {
            "success": True,
            "merged_apk": str(output_apk),
            "total_dex_count": merged_dex_count,
            "total_files_merged": merged_files_count,
            "size_bytes": output_apk.stat().st_size
        }

    @staticmethod
    def unpack_bundle_and_merge(bundle_path: str | Path, output_apk: str | Path, sign: bool = True) -> Dict[str, Any]:
        """Unpack .apks / .xapk / .apkm ZIP container and merge internal split APKs into a single APK."""
        bundle_path = Path(bundle_path)
        extract_dir = bundle_path.parent / f"bundle_{bundle_path.stem}"
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(bundle_path, "r") as zf:
                zf.extractall(extract_dir)

            split_apks = list(extract_dir.glob("*.apk"))
            if not split_apks:
                # Check subdirectories
                split_apks = list(extract_dir.rglob("*.apk"))

            if not split_apks:
                raise ValueError("No APK files found inside the bundle container")

            return AntiSplitMerger.merge_split_apks(split_apks, output_apk, sign=sign)
        finally:
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)
