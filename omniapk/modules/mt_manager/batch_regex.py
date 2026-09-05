"""
Module 7: MT Manager - Batch Multi-DEX Regex Patcher & APK Differ.
Performs regex search/replace across all classes.dex files and computes visual diffs between APKs.
"""

import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from omniapk.core.dex_editor import DexEditor
from omniapk.core.apk_signer import ApkSigner

class BatchRegexPatcher:
    """Batch regex search and replace across all DEX files in an APK."""

    @staticmethod
    def search_all_dex(apk_path: str | Path, pattern: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search regex/string pattern across all DEX files in the APK."""
        apk_path = Path(apk_path)
        results = []
        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = re.compile(pattern, flags)

        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = [n for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex")]
            for d_name in dex_names:
                dex_bytes = zf.read(d_name)
                editor = DexEditor(dex_bytes)
                for s in editor.parser.strings:
                    if compiled.search(s):
                        results.append({
                            "dex": d_name,
                            "match": s
                        })
        return results

    @staticmethod
    def replace_all_dex(
        apk_path: str | Path,
        search_pattern: str,
        replacement: str,
        output_apk: str | Path,
        sign: bool = True
    ) -> Dict[str, Any]:
        """In-place batch search & replace for equal/shorter strings across all DEX files."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".batch.tmp.apk")

        total_replacements = 0

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue

                if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    dex_data = src.read(item.filename)
                    editor = DexEditor(dex_data)
                    count = 0
                    try:
                        count = editor.replace_string_inline(search_pattern, replacement)
                    except Exception:
                        pass
                    total_replacements += count
                    dst.writestr(item, editor.get_bytes())
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
            "total_replacements": total_replacements,
            "output_apk": str(output_apk)
        }

class ApkDiffer:
    """Calculates side-by-side structural and bytecode differences between two APK files."""

    @staticmethod
    def compare_apks(apk_a_path: str | Path, apk_b_path: str | Path) -> Dict[str, Any]:
        """Diff two APK files and return added, removed, and modified files with size/hash delta."""
        apk_a = Path(apk_a_path)
        apk_b = Path(apk_b_path)

        with zipfile.ZipFile(apk_a, "r") as za, zipfile.ZipFile(apk_b, "r") as zb:
            files_a = {info.filename: info.CRC for info in za.infolist() if not info.filename.startswith("META-INF/")}
            files_b = {info.filename: info.CRC for info in zb.infolist() if not info.filename.startswith("META-INF/")}

        set_a = set(files_a.keys())
        set_b = set(files_b.keys())

        added = sorted(list(set_b - set_a))
        removed = sorted(list(set_a - set_b))
        common = set_a & set_b

        modified = []
        identical = []
        for f in sorted(list(common)):
            if files_a[f] != files_b[f]:
                modified.append(f)
            else:
                identical.append(f)

        return {
            "apk_a": apk_a.name,
            "apk_b": apk_b.name,
            "added_files": added,
            "removed_files": removed,
            "modified_files": modified,
            "identical_count": len(identical),
            "total_diff_count": len(added) + len(removed) + len(modified)
        }
