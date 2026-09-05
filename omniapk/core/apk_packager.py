"""
Pure-Python APK Unpacker, Repacker, and 4-Byte ZipAligner.
Handles multi-dex extraction, resource unbundling, signature stripping, and zip alignment.
"""

import os
import shutil
import zipfile
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional

class ApkPackager:
    """Handles APK filesystem operations, multi-DEX extraction, and repackaging."""
    
    @staticmethod
    def inspect(apk_path: str | Path) -> Dict[str, Any]:
        """Inspect APK archive and return complete structural inventory."""
        apk_path = Path(apk_path)
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        dex_files = []
        abis = set()
        has_arsc = False
        has_manifest = False
        is_signed = False
        file_count = 0
        total_uncompressed_size = 0
        file_tree = []

        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                file_count += 1
                total_uncompressed_size += info.file_size
                name = info.filename
                
                if name.startswith("classes") and name.endswith(".dex"):
                    dex_files.append({"name": name, "size": info.file_size})
                elif name == "AndroidManifest.xml":
                    has_manifest = True
                elif name == "resources.arsc":
                    has_arsc = True
                elif name.startswith("lib/"):
                    parts = name.split("/")
                    if len(parts) > 1 and parts[1]:
                        abis.add(parts[1])
                elif name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC") or name.endswith(".SF")):
                    is_signed = True

                file_tree.append({
                    "path": name,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "is_dir": info.is_dir()
                })

        return {
            "filename": apk_path.name,
            "path": str(apk_path),
            "size_bytes": apk_path.stat().st_size,
            "file_count": file_count,
            "total_uncompressed_size": total_uncompressed_size,
            "dex_files": sorted(dex_files, key=lambda x: x["name"]),
            "abis": sorted(list(abis)),
            "has_manifest": has_manifest,
            "has_arsc": has_arsc,
            "is_signed": is_signed,
            "file_tree": file_tree
        }

    @staticmethod
    def unpack(apk_path: str | Path, target_dir: str | Path, strip_signatures: bool = True) -> Path:
        """Extract all files from APK into target directory."""
        apk_path = Path(apk_path)
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(apk_path, "r") as zf:
            for member in zf.infolist():
                if strip_signatures and member.filename.startswith("META-INF/"):
                    # skip signature metadata
                    if member.filename.endswith((".SF", ".RSA", ".DSA", ".EC", ".MF")):
                        continue
                zf.extract(member, target_dir)

        return target_dir

    @staticmethod
    def repack(source_dir: str | Path, output_apk_path: str | Path, zipalign: bool = True) -> Path:
        """Repack a directory into an unaligned or aligned APK archive."""
        source_dir = Path(source_dir)
        output_apk_path = Path(output_apk_path)
        output_apk_path.parent.mkdir(parents=True, exist_ok=True)

        temp_zip = output_apk_path.with_suffix(".tmp.apk")
        
        # Files that must NOT be compressed (stored uncompressed for direct mmap on Android)
        NO_COMPRESS = {".so", ".png", ".jpg", ".jpeg", ".webp", ".ogg", ".mp3", ".wav", ".arsc"}

        with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(source_dir).as_posix()
                    
                    # Do not pack old signatures
                    if rel_path.startswith("META-INF/") and rel_path.endswith((".SF", ".RSA", ".DSA", ".EC", ".MF")):
                        continue

                    # Uncompressed if matches extension
                    if any(rel_path.endswith(ext) for ext in NO_COMPRESS):
                        zf.write(file_path, rel_path, compress_type=zipfile.ZIP_STORED)
                    else:
                        zf.write(file_path, rel_path, compress_type=zipfile.ZIP_DEFLATED)

        if zipalign:
            ApkPackager.align_zip(temp_zip, output_apk_path, alignment=4)
            if temp_zip.exists():
                temp_zip.unlink()
        else:
            if output_apk_path.exists():
                output_apk_path.unlink()
            temp_zip.rename(output_apk_path)

        return output_apk_path

    @staticmethod
    def align_zip(input_zip: Path, output_zip: Path, alignment: int = 4) -> None:
        """
        Pure-Python 4-Byte ZipAlign implementation.
        Aligns all uncompressed entries on 4-byte boundaries from the start of file.
        """
        if output_zip.exists():
            output_zip.unlink()

        with zipfile.ZipFile(input_zip, "r") as src, zipfile.ZipFile(output_zip, "w") as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                new_item = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                new_item.compress_type = item.compress_type
                new_item.external_attr = item.external_attr
                
                # If uncompressed, pad extra field to align data offset
                if item.compress_type == zipfile.ZIP_STORED:
                    # Estimate offset
                    current_offset = dst.fp.tell()
                    # ZIP local header size = 30 + len(filename) + len(extra)
                    local_hdr_len = 30 + len(new_item.filename.encode("utf-8"))
                    data_offset = current_offset + local_hdr_len
                    padding_needed = (alignment - (data_offset % alignment)) % alignment
                    if padding_needed > 0:
                        # Add padding via extra field (ID 0xD935 Android alignment tag or standard extra field)
                        if padding_needed >= 4:
                            extra = struct.pack("<HH", 0xD935, padding_needed - 4) + b"\x00" * (padding_needed - 4)
                        else:
                            extra = b"\x00" * padding_needed
                        new_item.extra = extra

                dst.writestr(new_item, data)
