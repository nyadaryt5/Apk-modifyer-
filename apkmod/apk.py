"""APK container: inventory, manifest/ARSC/DEX access, signature-scheme detection."""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .asn1 import ApkModError, parse_pkcs7_signed_data
from .axml import AxmlFile
from .util import human_size

__all__ = ["ApkContainer", "ApkEntry"]

EOCD_SIGNATURE = b"PK\x05\x06"
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

SIGNING_BLOCK_IDS = {
    0x7109871A: "v2 (APK Signature Scheme v2)",
    0xF05368C0: "v3 (APK Signature Scheme v3)",
    0x1B93AD61: "v3.1 (APK Signature Scheme v3.1)",
    0x0E83FB41: "v4 (APK Signature Scheme v4 / FS-Verity)",
    0x42726577: "verity padding block",
    0x2146444E: "channel block (Walle/pack)",
}

SIGNATURE_EXTENSIONS = (".RSA", ".DSA", ".EC")


@dataclass
class ApkEntry:
    name: str
    size: int
    compress_size: int
    compress_type: int
    crc: int

    @property
    def stored(self) -> bool:
        return self.compress_type == zipfile.ZIP_STORED


@dataclass
class ApkContainer:
    path: Path
    _zip: Optional[zipfile.ZipFile] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if not self.path.is_file():
            raise ApkModError(f"no such file: {self.path}")

    # -- lifecycle --------------------------------------------------------
    def __enter__(self) -> "ApkContainer":
        self._zip = zipfile.ZipFile(self.path)
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    @property
    def zip(self) -> zipfile.ZipFile:
        if self._zip is None:
            self._zip = zipfile.ZipFile(self.path)
        return self._zip

    # -- inventory --------------------------------------------------------
    def entries(self) -> List[ApkEntry]:
        return [
            ApkEntry(
                name=i.filename,
                size=i.file_size,
                compress_size=i.compress_size,
                compress_type=i.compress_type,
                crc=i.CRC,
            )
            for i in self.zip.infolist()
            if not i.is_dir()
        ]

    def names(self) -> List[str]:
        return [e.name for e in self.entries()]

    def read(self, name: str) -> bytes:
        return self.zip.read(name)

    def has(self, name: str) -> bool:
        return name in self.zip.namelist()

    def blobs(self, pattern_suffix: str) -> Dict[str, bytes]:
        return {n: self.read(n) for n in self.names() if n.endswith(pattern_suffix)}

    def dex_blobs(self) -> List[bytes]:
        dexes = sorted(n for n in self.names() if n.startswith("classes") and n.endswith(".dex"))
        return [self.read(n) for n in dexes]

    def native_libraries(self) -> Dict[str, List[str]]:
        abis: Dict[str, List[str]] = {}
        for name in self.names():
            if name.startswith("lib/") and name.endswith(".so"):
                parts = name.split("/")
                if len(parts) >= 3:
                    abis.setdefault(parts[1], []).append("/".join(parts[2:]))
        return abis

    def uncompressed_entries(self) -> List[str]:
        return [e.name for e in self.entries() if e.stored]

    # -- structured pieces ------------------------------------------------
    def manifest_axml(self) -> AxmlFile:
        if not self.has("AndroidManifest.xml"):
            raise ApkModError("APK has no AndroidManifest.xml")
        return AxmlFile.parse(self.read("AndroidManifest.xml"))

    def arsc_bytes(self) -> Optional[bytes]:
        return self.read("resources.arsc") if self.has("resources.arsc") else None

    # -- signing ----------------------------------------------------------
    def v1_signature_files(self) -> List[str]:
        found = []
        for name in self.names():
            upper = name.upper()
            if upper == "META-INF/MANIFEST.MF" or (
                upper.startswith("META-INF/") and upper.endswith(SIGNATURE_EXTENSIONS)
            ):
                found.append(name)
        return sorted(found)

    def signing_block_ids(self) -> List[int]:
        """IDs present in the APK Signing Block (v2/v3/v4), if there is one."""
        data = self.path.read_bytes()
        eocd = data.rfind(EOCD_SIGNATURE)
        if eocd < 0 or eocd + 22 > len(data):
            return []
        (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
        if cd_offset < 24 or cd_offset + 16 > len(data):
            return []
        if data[cd_offset - 16 : cd_offset] != APK_SIG_BLOCK_MAGIC:
            return []
        (size_of_block,) = struct.unpack_from("<Q", data, cd_offset - 24)
        # the block is: [size(8)][pairs][size(8)][magic(16)] then the central dir
        pairs_start = cd_offset - size_of_block
        if pairs_start < 0:
            return []
        ids: List[int] = []
        pos = pairs_start
        end = cd_offset - 24
        while pos + 12 <= end:
            (pair_len,) = struct.unpack_from("<Q", data, pos)
            if pair_len < 4 or pos + 8 + pair_len > end:
                break
            (pair_id,) = struct.unpack_from("<I", data, pos + 8)
            ids.append(pair_id)
            pos += 8 + pair_len
        return ids

    def certificates(self) -> List[dict]:
        certs = []
        for name in self.v1_signature_files():
            if not name.upper().endswith(SIGNATURE_EXTENSIONS):
                continue
            try:
                parsed = parse_pkcs7_signed_data(self.read(name))
            except (ApkModError, IndexError, ValueError):
                continue
            certs.append(
                {
                    "block": name,
                    "subject_cn": parsed.certificate.subject_cn,
                    "sha256": parsed.certificate.sha256,
                    "serial": int.from_bytes(parsed.certificate.serial, "big"),
                }
            )
        return certs

    def signing_info(self) -> dict:
        ids = self.signing_block_ids()
        labels = sorted({SIGNING_BLOCK_IDS.get(i, f"unknown block 0x{i:08x}") for i in ids})
        v1 = self.v1_signature_files()
        return {
            "v1_jar_signing": bool(v1),
            "v1_files": v1,
            "signing_block": labels,
            "v2": any(i == 0x7109871A for i in ids),
            "v3": any(i in (0xF05368C0, 0x1B93AD61) for i in ids),
            "v4": any(i == 0x0E83FB41 for i in ids),
            "certificates": self.certificates(),
        }

    # -- summary ----------------------------------------------------------
    def facts(self) -> dict:
        entries = self.entries()
        total = sum(e.size for e in entries)
        facts: dict = {
            "path": str(self.path),
            "file_size": self.path.stat().st_size,
            "file_size_human": human_size(self.path.stat().st_size),
            "entry_count": len(entries),
            "uncompressed_total": total,
            "uncompressed_total_human": human_size(total),
            "dex_files": [n for n in self.names() if n.startswith("classes") and n.endswith(".dex")],
            "native_libraries": self.native_libraries(),
            "assets": [n for n in self.names() if n.startswith("assets/")][:50],
            "has_resources_arsc": self.has("resources.arsc"),
            "signing": self.signing_info(),
            "biggest_entries": [
                {"name": e.name, "size": e.size}
                for e in sorted(entries, key=lambda x: -x.size)[:10]
            ],
        }
        try:
            facts["manifest"] = self.manifest_axml().manifest_facts()
        except ApkModError as exc:
            facts["manifest_error"] = str(exc)
        return facts
