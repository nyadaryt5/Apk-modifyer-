"""Tiny DEX header/string parser.

Just enough to grep an APK's strings without a decompiler: what SDKs are in
there, which crypto / signature APIs are referenced, what hosts it talks to.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Iterable, List

from .util import ApkModError

__all__ = ["DexFile", "DexStrings"]

DEX_MAGIC = b"dex\n"
ENDIAN_TAG = 0x12345678


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


@dataclass
class DexStrings:
    strings: List[str] = field(default_factory=list)
    type_descriptors: List[str] = field(default_factory=list)

    def search(self, pattern: str, ignore_case: bool = True) -> List[str]:
        flags = re.IGNORECASE if ignore_case else 0
        rx = re.compile(pattern, flags)
        return sorted({s for s in self.strings if rx.search(s)})


@dataclass
class DexFile:
    version: str
    checksum: int
    signature: bytes
    file_size: int
    string_count: int
    type_count: int
    class_count: int
    method_count: int
    strings: DexStrings

    @classmethod
    def parse(cls, data: bytes, *, load_strings: bool = True) -> "DexFile":
        if len(data) < 0x70 or not data.startswith(DEX_MAGIC):
            raise ApkModError("not a DEX file (bad magic or truncated header)")
        version = data[4:7].decode("ascii", "replace")
        checksum, = struct.unpack_from("<I", data, 8)
        signature = data[12:32]
        (endian,) = struct.unpack_from("<I", data, 40)
        if endian != ENDIAN_TAG:
            raise ApkModError("DEX is not little-endian (unsupported)")
        (
            file_size, _header_size, _endian, _link_size, _link_off, _map_off,
            string_ids_size, string_ids_off,
            type_ids_size, type_ids_off,
            _proto_size, _proto_off,
            _field_size, _field_off,
            method_ids_size, _method_off,
            class_defs_size, _class_off,
        ) = struct.unpack_from("<18I", data, 32)
        strings = DexStrings()
        if load_strings and string_ids_size:
            offsets = struct.unpack_from(f"<{string_ids_size}I", data, string_ids_off)
            for off in offsets:
                if off == 0 or off >= len(data):
                    strings.strings.append("")
                    continue
                _utf16_size, pos = _read_uleb128(data, off)
                end = data.find(b"\x00", pos)
                if end < 0:
                    end = len(data)
                strings.strings.append(_mutf8(data[pos:end]))
        if load_strings and type_ids_size:
            descriptor_ids = struct.unpack_from(f"<{type_ids_size}I", data, type_ids_off)
            for index in descriptor_ids:
                if 0 <= index < len(strings.strings):
                    strings.type_descriptors.append(strings.strings[index])
        return cls(
            version=version,
            checksum=checksum,
            signature=signature,
            file_size=file_size,
            string_count=string_ids_size,
            type_count=type_ids_size,
            class_count=class_defs_size,
            method_count=method_ids_size,
            strings=strings,
        )


def _mutf8(raw: bytes) -> str:
    """MUTF-8 differs from UTF-8 for NUL and supplementary characters."""
    out: List[str] = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0:
            out.append("\x00")
            i += 1
        elif b < 0x80:
            out.append(chr(b))
            i += 1
        elif b < 0xE0 and i + 1 < n:
            out.append(chr(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F)))
            i += 2
        elif b < 0xF0 and i + 2 < n:
            out.append(chr(((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F)))
            i += 3
        elif i + 5 < n:
            pair = (
                (((b & 0x07) << 18) | ((raw[i + 1] & 0x3F) << 12) | ((raw[i + 2] & 0x3F) << 6) | (raw[i + 3] & 0x3F))
                - 0x10000
            )
            out.append(chr(0x10000 + pair))
            i += 6
        else:
            out.append("\ufffd")
            i += 1
    return "".join(out)


def iter_dex_strings(blobs: Iterable[bytes]) -> DexStrings:
    merged = DexStrings()
    seen: set[str] = set()
    for blob in blobs:
        try:
            dex = DexFile.parse(blob)
        except ApkModError:
            continue
        for text in dex.strings.strings:
            if text and text not in seen:
                seen.add(text)
                merged.strings.append(text)
        for text in dex.strings.type_descriptors:
            if text and text not in merged.type_descriptors:
                merged.type_descriptors.append(text)
    return merged
