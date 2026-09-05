"""
Pure-Python Android Resource Table (resources.arsc) Parser & String Pool Editor.
Enables resource inspection, string extraction, and in-place localization/app name modifications.
"""

import struct
from typing import List, Dict, Any, Optional

RES_TABLE_TYPE = 0x0002
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

class ArscParser:
    """Parses Android resources.arsc binary file."""
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.strings: List[str] = []
        self.packages: List[Dict[str, Any]] = []
        self.key_strings: List[str] = []
        self.type_strings: List[str] = []
        self.parse()

    def parse(self):
        if len(self.data) < 12:
            return
        res_type, header_size, size = struct.unpack("<HHI", self.data[0:8])
        if res_type != RES_TABLE_TYPE:
            return

        package_count = struct.unpack("<I", self.data[8:12])[0]
        pos = header_size

        while pos < len(self.data):
            if pos + 8 > len(self.data):
                break
            c_type, c_header_size, c_size = struct.unpack("<HHI", self.data[pos : pos + 8])
            if c_size <= 0 or pos + c_size > len(self.data):
                break

            if c_type == RES_STRING_POOL_TYPE:
                self.strings = self._parse_string_pool(pos)
            elif c_type == RES_TABLE_PACKAGE_TYPE:
                self._parse_package(pos, c_size)

            pos += c_size

    def _parse_string_pool(self, offset: int) -> List[str]:
        if offset + 28 > len(self.data):
            return []
        (
            c_type,
            c_header_size,
            c_size,
            string_count,
            style_count,
            flags,
            strings_start,
            styles_start,
        ) = struct.unpack("<HHIIIIII", self.data[offset : offset + 28])

        is_utf8 = (flags & (1 << 8)) != 0
        offsets = []
        for i in range(string_count):
            off_pos = offset + 28 + i * 4
            if off_pos + 4 <= len(self.data):
                offsets.append(struct.unpack("<I", self.data[off_pos : off_pos + 4])[0])

        strings_base = offset + strings_start
        pool = []

        for off in offsets:
            str_pos = strings_base + off
            if str_pos >= len(self.data):
                pool.append("")
                continue

            try:
                if is_utf8:
                    skip = 0
                    while str_pos + skip < len(self.data) and (self.data[str_pos + skip] & 0x80):
                        skip += 1
                    skip += 1
                    while str_pos + skip < len(self.data) and (self.data[str_pos + skip] & 0x80):
                        skip += 1
                    skip += 1
                    start_str = str_pos + skip
                    end_str = self.data.find(b"\x00", start_str)
                    if end_str == -1:
                        end_str = len(self.data)
                    s = self.data[start_str:end_str].decode("utf-8", errors="replace")
                else:
                    length = struct.unpack("<H", self.data[str_pos : str_pos + 2])[0]
                    if length & 0x8000:
                        length = struct.unpack("<H", self.data[str_pos + 2 : str_pos + 4])[0]
                        str_pos += 2
                    str_pos += 2
                    raw = self.data[str_pos : str_pos + length * 2]
                    s = raw.decode("utf-16le", errors="replace")
                pool.append(s)
            except Exception:
                pool.append("")

        return pool

    def _parse_package(self, offset: int, size: int):
        if offset + 288 > len(self.data):
            return
        pkg_id = struct.unpack("<I", self.data[offset + 8 : offset + 12])[0]
        pkg_name_raw = self.data[offset + 12 : offset + 268]
        # utf-16 string terminated by 0x0000
        pkg_name = pkg_name_raw.decode("utf-16le", errors="ignore").split("\x00")[0]
        
        type_strings_off, last_public_type, key_strings_off, last_public_key = struct.unpack(
            "<IIII", self.data[offset + 268 : offset + 284]
        )

        pkg_info = {
            "id": pkg_id,
            "name": pkg_name,
            "offset": offset,
            "size": size
        }
        self.packages.append(pkg_info)

    def find_strings(self, pattern: str) -> List[Dict[str, Any]]:
        """Search strings in ARSC string pool."""
        matches = []
        p_lower = pattern.lower()
        for idx, s in enumerate(self.strings):
            if p_lower in s.lower():
                matches.append({"index": idx, "value": s})
        return matches

    def replace_string_inline(self, old_val: str, new_val: str) -> int:
        """In-place string replacement in string table if length allows."""
        old_bytes = old_val.encode("utf-8")
        new_bytes = new_val.encode("utf-8")
        if len(new_bytes) > len(old_bytes):
            raise ValueError("Replacement string length cannot exceed original string in inline mode")
        
        padded = new_bytes + b"\x00" * (len(old_bytes) - len(new_bytes))
        count = 0
        idx = 0
        while True:
            idx = self.data.find(old_bytes, idx)
            if idx == -1:
                break
            self.data[idx : idx + len(old_bytes)] = padded
            count += 1
            idx += len(old_bytes)
        return count

    def get_bytes(self) -> bytes:
        return bytes(self.data)
