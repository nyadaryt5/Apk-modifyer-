"""Native reader / patcher for resources.arsc (the compiled resource table).

Enough to enumerate packages, types, configs and entry names, and to rewrite
strings in the global value pool -- i.e. change the app label / any string
resource without a full decompile.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .axml import StringPool, TYPE_STRING
from .util import ApkModError

__all__ = ["ArscFile", "ArscPackage", "ArscEntry"]

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203
RES_TABLE_OVERLAYABLE_TYPE = 0x0204

FLAG_COMPLEX = 0x0001
FLAG_PUBLIC = 0x0002

_CONFIG_KEYS = (
    "size", "mcc", "mnc", "language", "country", "orientation", "touchscreen",
    "density", "keyboard", "navigation", "inputFlags", "inputPad0",
    "screenWidth", "screenHeight", "sdkVersion", "minorVersion",
)


@dataclass
class ArscEntry:
    name: str
    key_index: int
    flags: int
    data_type: int
    data: int
    config: str
    type_name: str

    @property
    def is_complex(self) -> bool:
        return bool(self.flags & FLAG_COMPLEX)


@dataclass
class ArscPackage:
    pkg_id: int
    name: str
    types: List[str] = field(default_factory=list)
    entries: List[ArscEntry] = field(default_factory=list)


class ArscFile:
    """resources.arsc: header + global value string pool + package chunks."""

    def __init__(
        self,
        package_count: int,
        value_strings: StringPool,
        packages: List[ArscPackage],
        tail: bytes,
    ) -> None:
        self.package_count = package_count
        self.value_strings = value_strings
        self.packages = packages
        self.tail = tail

    # -- parse ------------------------------------------------------------
    @classmethod
    def parse(cls, data: bytes) -> "ArscFile":
        if len(data) < 12:
            raise ApkModError("resources.arsc is too small")
        ctype, header_size, size = struct.unpack_from("<HHI", data, 0)
        if ctype != RES_TABLE_TYPE:
            raise ApkModError(f"not a resource table (magic 0x{ctype:04x})")
        (package_count,) = struct.unpack_from("<I", data, 8)
        pool, pool_size = StringPool.parse(data, header_size)
        tail_start = header_size + pool_size
        tail = data[tail_start:]
        packages = cls._parse_packages(data, tail_start, package_count)
        return cls(package_count, pool, packages, tail)

    @staticmethod
    def _read_package_name(raw: bytes) -> str:
        return raw[:256].decode("utf-16-le", "replace").rstrip("\x00")

    @classmethod
    def _parse_packages(cls, data: bytes, offset: int, package_count: int) -> List[ArscPackage]:
        packages: List[ArscPackage] = []
        pos = offset
        while pos + 8 <= len(data) and len(packages) < max(package_count, 1):
            ctype, header_size, size = struct.unpack_from("<HHI", data, pos)
            if size < 8 or pos + size > len(data):
                break
            if ctype != RES_TABLE_PACKAGE_TYPE:
                pos += size
                continue
            pkg_id, = struct.unpack_from("<I", data, pos + 8)
            name = cls._read_package_name(data[pos + 12 : pos + 12 + 256])
            type_strings_off, _last_pub_type, key_strings_off = struct.unpack_from("<III", data, pos + 268)
            type_pool = StringPool.parse(data, pos + type_strings_off)[0] if type_strings_off else StringPool()
            key_pool = StringPool.parse(data, pos + key_strings_off)[0] if key_strings_off else StringPool()
            package = ArscPackage(pkg_id=pkg_id, name=name)
            # walk the inner chunks of this package
            inner = pos + header_size
            end = pos + size
            while inner + 8 <= end:
                itype, iheader, isize = struct.unpack_from("<HHI", data, inner)
                if isize < 8 or inner + isize > end:
                    break
                if itype == RES_TABLE_TYPE_SPEC_TYPE:
                    (spec_id,) = struct.unpack_from("<B", data, inner + 8)
                    label = type_pool.get(spec_id - 1)
                    if label and label not in package.types:
                        package.types.append(label)
                elif itype == RES_TABLE_TYPE_TYPE:
                    (type_id,) = struct.unpack_from("<B", data, inner + 8)
                    entry_count, entries_start = struct.unpack_from("<II", data, inner + 12)
                    config_size = struct.unpack_from("<I", data, inner + 20)[0]
                    label = type_pool.get(type_id - 1) or f"type{type_id}"
                    if label not in package.types:
                        package.types.append(label)
                    config = cls._config_label(data, inner + 20, config_size)
                    base = inner + (entries_start or iheader)
                    for i in range(entry_count):
                        entry_off_pos = inner + iheader + 4 * i
                        if entry_off_pos + 4 > end:
                            break
                        (entry_off,) = struct.unpack_from("<I", data, entry_off_pos)
                        if entry_off == 0xFFFFFFFF:
                            continue
                        epos = base + entry_off
                        if epos + 8 > end:
                            continue
                        esize, flags, key_index = struct.unpack_from("<HHI", data, epos)
                        entry_name = key_pool.get(key_index) or f"entry{key_index}"
                        if flags & FLAG_COMPLEX:
                            package.entries.append(
                                ArscEntry(entry_name, key_index, flags, 0, 0, config, label)
                            )
                            continue
                        vpos = epos + esize
                        if vpos + 8 > end:
                            continue
                        vsize, _res0, data_type, value = struct.unpack_from("<HBBI", data, vpos)
                        package.entries.append(
                            ArscEntry(entry_name, key_index, flags, data_type, value, config, label)
                        )
                inner += isize
            packages.append(package)
            pos += size
        return packages

    @staticmethod
    def _config_label(data: bytes, offset: int, size: int) -> str:
        """ResTable_config: size(4) mcc(2) mnc(2) language(2) country(2) orientation(1)
        touchscreen(1) density(2) ... sdkVersion(2) minorVersion(2)."""
        if size < 12:
            return "default"
        language = data[offset + 8 : offset + 10].decode("ascii", "replace").rstrip("\x00")
        country = data[offset + 10 : offset + 12].decode("ascii", "replace").rstrip("\x00")
        density = 0
        sdk = 0
        if size >= 16:
            density = struct.unpack_from("<H", data, offset + 14)[0]
        if size >= 26:
            sdk = struct.unpack_from("<H", data, offset + 24)[0]
        bits = []
        if language:
            bits.append(language + ("-" + country if country else ""))
        if density:
            bits.append(f"{density}dpi")
        if sdk:
            bits.append(f"v{sdk}")
        return "-".join(bits) if bits else "default"

    # -- serialize --------------------------------------------------------
    def serialize(self) -> bytes:
        pool = self.value_strings.serialize()
        header = struct.pack("<HHII", RES_TABLE_TYPE, 12, 12 + len(pool) + len(self.tail), self.package_count)
        return header + pool + self.tail

    # -- string helpers ---------------------------------------------------
    def string_entries(self) -> List[Tuple[int, str, List[str]]]:
        """(pool index, string, [locations]) for every string-valued resource."""
        locations: Dict[int, List[str]] = {}
        for package in self.packages:
            for entry in package.entries:
                if entry.data_type == TYPE_STRING:
                    locations.setdefault(entry.data, []).append(
                        f"{package.name}:{entry.type_name}/{entry.name} [{entry.config}]"
                    )
        out = []
        for index, string in enumerate(self.value_strings.strings):
            out.append((index, string, locations.get(index, [])))
        return out

    def replace_string(self, index: int, new_text: str) -> str:
        """Replace one value-pool string in place (length may change)."""
        if index < 0 or index >= len(self.value_strings.strings):
            raise ApkModError(f"string index {index} out of range (pool has {len(self.value_strings.strings)})")
        old = self.value_strings.strings[index]
        self.value_strings.strings[index] = new_text
        return old

    def replace_all(self, old_text: str, new_text: str) -> int:
        count = 0
        for i, string in enumerate(self.value_strings.strings):
            if string == old_text:
                self.value_strings.strings[i] = new_text
                count += 1
        return count

    def app_label(self) -> Optional[str]:
        for package in self.packages:
            for entry in package.entries:
                if entry.type_name == "string" and entry.name == "app_name" and entry.data_type == TYPE_STRING:
                    return self.value_strings.get(entry.data)
        return None
