"""
Pure-Python Android Binary XML (AXML) Parser.
Decodes AndroidManifest.xml and binary XML resources into standard human-readable XML.
Works with zero dependencies on Linux and Android.
"""

import struct
from typing import List, Dict, Any, Tuple, Optional

# AXML Chunk Types
CHUNK_AXML_FILE = 0x00080003
CHUNK_RESOURCEIDS = 0x00080180
CHUNK_STRINGS = 0x001C0001
CHUNK_XML_START_NAMESPACE = 0x00100100
CHUNK_XML_END_NAMESPACE = 0x00100101
CHUNK_XML_START_TAG = 0x00100102
CHUNK_XML_END_TAG = 0x00100103
CHUNK_XML_TEXT = 0x00100104

# Attribute Types
TYPE_NULL = 0
TYPE_REFERENCE = 1
TYPE_ATTRIBUTE = 2
TYPE_STRING = 3
TYPE_FLOAT = 4
TYPE_DIMENSION = 5
TYPE_FRACTION = 6
TYPE_INT_DEC = 16
TYPE_INT_HEX = 17
TYPE_INT_BOOLEAN = 18

class AxmlParser:
    """Decodes compiled binary Android XML into standard text XML."""
    def __init__(self, data: bytes):
        self.data = data
        self.strings: List[str] = []
        self.resource_ids: List[int] = []
        self.xml_lines: List[str] = []
        self.namespaces: Dict[str, str] = {}
        self.package_name: str = ""
        self.permissions: List[str] = []
        self.activities: List[str] = []
        self.services: List[str] = []
        self.receivers: List[str] = []
        self.providers: List[str] = []
        self.meta_data: Dict[str, str] = {}
        self.is_debuggable: bool = False
        self.app_name: str = ""
        self.version_name: str = ""
        self.version_code: str = ""
        self.min_sdk: str = ""
        self.target_sdk: str = ""
        self.parse()

    def parse(self):
        if len(self.data) < 8:
            return
        magic = struct.unpack("<I", self.data[0:4])[0]
        if magic != CHUNK_AXML_FILE and magic != 0x00080003:
            # Fallback check if plain text
            try:
                text = self.data.decode("utf-8")
                if "<manifest" in text:
                    self.xml_lines = text.splitlines()
                    self._extract_metadata_from_text(text)
                    return
            except Exception:
                pass

        pos = 8
        indent = 0

        while pos < len(self.data):
            if pos + 8 > len(self.data):
                break
            chunk_type, chunk_size = struct.unpack("<II", self.data[pos:pos+8])
            if chunk_size <= 0 or pos + chunk_size > len(self.data) + 8:
                break

            if chunk_type == CHUNK_STRINGS or (chunk_type & 0xFFFF) == 0x0001:
                self._parse_strings(pos)
            elif chunk_type == CHUNK_RESOURCEIDS or (chunk_type & 0xFFFF) == 0x0180:
                self._parse_resource_ids(pos, chunk_size)
            elif chunk_type == CHUNK_XML_START_NAMESPACE or (chunk_type & 0xFFFF) == 0x0100:
                self._parse_start_namespace(pos)
            elif chunk_type == CHUNK_XML_START_TAG or (chunk_type & 0xFFFF) == 0x0102:
                line, indent = self._parse_start_tag(pos, indent)
                if line:
                    self.xml_lines.append(line)
            elif chunk_type == CHUNK_XML_END_TAG or (chunk_type & 0xFFFF) == 0x0103:
                line, indent = self._parse_end_tag(pos, indent)
                if line:
                    self.xml_lines.append(line)
            elif chunk_type == CHUNK_XML_TEXT or (chunk_type & 0xFFFF) == 0x0104:
                pass

            pos += chunk_size

        self._extract_metadata_from_text("\n".join(self.xml_lines))

    def _parse_strings(self, offset: int):
        if offset + 28 > len(self.data):
            return
        (
            chunk_type,
            chunk_size,
            string_count,
            style_count,
            flags,
            strings_start,
            styles_start,
        ) = struct.unpack("<IIIIIII", self.data[offset : offset + 28])

        is_utf8 = (flags & (1 << 8)) != 0
        offsets = []
        for i in range(string_count):
            off_pos = offset + 28 + i * 4
            if off_pos + 4 <= len(self.data):
                offsets.append(struct.unpack("<I", self.data[off_pos : off_pos + 4])[0])

        strings_base = offset + strings_start
        self.strings = []

        for off in offsets:
            str_pos = strings_base + off
            if str_pos >= len(self.data):
                self.strings.append("")
                continue

            try:
                if is_utf8:
                    # UTF-8: length prefix then null-terminated utf-8 bytes
                    # skip length headers
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
                    # UTF-16LE: 2-byte length then 2-byte characters ending in 0x0000
                    length = struct.unpack("<H", self.data[str_pos : str_pos + 2])[0]
                    if length & 0x8000:
                        length = struct.unpack("<H", self.data[str_pos + 2 : str_pos + 4])[0]
                        str_pos += 2
                    str_pos += 2
                    raw = self.data[str_pos : str_pos + length * 2]
                    s = raw.decode("utf-16le", errors="replace")
                self.strings.append(s)
            except Exception:
                self.strings.append("")

    def _parse_resource_ids(self, offset: int, chunk_size: int):
        count = (chunk_size - 8) // 4
        self.resource_ids = []
        for i in range(count):
            pos = offset + 8 + i * 4
            if pos + 4 <= len(self.data):
                self.resource_ids.append(struct.unpack("<I", self.data[pos : pos + 4])[0])

    def _parse_start_namespace(self, offset: int):
        if offset + 24 <= len(self.data):
            _, _, _, _, prefix_idx, uri_idx = struct.unpack("<IIIIii", self.data[offset : offset + 24])
            prefix = self._get_string(prefix_idx)
            uri = self._get_string(uri_idx)
            if prefix and uri:
                self.namespaces[prefix] = uri

    def _parse_start_tag(self, offset: int, indent: int) -> Tuple[str, int]:
        if offset + 36 > len(self.data):
            return "", indent
        (
            chunk_type,
            chunk_size,
            line_number,
            comment_idx,
            ns_idx,
            name_idx,
            attr_start,
            attr_size,
            attr_count,
            id_idx,
            class_idx,
            style_idx,
        ) = struct.unpack("<IIIIiiHHHhhh", self.data[offset : offset + 36])

        tag_name = self._get_string(name_idx)
        attrs = []

        curr_attr = offset + 36
        for i in range(attr_count):
            if curr_attr + 20 > len(self.data):
                break
            a_ns, a_name, a_val_str, a_type, a_data = struct.unpack("<iiihI", self.data[curr_attr : curr_attr + 20])
            attr_name_str = self._get_string(a_name)
            attr_val_str = self._format_attr_value(a_type, a_data, a_val_str)
            
            # Format android: prefix if namespace exists
            if self._get_string(a_ns):
                attr_name_str = f"android:{attr_name_str}"
            
            attrs.append(f'{attr_name_str}="{attr_val_str}"')
            curr_attr += 20

        # Inject default xmlns:android on manifest tag if not present
        if tag_name == "manifest" and "xmlns:android" not in " ".join(attrs):
            attrs.insert(0, 'xmlns:android="http://schemas.android.com/apk/res/android"')

        attr_str = (" " + " ".join(attrs)) if attrs else ""
        pad = "    " * indent
        line = f"{pad}<{tag_name}{attr_str}>"
        return line, indent + 1

    def _parse_end_tag(self, offset: int, indent: int) -> Tuple[str, int]:
        if offset + 24 > len(self.data):
            return "", indent
        _, _, _, _, ns_idx, name_idx = struct.unpack("<IIIIii", self.data[offset : offset + 24])
        tag_name = self._get_string(name_idx)
        new_indent = max(0, indent - 1)
        pad = "    " * new_indent
        return f"{pad}</{tag_name}>", new_indent

    def _get_string(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""

    def _format_attr_value(self, attr_type: int, data: int, val_idx: int) -> str:
        val_type = (attr_type >> 24) & 0xFF
        if val_idx != -1:
            return self._get_string(val_idx)
        elif val_type == TYPE_INT_BOOLEAN:
            return "true" if data != 0 else "false"
        elif val_type == TYPE_INT_HEX:
            return f"0x{data:08x}"
        elif val_type == TYPE_REFERENCE:
            return f"@0x{data:08x}"
        elif val_type == TYPE_INT_DEC:
            return str(data)
        return str(data)

    def _extract_metadata_from_text(self, text: str):
        import re
        pkg_m = re.search(r'package="([^"]+)"', text)
        if pkg_m:
            self.package_name = pkg_m.group(1)
        
        vcode_m = re.search(r'android:versionCode="([^"]+)"', text)
        if vcode_m:
            self.version_code = vcode_m.group(1)

        vname_m = re.search(r'android:versionName="([^"]+)"', text)
        if vname_m:
            self.version_name = vname_m.group(1)

        self.permissions = re.findall(r'<uses-permission\s+android:name="([^"]+)"', text)
        self.activities = re.findall(r'<activity[^>]*android:name="([^"]+)"', text)
        self.services = re.findall(r'<service[^>]*android:name="([^"]+)"', text)
        self.receivers = re.findall(r'<receiver[^>]*android:name="([^"]+)"', text)
        self.providers = re.findall(r'<provider[^>]*android:name="([^"]+)"', text)
        self.is_debuggable = 'android:debuggable="true"' in text

    def to_xml(self) -> str:
        """Return formatted XML string."""
        if not self.xml_lines:
            return '<?xml version="1.0" encoding="utf-8"?>\n<manifest />'
        return '<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(self.xml_lines)
