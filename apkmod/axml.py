"""Native reader / writer / patcher for Android binary XML (AXML).

This is the piece that lets the toolkit edit an APK's AndroidManifest.xml
*without* decompiling the whole package -- the same trick "APK Editor"-style
tools use. Everything here is pure Python, so it works with no JDK present.

The writer is faithful: parsing and re-serialising an untouched file yields
byte-identical output, which is what makes edits safe to make.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence, Tuple

from .util import ApkModError

__all__ = [
    "StringPool",
    "ResValue",
    "Attribute",
    "ElementStart",
    "AxmlFile",
    "ANDROID_NS",
    "RES_ID_ANDROID_NAME",
]

# --- chunk types ----------------------------------------------------------
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

UTF8_FLAG = 1 << 8
SORTED_FLAG = 1 << 0

# --- typed value data types ----------------------------------------------
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

NO_STRING = 0xFFFFFFFF
ANDROID_NS = "http://schemas.android.com/apk/res/android"
RES_ID_ANDROID_NAME = 0x01010003  # android:name

_TYPE_NAMES = {
    TYPE_NULL: "null",
    TYPE_REFERENCE: "reference",
    TYPE_ATTRIBUTE: "attribute",
    TYPE_STRING: "string",
    TYPE_FLOAT: "float",
    TYPE_DIMENSION: "dimension",
    TYPE_FRACTION: "fraction",
    TYPE_INT_DEC: "int_dec",
    TYPE_INT_HEX: "int_hex",
    TYPE_INT_BOOLEAN: "int_boolean",
    TYPE_INT_COLOR_ARGB8: "color_argb8",
    TYPE_INT_COLOR_RGB8: "color_rgb8",
    TYPE_INT_COLOR_ARGB4: "color_argb4",
    TYPE_INT_COLOR_RGB4: "color_rgb4",
}


# ==========================================================================
# string pool
# ==========================================================================
class StringPool:
    """ResStringPool_header + offsets + string data (+ optional raw styles)."""

    HEADER_SIZE = 28

    def __init__(
        self,
        strings: Optional[List[str]] = None,
        flags: int = UTF8_FLAG,
        styles_raw: bytes = b"",
        style_offsets: Sequence[int] = (),
    ) -> None:
        self.strings: List[str] = list(strings or [])
        self.flags = flags
        self.styles_raw = styles_raw
        self.style_offsets: List[int] = list(style_offsets)

    # -- properties -------------------------------------------------------
    @property
    def is_utf8(self) -> bool:
        return bool(self.flags & UTF8_FLAG)

    def get(self, index: int | None) -> Optional[str]:
        if index is None or index == NO_STRING or index < 0 or index >= len(self.strings):
            return None
        return self.strings[index]

    def index_of(self, text: str) -> int:
        try:
            return self.strings.index(text)
        except ValueError:
            return NO_STRING

    def intern(self, text: str) -> int:
        """Return the index of ``text``, appending it if it is not pooled yet."""
        existing = self.index_of(text)
        if existing != NO_STRING:
            return existing
        self.strings.append(text)
        return len(self.strings) - 1

    def __len__(self) -> int:
        return len(self.strings)

    # -- encoding ---------------------------------------------------------
    @staticmethod
    def _decode_len8(data: bytes, pos: int) -> Tuple[int, int]:
        first = data[pos]
        if first & 0x80:
            return ((first & 0x7F) << 8) | data[pos + 1], pos + 2
        return first, pos + 1

    @staticmethod
    def _decode_len16(data: bytes, pos: int) -> Tuple[int, int]:
        first = struct.unpack_from("<H", data, pos)[0]
        if first & 0x8000:
            second = struct.unpack_from("<H", data, pos + 2)[0]
            return ((first & 0x7FFF) << 16) | second, pos + 4
        return first, pos + 2

    @staticmethod
    def _encode_len8(value: int) -> bytes:
        if value > 0x7F:
            return bytes([0x80 | (value >> 8), value & 0xFF])
        return bytes([value])

    @staticmethod
    def _encode_len16(value: int) -> bytes:
        if value > 0x7FFF:
            return struct.pack("<HH", 0x8000 | (value >> 16), value & 0xFFFF)
        return struct.pack("<H", value)

    def _encode_string(self, text: str) -> bytes:
        if self.is_utf8:
            raw = text.encode("utf-8")
            return (
                self._encode_len8(len(text))
                + self._encode_len8(len(raw))
                + raw
                + b"\x00"
            )
        raw = text.encode("utf-16-le")
        units = len(raw) // 2
        return self._encode_len16(units) + raw + b"\x00\x00"

    # -- parse / serialize ------------------------------------------------
    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Tuple["StringPool", int]:
        if offset + cls.HEADER_SIZE > len(data):
            raise ApkModError("string pool header is truncated")
        ctype, header_size, size = struct.unpack_from("<HHI", data, offset)
        if ctype != RES_STRING_POOL_TYPE:
            raise ApkModError(f"expected a string pool (0x0001), got 0x{ctype:04x}")
        string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<IIIII", data, offset + 8
        )
        offsets = list(struct.unpack_from(f"<{string_count}I", data, offset + 28))
        style_offsets = list(
            struct.unpack_from(f"<{style_count}I", data, offset + 28 + 4 * string_count)
        )
        base = offset + strings_start
        pool = cls(flags=flags, style_offsets=style_offsets)
        for rel in offsets:
            pos = base + rel
            if flags & UTF8_FLAG:
                _chars, pos = cls._decode_len8(data, pos)
                nbytes, pos = cls._decode_len8(data, pos)
                pool.strings.append(data[pos : pos + nbytes].decode("utf-8", "replace"))
            else:
                units, pos = cls._decode_len16(data, pos)
                raw = data[pos : pos + 2 * units]
                pool.strings.append(raw.decode("utf-16-le", "replace"))
        if style_count and styles_start:
            styles_begin = offset + styles_start
            pool.styles_raw = data[styles_begin : offset + size]
        return pool, size

    def serialize(self) -> bytes:
        strings_start = self.HEADER_SIZE + 4 * len(self.strings) + 4 * len(self.style_offsets)
        blob = bytearray()
        offsets: List[int] = []
        for text in self.strings:
            offsets.append(len(blob))
            blob += self._encode_string(text)
        while len(blob) % 4:
            blob += b"\x00"
        styles_start = 0
        styles = bytearray()
        if self.style_offsets:
            styles_start = strings_start + len(blob)
            styles += self.styles_raw
            while len(styles) % 4:
                styles += b"\x00"
        size = strings_start + len(blob) + len(styles)
        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE,
            self.HEADER_SIZE,
            size,
            len(self.strings),
            len(self.style_offsets),
            self.flags,
            strings_start,
            styles_start,
        )
        return (
            header
            + struct.pack(f"<{len(offsets)}I", *offsets)
            + (struct.pack(f"<{len(self.style_offsets)}I", *self.style_offsets) if self.style_offsets else b"")
            + bytes(blob)
            + bytes(styles)
        )


# ==========================================================================
# nodes
# ==========================================================================
@dataclass
class ResValue:
    dataType: int = TYPE_NULL
    data: int = 0
    size: int = 8
    res0: int = 0

    def type_name(self) -> str:
        return _TYPE_NAMES.get(self.dataType, f"0x{self.dataType:02x}")

    def serialize(self) -> bytes:
        return struct.pack("<HBBI", self.size, self.res0, self.dataType, self.data & 0xFFFFFFFF)

    @classmethod
    def parse(cls, data: bytes, offset: int) -> "ResValue":
        size, res0, data_type, value = struct.unpack_from("<HBBI", data, offset)
        return cls(dataType=data_type, data=value, size=size, res0=res0)


@dataclass
class Attribute:
    ns: int  # string pool index of the namespace URI, or NO_STRING
    name: int  # string pool index of the attribute name
    rawValue: int  # string pool index or NO_STRING
    value: ResValue = field(default_factory=ResValue)

    def serialize(self) -> bytes:
        return struct.pack(
            "<III",
            self.ns if self.ns != NO_STRING else 0xFFFFFFFF,
            self.name,
            self.rawValue if self.rawValue != NO_STRING else 0xFFFFFFFF,
        ) + self.value.serialize()

    @classmethod
    def parse(cls, data: bytes, offset: int) -> "Attribute":
        ns, name, raw = struct.unpack_from("<III", data, offset)
        return cls(ns=ns, name=name, rawValue=raw, value=ResValue.parse(data, offset + 12))


class Node:
    """Base for every AXML chunk after the resource map."""

    chunk_type = 0

    def __init__(self, line: int = 0, comment: int = NO_STRING) -> None:
        self.line = line
        self.comment = comment

    def body(self) -> bytes:
        raise NotImplementedError

    def serialize(self) -> bytes:
        body = self.body()
        return struct.pack("<HHIII", self.chunk_type, 16, 16 + len(body), self.line, self.comment) + body


@dataclass
class NamespaceNode(Node):
    prefix: int = NO_STRING
    uri: int = NO_STRING
    is_start: bool = True

    def __init__(self, prefix: int, uri: int, is_start: bool, line: int = 0, comment: int = NO_STRING):
        super().__init__(line, comment)
        self.prefix = prefix
        self.uri = uri
        self.is_start = is_start
        self.chunk_type = RES_XML_START_NAMESPACE_TYPE if is_start else RES_XML_END_NAMESPACE_TYPE

    def body(self) -> bytes:
        return struct.pack("<II", self.prefix, self.uri)


class ElementEnd(Node):
    chunk_type = RES_XML_END_ELEMENT_TYPE

    def __init__(self, ns: int, name: int, line: int = 0, comment: int = NO_STRING):
        super().__init__(line, comment)
        self.ns = ns
        self.name = name

    def body(self) -> bytes:
        return struct.pack("<II", self.ns, self.name)


class CData(Node):
    chunk_type = RES_XML_CDATA_TYPE

    def __init__(self, data_ref: int, value: ResValue, line: int = 0, comment: int = NO_STRING):
        super().__init__(line, comment)
        self.data_ref = data_ref
        self.value = value

    def body(self) -> bytes:
        return struct.pack("<I", self.data_ref) + self.value.serialize()


class ElementStart(Node):
    chunk_type = RES_XML_START_ELEMENT_TYPE

    def __init__(
        self,
        ns: int,
        name: int,
        attributes: Optional[List[Attribute]] = None,
        line: int = 0,
        comment: int = NO_STRING,
        attribute_start: int = 20,
        attribute_size: int = 20,
        id_index: int = 0,
        class_index: int = 0,
        style_index: int = 0,
    ) -> None:
        super().__init__(line, comment)
        self.ns = ns
        self.name = name
        self.attributes: List[Attribute] = list(attributes or [])
        self.attribute_start = attribute_start
        self.attribute_size = attribute_size
        self.id_index = id_index
        self.class_index = class_index
        self.style_index = style_index

    def body(self) -> bytes:
        head = struct.pack(
            "<IIHHHHHH",
            self.ns,
            self.name,
            self.attribute_start,
            self.attribute_size,
            len(self.attributes),
            self.id_index,
            self.class_index,
            self.style_index,
        )
        return head + b"".join(a.serialize() for a in self.attributes)

    # -- attribute helpers ------------------------------------------------
    def find_attr(self, pool: StringPool, local_name: str, namespace: str | None = ANDROID_NS) -> Optional[Attribute]:
        for attr in self.attributes:
            if pool.get(attr.name) != local_name:
                continue
            if namespace is None:
                if attr.ns == NO_STRING or pool.get(attr.ns) is None:
                    return attr
            elif pool.get(attr.ns) == namespace:
                return attr
        return None

    def attr_value(self, pool: StringPool, local_name: str, namespace: str | None = ANDROID_NS) -> Optional[str]:
        attr = self.find_attr(pool, local_name, namespace)
        if attr is None:
            return None
        return attr.text(pool)

    def set_attr(
        self,
        pool: StringPool,
        local_name: str,
        text: str,
        namespace: str | None = ANDROID_NS,
        res_id: int | None = None,
    ) -> Attribute:
        attr = self.find_attr(pool, local_name, namespace)
        if attr is None:
            ns_index = NO_STRING
            if namespace is not None:
                ns_index = pool.index_of(namespace)
                if ns_index == NO_STRING:
                    raise ApkModError(f"namespace {namespace} is not declared in this file")
            attr = Attribute(ns=ns_index, name=pool.intern(local_name), rawValue=NO_STRING)
            self.attributes.append(attr)
        string_index = pool.intern(text)
        attr.rawValue = string_index
        attr.value = ResValue(dataType=TYPE_STRING, data=string_index)
        return attr


# Attribute needs ElementStart's pool helpers to resolve its own text.
def _number(element: "ElementStart", pool: StringPool, local_name: str) -> Optional[int]:
    attr = element.find_attr(pool, local_name)
    if attr is None:
        return None
    return attr.number()


def _attr_text(self: Attribute, pool: StringPool) -> Optional[str]:
    value = self.value
    if value.dataType == TYPE_STRING:
        text = pool.get(value.data)
        if text is not None:
            return text
        return pool.get(self.rawValue)
    if value.dataType == TYPE_INT_BOOLEAN:
        return "true" if value.data != 0 else "false"
    if value.dataType == TYPE_INT_HEX:
        return f"0x{value.data:x}"
    if value.dataType in (TYPE_INT_DEC, TYPE_NULL, TYPE_REFERENCE, TYPE_ATTRIBUTE, TYPE_DYNAMIC_REFERENCE):
        return str(value.data) if value.dataType != TYPE_NULL else None
    return str(value.data)


def _attr_number(self: Attribute) -> Optional[int]:
    """Numeric value of an integer-typed attribute, whatever the storage type."""
    if self.value.dataType in (TYPE_INT_DEC, TYPE_INT_HEX):
        return self.value.data
    if self.value.dataType == TYPE_INT_BOOLEAN:
        return int(self.value.data != 0)
    return None


def _attr_describe(self: Attribute, pool: StringPool) -> str:
    ns = pool.get(self.ns)
    prefix = ""
    if ns == ANDROID_NS:
        prefix = "android:"
    elif ns:
        prefix = f"{{{ns}}}:"
    return f"{prefix}{pool.get(self.name)}={self.text(pool)!r}"


Attribute.text = _attr_text  # type: ignore[attr-defined]
Attribute.number = _attr_number  # type: ignore[attr-defined]
Attribute.describe = _attr_describe  # type: ignore[attr-defined]


# ==========================================================================
# the file
# ==========================================================================
class AxmlFile:
    """A parsed binary XML document (AndroidManifest.xml, resources XML, ...)."""

    def __init__(
        self,
        pool: StringPool,
        nodes: List[Node],
        resource_ids: Optional[List[int]] = None,
    ) -> None:
        self.pool = pool
        self.nodes = nodes
        self.resource_ids: List[int] = list(resource_ids or [])

    # -- parse ------------------------------------------------------------
    @classmethod
    def parse(cls, data: bytes) -> "AxmlFile":
        if len(data) < 8:
            raise ApkModError("file too small to be binary XML")
        ctype, header_size, size = struct.unpack_from("<HHI", data, 0)
        if ctype != RES_XML_TYPE:
            raise ApkModError(
                f"not a binary XML document (magic 0x{ctype:04x}); "
                "is this an already-decoded plain-text manifest?"
            )
        pool, pool_size = StringPool.parse(data, 8)
        pos = 8 + pool_size
        resource_ids: List[int] = []
        nodes: List[Node] = []
        while pos + 8 <= len(data):
            chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", data, pos)
            if chunk_size < 8 or pos + chunk_size > len(data):
                break
            if chunk_type == RES_XML_RESOURCE_MAP_TYPE:
                count = (chunk_size - 8) // 4
                resource_ids = list(struct.unpack_from(f"<{count}I", data, pos + 8)) if count else []
            elif chunk_type in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
                prefix, uri = struct.unpack_from("<II", data, pos + 16)
                line, comment = struct.unpack_from("<II", data, pos + 8)
                nodes.append(
                    NamespaceNode(
                        prefix,
                        uri,
                        chunk_type == RES_XML_START_NAMESPACE_TYPE,
                        line,
                        comment,
                    )
                )
            elif chunk_type == RES_XML_START_ELEMENT_TYPE:
                line, comment = struct.unpack_from("<II", data, pos + 8)
                ns, name, attr_start, attr_size, attr_count, id_idx, class_idx, style_idx = struct.unpack_from(
                    "<IIHHHHHH", data, pos + 16
                )
                attrs = []
                for i in range(attr_count):
                    attrs.append(Attribute.parse(data, pos + 16 + attr_start + i * attr_size))
                nodes.append(
                    ElementStart(
                        ns,
                        name,
                        attrs,
                        line,
                        comment,
                        attr_start,
                        attr_size,
                        id_idx,
                        class_idx,
                        style_idx,
                    )
                )
            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                line, comment = struct.unpack_from("<II", data, pos + 8)
                ns, name = struct.unpack_from("<II", data, pos + 16)
                nodes.append(ElementEnd(ns, name, line, comment))
            elif chunk_type == RES_XML_CDATA_TYPE:
                line, comment = struct.unpack_from("<II", data, pos + 8)
                (data_ref,) = struct.unpack_from("<I", data, pos + 16)
                nodes.append(CData(data_ref, ResValue.parse(data, pos + 20), line, comment))
            pos += chunk_size
        return cls(pool, nodes, resource_ids)

    # -- serialize --------------------------------------------------------
    def serialize(self) -> bytes:
        body = self.pool.serialize()
        if self.resource_ids:
            body += struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + 4 * len(self.resource_ids))
            body += struct.pack(f"<{len(self.resource_ids)}I", *self.resource_ids)
        body += b"".join(node.serialize() for node in self.nodes)
        return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body)) + body

    # -- queries ----------------------------------------------------------
    def elements(self) -> List[ElementStart]:
        return [n for n in self.nodes if isinstance(n, ElementStart)]

    def elements_named(self, *names: str) -> List[ElementStart]:
        wanted = set(names)
        return [e for e in self.elements() if self.pool.get(e.name) in wanted]

    def root(self) -> Optional[ElementStart]:
        for node in self.nodes:
            if isinstance(node, ElementStart):
                return node
        return None

    def to_xml(self, indent: str = "  ") -> str:
        """Render a human-readable approximation of the document."""
        out: List[str] = []
        depth = 0
        for node in self.nodes:
            if isinstance(node, NamespaceNode) and node.is_start:
                continue
            if isinstance(node, NamespaceNode):
                continue
            if isinstance(node, ElementStart):
                attrs = " ".join(a.describe(self.pool) for a in node.attributes)
                attrs = (" " + attrs) if attrs else ""
                out.append(f"{indent * depth}<{self.pool.get(node.name)}{attrs}>")
                depth += 1
            elif isinstance(node, ElementEnd):
                depth = max(0, depth - 1)
                out.append(f"{indent * depth}</{self.pool.get(node.name)}>")
            elif isinstance(node, CData):
                out.append(f"{indent * depth}{self.pool.get(node.data_ref)}")
        return "\n".join(out)

    # -- manifest-oriented edits -----------------------------------------
    def _matching_end_index(self, start_index: int) -> int:
        """Index of the ElementEnd that closes ``nodes[start_index]``."""
        element = self.nodes[start_index]
        depth = 0
        for i in range(start_index, len(self.nodes)):
            node = self.nodes[i]
            if isinstance(node, ElementStart):
                depth += 1
            elif isinstance(node, ElementEnd):
                depth -= 1
                if depth == 0:
                    return i
        raise ApkModError(f"no closing tag found for {self.pool.get(element.name)}")

    def remove_elements(self, tag: str, attr_name: str | None = None, attr_value: str | None = None) -> int:
        """Delete every ``<tag>`` (and its subtree) optionally matching an attribute."""
        removed = 0
        for index in range(len(self.nodes) - 1, -1, -1):
            node = self.nodes[index]
            if not isinstance(node, ElementStart) or self.pool.get(node.name) != tag:
                continue
            if attr_name is not None:
                current = node.attr_value(self.pool, attr_name)
                if attr_value is not None and current != attr_value:
                    continue
                if attr_value is None and current is None:
                    continue
            end_index = self._matching_end_index(index)
            del self.nodes[index : end_index + 1]
            removed += 1
        return removed

    def remove_permission(self, permission: str) -> int:
        """Strip <uses-permission> / <uses-permission-sdk-23> entries for one permission."""
        count = 0
        for tag in ("uses-permission", "uses-permission-sdk-23"):
            count += self.remove_elements(tag, "name", permission)
        return count

    def permissions(self) -> List[str]:
        found: List[str] = []
        for element in self.elements_named("uses-permission", "uses-permission-sdk-23"):
            name = element.attr_value(self.pool, "name")
            if name:
                found.append(name)
        return found

    def add_permission(self, permission: str, tag: str = "uses-permission") -> bool:
        """Insert a <uses-permission> as the first child of <manifest>. False if already present."""
        if permission in self.permissions():
            return False
        manifest_index = next(
            (i for i, n in enumerate(self.nodes) if isinstance(n, ElementStart) and self.pool.get(n.name) == "manifest"),
            None,
        )
        if manifest_index is None:
            raise ApkModError("no <manifest> element in this document")
        manifest = self.nodes[manifest_index]
        assert isinstance(manifest, ElementStart)
        ns_index = self.pool.index_of(ANDROID_NS)
        if ns_index == NO_STRING:
            raise ApkModError("android namespace is not declared; cannot add an android:name attribute")
        name_index = self.pool.intern(permission)
        attr = Attribute(
            ns=ns_index,
            name=self.pool.intern("name"),
            rawValue=name_index,
            value=ResValue(dataType=TYPE_STRING, data=name_index),
        )
        element = ElementStart(
            ns=NO_STRING,
            name=self.pool.intern(tag),
            attributes=[attr],
            line=manifest.line,
        )
        self.nodes.insert(manifest_index + 1, element)
        self.nodes.insert(manifest_index + 2, ElementEnd(NO_STRING, self.pool.index_of(tag), manifest.line))
        return True

    def set_debuggable(self, enabled: bool) -> bool:
        for application in self.elements_named("application"):
            attr = application.find_attr(self.pool, "debuggable")
            data = 0xFFFFFFFF if enabled else 0
            if attr is None:
                ns_index = self.pool.index_of(ANDROID_NS)
                application.attributes.append(
                    Attribute(
                        ns=ns_index,
                        name=self.pool.intern("debuggable"),
                        rawValue=NO_STRING,
                        value=ResValue(dataType=TYPE_INT_BOOLEAN, data=data),
                    )
                )
            else:
                attr.value = ResValue(dataType=TYPE_INT_BOOLEAN, data=data)
            return True
        return False

    def manifest_facts(self) -> dict:
        """The handful of manifest facts every report wants."""
        facts: dict = {
            "package": None,
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "target_sdk": None,
            "debuggable": None,
            "permissions": self.permissions(),
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "launcher_activity": None,
            "exported_components": [],
        }
        manifest = self.elements_named("manifest")
        if manifest:
            root = manifest[0]
            facts["package"] = root.attr_value(self.pool, "package", namespace=None)
            facts["version_code"] = _number(root, self.pool, "versionCode")
            facts["version_name"] = root.attr_value(self.pool, "versionName")
        for element in self.elements_named("uses-sdk"):
            facts["min_sdk"] = _number(element, self.pool, "minSdkVersion")
            facts["target_sdk"] = _number(element, self.pool, "targetSdkVersion")
        for application in self.elements_named("application"):
            value = application.find_attr(self.pool, "debuggable")
            if value is not None:
                facts["debuggable"] = value.value.dataType == TYPE_INT_BOOLEAN and value.value.data != 0
            facts["app_label"] = application.attr_value(self.pool, "label")
            facts["app_icon"] = application.attr_value(self.pool, "icon")
        for kind, key in (
            ("activity", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers"),
        ):
            for element in self.elements_named(kind):
                name = element.attr_value(self.pool, "name", namespace=None) or element.attr_value(self.pool, "name")
                if name:
                    facts[key].append(name)
                exported = element.find_attr(self.pool, "exported")
                if exported is not None and exported.value.data != 0 and name:
                    facts["exported_components"].append(name)
                for intent in self.elements_named("intent-filter"):
                    pass
        # launcher activity: an <activity> that owns a MAIN/LAUNCHER intent filter
        facts["launcher_activity"] = self._launcher_activity()
        return facts

    def _launcher_activity(self) -> Optional[str]:
        stack: List[ElementStart] = []
        pending_activity: Optional[str] = None
        for node in self.nodes:
            if isinstance(node, ElementStart):
                name = self.pool.get(node.name)
                if name == "activity":
                    pending_activity = node.attr_value(self.pool, "name", namespace=None) or node.attr_value(
                        self.pool, "name"
                    )
                if name == "action" and pending_activity:
                    # <action android:name="..."> in practice, but accept a bare name too
                    action_name = node.attr_value(self.pool, "name") or node.attr_value(
                        self.pool, "name", namespace=None
                    )
                    if action_name == "android.intent.action.MAIN":
                        return pending_activity
                stack.append(node)
            elif isinstance(node, ElementEnd):
                if stack and self.pool.get(stack[-1].name) == "activity":
                    pending_activity = None
                if stack:
                    stack.pop()
        return None
