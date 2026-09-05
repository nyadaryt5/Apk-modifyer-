"""Hand-built Android binaries, encoded straight from the format spec.

Nothing here imports ``apkmod``. These fixtures are a second, independent
implementation of the same byte layouts, so the tests check the toolkit
against something other than itself.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

NO_STRING = 0xFFFFFFFF
ANDROID_NS = "http://schemas.android.com/apk/res/android"

TYPE_NULL = 0x00
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

XML_TYPE = 0x0003
STRING_POOL_TYPE = 0x0001
RESOURCE_MAP_TYPE = 0x0180
START_NAMESPACE = 0x0100
END_NAMESPACE = 0x0101
START_ELEMENT = 0x0102
END_ELEMENT = 0x0103

TABLE_TYPE = 0x0002
PACKAGE_TYPE = 0x0200
TYPE_TYPE = 0x0201
TYPE_SPEC_TYPE = 0x0202


# ==========================================================================
# string pool
# ==========================================================================
def _len8(value: int) -> bytes:
    return bytes([0x80 | (value >> 8), value & 0xFF]) if value > 0x7F else bytes([value])


def _len16(value: int) -> bytes:
    return struct.pack("<HH", 0x8000 | (value >> 16), value & 0xFFFF) if value > 0x7FFF else struct.pack("<H", value)


def string_pool(strings: Sequence[str], utf8: bool = True) -> bytes:
    offsets: List[int] = []
    blob = bytearray()
    for text in strings:
        offsets.append(len(blob))
        if utf8:
            raw = text.encode("utf-8")
            blob += _len8(len(text)) + _len8(len(raw)) + raw + b"\x00"
        else:
            raw = text.encode("utf-16-le")
            blob += _len16(len(raw) // 2) + raw + b"\x00\x00"
    while len(blob) % 4:
        blob.append(0)
    start = 28 + 4 * len(strings)
    return (
        struct.pack("<HHIIIIII", STRING_POOL_TYPE, 28, start + len(blob), len(strings), 0, 0x100 if utf8 else 0, start, 0)
        + struct.pack(f"<{len(strings)}I", *offsets)
        + bytes(blob)
    )


# ==========================================================================
# binary XML
# ==========================================================================
def node(chunk_type: int, line: int, ext: bytes, comment: int = NO_STRING) -> bytes:
    return struct.pack("<HHIII", chunk_type, 16, 16 + len(ext), line, comment) + ext


def attribute(ns: int, name: int, raw: int, data_type: int, data: int) -> bytes:
    return struct.pack("<III", ns, name, raw) + struct.pack("<HBBI", 8, 0, data_type, data)


def start_element(ns: int, name: int, attrs: Sequence[bytes], line: int) -> bytes:
    ext = struct.pack("<IIHHHHHH", ns, name, 20, 20, len(attrs), 0, 0, 0) + b"".join(attrs)
    return node(START_ELEMENT, line, ext)


def end_element(ns: int, name: int, line: int) -> bytes:
    return node(END_ELEMENT, line, struct.pack("<II", ns, name))


def namespace(prefix: int, uri: int, start: bool, line: int) -> bytes:
    return node(START_NAMESPACE if start else END_NAMESPACE, line, struct.pack("<II", prefix, uri))


def axml(strings: Sequence[str], res_ids: Sequence[int], nodes: Sequence[bytes]) -> bytes:
    body = string_pool(strings)
    if res_ids:
        body += struct.pack("<HHI", RESOURCE_MAP_TYPE, 8, 8 + 4 * len(res_ids))
        body += struct.pack(f"<{len(res_ids)}I", *res_ids)
    body += b"".join(nodes)
    return struct.pack("<HHI", XML_TYPE, 8, 8 + len(body)) + body


MANIFEST_STRINGS = [
    "package",            # 0
    "versionCode",        # 1
    "versionName",        # 2
    "name",               # 3
    "label",              # 4
    "debuggable",         # 5
    "minSdkVersion",      # 6
    "targetSdkVersion",   # 7
    "exported",           # 8
    "manifest",           # 9
    "uses-sdk",           # 10
    "uses-permission",    # 11
    "application",        # 12
    "activity",           # 13
    "intent-filter",      # 14
    "action",             # 15
    "category",           # 16
    "com.example.demo",   # 17
    "1.0",                # 18
    "android.permission.INTERNET",          # 19
    "android.permission.CAMERA",            # 20
    "Demo App",           # 21
    ".MainActivity",      # 22
    "android.intent.action.MAIN",           # 23
    "android.intent.category.LAUNCHER",     # 24
    ANDROID_NS,           # 25
    "android",            # 26
]

MANIFEST_RES_IDS = [
    0x0101021B,  # package
    0x0101021C,  # versionCode
    0x0101021D,  # versionName
    0x01010003,  # name
    0x01010001,  # label
    0x0101000F,  # debuggable
    0x0101020C,  # minSdkVersion
    0x01010270,  # targetSdkVersion
    0x01010010,  # exported
]

PKG, VERCODE, VERNAME, NAME, LABEL = 0, 1, 2, 3, 4
DEBUGGABLE, MINSDK, TARGETSDK, EXPORTED = 5, 6, 7, 8
MANIFEST, USES_SDK, USES_PERM, APPLICATION, ACTIVITY = 9, 10, 11, 12, 13
INTENT_FILTER, ACTION, CATEGORY = 14, 15, 16
PACKAGE_NAME, VERSION_TEXT = 17, 18
PERM_INTERNET, PERM_CAMERA = 19, 20
APP_LABEL, MAIN_ACTIVITY = 21, 22
ACTION_MAIN, CATEGORY_LAUNCHER = 23, 24
NS_URI, NS_PREFIX = 25, 26


def build_manifest_axml() -> bytes:
    """A realistic little AndroidManifest.xml: 2 permissions, 1 launcher activity."""
    nodes = [
        namespace(NS_PREFIX, NS_URI, True, 1),
        start_element(
            NO_STRING,
            MANIFEST,
            [
                attribute(NO_STRING, PKG, PACKAGE_NAME, TYPE_STRING, PACKAGE_NAME),
                attribute(NS_URI, VERCODE, NO_STRING, TYPE_INT_DEC, 1),
                attribute(NS_URI, VERNAME, VERSION_TEXT, TYPE_STRING, VERSION_TEXT),
            ],
            2,
        ),
        start_element(
            NO_STRING,
            USES_SDK,
            [
                attribute(NS_URI, MINSDK, NO_STRING, TYPE_INT_DEC, 21),
                attribute(NS_URI, TARGETSDK, NO_STRING, TYPE_INT_DEC, 34),
            ],
            3,
        ),
        end_element(NO_STRING, USES_SDK, 3),
        start_element(
            NO_STRING, USES_PERM, [attribute(NS_URI, NAME, PERM_INTERNET, TYPE_STRING, PERM_INTERNET)], 4
        ),
        end_element(NO_STRING, USES_PERM, 4),
        start_element(NO_STRING, USES_PERM, [attribute(NS_URI, NAME, PERM_CAMERA, TYPE_STRING, PERM_CAMERA)], 5),
        end_element(NO_STRING, USES_PERM, 5),
        start_element(
            NO_STRING,
            APPLICATION,
            [
                attribute(NS_URI, LABEL, APP_LABEL, TYPE_STRING, APP_LABEL),
                attribute(NS_URI, DEBUGGABLE, NO_STRING, TYPE_INT_BOOLEAN, 0),
            ],
            6,
        ),
        start_element(
            NO_STRING,
            ACTIVITY,
            [
                attribute(NS_URI, NAME, MAIN_ACTIVITY, TYPE_STRING, MAIN_ACTIVITY),
                attribute(NS_URI, EXPORTED, NO_STRING, TYPE_INT_BOOLEAN, 0xFFFFFFFF),
            ],
            7,
        ),
        start_element(NO_STRING, INTENT_FILTER, [], 8),
        start_element(NO_STRING, ACTION, [attribute(NS_URI, NAME, ACTION_MAIN, TYPE_STRING, ACTION_MAIN)], 9),
        end_element(NO_STRING, ACTION, 9),
        start_element(
            NO_STRING, CATEGORY, [attribute(NS_URI, NAME, CATEGORY_LAUNCHER, TYPE_STRING, CATEGORY_LAUNCHER)], 10
        ),
        end_element(NO_STRING, CATEGORY, 10),
        end_element(NO_STRING, INTENT_FILTER, 8),
        end_element(NO_STRING, ACTIVITY, 7),
        end_element(NO_STRING, APPLICATION, 6),
        end_element(NO_STRING, MANIFEST, 2),
        namespace(NS_PREFIX, NS_URI, False, 1),
    ]
    return axml(MANIFEST_STRINGS, MANIFEST_RES_IDS, nodes)


# ==========================================================================
# resources.arsc
# ==========================================================================
def build_arsc(
    value_strings: Sequence[str] = ("Demo App", "Hello world"),
    package_name: str = "com.example.demo",
    type_names: Sequence[str] = ("string",),
    key_names: Sequence[str] = ("app_name", "greeting"),
    entries: Sequence[Tuple[int, int, int]] = ((0, 0, 0), (0, 1, 1)),
    package_id: int = 0x7F,
) -> bytes:
    """One package, one type, a couple of string resources."""
    config = struct.pack(
        "<IHH2s2sBBHBBBBHHHH",
        28, 0, 0, b"\x00\x00", b"\x00\x00", 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0
    )
    header_size = 20 + len(config)

    entry_blob = bytearray()
    offsets: List[int] = []
    for _type_index, key_index, value_index in entries:
        offsets.append(len(entry_blob))
        entry_blob += struct.pack("<HHI", 8, 0, key_index)  # ResTable_entry
        entry_blob += struct.pack("<HBBI", 8, 0, TYPE_STRING, value_index)  # Res_value

    type_chunk = (
        struct.pack("<HHIBBHHII", TYPE_TYPE, header_size, 0, 1, 0, 0, len(entries), header_size + 4 * len(entries), 0)[:0]
        + struct.pack("<HHI", TYPE_TYPE, header_size, 0)
        + struct.pack("<BBH", 1, 0, 0)
        + struct.pack("<II", len(entries), header_size + 4 * len(entries))
        + config
        + struct.pack(f"<{len(offsets)}I", *offsets)
        + bytes(entry_blob)
    )
    # fix the chunk size now that everything is known
    type_chunk = type_chunk[:4] + struct.pack("<I", len(type_chunk)) + type_chunk[8:]

    spec_chunk = struct.pack("<HHI", TYPE_SPEC_TYPE, 16, 16 + 4 * len(type_names)) + struct.pack("<BBH", 1, 0, 0)
    spec_chunk += struct.pack("<I", len(type_names)) + struct.pack(f"<{len(type_names)}I", *([0] * len(type_names)))

    type_pool = string_pool(type_names)
    key_pool = string_pool(key_names)

    package = struct.pack("<HHI", PACKAGE_TYPE, 288, 0) + struct.pack("<I", package_id)
    package += package_name.encode("utf-16-le").ljust(256, b"\x00")[:256]
    package += struct.pack("<IIIII", 288, 0, 288 + len(type_pool), 0, 0)
    package += type_pool + key_pool + spec_chunk + type_chunk
    package = package[:4] + struct.pack("<I", len(package)) + package[8:]

    value_pool = string_pool(value_strings)
    table = struct.pack("<HHII", TABLE_TYPE, 12, 0, 1) + value_pool + package
    return table[:4] + struct.pack("<I", len(table)) + table[8:]


# ==========================================================================
# classes.dex
# ==========================================================================
def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def mutf8(text: str) -> bytes:
    out = bytearray()
    for char in text:
        code = ord(char)
        if code == 0:
            out += b"\xc0\x80"
        elif code < 0x80:
            out.append(code)
        elif code < 0x800:
            out += bytes([0xC0 | (code >> 6), 0x80 | (code & 0x3F)])
        else:
            out += bytes([0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F)])
    return bytes(out)


DEX_STRINGS = [
    "Lcom/example/demo/MainActivity;",
    "GET_SIGNATURES",
    "getPackageInfo",
    "Landroid/content/pm/Signature;",
    "com/appsflyer/AppsFlyerLib",
    "com/google/android/gms/ads/AdView",
    "https://api.example.com/v1/login",
    "apiKey=0123456789abcdef0123456789abcdef",
    "café",          # two-byte MUTF-8
    "a\x00b",        # NUL encoded as C0 80, not a bare 0x00
]


def build_dex(strings: Sequence[str] = DEX_STRINGS, type_indices: Sequence[int] = (0, 3)) -> bytes:
    header_size = 0x70
    string_ids_off = header_size
    data_off = string_ids_off + 4 * len(strings)

    body = bytearray()
    offsets: List[int] = []
    for text in strings:
        offsets.append(data_off + len(body))
        encoded = mutf8(text)
        body += _uleb128(len(text)) + encoded + b"\x00"
    while len(body) % 4:
        body.append(0)

    type_ids_off = data_off + len(body)
    type_blob = struct.pack(f"<{len(type_indices)}I", *type_indices)

    file_size = type_ids_off + len(type_blob)
    # DEX header: magic(8) checksum(4) signature(20) file_size(4) header_size(4)
    #             endian_tag(4) link(8) map_off(4) string_ids(8) type_ids(8) ...
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)         # endian_tag
    struct.pack_into("<I", header, 56, len(strings))       # string_ids_size
    struct.pack_into("<I", header, 60, string_ids_off)     # string_ids_off
    struct.pack_into("<I", header, 64, len(type_indices))  # type_ids_size
    struct.pack_into("<I", header, 68, type_ids_off)       # type_ids_off
    struct.pack_into("<I", header, 96, 0)                  # class_defs_size
    struct.pack_into("<I", header, 104, len(body))         # data_size
    struct.pack_into("<I", header, 108, data_off)          # data_off

    blob = bytes(header) + struct.pack(f"<{len(strings)}I", *offsets) + bytes(body) + type_blob
    blob = blob[:8] + struct.pack("<I", zlib.adler32(blob[12:])) + blob[12:]
    blob = blob[:12] + hashlib.sha1(blob[32:]).digest() + blob[32:]
    return blob


# ==========================================================================
# the APK itself
# ==========================================================================
APK_ENTRIES = {
    "lib/arm64-v8a/libdemo.so": b"\x7fELF" + b"\x00" * 512,
    "assets/config.json": b'{"endpoint":"https://api.example.com/v1","ads":true}',
    "res/raw/keep.txt": b"do not delete\n",
}


def build_apk(path: Path) -> Path:
    """A minimal but structurally honest APK: manifest, ARSC, DEX, a .so, an asset."""
    path = Path(path)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", build_manifest_axml(), compress_type=zipfile.ZIP_STORED)
        zf.writestr("resources.arsc", build_arsc(), compress_type=zipfile.ZIP_STORED)
        zf.writestr("classes.dex", build_dex(), compress_type=zipfile.ZIP_DEFLATED)
        for name, data in APK_ENTRIES.items():
            method = zipfile.ZIP_STORED if name.endswith(".so") else zipfile.ZIP_DEFLATED
            zf.writestr(name, data, compress_type=method)
    return path


def add_signing_block(apk: Path, block_ids: Sequence[int] = (0x7109871A,)) -> Path:
    """Insert a fake APK Signing Block so scheme detection can be tested."""
    data = bytearray(Path(apk).read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    pairs = bytearray()
    for block_id in block_ids:
        payload = b"\x00" * 16
        pairs += struct.pack("<QI", 4 + len(payload), block_id) + payload
    size_of_block = len(pairs) + 8 + 16  # pairs + trailing size + magic
    block = struct.pack("<Q", size_of_block) + bytes(pairs) + struct.pack("<Q", size_of_block) + b"APK Sig Block 42"
    new = bytes(data[:cd_offset]) + block + bytes(data[cd_offset:])
    new_eocd = new.rfind(b"PK\x05\x06")
    patched = bytearray(new)
    struct.pack_into("<I", patched, new_eocd + 16, cd_offset + len(block))
    Path(apk).write_bytes(bytes(patched))
    return Path(apk)


def build_signed_pair(dir_path: Path) -> Tuple[Path, Path]:
    """An unsigned APK plus an already-modified copy, for signature tests."""
    unsigned = build_apk(Path(dir_path) / "unsigned.apk")
    return unsigned, unsigned
