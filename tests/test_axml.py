"""Binary AndroidManifest parsing, patching and re-serialisation."""

from __future__ import annotations

import struct

import pytest

import fixture

from apkmod.axml import ANDROID_NS, AxmlFile, StringPool
from apkmod.util import ApkModError

CAMERA = "android.permission.CAMERA"
INTERNET = "android.permission.INTERNET"


def _parse(blob: bytes) -> AxmlFile:
    return AxmlFile.parse(blob)


def test_roundtrip_is_byte_identical(apk_bytes):
    """parse -> serialize must reproduce the input exactly, or edits are unsafe."""
    assert _parse(apk_bytes).serialize() == apk_bytes


def test_header_size_field_matches_payload(apk_bytes):
    _ctype, _header, size = struct.unpack_from("<HHI", apk_bytes, 0)
    assert size == len(apk_bytes)


def test_string_pool_reads_every_string(apk_bytes):
    pool = _parse(apk_bytes).pool
    assert pool.is_utf8
    assert pool.strings == list(fixture.MANIFEST_STRINGS)
    assert pool.index_of(CAMERA) == fixture.PERM_CAMERA


def test_resource_map_covers_attribute_names(apk_bytes):
    document = _parse(apk_bytes)
    assert document.resource_ids == list(fixture.MANIFEST_RES_IDS)


def test_manifest_facts(apk_bytes):
    facts = _parse(apk_bytes).manifest_facts()
    assert facts["package"] == "com.example.demo"
    assert facts["version_code"] == 1
    assert facts["version_name"] == "1.0"
    assert facts["min_sdk"] == 21
    assert facts["target_sdk"] == 34
    assert facts["debuggable"] is False
    assert facts["permissions"] == [INTERNET, CAMERA]
    assert facts["activities"] == [".MainActivity"]
    assert facts["launcher_activity"] == ".MainActivity"
    assert facts["exported_components"] == [".MainActivity"]
    assert facts["app_label"] == "Demo App"


def test_to_xml_renders_readable_manifest(apk_bytes):
    xml = _parse(apk_bytes).to_xml()
    assert "<manifest" in xml and "package='com.example.demo'" in xml
    assert 'android:name=\'android.permission.CAMERA\'' in xml
    assert xml.count("</manifest>") == 1


def test_remove_permission(apk_bytes):
    document = _parse(apk_bytes)
    assert document.remove_permission(CAMERA) == 1

    patched = _parse(document.serialize())
    assert patched.manifest_facts()["permissions"] == [INTERNET]
    # everything else survives the edit
    facts = patched.manifest_facts()
    assert facts["package"] == "com.example.demo"
    assert facts["launcher_activity"] == ".MainActivity"
    assert facts["app_label"] == "Demo App"
    assert patched.serialize() == document.serialize()


def test_remove_permission_is_idempotent(apk_bytes):
    document = _parse(apk_bytes)
    assert document.remove_permission(CAMERA) == 1
    assert document.remove_permission(CAMERA) == 0


def test_remove_unknown_permission_changes_nothing(apk_bytes):
    before = _parse(apk_bytes).serialize()
    document = _parse(apk_bytes)
    assert document.remove_permission("android.permission.NFC") == 0
    assert document.serialize() == before


def test_add_permission_then_remove_it(apk_bytes):
    document = _parse(apk_bytes)
    assert document.add_permission("android.permission.VIBRATE") is True
    # a new <uses-permission> goes in as the first child of <manifest>
    assert document.manifest_facts()["permissions"] == [
        "android.permission.VIBRATE",
        INTERNET,
        CAMERA,
    ]
    # the new string pool survives a round-trip
    assert _parse(document.serialize()).manifest_facts()["permissions"][0] == "android.permission.VIBRATE"
    assert document.remove_permission("android.permission.VIBRATE") == 1


def test_add_duplicate_permission_is_rejected(apk_bytes):
    document = _parse(apk_bytes)
    assert document.add_permission(INTERNET) is False


def test_set_debuggable_round_trips(apk_bytes):
    document = _parse(apk_bytes)
    assert document.set_debuggable(True) is True
    assert _parse(document.serialize()).manifest_facts()["debuggable"] is True


def test_utf16_string_pool_round_trips():
    blob = fixture.axml(
        fixture.MANIFEST_STRINGS,
        fixture.MANIFEST_RES_IDS,
        [fixture.start_element(fixture.NO_STRING, fixture.MANIFEST, [], 1)],
    )
    # rebuild the same document with a UTF-16 pool
    utf16_pool = fixture.string_pool(fixture.MANIFEST_STRINGS, utf8=False)
    body = utf16_pool
    body += struct.pack("<HHI", fixture.RESOURCE_MAP_TYPE, 8, 8 + 4 * len(fixture.MANIFEST_RES_IDS))
    body += struct.pack(f"<{len(fixture.MANIFEST_RES_IDS)}I", *fixture.MANIFEST_RES_IDS)
    body += fixture.start_element(fixture.NO_STRING, fixture.MANIFEST, [], 1)
    blob = struct.pack("<HHI", fixture.XML_TYPE, 8, 8 + len(body)) + body

    pool, size = StringPool.parse(blob, 8)
    assert not pool.is_utf8
    assert pool.strings == list(fixture.MANIFEST_STRINGS)

    document = AxmlFile.parse(blob)
    assert document.serialize() == blob
    # this document is a bare <manifest/> with no attributes
    assert document.manifest_facts()["package"] is None
    assert [s for s in document.pool.strings if s == ANDROID_NS] == [ANDROID_NS]


def test_rejects_plain_text_xml():
    with pytest.raises(ApkModError, match="not a binary XML"):
        AxmlFile.parse(b'<?xml version="1.0"?><manifest package="x"/>')


def test_intern_reuses_existing_strings(apk_bytes):
    pool = _parse(apk_bytes).pool
    before = len(pool.strings)
    assert pool.intern("Demo App") == fixture.APP_LABEL
    assert len(pool.strings) == before
    fresh = pool.intern("something-new")
    assert fresh == before
    assert pool.strings[-1] == "something-new"
