"""
Cross-validation against androguard, an independent mature implementation of the
same binary formats.

Every other test here compares my parsers against fixtures I wrote myself, which
can only ever prove self-consistency. These tests compare against a parser
written by someone else, so a mistake shared between my fixture and my parser
cannot hide.

androguard is a *test-only* dependency. It is not required to install or run
apkmod; the module skips when it is absent.

This file earned its place by finding two real bugs in ``tests/fixture.py``:

1. The resource map assigned ``0x0101021b`` to the string ``package``, but that
   id is actually ``versionCode``, and ``package`` is unprefixed with no android
   resource id at all. My parser was unaffected -- it reads attribute names from
   the string pool -- but the fixture was not a faithful manifest, and
   androguard, which resolves names through the resource map, rendered every
   attribute name shifted by one.

2. The DEX Adler32 was computed *before* the SHA-1 signature was written. The
   checksum covers bytes [12:], which includes the 20 signature bytes at
   [12:32), so it digested 20 zeros and every real tool rejected the file with
   "Wrong Adler32 checksum for DEX file!".
"""
from __future__ import annotations

import hashlib
import logging
import struct
import sys
import zlib

import pytest

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import fixture  # noqa: E402

from apkmod.align import repack  # noqa: E402
from apkmod.apk import ApkContainer  # noqa: E402
from apkmod.arsc import ArscFile  # noqa: E402
from apkmod.axml import TYPE_STRING, AxmlFile  # noqa: E402
from apkmod.dex import DexFile, iter_dex_strings  # noqa: E402

androguard = pytest.importorskip(
    "androguard", reason="androguard is an optional cross-check dependency"
)
from androguard.core.axml import AXMLPrinter, ARSCParser  # noqa: E402
from androguard.core.resources.public import SYSTEM_RESOURCES  # noqa: E402

# androguard logs every chunk it walks, and it uses loguru rather than stdlib
# logging, so silencing it needs the loguru switch.
try:
    from loguru import logger as _loguru

    _loguru.disable("androguard")
except ImportError:
    pass
logging.getLogger("androguard").setLevel(logging.WARNING)

AND = "{http://schemas.android.com/apk/res/android}"


def _ag_manifest(blob: bytes) -> dict:
    """androguard's view of a manifest, flattened to the facts I care about."""
    root = AXMLPrinter(blob).get_xml_obj()

    def first(tag: str):
        return next((e for e in root.iter() if e.tag.endswith(tag)), None)

    app, act, sdk = first("application"), first("activity"), first("uses-sdk")
    return {
        "package": root.get("package"),
        "versionCode": root.get(f"{AND}versionCode"),
        "versionName": root.get(f"{AND}versionName"),
        "permissions": [
            e.get(f"{AND}name")
            for e in root.iter()
            if e.tag.endswith("uses-permission")
        ],
        "label": app.get(f"{AND}label") if app is not None else None,
        "debuggable": app.get(f"{AND}debuggable") if app is not None else None,
        "activity": act.get(f"{AND}name") if act is not None else None,
        "minSdk": sdk.get(f"{AND}minSdkVersion") if sdk is not None else None,
        "targetSdk": sdk.get(f"{AND}targetSdkVersion") if sdk is not None else None,
    }


def test_manifest_agrees_with_androguard():
    """Same bytes, two implementations, one answer."""
    blob = fixture.build_manifest_axml()
    mine = AxmlFile.parse(blob).manifest_facts()
    theirs = _ag_manifest(blob)

    assert theirs["package"] == mine["package"] == "com.example.demo"
    assert theirs["versionName"] == mine["version_name"] == "1.0"
    assert str(theirs["versionCode"]) == str(mine["version_code"]) == "1"
    assert theirs["permissions"] == mine["permissions"] == [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]
    assert theirs["label"] == mine["app_label"] == "Demo App"
    assert theirs["activity"] == ".MainActivity"
    assert mine["launcher_activity"] == ".MainActivity"
    assert str(theirs["minSdk"]) == str(mine["min_sdk"]) == "21"
    assert str(theirs["targetSdk"]) == str(mine["target_sdk"]) == "34"
    # androguard renders the boolean as the literal "false"; mine as a bool.
    assert theirs["debuggable"] in ("false", False)
    assert mine["debuggable"] is False


def test_resource_map_ids_match_the_framework():
    """
    The resource map is positional, so every id must be the real framework id
    for the attribute name sitting under it. This is the check that caught the
    original fixture bug, and it needs only androguard's table, not its parser.
    """
    forward = SYSTEM_RESOURCES["attributes"]["forward"]
    for index, res_id in enumerate(fixture.MANIFEST_RES_IDS):
        name = fixture.MANIFEST_STRINGS[index]
        expected = forward.get(name)
        assert expected == res_id, (
            f"string {index} ({name!r}) is mapped to 0x{res_id:08x}, but the "
            f"framework id for {name!r} is "
            f"{('0x%08x' % expected) if expected else 'absent'}"
        )


def test_arsc_agrees_with_androguard():
    """Package names and every string value, read two independent ways."""
    blob = fixture.build_arsc()
    mine = ArscFile.parse(blob)
    theirs = ARSCParser(blob)

    assert theirs.get_packages_names() == ["com.example.demo"]
    assert [p.name for p in mine.packages] == ["com.example.demo"]

    # androguard groups as {package: {config: {resource id: value}}}. The
    # string type is id 1, so these land at 0x7F010000 / 0x7F010001.
    assert theirs.get_resolved_strings()["com.example.demo"]["DEFAULT"] == {
        0x7F010000: "Demo App",
        0x7F010001: "Hello world",
    }

    # The same values, by resource name, from my side.
    assert mine.app_label() == "Demo App"
    by_name = {
        entry.name: mine.value_strings.get(entry.data)
        for package in mine.packages
        for entry in package.entries
        if entry.type_name == "string" and entry.data_type == TYPE_STRING
    }
    assert by_name == {"app_name": "Demo App", "greeting": "Hello world"}


def test_dex_checksums_are_self_consistent():
    """
    Guards the ordering bug directly: the signature covers [32:] and the
    Adler32 covers [12:], so the checksum is only right if it is computed
    after the signature has been written.
    """
    blob = fixture.build_dex()
    assert struct.unpack_from("<I", blob, 8)[0] == zlib.adler32(blob[12:])
    assert blob[12:32] == hashlib.sha1(blob[32:]).digest()
    assert struct.unpack_from("<I", blob, 32)[0] == len(blob)
    # And the map list the header points at must really be there.
    map_off = struct.unpack_from("<I", blob, 52)[0]
    assert map_off and struct.unpack_from("<I", blob, map_off)[0] == 5


def test_androguard_no_longer_rejects_the_dex_checksum():
    """
    Before the fix androguard failed with "Wrong Adler32 checksum for DEX
    file!". It still declines to fully parse this fixture -- the DEX is
    deliberately minimal and carries no field, method or class tables -- but it
    must get past the integrity check, which is the part that was broken.
    """
    blob = fixture.build_dex()
    try:
        androguard.core.dex.DEX(blob)
    except Exception as exc:  # noqa: BLE001 - any failure is fine but one
        assert "adler" not in str(exc).lower(), f"checksum still rejected: {exc}"
    # My own parser reads every string, which is the behaviour under test.
    assert iter_dex_strings([blob]).strings == list(fixture.DEX_STRINGS)


def test_androguard_reads_back_a_manifest_my_writer_produced():
    """
    The strongest available check: edit with my writer, then have androguard --
    which shares no code with me -- parse the result. This validates the
    serializer, not merely the parser.
    """
    ax = AxmlFile.parse(fixture.build_manifest_axml())
    ax.remove_permission("android.permission.CAMERA")
    ax.set_debuggable(True)

    theirs = _ag_manifest(ax.serialize())
    assert theirs["permissions"] == ["android.permission.INTERNET"]
    assert theirs["debuggable"] in ("true", True)
    # Nothing else may have moved.
    assert theirs["package"] == "com.example.demo"
    assert theirs["versionName"] == "1.0"
    assert theirs["label"] == "Demo App"
    assert theirs["activity"] == ".MainActivity"


def test_androguard_reads_back_a_arsc_my_writer_produced():
    """The same check for the resource table writer."""
    arsc = ArscFile.parse(fixture.build_arsc())
    indices, old = arsc.replace_by_name("app_name", "Renamed App")
    assert old == "Demo App" and indices

    theirs = ARSCParser(arsc.serialize())
    values = {
        value
        for config in theirs.get_resolved_strings()["com.example.demo"].values()
        for value in config.values()
    }
    assert values == {"Renamed App", "Hello world"}


def test_androguard_reads_back_a_rebuilt_container(tmp_path):
    """End to end: a real file on disk that an independent parser accepts."""
    apk = fixture.build_apk(tmp_path / "app.apk")
    with ApkContainer(apk) as container:
        before = _ag_manifest(container.manifest_axml().serialize())

    ax = AxmlFile.parse(fixture.build_manifest_axml())
    ax.remove_permission("android.permission.CAMERA")

    out = tmp_path / "out.apk"
    result = repack(apk, out, replace={"AndroidManifest.xml": ax.serialize()})
    assert "AndroidManifest.xml" in result.replaced

    with ApkContainer(out) as container:
        after = _ag_manifest(container.manifest_axml().serialize())
        assert container.manifest_axml().manifest_facts()["package"] == "com.example.demo"

    assert before["permissions"] == [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]
    assert after["permissions"] == ["android.permission.INTERNET"]
    assert after["package"] == before["package"]
    assert after["label"] == before["label"]
    assert after["activity"] == before["activity"]


def test_my_parser_still_reads_what_it_always_did():
    """
    Regression guard for the fixture changes themselves: the ids moved, so this
    pins the values the rest of the suite depends on.
    """
    dex = DexFile.parse(fixture.build_dex())
    assert dex.version == "035"
    assert dex.type_count == 2
    assert dex.strings.type_descriptors == [
        "Lcom/example/demo/MainActivity;",
        "Landroid/content/pm/Signature;",
    ]
