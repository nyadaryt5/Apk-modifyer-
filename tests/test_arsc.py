"""resources.arsc parsing and string rewriting."""

from __future__ import annotations

import struct

import pytest

import fixture

from apkmod.arsc import ArscFile
from apkmod.util import ApkModError


def test_parse_structure():
    table = ArscFile.parse(fixture.build_arsc())
    assert table.package_count == 1
    assert [p.name for p in table.packages] == ["com.example.demo"]
    assert table.packages[0].pkg_id == 0x7F
    assert table.packages[0].types == ["string"]


def test_entries_and_config_label():
    table = ArscFile.parse(fixture.build_arsc())
    entries = table.packages[0].entries
    assert [e.name for e in entries] == ["app_name", "greeting"]
    assert [e.data for e in entries] == [0, 1]
    assert {e.config for e in entries} == {"v21"}


def test_value_strings():
    table = ArscFile.parse(fixture.build_arsc())
    assert table.value_strings.strings == ["Demo App", "Hello world"]
    assert table.app_label() == "Demo App"


def test_string_entries_report_usage():
    table = ArscFile.parse(fixture.build_arsc())
    entries = dict((i, (v, u)) for i, v, u in table.string_entries())
    assert entries[0][0] == "Demo App"
    assert entries[0][1] == ["com.example.demo:string/app_name [v21]"]


def test_replace_string_changes_length_and_survives_roundtrip():
    table = ArscFile.parse(fixture.build_arsc())
    assert table.replace_string(0, "A Much Longer Modified App Name") == "Demo App"
    blob = table.serialize()

    # header size must describe the new payload
    _ctype, _header, size = struct.unpack_from("<HHI", blob, 0)
    assert size == len(blob)

    reparsed = ArscFile.parse(blob)
    assert reparsed.app_label() == "A Much Longer Modified App Name"
    assert reparsed.value_strings.strings[1] == "Hello world"
    assert [e.name for e in reparsed.packages[0].entries] == ["app_name", "greeting"]


def test_replace_all():
    table = ArscFile.parse(fixture.build_arsc(value_strings=("Demo App", "Demo App")))
    assert table.replace_all("Demo App", "Renamed") == 2
    assert ArscFile.parse(table.serialize()).value_strings.strings == ["Renamed", "Renamed"]


def test_replace_out_of_range():
    table = ArscFile.parse(fixture.build_arsc())
    with pytest.raises(ApkModError, match="out of range"):
        table.replace_string(99, "nope")


def test_rejects_non_arsc():
    with pytest.raises(ApkModError, match="not a resource table"):
        ArscFile.parse(b"not a resource table at all")
