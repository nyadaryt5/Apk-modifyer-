"""DEX string-table parsing, including MUTF-8 quirks."""

from __future__ import annotations

import pytest

import fixture

from apkmod.dex import DexFile, iter_dex_strings
from apkmod.util import ApkModError


def test_header_fields():
    dex = DexFile.parse(fixture.build_dex())
    assert dex.version == "035"
    assert dex.string_count == len(fixture.DEX_STRINGS)
    assert dex.type_count == 2
    assert dex.file_size == len(fixture.build_dex())


def test_strings_round_trip():
    dex = DexFile.parse(fixture.build_dex())
    assert dex.strings.strings == list(fixture.DEX_STRINGS)


def test_mutf8_specials():
    """MUTF-8 encodes NUL as C0 80 and must not truncate there."""
    dex = DexFile.parse(fixture.build_dex())
    assert "café" in dex.strings.strings
    assert "a\x00b" in dex.strings.strings
    assert dex.strings.strings[-1] == "a\x00b"


def test_type_descriptors():
    dex = DexFile.parse(fixture.build_dex())
    assert dex.strings.type_descriptors == [
        "Lcom/example/demo/MainActivity;",
        "Landroid/content/pm/Signature;",
    ]


def test_search_is_case_insensitive():
    dex = DexFile.parse(fixture.build_dex())
    assert dex.strings.search("GET_SIGNatures") == ["GET_SIGNATURES"]


def test_iter_merges_and_dedupes():
    merged = iter_dex_strings([fixture.build_dex(), fixture.build_dex()])
    assert len(merged.strings) == len(fixture.DEX_STRINGS)


def test_rejects_garbage():
    with pytest.raises(ApkModError, match="not a DEX file"):
        DexFile.parse(b"PK\x03\x04 this is a zip, not a dex")


def test_iter_skips_non_dex_blobs():
    merged = iter_dex_strings([b"nonsense", fixture.build_dex()])
    assert "GET_SIGNATURES" in merged.strings
