"""Native zipalign / repack."""

from __future__ import annotations

import zipfile

import pytest

from apkmod.align import align, local_data_offsets, repack, verify_alignment
from apkmod.util import ApkModError


def test_stored_entries_are_aligned(apk, tmp_path):
    out = tmp_path / "aligned.apk"
    align(apk, out)
    assert verify_alignment(out) == []


def test_native_library_is_page_aligned(apk, tmp_path):
    out = tmp_path / "aligned.apk"
    align(apk, out)
    offsets = {name: (off, req) for name, off, req in local_data_offsets(out)}
    name = "lib/arm64-v8a/libdemo.so"
    assert offsets[name][1] == 4096
    assert offsets[name][0] % 4096 == 0


def test_deflated_entries_are_left_alone(apk, tmp_path):
    out = tmp_path / "aligned.apk"
    align(apk, out)
    with zipfile.ZipFile(out) as zf:
        assert zf.getinfo("classes.dex").compress_type == zipfile.ZIP_DEFLATED
    requirements = {name: req for name, _off, req in local_data_offsets(out)}
    assert requirements["classes.dex"] == 0


def test_contents_survive_the_rewrite(apk, tmp_path):
    out = tmp_path / "aligned.apk"
    align(apk, out)
    with zipfile.ZipFile(apk) as before, zipfile.ZipFile(out) as after:
        assert sorted(before.namelist()) == sorted(after.namelist())
        for name in before.namelist():
            assert before.read(name) == after.read(name)


def test_replace_swaps_payload(apk, tmp_path):
    out = tmp_path / "edited.apk"
    result = repack(apk, out, replace={"assets/config.json": b'{"ads":false}'})
    assert result.replaced == ["assets/config.json"]
    with zipfile.ZipFile(out) as zf:
        assert zf.read("assets/config.json") == b'{"ads":false}'
        assert zf.read("classes.dex") == zipfile.ZipFile(apk).read("classes.dex")


def test_replace_missing_entry_fails(apk, tmp_path):
    with pytest.raises(ApkModError, match="not present"):
        repack(apk, tmp_path / "nope.apk", replace={"assets/absent.txt": b"x"})


def test_exclude_drops_entries(apk, tmp_path):
    out = tmp_path / "slim.apk"
    result = repack(apk, out, exclude={"res/raw/keep.txt"})
    assert result.removed == ["res/raw/keep.txt"]
    assert "res/raw/keep.txt" not in zipfile.ZipFile(out).namelist()


def test_prepend_writes_first(apk, tmp_path):
    out = tmp_path / "prepended.apk"
    repack(apk, out, prepend=[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")])
    assert zipfile.ZipFile(out).namelist()[0] == "META-INF/MANIFEST.MF"


def test_unaligned_input_is_reported(apk):
    """The original fixture zip is written by zipfile with no padding at all."""
    problems = verify_alignment(apk)
    assert problems, "expected the freshly zipped fixture to be misaligned"
    assert any(p["name"] == "lib/arm64-v8a/libdemo.so" for p in problems)
