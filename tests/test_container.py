"""APK container inventory and signature-scheme detection."""

from __future__ import annotations

import fixture

from apkmod.apk import ApkContainer


def test_inventory(apk):
    with ApkContainer(apk) as container:
        names = container.names()
    assert "AndroidManifest.xml" in names
    assert "resources.arsc" in names
    assert "classes.dex" in names
    assert "lib/arm64-v8a/libdemo.so" in names


def test_facts(apk):
    with ApkContainer(apk) as container:
        facts = container.facts()
    assert facts["entry_count"] == 6
    assert facts["dex_files"] == ["classes.dex"]
    assert facts["native_libraries"] == {"arm64-v8a": ["libdemo.so"]}
    assert facts["has_resources_arsc"] is True
    assert facts["manifest"]["package"] == "com.example.demo"
    assert facts["manifest"]["permissions"] == [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]


def test_dex_and_lib_access(apk):
    with ApkContainer(apk) as container:
        blobs = container.dex_blobs()
        assert len(blobs) == 1
        assert blobs[0].startswith(b"dex\n")
        assert container.read("assets/config.json").startswith(b"{")


def test_unsigned_apk_reports_no_v1(apk):
    with ApkContainer(apk) as container:
        signing = container.signing_info()
    assert signing["v1_jar_signing"] is False
    assert signing["v2"] is False
    assert signing["certificates"] == []


def test_signing_block_detection(apk, tmp_path):
    """A v2-signed archive carries an APK Signing Block before the central directory."""
    assert ApkContainer(apk).signing_block_ids() == []
    fixture.add_signing_block(apk, block_ids=(0x7109871A, 0xF05368C0))
    with ApkContainer(apk) as container:
        signing = container.signing_info()
    assert signing["v2"] is True
    assert signing["v3"] is True
    assert any("v2" in label for label in signing["signing_block"])
