"""Static analysis and the protection scan."""

from __future__ import annotations

import json

from apkmod.analyze import analyze_apk
from apkmod.engines.patcher import DISCLAIMER, PatcherEngine


def test_identity_and_permissions(apk):
    report = analyze_apk(apk)
    assert report.manifest["package"] == "com.example.demo"
    assert "android.permission.CAMERA" in report.manifest["permissions"]
    assert report.dex_stats["string_count"] == 10


def test_sdk_inventory(apk):
    sdk = analyze_apk(apk).sdk
    assert "AppsFlyer" in sdk
    assert "AdMob / Google Mobile Ads" in sdk


def test_integrity_indicators(apk):
    integrity = analyze_apk(apk).integrity
    assert "reads its own signature" in integrity


def test_network_hosts_and_secrets(apk):
    report = analyze_apk(apk)
    assert "api.example.com" in report.hosts
    assert report.possible_secrets, "the fixture carries an apiKey= string"


def test_findings_include_notice_and_exported_components(apk):
    findings = {f.title: f for f in analyze_apk(apk).findings}
    assert any("runtime-sensitive permissions" in t for t in findings)
    assert any("exported components" in t for t in findings)
    assert any("self-integrity checks" in t for t in findings)


def test_unsigned_warning(apk):
    findings = analyze_apk(apk).findings
    assert any(f.title == "APK appears unsigned" for f in findings)


def test_json_and_markdown_shapes(apk):
    report = analyze_apk(apk)
    payload = json.loads(json.dumps(report.as_dict(), default=str))
    assert payload["manifest"]["package"] == "com.example.demo"
    assert "sdk" in payload and "network_hosts" in payload

    markdown = report.as_markdown()
    assert markdown.startswith("# APK analysis:")
    assert "## Permissions" in markdown
    # the notice is wrapped across lines, so match a contiguous fragment
    assert "does not defeat licence" in markdown.replace("\n", " ")
    assert "server-side entitlements" in markdown.replace("\n", " ")

    text = report.as_text()
    assert "APK analysis:" in text
    assert "com.example.demo" in text


def test_tamper_scan(apk):
    report = PatcherEngine().scan(apk)
    assert "reads its own signature" in report.protections
    assert any("AppsFlyer" in t for t in report.trackers)
    assert report.signature_status["v1_present"] is False
    assert "no obvious self-checks" not in report.verdict
    assert report.as_dict()["notice"] == DISCLAIMER
    assert "Tamper surface:" in report.as_text()


def test_scan_of_a_signed_apk(apk, tmp_path, signing_material):
    from apkmod.signing import sign_v1

    signed = tmp_path / "signed.apk"
    sign_v1(apk, signed, *signing_material)
    report = PatcherEngine().scan(signed)
    assert report.signature_status["v1_present"] is True
    assert report.signature_status["v1_valid"] is True
