"""v1 (JAR) signing -- including an independent OpenSSL check of the RSA signature."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from apkmod.align import repack
from apkmod.asn1 import parse_pkcs7_signed_data
from apkmod.signing import sign_v1, verify_v1
from apkmod.util import ApkModError, ToolResult, run

OPENSSL = shutil.which("openssl")


def _sign(apk: Path, out: Path, material) -> Path:
    key_pem, cert_pem = material
    sign_v1(apk, out, key_pem, cert_pem)
    return out


def test_sign_then_verify(apk, tmp_path, signing_material):
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)
    result = verify_v1(signed)
    assert result.ok is True, result.problems
    assert result.signed is True
    assert result.signature_valid is True
    assert result.entries_checked == 6
    assert result.mismatched == []
    assert result.unsigned == []
    assert result.digest_name == "SHA-256"


def test_signature_files_are_written(apk, tmp_path, signing_material):
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)
    names = zipfile.ZipFile(signed).namelist()
    assert "META-INF/MANIFEST.MF" in names
    assert "META-INF/APKMOD.SF" in names
    assert "META-INF/APKMOD.RSA" in names


def test_certificate_details_are_reported(apk, tmp_path, signing_material):
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)
    result = verify_v1(signed)
    assert result.subject == "APK Modifyer Tests"
    assert len(result.certificate_sha256) == 64


def test_tampering_is_detected(apk, tmp_path, signing_material):
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)
    tampered = tmp_path / "tampered.apk"
    repack(signed, tampered, replace={"assets/config.json": b'{"tampered":true}'})

    result = verify_v1(tampered)
    assert result.ok is False
    assert "assets/config.json" in result.mismatched


def test_entries_added_after_signing_are_flagged(apk, tmp_path, signing_material):
    """v1 signing only covers listed entries, so an added file must be *reported*.

    Android's v1 verifier ignores uncovered files outside META-INF, hence the
    signature itself still verifies; the point is that we surface the gap.
    """
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)
    injected = tmp_path / "injected.apk"
    with zipfile.ZipFile(signed) as zin, zipfile.ZipFile(injected, "w") as zout:
        for name in zin.namelist():
            zout.writestr(name, zin.read(name))
        zout.writestr("assets/sneaky.txt", b"added after signing")

    result = verify_v1(injected)
    assert result.unsigned == ["assets/sneaky.txt"]
    assert any("not covered by the manifest" in p for p in result.problems)


def test_unsigned_apk(apk):
    result = verify_v1(apk)
    assert result.signed is False
    assert result.ok is False
    assert any("not v1 signed" in p for p in result.problems)


def test_resigning_replaces_the_old_signature(apk, tmp_path, signing_material):
    first = _sign(apk, tmp_path / "first.apk", signing_material)
    second = tmp_path / "second.apk"
    key_pem, cert_pem = signing_material
    sign_v1(first, second, key_pem, cert_pem, signature_name="OTHER")
    names = zipfile.ZipFile(second).namelist()
    assert "META-INF/OTHER.RSA" in names
    assert "META-INF/APKMOD.RSA" not in names
    assert verify_v1(second).ok is True


def test_unknown_digest_rejected(apk, tmp_path, signing_material):
    key_pem, cert_pem = signing_material
    with pytest.raises(ApkModError, match="unsupported digest"):
        sign_v1(apk, tmp_path / "x.apk", key_pem, cert_pem, digest="md5")


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_openssl_independently_verifies_the_signature(apk, tmp_path, signing_material):
    """The RSA/PKCS#7 we produce must satisfy a real, unrelated verifier."""
    key_pem, cert_pem = signing_material
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)

    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(cert_pem)
    # `openssl dgst -verify` wants a SubjectPublicKeyInfo, not a certificate
    pubkey = run([OPENSSL, "x509", "-in", str(cert_path), "-pubkey", "-noout"])
    assert pubkey.ok, pubkey.output
    pub_path = tmp_path / "pub.pem"
    pub_path.write_text(pubkey.stdout)

    with zipfile.ZipFile(signed) as zf:
        (tmp_path / "CERT.SF").write_bytes(zf.read("META-INF/APKMOD.SF"))
        parsed = parse_pkcs7_signed_data(zf.read("META-INF/APKMOD.RSA"))
    (tmp_path / "sig.bin").write_bytes(parsed.signature)

    result = run(
        [
            OPENSSL, "dgst", "-sha256", "-verify", str(pub_path),
            "-signature", str(tmp_path / "sig.bin"), str(tmp_path / "CERT.SF"),
        ]
    )
    assert result.ok, result.output
    assert "Verified OK" in result.stdout


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_openssl_rejects_a_corrupted_signature(apk, tmp_path, signing_material):
    key_pem, cert_pem = signing_material
    signed = _sign(apk, tmp_path / "signed.apk", signing_material)
    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(cert_pem)
    pub_path = tmp_path / "pub.pem"
    pub_path.write_text(run([OPENSSL, "x509", "-in", str(cert_path), "-pubkey", "-noout"]).stdout)

    with zipfile.ZipFile(signed) as zf:
        (tmp_path / "CERT.SF").write_bytes(zf.read("META-INF/APKMOD.SF") + b"tampered")
        parsed = parse_pkcs7_signed_data(zf.read("META-INF/APKMOD.RSA"))
    (tmp_path / "sig.bin").write_bytes(parsed.signature)

    result = run(
        [
            OPENSSL, "dgst", "-sha256", "-verify", str(pub_path),
            "-signature", str(tmp_path / "sig.bin"), str(tmp_path / "CERT.SF"),
        ]
    )
    assert not result.ok


def test_material_requires_a_source(apk):
    from apkmod.signing import load_material

    with pytest.raises(ApkModError, match="provide --key/--cert"):
        load_material()


# ==========================================================================
# backend selection
# ==========================================================================
def test_signer_statuses_shape():
    from apkmod.signing import signer_statuses

    statuses = {s.name: s for s in signer_statuses()}
    assert "apksigner" in statuses and "uber-apk-signer" in statuses
    assert statuses["native (pure Python)"].available is True
    assert statuses["native (pure Python)"].schemes == ("v1",)
    assert "v2" in statuses["apksigner"].schemes


def test_auto_falls_back_to_native_when_no_sdk(apk, tmp_path, signing_material, monkeypatch):
    """No apksigner and no uber jar here, so auto must land on the native signer."""
    from apkmod import signing as signing_mod

    monkeypatch.setattr(signing_mod, "find_apksigner", lambda: None)
    monkeypatch.setattr(signing_mod, "find_uber_signer_jar", lambda: None)
    outcome = signing_mod.sign(apk, tmp_path / "auto.apk", engine="auto", key_pem=signing_material[0], cert_pem=signing_material[1])
    assert outcome.engine == "native"
    assert outcome.schemes == ["v1"]
    assert verify_v1(outcome.path).ok is True


def test_explicit_native_engine(apk, tmp_path, signing_material):
    from apkmod import signing as signing_mod

    outcome = signing_mod.sign(
        apk, tmp_path / "n.apk", engine="native", key_pem=signing_material[0], cert_pem=signing_material[1]
    )
    assert outcome.engine == "native"
    assert any("v1 signed" in n for n in outcome.notes)


def test_unknown_engine_rejected(apk, tmp_path, signing_material):
    from apkmod import signing as signing_mod

    with pytest.raises(ApkModError, match="unknown signing engine"):
        signing_mod.sign(
            apk, tmp_path / "x.apk", engine="magic", key_pem=signing_material[0], cert_pem=signing_material[1]
        )


def test_apksigner_engine_reports_when_absent(apk, tmp_path, signing_material, monkeypatch):
    from apkmod import signing as signing_mod

    monkeypatch.setattr(signing_mod, "find_apksigner", lambda: None)
    with pytest.raises(ApkModError, match="apksigner is not installed"):
        signing_mod.sign(
            apk, tmp_path / "x.apk", engine="apksigner", key_pem=signing_material[0], cert_pem=signing_material[1]
        )


def test_uber_engine_reports_when_absent(apk, tmp_path, monkeypatch):
    from apkmod import signing as signing_mod

    monkeypatch.setattr(signing_mod, "find_uber_signer_jar", lambda: None)
    with pytest.raises(ApkModError, match="uber-apk-signer needs"):
        signing_mod.sign_with_uber(apk, tmp_path / "x.apk", keystore=Path("/keys/release.p12"))


def test_uber_engine_wants_a_keystore(apk, tmp_path, monkeypatch):
    from apkmod import signing as signing_mod

    monkeypatch.setattr(signing_mod, "find_uber_signer_jar", lambda: "/cache/uber-apk-signer.jar")
    monkeypatch.setattr("apkmod.engines.apktool.find_java", lambda: "/jdk/bin/java")
    with pytest.raises(ApkModError, match="needs --keystore"):
        signing_mod.sign_with_uber(apk, tmp_path / "x.apk")


def test_sign_requires_material(apk, tmp_path):
    from apkmod import signing as signing_mod

    with pytest.raises(ApkModError, match="provide --key/--cert"):
        signing_mod.sign(apk, tmp_path / "x.apk")


def test_apksigner_command_is_built_from_a_keystore(apk, tmp_path, monkeypatch):
    """Even without the SDK present, the delegated command line must be correct."""
    from apkmod import signing as signing_mod

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = [str(c) for c in cmd]
        (tmp_path / "delegated.apk").write_bytes((tmp_path / "seed.apk").read_bytes())
        return ToolResult(captured["cmd"], 0, "Signed\n", "")

    (tmp_path / "seed.apk").write_bytes(apk.read_bytes())
    monkeypatch.setattr(signing_mod, "find_apksigner", lambda: "/sdk/build-tools/34/apksigner")
    monkeypatch.setattr(signing_mod, "run", fake_run)
    monkeypatch.setattr(signing_mod, "_resulting_schemes", lambda p: ["v1"])

    signing_mod.sign_with_apksigner(
        apk, tmp_path / "delegated.apk", keystore=Path("/keys/release.p12"), storepass="secret", alias="rel"
    )
    cmd = captured["cmd"]
    assert cmd[0].endswith("apksigner")
    assert cmd[1] == "sign"
    assert "--ks" in cmd and "/keys/release.p12" in cmd
    assert "--ks-pass" in cmd and "pass:secret" in cmd
    assert "--ks-key-alias" in cmd and "rel" in cmd
    assert "--out" in cmd


def test_apksigner_rejects_missing_material(apk, tmp_path, monkeypatch):
    from apkmod import signing as signing_mod

    monkeypatch.setattr(signing_mod, "find_apksigner", lambda: "/sdk/apksigner")
    with pytest.raises(ApkModError, match="needs --keystore"):
        signing_mod.sign_with_apksigner(apk, tmp_path / "x.apk")

