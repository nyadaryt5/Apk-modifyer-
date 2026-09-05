"""v1 (JAR) signing -- including an independent OpenSSL check of the RSA signature."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from apkmod.align import repack
from apkmod.asn1 import parse_pkcs7_signed_data
from apkmod.signing import sign_v1, verify_v1
from apkmod.util import ApkModError, run

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
