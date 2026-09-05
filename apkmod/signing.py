"""APK signing.

Two backends:
  * ``native``  - pure-Python v1 (JAR) signing: MANIFEST.MF + .SF + PKCS#7 .RSA.
                  Works with no JDK at all, which matters on a phone or a
                  minimal container.
  * ``apksigner`` / ``uber-apk-signer`` - delegated, when they are installed.
                  Use these if you need v2/v3 scheme coverage for Play.

The native path is verifiable with stock OpenSSL:
    openssl dgst -sha256 -verify cert.pem -signature sig.bin CERT.SF
"""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import asn1
from .align import repack
from .util import ApkModError, run

__all__ = [
    "sign_v1",
    "verify_v1",
    "build_manifest",
    "build_signature_file",
    "manifest_sections",
    "load_material",
    "generate_key",
]

DIGESTS = {"sha-256": "SHA-256", "sha-512": "SHA-512", "sha256": "SHA-256", "sha512": "SHA-512"}
LINE_LIMIT = 70
_SIGNATURE_SUFFIXES = (".RSA", ".DSA", ".EC")


def _is_signature_entry(name: str) -> bool:
    upper = name.upper()
    if not upper.startswith("META-INF/"):
        return False
    return upper == "META-INF/MANIFEST.MF" or upper.endswith(_SIGNATURE_SUFFIXES) or upper.endswith(".SF")


def _hash(data: bytes, digest: str) -> str:
    return base64.b64encode(hashlib.new(digest, data).digest()).decode("ascii")


def _wrap(line: str, limit: int = LINE_LIMIT) -> str:
    """JAR manifest lines are capped at 72 bytes; continuations start with a space."""
    raw = line.encode("utf-8")
    if len(raw) <= limit:
        return line
    out: List[str] = []
    first = True
    while raw:
        take = limit if first else limit - 1
        chunk, raw = raw[:take], raw[take:]
        # never split a UTF-8 sequence
        while chunk and (chunk[-1] & 0xC0) == 0x80:
            raw = chunk[-1:] + raw
            chunk = chunk[:-1]
        out.append(chunk.decode("utf-8") if first else " " + chunk.decode("utf-8"))
        first = False
    return "\r\n".join(out)


def build_manifest(digests: Sequence[Tuple[str, str]], digest_name: str = "SHA-256") -> str:
    """Render MANIFEST.MF: a main section then one section per entry."""
    sections = [
        "Manifest-Version: 1.0\r\n"
        "Built-By: Generated-by-APKModifyer\r\n"
        "Created-By: 1.0 (Android)\r\n\r\n"
    ]
    for name, digest in digests:
        sections.append(_wrap(f"Name: {name}") + "\r\n" + _wrap(f"{digest_name}-Digest: {digest}") + "\r\n\r\n")
    return "".join(sections)


def build_signature_file(
    manifest: str,
    digest_name: str = "SHA-256",
    digest_hash: str = "sha256",
    extra_headers: Sequence[str] = (),
) -> str:
    """Render CERT.SF: whole-manifest digest plus a digest per manifest section."""
    manifest_bytes = manifest.encode("utf-8")
    parts = [
        "Signature-Version: 1.0\r\n"
        "Created-By: 1.0 (APKModifyer)\r\n"
        + "".join(h + "\r\n" for h in extra_headers)
        + _wrap(f"{digest_name}-Digest-Manifest: {_hash(manifest_bytes, digest_hash)}")
        + "\r\n\r\n"
    ]
    for section in manifest_sections(manifest_bytes):
        text = section.decode("utf-8", "replace")
        name = _section_name(text)
        if name is None:
            continue
        parts.append(_wrap(f"Name: {name}") + "\r\n" + _wrap(f"{digest_name}-Digest: {_hash(section, digest_hash)}") + "\r\n\r\n")
    return "".join(parts)


def manifest_sections(raw: bytes) -> List[bytes]:
    """Entry sections of a manifest, each including its trailing blank line."""
    if b"\r\n\r\n" in raw:
        chunks = raw.split(b"\r\n\r\n")
        sep = b"\r\n\r\n"
    else:
        chunks = raw.split(b"\n\n")
        sep = b"\n\n"
    return [c + sep for c in chunks[1:] if c.strip()]


def _section_name(section_text: str) -> Optional[str]:
    match = re.search(r"^Name:\s*(.+?)\s*$", section_text, re.MULTILINE)
    return match.group(1) if match else None


def _unfold(block: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    current: Optional[str] = None
    for line in block.splitlines():
        if line.startswith(" ") and current:
            attrs[current] += line[1:]
        elif ":" in line:
            key, value = line.split(":", 1)
            current = key.strip()
            attrs[current] = value.strip()
    return attrs


def parse_manifest(raw: bytes) -> Dict[str, Dict[str, str]]:
    text = raw.decode("utf-8", "replace")
    blocks = re.split(r"\r?\n\r?\n", text)
    out: Dict[str, Dict[str, str]] = {}
    for block in blocks[1:]:
        if not block.strip():
            continue
        attrs = _unfold(block)
        name = attrs.get("Name")
        if name:
            out[name] = attrs
    return out


# ==========================================================================
# signing
# ==========================================================================
@dataclass
class SignResult:
    path: Path
    signature_name: str
    digest_name: str
    signed_entries: int
    certificate_sha256: str
    subject: str


def sign_v1(
    apk: Path,
    out: Path,
    key_pem: bytes,
    cert_pem: bytes,
    *,
    signature_name: str = "APKMOD",
    digest: str = "sha256",
    extra_headers: Sequence[str] = (),
) -> SignResult:
    """Apply a v1 (JAR) signature, replacing any existing one."""
    apk, out = Path(apk), Path(out)
    digest_name = DIGESTS.get(digest.lower())
    if digest_name is None:
        raise ApkModError(f"unsupported digest '{digest}' (use sha-256 or sha-512)")
    digest_hash = "sha256" if digest_name == "SHA-256" else "sha512"

    key = asn1.parse_rsa_private_key(key_pem)
    cert_der = asn1.pem_to_der(cert_pem, expected="CERTIFICATE")
    certificate = asn1.Certificate.parse(cert_der)

    import zipfile

    digests: List[Tuple[str, str]] = []
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            if info.is_dir() or _is_signature_entry(info.filename):
                continue
            digests.append((info.filename, _hash(zf.read(info.filename), digest_hash)))
    digests.sort(key=lambda item: item[0].lower())

    manifest = build_manifest(digests, digest_name)
    signature_file = build_signature_file(manifest, digest_name, digest_hash, extra_headers)
    sf_bytes = signature_file.encode("utf-8")

    signature = asn1.pkcs1_v15_sign(key, hashlib.new(digest_hash, sf_bytes).digest())
    pkcs7 = asn1.build_pkcs7_signed_data(sf_bytes, cert_der, signature)

    base = signature_name.upper()
    prepend = [
        ("META-INF/MANIFEST.MF", manifest.encode("utf-8")),
        (f"META-INF/{base}.SF", sf_bytes),
        (f"META-INF/{base}.RSA", pkcs7),
    ]
    excluded = set()
    with zipfile.ZipFile(apk) as zf:
        excluded = {n for n in zf.namelist() if _is_signature_entry(n)}

    repack(apk, out, replace={}, exclude=excluded, prepend=prepend)
    return SignResult(
        path=out,
        signature_name=f"META-INF/{base}.RSA",
        digest_name=digest_name,
        signed_entries=len(digests),
        certificate_sha256=certificate.sha256,
        subject=certificate.subject_cn,
    )


# ==========================================================================
# verification
# ==========================================================================
@dataclass
class VerifyResult:
    ok: bool
    signed: bool
    signature_file: Optional[str] = None
    digest_name: Optional[str] = None
    entries_checked: int = 0
    mismatched: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unsigned: List[str] = field(default_factory=list)
    signature_valid: Optional[bool] = None
    certificate_sha256: Optional[str] = None
    subject: Optional[str] = None
    problems: List[str] = field(default_factory=list)


def verify_v1(apk: Path) -> VerifyResult:
    """Check a v1 signature the way Android's JarVerifier roughly does.

    ``ok`` means: the archive is v1 signed, every entry the manifest covers
    still matches its digest, and the RSA signature over the .SF file is valid.
    Entries that were *added* after signing are reported in ``unsigned`` and in
    ``problems`` but do not by themselves fail the check, because Android's v1
    verifier ignores uncovered files outside META-INF.
    """
    import zipfile

    apk = Path(apk)
    result = VerifyResult(ok=False, signed=False)
    with zipfile.ZipFile(apk) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        manifest_name = next((n for n in names if n.upper() == "META-INF/MANIFEST.MF"), None)
        sf_name = next((n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith(".SF")), None)
        sig_name = next(
            (n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith(_SIGNATURE_SUFFIXES)),
            None,
        )
        if manifest_name is None:
            result.problems.append("no META-INF/MANIFEST.MF - APK is not v1 signed")
            result.unsigned = names
            return result
        result.signed = True

        manifest_raw = zf.read(manifest_name)
        manifest = parse_manifest(manifest_raw)
        digest_name = "SHA-256-Digest" if b"SHA-256-Digest" in manifest_raw else "SHA-1-Digest"
        digest_hash = "sha256" if digest_name.startswith("SHA-256") else "sha1"
        result.digest_name = digest_name.split("-")[0] + "-" + digest_name.split("-")[1]

        real = {n for n in names if not _is_signature_entry(n)}
        for name, attrs in manifest.items():
            digest = attrs.get(digest_name)
            if digest is None:
                result.mismatched.append(name)
                continue
            if name not in real:
                result.missing.append(name)
                continue
            actual = base64.b64encode(hashlib.new(digest_hash, zf.read(name)).digest()).decode("ascii")
            result.entries_checked += 1
            if actual != digest:
                result.mismatched.append(name)
        result.unsigned = sorted(real - set(manifest))
        if result.unsigned:
            result.problems.append(f"{len(result.unsigned)} entries are not covered by the manifest")

        if sf_name is None:
            result.problems.append("no .SF signature file")
        elif sig_name is None:
            result.problems.append("no .RSA/.DSA/.EC signature block")
        else:
            sf_bytes = zf.read(sf_name)
            sf_text = sf_bytes.decode("utf-8", "replace")
            whole = re.search(rf"{digest_name}-Manifest:\s*(\S+)", sf_text)
            if whole is None:
                result.problems.append(f"{sf_name} has no {digest_name}-Manifest attribute")
            else:
                expected = base64.b64encode(hashlib.new(digest_hash, manifest_raw).digest()).decode("ascii")
                if expected != whole.group(1):
                    result.problems.append("manifest digest does not match the .SF header")
            # per-section digests
            sections = manifest_sections(manifest_raw)
            sf_sections = {}
            for block in re.split(r"\r?\n\r?\n", sf_text)[1:]:
                attrs = _unfold(block)
                if attrs.get("Name"):
                    sf_sections[attrs["Name"]] = attrs.get(digest_name)
            for section in sections:
                name = _section_name(section.decode("utf-8", "replace"))
                if name is None or name not in sf_sections:
                    continue
                actual = base64.b64encode(hashlib.new(digest_hash, section).digest()).decode("ascii")
                if actual != sf_sections[name]:
                    result.problems.append(f"section digest mismatch for {name}")

            try:
                parsed = asn1.parse_pkcs7_signed_data(zf.read(sig_name))
            except ApkModError as exc:
                parsed = None
                result.problems.append(f"cannot read {sig_name}: {exc}")
            if parsed is not None:
                result.certificate_sha256 = parsed.certificate.sha256
                result.subject = parsed.certificate.subject_cn
                if parsed.content != sf_bytes:
                    result.problems.append("PKCS#7 eContent does not match the .SF file")
                try:
                    n, e = parsed.certificate.public_numbers
                    result.signature_valid = asn1.pkcs1_v15_verify(n, e, parsed.signature, hashlib.new(digest_hash, sf_bytes).digest())
                except (ApkModError, ValueError) as exc:
                    result.problems.append(f"cannot verify the RSA signature: {exc}")
                    result.signature_valid = False
                if result.signature_valid is False:
                    result.problems.append("RSA signature over the .SF file is INVALID")

    result.ok = result.signed and not result.mismatched and result.signature_valid is True
    return result


# ==========================================================================
# key material
# ==========================================================================
def load_material(
    key: Optional[Path] = None,
    cert: Optional[Path] = None,
    keystore: Optional[Path] = None,
    storepass: str = "",
    alias: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    """Return (key_pem, cert_pem) from either a PEM pair or a PKCS#12 keystore."""
    if keystore is not None:
        keystore = Path(keystore)
        if not keystore.is_file():
            raise ApkModError(f"no such keystore: {keystore}")
        if shutil.which("openssl") is None:
            raise ApkModError("reading a keystore needs the 'openssl' binary on PATH")
        suffix = keystore.suffix.lower()
        if suffix in (".jks", ".keystore"):
            raise ApkModError(
                "JKS keystores are not supported directly - convert first with:\n"
                f"  keytool -importkeystore -srckeystore {keystore} -destkeystore keys.p12 -deststoretype PKCS12"
            )
        common = ["openssl", "pkcs12", "-in", str(keystore), "-passin", f"pass:{storepass}", "-nomacver"]
        key_run = run(common + ["-nocerts", "-nodes"])
        cert_run = run(common + ["-clcerts", "-nokeys"])
        if not key_run.ok or b"PRIVATE KEY" not in key_run.stdout.encode():
            raise ApkModError(f"could not read a private key from {keystore}: {key_run.output[:300]}")
        if not cert_run.ok or b"BEGIN CERTIFICATE" not in cert_run.stdout.encode():
            raise ApkModError(f"could not read a certificate from {keystore}: {cert_run.output[:300]}")
        return key_run.stdout.encode(), cert_run.stdout.encode()

    if key is None or cert is None:
        raise ApkModError("provide --key/--cert, or --keystore with --storepass")
    key, cert = Path(key), Path(cert)
    for path in (key, cert):
        if not path.is_file():
            raise ApkModError(f"no such file: {path}")
    return key.read_bytes(), cert.read_bytes()


def generate_key(out_dir: Path, common_name: str = "APK Modifyer", days: int = 10950) -> Tuple[Path, Path]:
    """Self-signed RSA key + certificate via OpenSSL (the debug-key equivalent)."""
    if shutil.which("openssl") is None:
        raise ApkModError("generating a key needs the 'openssl' binary on PATH")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "apkmod-key.pem"
    cert_path = out_dir / "apkmod-cert.pem"
    result = run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", str(days), "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-subj", f"/CN={common_name}/OU=APK Modifyer/O=APK Modifyer",
        ]
    )
    if not result.ok:
        raise ApkModError(f"openssl failed: {result.output[:400]}")
    return key_path, cert_path
