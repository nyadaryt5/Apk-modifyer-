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
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import asn1
from .align import repack
from .util import ApkModError, cache_dir, find_binary, run

__all__ = [
    "sign",
    "sign_v1",
    "verify_v1",
    "build_manifest",
    "build_signature_file",
    "manifest_sections",
    "load_material",
    "generate_key",
    "find_apksigner",
    "find_uber_signer_jar",
    "signer_statuses",
    "SignOutcome",
    "SignerStatus",
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
# external signers (v2/v3 scheme coverage)
# ==========================================================================
@dataclass
class SignerStatus:
    name: str
    available: bool
    location: Optional[str] = None
    version: Optional[str] = None
    schemes: tuple = ()
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "available": self.available,
            "location": self.location,
            "version": self.version,
            "schemes": list(self.schemes),
            "note": self.note,
        }


def _android_build_tools_dirs() -> List[str]:
    roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path.home() / "Android" / "Sdk"),
        str(Path.home() / "Library" / "Android" / "sdk"),
    ]
    dirs: List[str] = []
    for root in roots:
        if not root:
            continue
        base = Path(root) / "build-tools"
        if base.is_dir():
            dirs += [str(p) for p in sorted(base.iterdir(), reverse=True) if p.is_dir()]
    return dirs


def find_apksigner() -> Optional[str]:
    """apksigner from the Android SDK build-tools, wherever it happens to live."""
    return find_binary(["apksigner", "apksigner.bat"], extra_dirs=_android_build_tools_dirs())


def find_uber_signer_jar(explicit: Optional[Path] = None) -> Optional[str]:
    """uber-apk-signer jar: explicit path, env var, or the cache."""
    if explicit and Path(explicit).is_file():
        return str(explicit)
    env = os.environ.get("APKMOD_UBER_JAR")
    if env and Path(env).is_file():
        return env
    from .engines.apktool import find_java

    if find_java() is None:
        return None  # the jar is useless without a JVM
    cached = sorted(cache_dir().glob("uber-apk-signer*.jar"), key=lambda p: p.name, reverse=True)
    return str(cached[0]) if cached else None


def signer_statuses() -> List[SignerStatus]:
    """What can produce a signature on this machine, and which schemes it covers."""
    from .engines.apktool import find_java, java_version

    out: List[SignerStatus] = []

    apksigner = find_apksigner()
    if apksigner:
        probe = run([apksigner, "--version"], timeout=30)
        out.append(
            SignerStatus(
                name="apksigner",
                available=True,
                location=apksigner,
                version=probe.stdout.strip() or None,
                schemes=("v1", "v2", "v3", "v4"),
                note="Android SDK build-tools",
            )
        )
    else:
        out.append(
            SignerStatus(
                name="apksigner",
                available=False,
                schemes=("v1", "v2", "v3", "v4"),
                note="install Android SDK build-tools, or set ANDROID_HOME",
            )
        )

    uber = find_uber_signer_jar()
    if uber:
        out.append(
            SignerStatus(
                name="uber-apk-signer",
                available=True,
                location=uber,
                schemes=("v1", "v2", "v3"),
                note="signs, aligns and verifies in one pass",
            )
        )
    else:
        out.append(
            SignerStatus(
                name="uber-apk-signer",
                available=False,
                schemes=("v1", "v2", "v3"),
                note="drop uber-apk-signer.jar in the cache or set APKMOD_UBER_JAR",
            )
        )

    java = find_java()
    jarsigner = shutil.which("jarsigner")
    out.append(
        SignerStatus(
            name="native (pure Python)",
            available=True,
            location="apkmod.signing.sign_v1",
            version=f"jvm {java_version(java)}" if java else "no jvm needed",
            schemes=("v1",),
            note="always available; v1 only" + ("" if jarsigner else ", jarsigner not on PATH"),
        )
    )
    return out


@dataclass
class SignOutcome:
    path: Path
    engine: str
    notes: List[str]
    schemes: List[str]
    certificate_sha256: Optional[str] = None
    subject: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "engine": self.engine,
            "notes": self.notes,
            "schemes": self.schemes,
            "certificate_sha256": self.certificate_sha256,
            "subject": self.subject,
        }


def _resulting_schemes(apk: Path) -> List[str]:
    from .apk import ApkContainer

    with ApkContainer(apk) as container:
        info = container.signing_info()
    return [
        name
        for name, present in (("v1", info["v1_jar_signing"]), ("v2", info["v2"]), ("v3", info["v3"]))
        if present
    ]


def sign_with_apksigner(
    apk: Path,
    out: Path,
    *,
    key_pem: Optional[bytes] = None,
    cert_pem: Optional[bytes] = None,
    keystore: Optional[Path] = None,
    storepass: str = "",
    alias: Optional[str] = None,
) -> SignOutcome:
    """Delegate to the SDK signer for v2/v3 coverage."""
    binary = find_apksigner()
    if binary is None:
        raise ApkModError("apksigner is not installed (Android SDK build-tools)")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    args: List[str] = ["sign", "--out", str(out), str(apk)]
    if keystore is not None:
        args[1:1] = ["--ks", str(keystore), "--ks-pass", f"pass:{storepass}"]
        if alias:
            args[1:1] = ["--ks-key-alias", alias]
    elif key_pem is not None and cert_pem is not None:
        # apksigner reads files, so PEM material has to land on disk
        tmp = out.parent / f".{out.name}.pem"
        tmp.mkdir(parents=True, exist_ok=True)
        key_path = tmp / "key.pem"
        cert_path = tmp / "cert.pem"
        key_path.write_bytes(key_pem)
        cert_path.write_bytes(cert_pem)
        args[1:1] = ["--key", str(key_path), "--cert", str(cert_path)]
    else:
        raise ApkModError("apksigner needs --keystore, or a --key/--cert pair")

    result = run([binary, *args], timeout=900)
    if not result.ok:
        raise ApkModError(f"apksigner failed: {result.output[-600:]}")
    check = verify_v1(out)
    return SignOutcome(
        path=out,
        engine="apksigner",
        notes=[line for line in result.output.splitlines() if line.strip()][:6],
        schemes=_resulting_schemes(out),
        certificate_sha256=check.certificate_sha256,
        subject=check.subject,
    )


def sign_with_uber(
    apk: Path,
    out: Path,
    *,
    keystore: Optional[Path] = None,
    storepass: str = "",
    alias: Optional[str] = None,
    key_pem: Optional[bytes] = None,
    cert_pem: Optional[bytes] = None,
) -> SignOutcome:
    """Delegate to uber-apk-signer: it signs, aligns and verifies in one pass."""
    from .engines.apktool import find_java

    jar = find_uber_signer_jar()
    java = find_java()
    if jar is None or java is None:
        raise ApkModError("uber-apk-signer needs its jar (APKMOD_UBER_JAR) and a JVM")
    out = Path(out)
    work = out.parent / f".{out.name}.uber"
    work.mkdir(parents=True, exist_ok=True)

    args = [java, "-jar", jar, "--apks", str(apk), "-o", str(work), "--allowResign"]
    if keystore is not None:
        args += ["--ks", str(keystore), "--ksPass", storepass or ""]
        if alias:
            args += ["--ksAlias", alias]
    elif key_pem is not None and cert_pem is not None:
        key_path = work / "key.pem"
        cert_path = work / "cert.pem"
        key_path.write_bytes(key_pem)
        cert_path.write_bytes(cert_pem)
        args += ["--ks", str(work / "unused.keystore")]  # uber wants a keystore
        raise ApkModError(
            "uber-apk-signer only accepts a keystore; use --keystore, or --engine apksigner/native for PEM"
        )
    else:
        raise ApkModError("uber-apk-signer needs --keystore")

    result = run(args, timeout=900)
    produced = sorted(work.glob("*-signed.apk")) or sorted(work.glob("*.apk"))
    if not result.ok or not produced:
        raise ApkModError(f"uber-apk-signer failed: {result.output[-600:]}")
    shutil.copyfile(produced[0], out)
    shutil.rmtree(work, ignore_errors=True)
    check = verify_v1(out)
    return SignOutcome(
        path=out,
        engine="uber-apk-signer",
        notes=[line for line in result.output.splitlines() if line.strip()][:6],
        schemes=_resulting_schemes(out),
        certificate_sha256=check.certificate_sha256,
        subject=check.subject,
    )


def sign(
    apk: Path,
    out: Path,
    *,
    engine: str = "auto",
    key_pem: Optional[bytes] = None,
    cert_pem: Optional[bytes] = None,
    keystore: Optional[Path] = None,
    storepass: str = "",
    alias: Optional[str] = None,
    digest: str = "sha256",
    signature_name: str = "APKMOD",
) -> SignOutcome:
    """Sign with the best available backend, or the one you asked for.

    ``auto`` prefers apksigner (v1+v2+v3), then uber-apk-signer, then the native
    v1 signer -- which always works, but only covers scheme v1.
    """
    if keystore is None and (key_pem is None or cert_pem is None):
        key_pem, cert_pem = load_material(key=None, cert=None, keystore=None)

    def _native() -> SignOutcome:
        result = sign_v1(apk, out, key_pem, cert_pem, signature_name=signature_name, digest=digest)
        return SignOutcome(
            path=result.path,
            engine="native",
            notes=[f"v1 signed {result.signed_entries} entries with {result.digest_name}"],
            schemes=_resulting_schemes(result.path),
            certificate_sha256=result.certificate_sha256,
            subject=result.subject,
        )

    if engine == "native":
        return _native()
    if engine == "apksigner":
        return sign_with_apksigner(
            apk, out, key_pem=key_pem, cert_pem=cert_pem, keystore=keystore, storepass=storepass, alias=alias
        )
    if engine == "uber":
        return sign_with_uber(apk, out, keystore=keystore, storepass=storepass, alias=alias)
    if engine != "auto":
        raise ApkModError(f"unknown signing engine '{engine}' (auto, native, apksigner, uber)")

    if find_apksigner():
        try:
            return sign_with_apksigner(
                apk, out, key_pem=key_pem, cert_pem=cert_pem, keystore=keystore, storepass=storepass, alias=alias
            )
        except ApkModError:
            pass  # fall through to the next backend
    if find_uber_signer_jar() and keystore is not None:
        try:
            return sign_with_uber(apk, out, keystore=keystore, storepass=storepass, alias=alias)
        except ApkModError:
            pass
    return _native()


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
