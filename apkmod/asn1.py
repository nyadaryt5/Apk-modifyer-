"""Minimal DER/ASN.1 reader + writer.

Only what JAR (v1) signing needs:
  * parse an X.509 certificate far enough to lift out issuer + serial + SPKI
  * parse a PKCS#1 / PKCS#8 RSA private key into (n, e, d)
  * emit a PKCS#7 SignedData blob wrapping a SHA-256 RSA signature
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import List, Tuple

from .util import ApkModError

# --- tags -----------------------------------------------------------------
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
SEQUENCE = 0x30
SET = 0x31

OID_SHA256 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
OID_RSA = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
OID_PKCS7_SIGNED_DATA = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
OID_PKCS7_DATA = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])


# --- low level ------------------------------------------------------------
def _read_len(data: bytes, i: int) -> Tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    nbytes = first & 0x7F
    if nbytes == 0 or nbytes > 4:
        raise ApkModError(f"unsupported DER length encoding at offset {i}")
    length = int.from_bytes(data[i : i + nbytes], "big")
    return length, i + nbytes


def read_tlv(data: bytes, i: int = 0) -> Tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_index)."""
    tag = data[i]
    length, i = _read_len(data, i + 1)
    return tag, data[i : i + length], i + length


def children(data: bytes) -> List[Tuple[int, bytes]]:
    """Split a constructed value into its (tag, value) children."""
    out: List[Tuple[int, bytes]] = []
    i = 0
    while i < len(data):
        tag, value, i = read_tlv(data, i)
        out.append((tag, value))
    return out


def enc_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(value)) + value


def seq(*parts: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(parts))


def oid(value: bytes) -> bytes:
    return tlv(OID, value)


def integer(value: int | bytes) -> bytes:
    if isinstance(value, bytes):
        body = value
        if body and body[0] & 0x80:  # keep positive
            body = b"\x00" + body
        if not body:
            body = b"\x00"
        return tlv(INTEGER, body)
    if value == 0:
        return tlv(INTEGER, b"\x00")
    length = (value.bit_length() + 8) // 8
    return tlv(INTEGER, value.to_bytes(length, "big"))


# --- PEM ------------------------------------------------------------------
def pem_to_der(pem: bytes, expected: str | None = None) -> bytes:
    text = pem.decode("utf-8", "replace")
    if "-----BEGIN" not in text:
        raise ApkModError("expected a PEM block, got raw bytes")
    blocks: List[str] = []
    current: List[str] | None = None
    label = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("-----BEGIN "):
            label = line[11:-5].strip()
            current = []
        elif line.startswith("-----END "):
            if current is not None:
                blocks.append("".join(current))
            current = None
        elif current is not None:
            current.append(line)
    if not blocks:
        raise ApkModError("no complete PEM block found")
    der = base64.b64decode(blocks[0])
    if expected and label and expected.lower() not in label.lower():
        raise ApkModError(f"expected a PEM '{expected}' block, found '{label}'")
    return der


# --- X.509 ----------------------------------------------------------------
@dataclass
class Certificate:
    der: bytes
    issuer: bytes  # raw DER of the Name
    subject: bytes  # raw DER of the subject Name
    serial: bytes  # raw big-endian integer bytes
    public_key_der: bytes

    @property
    def subject_cn(self) -> str:
        """Best-effort common name, e.g. 'CN=Android Debug'."""
        for _set in children(self.subject):
            for _seq in children(_set[1]):
                parts = children(_seq[1])
                if len(parts) == 2 and parts[0][0] == OID:
                    oid_bytes = parts[0][1]
                    if oid_bytes == bytes([0x55, 0x04, 0x03]):  # id-at-commonName
                        return parts[1][1].decode("utf-8", "replace")
        return ""

    @property
    def sha256(self) -> str:
        import hashlib

        return hashlib.sha256(self.der).hexdigest()

    @property
    def public_numbers(self) -> Tuple[int, int]:
        return parse_rsa_public_numbers(self.public_key_der)

    @classmethod
    def parse(cls, der: bytes) -> "Certificate":
        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        outer = children(der)
        if not outer or outer[0][0] != SEQUENCE:
            raise ApkModError("certificate does not start with a SEQUENCE")
        cert_fields = children(outer[0][1])
        if not cert_fields or cert_fields[0][0] != SEQUENCE:
            raise ApkModError("certificate has no TBSCertificate")
        tbs = children(cert_fields[0][1])

        # TBSCertificate ::= [0] version?, serialNumber, signature, issuer,
        #                    validity, subject, subjectPublicKeyInfo, ...
        idx = 0
        if tbs[idx][0] == 0xA0:  # explicit version
            idx += 1
        serial = tbs[idx][1]
        issuer = tbs[idx + 2][1]
        subject = tbs[idx + 4][1]

        # subjectPublicKeyInfo is the first field that carries a BIT STRING
        spki = None
        for tag, value in tbs:
            if tag == SEQUENCE and any(t == BIT_STRING for t, _ in children(value)):
                spki = tlv(SEQUENCE, value)
                break
        if spki is None:
            raise ApkModError("could not locate SubjectPublicKeyInfo in certificate")
        return cls(der=der, issuer=issuer, subject=subject, serial=serial, public_key_der=spki)


# --- RSA private key ------------------------------------------------------
@dataclass
class RsaKey:
    n: int
    e: int
    d: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8


def parse_rsa_private_key(pem: bytes) -> RsaKey:
    der = pem_to_der(pem, expected="PRIVATE KEY")
    tag, body, _ = read_tlv(der)
    if tag != SEQUENCE:
        raise ApkModError("private key is not a DER SEQUENCE")
    parts = children(body)
    is_pkcs8 = (
        len(parts) >= 3
        and parts[0][0] == INTEGER
        and parts[1][0] == SEQUENCE  # AlgorithmIdentifier
        and parts[2][0] == OCTET_STRING
    )
    if is_pkcs8:
        # PrivateKeyInfo: version, AlgorithmIdentifier, OCTET STRING(RSAPrivateKey).
        # The OCTET STRING *contains* a DER SEQUENCE, so unwrap that first.
        wrapped_tag, wrapped_body, _ = read_tlv(parts[2][1])
        if wrapped_tag != SEQUENCE:
            raise ApkModError("PKCS#8 body is not an RSAPrivateKey SEQUENCE")
        inner = children(wrapped_body)
    else:
        inner = parts  # PKCS#1 RSAPrivateKey: version, n, e, d, p, q, ...
    ints = [int.from_bytes(v, "big") for t, v in inner if t == INTEGER]
    if len(ints) < 3:
        raise ApkModError("private key did not contain RSA integers (is it encrypted?)")
    # RSAPrivateKey: version, n, e, d, p, q, ...
    return RsaKey(n=ints[1], e=ints[2], d=ints[3])


def parse_rsa_public_numbers(spki_der: bytes) -> Tuple[int, int]:
    spki = children(spki_der)[0][1]
    for tag, value in children(spki):
        if tag == BIT_STRING:
            key_bits = value[1:]  # strip unused-bits octet
            nums = children(children(key_bits)[0][1])
            ints = [int.from_bytes(v, "big") for t, v in nums if t == INTEGER]
            return ints[0], ints[1]
    raise ApkModError("no BIT STRING in SubjectPublicKeyInfo")


# --- PKCS#1 v1.5 ----------------------------------------------------------
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def pkcs1_v15_sign(key: RsaKey, digest: bytes) -> bytes:
    em = b"\x00\x01" + b"\xff" * (key.size - len(digest) - len(_SHA256_DIGEST_INFO) - 3) + b"\x00"
    em += _SHA256_DIGEST_INFO + digest
    m = int.from_bytes(em, "big")
    if m >= key.n:
        raise ApkModError("RSA modulus too small for the message")
    return pow(m, key.d, key.n).to_bytes(key.size, "big")


def pkcs1_v15_verify(n: int, e: int, signature: bytes, digest: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(k, "big")
    expected = b"\x00\x01" + b"\xff" * (k - len(digest) - len(_SHA256_DIGEST_INFO) - 3) + b"\x00"
    expected += _SHA256_DIGEST_INFO + digest
    return em == expected


# --- PKCS#7 SignedData ----------------------------------------------------
def _alg(identifier: bytes) -> bytes:
    return seq(oid(identifier), tlv(NULL, b""))


def build_pkcs7_signed_data(content: bytes, cert_der: bytes, signature: bytes) -> bytes:
    """Classic JAR-signing SignedData: eContent included, no authenticated attrs."""
    cert = Certificate.parse(cert_der)
    digest_algorithms = tlv(SET, _alg(OID_SHA256))
    encap = seq(
        oid(OID_PKCS7_DATA),
        tlv(0xA0, tlv(OCTET_STRING, content)),
    )
    certificates = tlv(0xA0, cert.der)
    signer_info = seq(
        integer(1),
        seq(tlv(SEQUENCE, cert.issuer), integer(cert.serial)),
        _alg(OID_SHA256),
        _alg(OID_RSA),
        tlv(OCTET_STRING, signature),
    )
    signed_data = seq(
        integer(1),
        digest_algorithms,
        encap,
        certificates,
        tlv(SET, signer_info),
    )
    return seq(oid(OID_PKCS7_SIGNED_DATA), tlv(0xA0, signed_data))


@dataclass
class Pkcs7Signature:
    content: bytes
    signature: bytes
    certificate: Certificate


def parse_pkcs7_signed_data(der: bytes) -> Pkcs7Signature:
    """Pull eContent, the signature and the first certificate back out of a .RSA."""
    top = children(der)[0]
    if top[0] != SEQUENCE:
        raise ApkModError("PKCS#7 blob is not a SEQUENCE")
    parts = children(top[1])
    if parts[0][0] != OID or parts[0][1] != OID_PKCS7_SIGNED_DATA:
        raise ApkModError("not a signedData ContentInfo")
    # parts[1] is the [0] EXPLICIT wrapper; inside it sits the SignedData SEQUENCE
    sd_tag, sd_body, _ = read_tlv(parts[1][1])
    if sd_tag != SEQUENCE:
        raise ApkModError("signedData content is not a SEQUENCE")
    signed_data = children(sd_body)
    content = b""
    cert_der = b""
    signature = b""
    for tag, value in signed_data:
        if tag == 0xA0:
            # [0] certificates: an IMPLICIT set whose content is the raw DER cert
            cert_der = value
        elif tag == SEQUENCE:
            # encapContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT OCTET STRING }
            for ktag, kvalue in children(value):
                if ktag != 0xA0:
                    continue
                inner_tag, inner_body, _ = read_tlv(kvalue)
                if inner_tag == OCTET_STRING:
                    content = inner_body
        elif tag == SET:
            # signerInfos: take the encryptedDigest OCTET STRING out of SignerInfo
            for ktag, kvalue in children(value):
                if ktag != SEQUENCE:
                    continue
                for ftag, fvalue in children(kvalue):
                    if ftag == OCTET_STRING:
                        signature = fvalue
    if not cert_der:
        raise ApkModError("PKCS#7 blob carries no certificate")
    return Pkcs7Signature(content=content, signature=signature, certificate=Certificate.parse(cert_der))
