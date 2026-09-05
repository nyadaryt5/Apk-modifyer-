"""Shared fixtures: a synthetic APK, and real signing material when OpenSSL exists."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))          # for fixture.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # for apkmod/

import fixture  # noqa: E402  (local hand-built binaries)

from apkmod.signing import generate_key  # noqa: E402

OPENSSL = shutil.which("openssl")


@pytest.fixture(scope="session")
def apk_bytes() -> bytes:
    return fixture.build_manifest_axml()


@pytest.fixture
def apk(tmp_path: Path) -> Path:
    return fixture.build_apk(tmp_path / "demo.apk")


@pytest.fixture(scope="session")
def signing_material(tmp_path_factory) -> tuple[bytes, bytes]:
    if OPENSSL is None:
        pytest.skip("openssl is not installed")
    key, cert = generate_key(tmp_path_factory.mktemp("keys"), common_name="APK Modifyer Tests")
    return key.read_bytes(), cert.read_bytes()
