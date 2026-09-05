"""Engine adapters: what is available, and how they fail when it is not."""

from __future__ import annotations

import pytest

from apkmod.engines import registry
from apkmod.engines.aee import NativeEditor
from apkmod.engines.apktool import ApktoolEngine, find_apktool_jar, find_java, install_apktool
from apkmod.engines.apktoolm import ApktoolMEngine
from apkmod.engines.patcher import DISCLAIMER, PatcherEngine
from apkmod.util import ApkModError, ToolResult


def test_registry_exposes_four_engines():
    assert registry.names == ["apktool", "apktool-m", "aee", "patcher"]


def test_registry_rejects_unknown_engine():
    with pytest.raises(ApkModError, match="unknown engine"):
        registry.get("nope")


def test_native_editor_is_always_ready():
    status = NativeEditor().status()
    assert status.available is True
    assert "manifest read/write" in status.capabilities
    assert "no external tools required" in status.notes


def test_patcher_engine_states_its_limits():
    status = PatcherEngine().status()
    assert status.available is True
    assert any("Analysis only" in note for note in status.notes)
    assert DISCLAIMER.startswith("Analysis only")


def test_apktool_engine_reports_a_missing_jar(tmp_path, monkeypatch):
    monkeypatch.delenv("APKMOD_APKTOOL_JAR", raising=False)
    monkeypatch.setattr("apkmod.engines.apktool.cache_dir", lambda: tmp_path)
    status = ApktoolEngine().status()
    assert status.available is False
    assert any("no apktool jar" in note for note in status.notes)
    assert "install-apktool" in status.install_hint


def test_apktool_decode_refuses_without_a_jar(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.apktool.cache_dir", lambda: tmp_path)
    engine = ApktoolEngine()
    monkeypatch.setattr(engine, "jar", lambda: None)
    with pytest.raises(ApkModError, match="no apktool jar available"):
        engine.decode("in.apk", tmp_path / "out")


def test_apktool_explicit_missing_jar_is_reported(tmp_path):
    with pytest.raises(ApkModError, match="no apktool jar at"):
        find_apktool_jar(tmp_path / "absent.jar")


def test_install_apktool_survives_a_blocked_network(tmp_path, monkeypatch):
    def fake_run(cmd, **kwargs):
        return ToolResult(list(cmd), 35, "", "curl: (35) SSL_ERROR_SYSCALL", ok=False)

    monkeypatch.setattr("apkmod.engines.apktool.run", fake_run)
    with pytest.raises(ApkModError, match="could not download"):
        install_apktool("2.11.1", dest=tmp_path)


def test_apktool_install_uses_the_cache(tmp_path, monkeypatch):
    jar = tmp_path / "apktool_2.11.1.jar"
    jar.write_bytes(b"PK\x03\x04" + b"\x00" * 4096)
    monkeypatch.setattr("apkmod.engines.apktool.cache_dir", lambda: tmp_path)
    assert install_apktool("2.11.1") == jar


def test_java_discovery():
    """A JVM is optional; if present we must find and version it."""
    java = find_java()
    if java is None:
        pytest.skip("no JVM in this environment")
    from apkmod.engines.apktool import java_version

    assert java_version(java) is not None


def test_apktool_m_without_adb(monkeypatch):
    monkeypatch.setattr("apkmod.engines.apktoolm.find_adb", lambda: None)
    engine = ApktoolMEngine()
    status = engine.status()
    assert status.available is False
    assert any("adb not found" in note for note in status.notes)
    assert engine.devices() == []


def test_apktool_m_push_needs_a_file(monkeypatch, tmp_path):
    monkeypatch.setattr("apkmod.engines.apktoolm.find_adb", lambda: "/bin/true")
    with pytest.raises(ApkModError, match="no such file"):
        ApktoolMEngine().push(tmp_path / "absent.apk")


def test_status_format_is_readable():
    text = NativeEditor().status().format()
    assert "ready" in text
    assert "native" in text
