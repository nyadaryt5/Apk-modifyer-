"""
The three engines added alongside the AI layer, plus host detection.

JADX and Frida drive external binaries that are not installed here, so what is
tested is the part that is actually ours: that they report their absence
honestly, and that when they do run they build the command line we intend. The
command construction is asserted by monkeypatching ``run`` and capturing argv --
a real decompile or a real device is not required for that, and asserting the
exact command catches argument-order mistakes a smoke test would miss.

MT Manager's diffing and bundle handling are native, so they are tested for
real against actual APK bytes.
"""

from __future__ import annotations

import pathlib
import sys
import zipfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import fixture  # noqa: E402

from apkmod.align import repack  # noqa: E402
from apkmod.apk import ApkContainer  # noqa: E402
from apkmod.arsc import ArscFile  # noqa: E402
from apkmod.engines.frida import FridaEngine, find_adb, find_frida  # noqa: E402
from apkmod.engines.jadx import JadxEngine, find_jadx  # noqa: E402
from apkmod.engines.mtmanager import (  # noqa: E402
    MTManagerEngine,
    diff_apks,
    open_bundle,
    rebuild_bundle,
)
from apkmod.platform_info import detect  # noqa: E402
from apkmod.util import ApkModError, ToolResult  # noqa: E402


@pytest.fixture
def two_apks(tmp_path):
    """An APK and a modified copy: one changed entry, one removed."""
    base = fixture.build_apk(tmp_path / "base.apk")
    with ApkContainer(base) as container:
        arsc = ArscFile.parse(container.arsc_bytes())
        arsc.replace_by_name("app_name", "Modified")
        payload = arsc.serialize()
    changed = tmp_path / "changed.apk"
    repack(base, changed, replace={"resources.arsc": payload}, exclude=["res/raw/keep.txt"])
    return base, changed


# ==========================================================================
# MT Manager: diffing
# ==========================================================================
def test_diff_classifies_every_entry(two_apks):
    base, changed = two_apks
    diff = diff_apks(base, changed)

    by_name = {entry.name: entry.status for entry in diff.entries}
    assert by_name["resources.arsc"] == "changed"
    assert by_name["res/raw/keep.txt"] == "removed"
    assert by_name["AndroidManifest.xml"] == "identical"
    assert len(diff.added) == 0
    assert len(diff.identical) == 4


def test_diff_an_added_entry(two_apks):
    base, changed = two_apks
    with_added = changed.parent / "added.apk"
    repack(changed, with_added, prepend=[("assets/injected.json", b'{"x":1}')])

    diff = diff_apks(changed, with_added)
    assert [e.name for e in diff.added] == ["assets/injected.json"]
    assert diff.added[0].new_size == len(b'{"x":1}')


def test_diff_confirms_a_crc_change_with_content(two_apks):
    """
    Same size, same length, different bytes: a CRC-only comparison would still
    catch this, but the SHA-256 pass is what makes the verdict trustworthy.
    """
    base, changed = two_apks
    entry = next(e for e in diff_apks(base, changed).entries if e.status == "changed")
    assert entry.old_sha256 and entry.new_sha256
    assert entry.old_sha256 != entry.new_sha256
    assert entry.old_size == entry.new_size  # the rename kept the same footprint


def test_diff_fast_mode_skips_hashing(two_apks):
    base, changed = two_apks
    fast = diff_apks(base, changed, compare_content=False)
    entry = next(e for e in fast.entries if e.name == "resources.arsc")
    assert entry.status == "changed"
    assert entry.old_sha256 == "" and entry.new_sha256 == ""


def test_diff_of_identical_files_is_all_identical(two_apks):
    base, _ = two_apks
    diff = diff_apks(base, base)
    assert len(diff.changed) == 0
    assert len(diff.identical) == 6
    assert diff.changed_bytes == 0


def test_diff_rejects_a_missing_file(tmp_path, two_apks):
    base, _ = two_apks
    with pytest.raises(ApkModError, match="no such file"):
        diff_apks(base, tmp_path / "absent.apk")


def test_diff_rejects_a_non_zip(tmp_path, two_apks):
    base, _ = two_apks
    junk = tmp_path / "junk.apk"
    junk.write_bytes(b"this is not a zip file at all")
    with pytest.raises(ApkModError, match="not a readable zip"):
        diff_apks(base, junk)


def test_diff_format_and_json(two_apks):
    base, changed = two_apks
    diff = diff_apks(base, changed)
    text = diff.format()
    assert text.startswith("base.apk -> changed.apk")
    assert "- res/raw/keep.txt" in text
    payload = diff.as_dict()
    assert payload["counts"]["removed"] == 1
    assert payload["counts"]["changed"] == 1


def test_diff_report_is_ordered_by_interest(two_apks):
    base, changed = two_apks
    with_added = changed.parent / "added.apk"
    repack(changed, with_added, prepend=[("assets/injected.json", b'{"x":1}')])
    rows = diff_apks(base, with_added).interesting()
    # removals first, then additions, then changes; identical entries excluded
    assert [e.status for e in rows] == ["removed", "added", "changed"]


# ==========================================================================
# MT Manager: bundles
# ==========================================================================
def make_bundle(tmp_path, *, base, splits=("config.arm64_v8a.apk",), sidecars=("manifest.json",)):
    bundle = tmp_path / "app.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.write(base, "base.apk")
        for split in splits:
            zf.write(base, split)
        for sidecar in sidecars:
            zf.writestr(sidecar, '{"package":"com.example.demo"}')
    return bundle


def test_bundle_round_trip_has_no_duplicates(tmp_path, two_apks):
    """Regression guard: the parts used to be written twice."""
    base, _ = two_apks
    bundle = make_bundle(tmp_path, base=base)
    parts, others = open_bundle(bundle, tmp_path / "unpacked")

    assert [p.name for p in parts] == ["base.apk", "config.arm64_v8a.apk"]
    assert parts[0].is_base is True
    assert others == ["manifest.json"]

    out = rebuild_bundle(parts, tmp_path / "unpacked", tmp_path / "rebuilt.xapk")
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    assert len(names) == len(set(names)) == 3
    assert set(names) == {"base.apk", "config.arm64_v8a.apk", "manifest.json"}


def test_bundle_base_is_listed_first(tmp_path, two_apks):
    base, _ = two_apks
    # Written in an awkward order on purpose.
    bundle = tmp_path / "odd.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.write(base, "config.xhdpi.apk")
        zf.write(base, "base.apk")
    parts, _ = open_bundle(bundle, tmp_path / "u")
    assert parts[0].name == "base.apk" and parts[0].is_base


def test_bundle_without_apks_is_rejected(tmp_path):
    bundle = tmp_path / "nope.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("manifest.json", "{}")
    with pytest.raises(ApkModError, match="contains no .apk members"):
        open_bundle(bundle, tmp_path / "u")


def test_bundle_missing_file(tmp_path):
    with pytest.raises(ApkModError, match="no such file"):
        open_bundle(tmp_path / "absent.xapk", tmp_path / "u")


def test_rebuild_reports_a_missing_part(tmp_path, two_apks):
    base, _ = two_apks
    bundle = make_bundle(tmp_path, base=base)
    parts, _ = open_bundle(bundle, tmp_path / "unpacked")
    parts[0].path = tmp_path / "deleted.apk"
    with pytest.raises(ApkModError, match="missing part"):
        rebuild_bundle(parts, tmp_path / "unpacked", tmp_path / "out.xapk")


def test_mtmanager_engine_is_always_available():
    status = MTManagerEngine().status()
    assert status.available is True
    assert "diff-apks" in status.capabilities
    assert any("native Python" in note for note in status.notes)


# ==========================================================================
# JADX
# ==========================================================================
def test_jadx_reports_absence(tmp_path, monkeypatch):
    monkeypatch.delenv("JADX_HOME", raising=False)
    monkeypatch.delenv("JADX_PATH", raising=False)
    monkeypatch.setattr("apkmod.engines.jadx.cache_dir", lambda: tmp_path)
    monkeypatch.setattr("apkmod.engines.jadx.shutil.which", lambda name: None)

    status = JadxEngine().status()
    assert status.available is False
    assert any("not found" in note for note in status.notes)
    assert "jadx" in status.install_hint


def test_jadx_refuses_to_decompile_without_the_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.jadx.find_jadx", lambda explicit=None: None)
    with pytest.raises(ApkModError, match="jadx is not installed"):
        JadxEngine().decompile(tmp_path / "in.apk", tmp_path / "out")


def test_jadx_explicit_missing_path_is_an_error(tmp_path):
    with pytest.raises(ApkModError, match="no jadx at"):
        find_jadx(str(tmp_path / "absent" / "jadx"))


def test_jadx_builds_the_command_we_intend(tmp_path, monkeypatch, two_apks):
    """Assert the exact argv: argument order here is easy to get silently wrong."""
    base, _ = two_apks
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = [str(c) for c in cmd]
        captured["timeout"] = kwargs.get("timeout")
        (tmp_path / "out" / "sources").mkdir(parents=True, exist_ok=True)
        (tmp_path / "out" / "sources" / "A.java").write_text("class A {}")
        return ToolResult(captured["cmd"], 0, "done", "")

    monkeypatch.setattr("apkmod.engines.jadx.find_jadx", lambda explicit=None: "/usr/bin/jadx")
    monkeypatch.setattr("apkmod.engines.jadx.run", fake_run)

    result = JadxEngine().decompile(
        base, tmp_path / "out", threads=8, deobfuscate=True, include_resources=False, timeout=33
    )
    cmd = captured["cmd"]
    assert cmd[0] == "/usr/bin/jadx"
    assert cmd[-1] == str(base)
    assert cmd[cmd.index("--output-dir") + 1] == str(tmp_path / "out")
    assert cmd[cmd.index("--threads") + 1] == "8"
    assert "--deobf" in cmd and "--no-res" in cmd
    assert captured["timeout"] == 33
    assert result["java_files"] == 1
    assert result["ok"] is True


def test_jadx_partial_failure_is_reported_not_hidden(tmp_path, monkeypatch, two_apks):
    """JADX exits non-zero on obfuscated classes; the sources are still useful."""
    base, _ = two_apks

    def fake_run(cmd, **kwargs):
        # `ok` is its own field and defaults True, so a fake failure must say so
        # explicitly -- exactly as util.run() does for a real subprocess.
        return ToolResult(
            cmd, 1, "WARN: 12 classes failed to decompile", "error: incomplete", ok=False
        )

    monkeypatch.setattr("apkmod.engines.jadx.find_jadx", lambda explicit=None: "/usr/bin/jadx")
    monkeypatch.setattr("apkmod.engines.jadx.run", fake_run)

    result = JadxEngine().decompile(base, tmp_path / "out")
    assert result["ok"] is False
    assert "12 classes failed" in " ".join(result["warnings"])
    assert result["note"]  # the user is told this is expected


def test_jadx_search_reads_the_decompiled_tree(tmp_path):
    root = tmp_path / "src"
    (root / "com" / "example").mkdir(parents=True)
    (root / "com" / "example" / "A.java").write_text(
        "class A {\n  void check() {\n    verifySignature();\n  }\n}\n"
    )
    (root / "com" / "example" / "B.java").write_text("class B {}\n")

    hits = JadxEngine().search(root, "verifySignature")
    assert len(hits) == 1
    assert hits[0]["line"] == 3
    assert "verifySignature" in hits[0]["text"]


def test_jadx_search_rejects_a_bad_regex_and_missing_tree(tmp_path):
    (tmp_path / "src").mkdir()
    with pytest.raises(ApkModError, match="bad regex"):
        JadxEngine().search(tmp_path / "src", "[unclosed")
    with pytest.raises(ApkModError, match="no decompiled tree"):
        JadxEngine().search(tmp_path / "absent", "x")


def test_jadx_version_is_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "apkmod.engines.jadx.run",
        lambda cmd, **kw: ToolResult(cmd, 0, "jadx 1.5.1", ""),
    )
    assert JadxEngine._version("/usr/bin/jadx") == "1.5.1"
    monkeypatch.setattr(
        "apkmod.engines.jadx.run", lambda cmd, **kw: ToolResult(cmd, 1, "", "failed", ok=False)
    )
    assert JadxEngine._version("/usr/bin/jadx") is None


# ==========================================================================
# Frida
# ==========================================================================
def test_frida_reports_absence(tmp_path, monkeypatch):
    monkeypatch.delenv("FRIDA_HOME", raising=False)
    monkeypatch.delenv("FRIDA_PATH", raising=False)
    monkeypatch.setattr("apkmod.engines.frida.cache_dir", lambda: tmp_path)
    monkeypatch.setattr("apkmod.engines.frida.shutil.which", lambda name: None)

    status = FridaEngine().status()
    assert status.available is False
    assert any("not found" in note for note in status.notes)
    assert "frida-tools" in status.install_hint


def test_frida_present_but_no_device_is_reported(monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida", lambda explicit=None: "/usr/bin/frida")
    monkeypatch.setattr("apkmod.engines.frida.find_adb", lambda: None)
    monkeypatch.setattr("apkmod.engines.frida.find_frida_ps", lambda: "/usr/bin/frida-ps")
    monkeypatch.setattr(
        "apkmod.engines.frida.run", lambda cmd, **kw: ToolResult(cmd, 0, "16.2.1", "")
    )

    status = FridaEngine().status()
    assert status.available is True
    assert status.version == "16.2.1"
    assert any("adb not found" in note for note in status.notes)


def test_frida_lists_connected_devices(monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida", lambda explicit=None: "/usr/bin/frida")
    monkeypatch.setattr("apkmod.engines.frida.find_adb", lambda: "/usr/bin/adb")
    monkeypatch.setattr("apkmod.engines.frida.find_frida_ps", lambda: "/usr/bin/frida-ps")
    monkeypatch.setattr(
        "apkmod.engines.frida.run",
        lambda cmd, **kw: ToolResult(cmd, 0, "List of devices attached\nemulator-5554\tdevice\n", ""),
    )
    status = FridaEngine().status()
    assert any("emulator-5554" in note for note in status.notes)


def test_frida_requires_a_target(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida", lambda explicit=None: "/usr/bin/frida")
    script = tmp_path / "hook.js"
    script.write_text("console.log(1)")
    with pytest.raises(ApkModError, match="give either a package name or a pid"):
        FridaEngine().run_script(script)


def test_frida_spawn_versus_attach_command(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida", lambda explicit=None: "/usr/bin/frida")
    script = tmp_path / "hook.js"
    script.write_text("console.log(1)")
    seen = []
    monkeypatch.setattr(
        "apkmod.engines.frida.run",
        lambda cmd, **kw: (seen.append([str(c) for c in cmd]), ToolResult(cmd, 0, "ok", ""))[1],
    )

    FridaEngine().run_script(script, package="com.example.demo")
    assert "-f" in seen[0] and "--no-pause" in seen[0]
    assert seen[0][seen[0].index("-f") + 1] == "com.example.demo"

    FridaEngine().run_script(script, package="com.example.demo", spawn=False)
    assert "-n" in seen[1] and "-f" not in seen[1]

    FridaEngine().run_script(script, pid=4242)
    assert seen[2][seen[2].index("-p") + 1] == "4242"


def test_frida_rejects_a_missing_script(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida", lambda explicit=None: "/usr/bin/frida")
    with pytest.raises(ApkModError, match="no such script"):
        FridaEngine().run_script(tmp_path / "absent.js", package="com.x")


def test_frida_list_processes_parses_the_table(monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida_ps", lambda: "/usr/bin/frida-ps")
    monkeypatch.setattr(
        "apkmod.engines.frida.run",
        lambda cmd, **kw: ToolResult(cmd, 0, "  PID  Name\n 1234  com.example.demo\n 5678  system_server\n", ""),
    )
    result = FridaEngine().list_processes()
    assert result["count"] == 2
    assert result["processes"][0] == {"pid": 1234, "name": "com.example.demo"}


def test_frida_push_needs_a_binary_that_exists(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_adb", lambda: "/usr/bin/adb")
    with pytest.raises(ApkModError, match="no frida-server binary"):
        FridaEngine().push_server(tmp_path / "absent-server")


def test_frida_push_and_start_build_adb_commands(tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_adb", lambda: "/usr/bin/adb")
    seen = []
    monkeypatch.setattr(
        "apkmod.engines.frida.run",
        lambda cmd, **kw: (seen.append([str(c) for c in cmd]), ToolResult(cmd, 0, "", ""))[1],
    )
    server = tmp_path / "frida-server"
    server.write_bytes(b"\x7fELF")

    result = FridaEngine().push_server(server, serial="emulator-5554")
    assert result["ok"] is True
    assert seen[0][:4] == ["/usr/bin/adb", "-s", "emulator-5554", "push"]
    # argv is [adb, -s, serial, shell, chmod, 755, path]
    assert seen[1][-3:] == ["chmod", "755", "/data/local/tmp/frida-server"]

    FridaEngine().start_server(serial="emulator-5554")
    assert "su -c" in " ".join(seen[2])


def test_frida_without_adb_is_a_clean_error(monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_adb", lambda: None)
    with pytest.raises(ApkModError, match="adb is not installed"):
        FridaEngine().push_server(pathlib.Path("x"))


# ==========================================================================
# platform detection
# ==========================================================================
def test_detect_describes_this_machine():
    info = detect()
    assert info.system in ("linux", "android", "macos", "windows")
    assert info.family in ("desktop", "android", "other")
    assert info.machine
    # openssl is present in this image; the report must say so.
    assert "openssl" in info.binaries


def test_detect_dict_and_text_agree():
    info = detect()
    payload = info.as_dict()
    text = info.format()
    assert payload["system"] in text
    assert ("root: yes" in text) == payload["root"]


def test_android_detection_uses_real_evidence(monkeypatch):
    from apkmod import platform_info

    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    assert platform_info._is_termux() is True
    assert platform_info._is_android() is True

    monkeypatch.delenv("PREFIX", raising=False)
    monkeypatch.setattr(platform_info.Path, "is_dir", lambda self: False)
    monkeypatch.setattr(platform_info.Path, "is_file", lambda self: False)
    monkeypatch.setattr(platform_info.platform, "system", lambda: "Linux")
    assert platform_info._is_android() is False


def test_android_advice_differs_from_desktop(monkeypatch):
    from apkmod import platform_info

    monkeypatch.setattr(platform_info, "_is_android", lambda: True)
    monkeypatch.setattr(platform_info, "_is_termux", lambda: True)
    monkeypatch.setattr(platform_info, "_has_root", lambda: True)
    android = platform_info.detect()
    assert android.family == "android"
    assert any("on-device editing" in note for note in android.notes)
    assert any("root is available" in note for note in android.notes)

    monkeypatch.setattr(platform_info, "_is_android", lambda: False)
    desktop = platform_info.detect()
    assert desktop.family == "desktop"
    assert any("adb" in note for note in desktop.notes)


def test_root_requires_a_working_su(monkeypatch):
    from apkmod import platform_info

    monkeypatch.setattr(platform_info.shutil, "which", lambda name: None)
    assert platform_info._has_root() is False

    monkeypatch.setattr(platform_info.shutil, "which", lambda name: "/system/bin/su")
    monkeypatch.setattr(
        platform_info, "run", lambda cmd, **kw: ToolResult(cmd, 0, "1000\n", "")
    )
    assert platform_info._has_root() is False  # su exists but is not root

    monkeypatch.setattr(platform_info, "run", lambda cmd, **kw: ToolResult(cmd, 0, "0\n", ""))
    assert platform_info._has_root() is True
