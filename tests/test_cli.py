"""End-to-end CLI runs."""

from __future__ import annotations

import json
import shutil
import zipfile

import pytest

from apkmod.cli import main

OPENSSL = shutil.which("openssl")


def _out(capsys) -> str:
    return capsys.readouterr().out


def test_doctor(capsys):
    assert main(["doctor"]) == 0
    out = _out(capsys)
    for engine in ("apktool", "apktool-m", "aee", "patcher"):
        assert engine in out
    assert "ready:" in out


def test_doctor_json(capsys):
    assert main(["doctor", "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert [e["name"] for e in payload] == ["apktool", "apktool-m", "aee", "patcher"]


def test_info(capsys, apk):
    assert main(["info", str(apk)]) == 0
    out = _out(capsys)
    assert "com.example.demo" in out
    assert "permissions : 2" in out


def test_info_json(capsys, apk):
    assert main(["info", str(apk), "--json"]) == 0
    assert json.loads(_out(capsys))["manifest"]["package"] == "com.example.demo"


def test_manifest_xml(capsys, apk):
    assert main(["manifest", str(apk), "--xml"]) == 0
    assert "<manifest" in _out(capsys)


def test_manifest_facts(capsys, apk):
    assert main(["manifest", str(apk)]) == 0
    assert json.loads(_out(capsys))["launcher_activity"] == ".MainActivity"


def test_strings(capsys, apk):
    assert main(["strings", str(apk)]) == 0
    assert "Demo App" in _out(capsys)


def test_strings_filter(capsys, apk):
    assert main(["strings", str(apk), "--match", "hello"]) == 0
    assert "Hello world" in _out(capsys)


def test_align(capsys, apk, tmp_path):
    out = tmp_path / "aligned.apk"
    assert main(["align", str(apk), "-o", str(out)]) == 0
    assert "misaligned entries: 0" in _out(capsys)


def test_remove_permission(capsys, apk, tmp_path):
    out = tmp_path / "noperm.apk"
    assert main(["remove-permission", str(apk), "-o", str(out), "-p", "android.permission.CAMERA"]) == 0
    from apkmod.apk import ApkContainer

    with ApkContainer(out) as container:
        assert container.manifest_axml().permissions() == ["android.permission.INTERNET"]
    assert "removed 1 x android.permission.CAMERA" in _out(capsys)


def test_add_permission(capsys, apk, tmp_path):
    out = tmp_path / "perm.apk"
    assert main(["add-permission", str(apk), "-o", str(out), "-p", "android.permission.VIBRATE"]) == 0
    assert "added android.permission.VIBRATE" in _out(capsys)


def test_replace_string(capsys, apk, tmp_path):
    out = tmp_path / "renamed.apk"
    assert main(["replace-string", str(apk), "-o", str(out), "--old", "Demo App", "--new", "Modded App"]) == 0
    from apkmod.arsc import ArscFile
    from apkmod.apk import ApkContainer

    with ApkContainer(out) as container:
        assert ArscFile.parse(container.read("resources.arsc")).app_label() == "Modded App"


def test_replace_string_needs_a_target(capsys, apk, tmp_path):
    assert main(["replace-string", str(apk), "-o", str(tmp_path / "x.apk"), "--new", "x"]) == 2
    assert "error:" in capsys.readouterr().err


def test_replace_file(capsys, apk, tmp_path):
    source = tmp_path / "config.json"
    source.write_bytes(b'{"ads":false}')
    out = tmp_path / "noads.apk"
    assert main(["replace-file", str(apk), "-o", str(out), "--entry", "assets/config.json", "--file", str(source)]) == 0
    assert zipfile.ZipFile(out).read("assets/config.json") == b'{"ads":false}'


def test_add_and_remove_entry(capsys, apk, tmp_path):
    source = tmp_path / "extra.txt"
    source.write_bytes(b"hello")
    out = tmp_path / "with-extra.apk"
    assert main(["replace-file", str(apk), "-o", str(out), "--entry", "assets/extra.txt", "--file", str(source), "--add"]) == 0
    assert "assets/extra.txt" in zipfile.ZipFile(out).namelist()

    slim = tmp_path / "slim.apk"
    assert main(["remove-entry", str(out), "-o", str(slim), "--entry", "assets/extra.txt"]) == 0
    assert "assets/extra.txt" not in zipfile.ZipFile(slim).namelist()


def test_analyze(capsys, apk):
    assert main(["analyze", str(apk)]) == 0
    assert "AppsFlyer" in _out(capsys)


def test_analyze_json(capsys, apk):
    assert main(["analyze", str(apk), "--json"]) == 0
    assert "com.example.demo" in json.loads(_out(capsys))["manifest"]["package"]


def test_scan(capsys, apk):
    assert main(["scan", str(apk)]) == 0
    assert "Tamper surface" in _out(capsys)


def test_decode_without_apktool_is_explained(capsys, apk, tmp_path):
    code = main(["decode", str(apk), "-o", str(tmp_path / "out")])
    assert code == 2
    assert "apktool" in capsys.readouterr().err


def test_smali_search_and_replace(tmp_path, capsys):
    project = tmp_path / "project" / "smali_classes" / "com" / "example"
    project.mkdir(parents=True)
    (project / "Check.smali").write_text(
        ".class public Lcom/example/Check;\n"
        "    const-string v0, \"GET_SIGNATURES\"\n"
        "    invoke-virtual {v0}, Ljava/lang/String;->length()I\n"
        "    invoke-virtual {p1, p2, v0}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\n",
        encoding="utf-8",
    )
    root = tmp_path / "project"
    assert main(["smali-search", str(root), "GET_SIGNATURES"]) == 0
    assert "Check.smali:2" in _out(capsys)

    assert main(["smali-replace", str(root), "GET_SIGNATURES", "GET_NOTHING"]) == 0
    assert "dry run" in _out(capsys)
    assert "GET_SIGNATURES" in (project / "Check.smali").read_text()

    assert main(["smali-replace", str(root), "GET_SIGNATURES", "GET_NOTHING", "--apply"]) == 0
    assert "GET_NOTHING" in (project / "Check.smali").read_text()

    capsys.readouterr()  # clear the buffer so only the JSON is captured
    assert main(["findings", str(root), "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert "reads PackageInfo signatures" in payload


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_sign_and_verify(capsys, apk, tmp_path, signing_material):
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    key_path.write_bytes(signing_material[0])
    cert_path.write_bytes(signing_material[1])
    signed = tmp_path / "signed.apk"

    assert main(["sign", str(apk), "-o", str(signed), "--key", str(key_path), "--cert", str(cert_path)]) == 0
    assert "verify  : OK" in _out(capsys)

    assert main(["verify", str(signed)]) == 0
    assert "signature ok : True" in _out(capsys)


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_edit_then_sign_flag(capsys, apk, tmp_path, signing_material):
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    key_path.write_bytes(signing_material[0])
    cert_path.write_bytes(signing_material[1])
    out = tmp_path / "edited-signed.apk"

    assert main(
        [
            "remove-permission", str(apk), "-o", str(out),
            "-p", "android.permission.CAMERA",
            "--sign", "--key", str(key_path), "--cert", str(cert_path),
        ]
    ) == 0
    out_text = _out(capsys)
    assert "signed with a v1 (JAR) signature" in out_text
    # we signed it, so nagging about a broken signature would be wrong
    assert "re-sign before installing" not in out_text
    # and -o is the final signed artifact, not a leftover unsigned twin
    assert main(["verify", str(out)]) == 0
    assert not (tmp_path / "edited-signed-signed.apk").exists()


def test_unsigned_edit_warns_to_resign(capsys, apk, tmp_path):
    out = tmp_path / "edited.apk"
    assert main(["remove-permission", str(apk), "-o", str(out), "-p", "android.permission.CAMERA"]) == 0
    assert "re-sign before installing" in _out(capsys)


def test_keep_signature_flag_silences_the_warning(capsys, apk, tmp_path):
    out = tmp_path / "edited.apk"
    assert main(
        ["remove-permission", str(apk), "-o", str(out), "-p", "android.permission.CAMERA", "--keep-signature"]
    ) == 0
    assert "re-sign before installing" not in _out(capsys)


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_genkey(capsys, tmp_path):
    assert main(["genkey", "-o", str(tmp_path / "keys"), "--cn", "CLI Test"]) == 0
    assert (tmp_path / "keys" / "apkmod-key.pem").is_file()
    assert (tmp_path / "keys" / "apkmod-cert.pem").is_file()


def test_verify_unsigned_apk(capsys, apk):
    assert main(["verify", str(apk)]) == 1
    assert "v1 signature : ABSENT" in _out(capsys)


def test_missing_file_is_a_clean_error(capsys, tmp_path):
    assert main(["info", str(tmp_path / "nope.apk")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_adb_commands_without_a_device(capsys, apk, monkeypatch):
    monkeypatch.setattr("apkmod.engines.apktoolm.find_adb", lambda: None)
    assert main(["adb-push", str(apk)]) == 2
    assert "adb is not available" in capsys.readouterr().err
