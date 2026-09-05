"""End-to-end CLI runs."""

from __future__ import annotations

import json
import shutil
import zipfile

import pytest

from apkmod.cli import main
from apkmod.engines import registry as engine_registry

OPENSSL = shutil.which("openssl")

# The full adapter set. Asserted against the registry rather than hardcoded
# twice, so adding an engine updates the expectation in one place.
ENGINE_NAMES = engine_registry.names


def _out(capsys) -> str:
    return capsys.readouterr().out


def test_doctor(capsys):
    assert main(["doctor"]) == 0
    out = _out(capsys)
    for engine in ENGINE_NAMES:
        assert engine in out
    assert "ready:" in out


def test_doctor_json(capsys):
    assert main(["doctor", "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert [e["name"] for e in payload] == ENGINE_NAMES


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


def test_replace_string_by_resource_name(capsys, apk, tmp_path):
    """Rename the app without knowing its current value."""
    from apkmod.apk import ApkContainer
    from apkmod.arsc import ArscFile

    out = tmp_path / "renamed.apk"
    assert main(["replace-string", str(apk), "-o", str(out), "--res-name", "app_name", "--new", "My App"]) == 0
    assert "string/app_name: 'Demo App' -> 'My App'" in _out(capsys)
    with ApkContainer(out) as container:
        assert ArscFile.parse(container.read("resources.arsc")).app_label() == "My App"


def test_replace_string_by_qualified_resource_name(capsys, apk, tmp_path):
    out = tmp_path / "renamed.apk"
    assert main(["replace-string", str(apk), "-o", str(out), "--res-name", "string/greeting", "--new", "Yo"]) == 0
    assert "string/greeting: 'Hello world' -> 'Yo'" in _out(capsys)


def test_replace_string_unknown_resource_lists_alternatives(capsys, apk, tmp_path):
    code = main(["replace-string", str(apk), "-o", str(tmp_path / "x.apk"), "--res-name", "nope", "--new", "x"])
    assert code == 2
    err = capsys.readouterr().err
    assert "no string/nope string resource" in err
    assert "string/app_name" in err  # it tells you what does exist


def test_replace_string_rejects_two_targets(capsys, apk, tmp_path):
    code = main(
        ["replace-string", str(apk), "-o", str(tmp_path / "x.apk"),
         "--res-name", "app_name", "--old", "Demo App", "--new", "x"]
    )
    assert code == 2
    assert "pick exactly one target" in capsys.readouterr().err


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


def test_signers_command(capsys):
    assert main(["signers"]) == 0
    out = _out(capsys)
    assert "apksigner" in out and "uber-apk-signer" in out
    assert "native (pure Python)" in out


def test_signers_json(capsys):
    assert main(["signers", "--json"]) == 0
    names = [s["name"] for s in json.loads(_out(capsys))]
    assert "apksigner" in names


def test_sign_reports_engine_and_schemes(capsys, apk, tmp_path, signing_material):
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    key_path.write_bytes(signing_material[0])
    cert_path.write_bytes(signing_material[1])
    assert main(
        ["sign", str(apk), "-o", str(tmp_path / "s.apk"),
         "--engine", "native", "--key", str(key_path), "--cert", str(cert_path)]
    ) == 0
    out = _out(capsys)
    assert "engine  : native" in out
    assert "schemes : v1" in out
    assert "Android 11+ also wants v2/v3" in out


def test_sign_needs_material(capsys, apk, tmp_path):
    assert main(["sign", str(apk), "-o", str(tmp_path / "s.apk")]) == 2
    assert "provide --key/--cert" in capsys.readouterr().err


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


# ==========================================================================
# the engines added alongside the AI layer
# ==========================================================================
def _modified_apk(apk, tmp_path):
    """A copy with one changed entry and one removed, for diff tests."""
    from apkmod.align import repack
    from apkmod.apk import ApkContainer
    from apkmod.arsc import ArscFile

    with ApkContainer(apk) as container:
        arsc = ArscFile.parse(container.arsc_bytes())
        arsc.replace_by_name("app_name", "Modified")
        payload = arsc.serialize()
    out = tmp_path / "changed.apk"
    repack(apk, out, replace={"resources.arsc": payload}, exclude=["res/raw/keep.txt"])
    return out


def test_diff(capsys, apk, tmp_path):
    changed = _modified_apk(apk, tmp_path)
    assert main(["diff", str(apk), str(changed)]) == 0
    out = _out(capsys)
    assert "- res/raw/keep.txt" in out
    assert "~ resources.arsc" in out


def test_diff_json(capsys, apk, tmp_path):
    changed = _modified_apk(apk, tmp_path)
    assert main(["diff", str(apk), str(changed), "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert payload["counts"]["removed"] == 1
    assert payload["counts"]["changed"] == 1
    assert payload["counts"]["identical"] == 4


def test_diff_all_includes_unchanged(capsys, apk, tmp_path):
    changed = _modified_apk(apk, tmp_path)
    assert main(["diff", str(apk), str(changed), "--all"]) == 0
    assert "AndroidManifest.xml" in _out(capsys)


def test_bundle_round_trip(capsys, apk, tmp_path):
    bundle = tmp_path / "app.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.write(apk, "base.apk")
        zf.write(apk, "config.arm64_v8a.apk")
        zf.writestr("manifest.json", "{}")

    assert main(["bundle-unpack", str(bundle), "--out", str(tmp_path / "u")]) == 0
    out = _out(capsys)
    assert "2 APK(s)" in out
    assert "[base ] base.apk" in out

    rebuilt = tmp_path / "rebuilt.xapk"
    assert main(["bundle-pack", str(tmp_path / "u"), "--out", str(rebuilt)]) == 0
    with zipfile.ZipFile(rebuilt) as zf:
        names = zf.namelist()
    assert len(names) == len(set(names)) == 3


def test_bundle_unpack_json(capsys, apk, tmp_path):
    bundle = tmp_path / "app.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.write(apk, "base.apk")
        zf.writestr("manifest.json", "{}")
    assert main(["bundle-unpack", str(bundle), "--out", str(tmp_path / "u"), "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert payload["parts"][0]["is_base"] is True
    assert payload["other_files"] == ["manifest.json"]


def test_platform(capsys):
    assert main(["platform"]) == 0
    out = _out(capsys)
    assert "root:" in out
    assert "present:" in out


def test_platform_json(capsys):
    assert main(["platform", "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert payload["family"] in ("desktop", "android", "other")
    assert "openssl" in payload["binaries"]


def test_ai_doctor_with_nothing_configured(capsys, monkeypatch, tmp_path):
    for var in ("APKMOD_AI_CONFIG", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY", "OPENROUTER_API_KEY", "APKMOD_AI_KEYS",
                "GROQ_API_KEY", "DEEPSEEK_API_KEY", "MISTRAL_API_KEY",
                "XAI_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)

    assert main(["ai-doctor"]) == 0
    out = _out(capsys)
    assert "no provider configured" in out
    assert "OPENAI_API_KEY" in out  # tells the user what to do next


def test_ai_doctor_shows_providers_without_leaking_keys(capsys, tmp_path):
    config = tmp_path / "ai.json"
    config.write_text(
        json.dumps(
            {
                "default_model": "gpt-x",
                "providers": [
                    {"name": "primary", "keys": ["sk-super-secret-value"], "models": ["gpt-x"]}
                ],
            }
        )
    )
    assert main(["ai-doctor", "--config", str(config)]) == 0
    out = _out(capsys)
    assert "primary" in out
    assert "sk-super-secret-value" not in out
    assert "1 provider(s) usable" in out


def test_ai_doctor_json(capsys, tmp_path):
    config = tmp_path / "ai.json"
    config.write_text(json.dumps({"providers": [{"name": "p", "keys": ["k"], "models": ["m"]}]}))
    assert main(["ai-doctor", "--config", str(config), "--json"]) == 0
    payload = json.loads(_out(capsys))
    assert payload["usable_providers"] == ["p"]
    assert payload["routing"]["strategy"] == "priority"


def test_ai_without_a_provider_is_a_clean_error(capsys, monkeypatch, tmp_path):
    for var in ("APKMOD_AI_CONFIG", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY", "OPENROUTER_API_KEY", "APKMOD_AI_KEYS",
                "GROQ_API_KEY", "DEEPSEEK_API_KEY", "MISTRAL_API_KEY",
                "XAI_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)

    # Not a traceback and not a hang: exit 2 with a message.
    assert main(["ai", "rename the app"]) == 2


def test_ai_rejects_a_missing_apk(capsys, tmp_path):
    assert main(["ai", "do something", "--apk", str(tmp_path / "absent.apk")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_decompile_java_without_jadx_is_a_clean_error(capsys, apk, tmp_path, monkeypatch):
    monkeypatch.setattr("apkmod.engines.jadx.find_jadx", lambda explicit=None: None)
    assert main(["decompile-java", str(apk), "--out", str(tmp_path / "java")]) == 2
    assert "jadx is not installed" in capsys.readouterr().err


def test_frida_ps_without_frida_is_a_clean_error(capsys, monkeypatch):
    monkeypatch.setattr("apkmod.engines.frida.find_frida_ps", lambda: None)
    assert main(["frida-ps"]) == 2
    assert "frida-ps is not installed" in capsys.readouterr().err


def test_frida_run_requires_a_target(capsys, tmp_path):
    script = tmp_path / "hook.js"
    script.write_text("console.log(1)")
    with pytest.raises(SystemExit):
        main(["frida-run", "--script", str(script)])  # neither --package nor --pid
