"""The local web UI, driven over real HTTP."""

from __future__ import annotations

import io
import json
import shutil
import threading
import uuid
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib import request

import pytest

from apkmod.server.app import Store, build_handler


@pytest.fixture
def server(tmp_path):
    store = Store(tmp_path / "uploads")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(store))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", store
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _get(url: str):
    with request.urlopen(url, timeout=20) as response:
        return response.status, response.read()


def _post_json(url: str, payload: dict):
    body = json.dumps(payload).encode()
    req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req, timeout=30) as response:
        return response.status, json.loads(response.read())


def _upload(url: str, apk: Path):
    boundary = uuid.uuid4().hex
    payload = io.BytesIO()
    payload.write(f"--{boundary}\r\n".encode())
    payload.write(b'Content-Disposition: form-data; name="apk"; filename="demo.apk"\r\n')
    payload.write(b"Content-Type: application/octet-stream\r\n\r\n")
    payload.write(apk.read_bytes())
    payload.write(f"\r\n--{boundary}--\r\n".encode())
    req = request.Request(
        url,
        data=payload.getvalue(),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())


def test_index_page(server):
    status, body = _get(server[0] + "/")
    assert status == 200
    assert b"APK" in body and b"<html" in body
    assert b"http://localhost" not in body  # relative URLs only


def test_doctor_endpoint(server):
    status, body = _get(server[0] + "/api/doctor")
    assert status == 200
    names = [e["name"] for e in json.loads(body)]
    assert names == [
        "apktool",
        "apktool-m",
        "aee",
        "patcher",
        "jadx",
        "frida",
        "mtmanager",
    ]


def test_upload_then_inspect(server, apk):
    base, _store = server
    uploaded = _upload(base + "/api/upload", apk)
    assert uploaded["manifest"]["package"] == "com.example.demo"
    file_id = uploaded["id"]

    status, body = _get(f"{base}/api/apk/{file_id}")
    assert status == 200
    info = json.loads(body)
    assert info["entry_count"] == 6
    assert info["name"] == "demo.apk"

    status, xml = _get(f"{base}/api/apk/{file_id}/manifest?xml=1")
    assert b"<manifest" in xml

    status, body = _get(f"{base}/api/apk/{file_id}/strings?match=demo")
    assert json.loads(body)["count"] >= 1

    status, body = _get(f"{base}/api/apk/{file_id}/analyze")
    assert b"AppsFlyer" in body

    status, body = _get(f"{base}/api/apk/{file_id}/scan")
    assert b"Tamper surface" in body


def test_action_edits_and_downloads(server, apk):
    base, _store = server
    file_id = _upload(base + "/api/upload", apk)["id"]

    status, result = _post_json(
        f"{base}/api/apk/{file_id}/action",
        {"action": "remove-permission", "permissions": ["android.permission.CAMERA"]},
    )
    assert status == 200
    assert any("removed 1 x android.permission.CAMERA" in n for n in result["notes"])

    status, data = _get(f"{base}/api/download/{result['id']}")
    assert status == 200
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert "AndroidManifest.xml" in zf.namelist()
    # the download must still be a valid, aligned APK
    from apkmod.align import verify_alignment

    tmp = Path(_store.root) / "downloaded.apk"
    tmp.write_bytes(data)
    assert verify_alignment(tmp) == []


def test_action_replace_string(server, apk):
    base, _store = server
    file_id = _upload(base + "/api/upload", apk)["id"]
    status, result = _post_json(
        f"{base}/api/apk/{file_id}/action",
        {"action": "replace-string", "old": "Demo App", "new": "UI App"},
    )
    assert status == 200
    from apkmod.apk import ApkContainer
    from apkmod.arsc import ArscFile

    with ApkContainer(_store.path(result["id"])) as container:
        assert ArscFile.parse(container.read("resources.arsc")).app_label() == "UI App"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_sign_action(server, apk, tmp_path):
    """The UI's Sign button must produce a signature that actually verifies."""
    from apkmod.signing import verify_v1

    base, store = server
    file_id = _upload(base + "/api/upload", apk)["id"]

    status, result = _post_json(f"{base}/api/apk/{file_id}/action", {"action": "sign"})
    assert status == 200
    assert any("signed with native" in n for n in result["notes"]), result["notes"]
    # a sign action must not also claim the file was left unsigned
    assert not any("not re-signed" in n for n in result["notes"]), result["notes"]

    downloaded = tmp_path / "ui-signed.apk"
    status, data = _get(f"{base}/api/download/{result['id']}")
    downloaded.write_bytes(data)
    check = verify_v1(downloaded)
    assert check.ok is True, check.problems
    assert check.subject == "APK Modifyer UI"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_edit_with_autosign(server, apk, tmp_path):
    """An edit plus sign:true must leave a verifiable signature behind."""
    from apkmod.signing import verify_v1

    base, store = server
    file_id = _upload(base + "/api/upload", apk)["id"]

    status, result = _post_json(
        f"{base}/api/apk/{file_id}/action",
        {"action": "set-debuggable", "enabled": True, "sign": True},
    )
    assert status == 200
    assert any("re-signed with" in n for n in result["notes"]), result["notes"]

    status, data = _get(f"{base}/api/download/{result['id']}")
    downloaded = tmp_path / "ui-debug-signed.apk"
    downloaded.write_bytes(data)
    assert verify_v1(downloaded).ok is True

    # and the manifest edit really took effect
    from apkmod.apk import ApkContainer

    with ApkContainer(downloaded) as container:
        assert container.manifest_axml().manifest_facts()["debuggable"] is True


def test_action_replace_string_by_resource_name(server, apk):
    """The UI's resource-name field renames the app without the old value."""
    base, store = server
    file_id = _upload(base + "/api/upload", apk)["id"]

    status, result = _post_json(
        f"{base}/api/apk/{file_id}/action",
        {"action": "replace-string", "res_name": "app_name", "new": "UI Renamed"},
    )
    assert status == 200
    assert any("string/app_name" in n for n in result["notes"]), result["notes"]

    from apkmod.apk import ApkContainer
    from apkmod.arsc import ArscFile

    with ApkContainer(store.path(result["id"])) as container:
        assert ArscFile.parse(container.read("resources.arsc")).app_label() == "UI Renamed"


def test_action_replace_string_needs_a_target(server, apk):
    base, _store = server
    file_id = _upload(base + "/api/upload", apk)["id"]
    req = request.Request(
        f"{base}/api/apk/{file_id}/action",
        data=json.dumps({"action": "replace-string", "new": "x"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(Exception) as excinfo:
        request.urlopen(req, timeout=20)
    assert "400" in str(excinfo.value)


def test_unknown_action_is_rejected(server, apk):
    base, _store = server
    file_id = _upload(base + "/api/upload", apk)["id"]
    req = request.Request(
        f"{base}/api/apk/{file_id}/action",
        data=json.dumps({"action": "rm-rf"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(Exception) as excinfo:
        request.urlopen(req, timeout=20)
    assert "400" in str(excinfo.value)


def test_bad_file_id_is_rejected(server):
    with pytest.raises(Exception) as excinfo:
        _get(server[0] + "/api/apk/../../etc/passwd")
    assert "40" in str(excinfo.value) or "50" in str(excinfo.value)


def test_unknown_route_is_404(server):
    with pytest.raises(Exception) as excinfo:
        _get(server[0] + "/api/nope")
    assert "404" in str(excinfo.value)
