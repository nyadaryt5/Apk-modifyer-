"""A small local web UI over the same engines the CLI uses.

Deliberately dependency-free (``http.server`` + one HTML page) so it runs on a
phone under Termux as happily as on a workstation. Everything is addressed by
relative URLs, so it also works behind a proxy or a port forward.
"""

from __future__ import annotations

import json
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from ..align import align
from ..analyze import analyze_apk
from ..apk import ApkContainer
from ..asn1 import ApkModError
from ..engines import registry
from ..engines.aee import NativeEditor
from ..engines.patcher import PatcherEngine
from ..signing import generate_key, sign_v1
from ..util import work_dir

__all__ = ["serve", "build_handler", "Store"]

UPLOAD_DIRNAME = "uploads"


class Store:
    """Tiny id -> file store, so the browser never handles absolute paths."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else work_dir() / UPLOAD_DIRNAME
        self.root.mkdir(parents=True, exist_ok=True)
        self.meta: Dict[str, dict] = {}

    def put(self, data: bytes, name: str) -> str:
        file_id = uuid.uuid4().hex[:12]
        (self.root / f"{file_id}.apk").write_bytes(data)
        self.meta[file_id] = {"name": name, "size": len(data)}
        return file_id

    def path(self, file_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{6,32}", file_id or ""):
            raise ApkModError("bad file id")
        path = self.root / f"{file_id}.apk"
        if not path.is_file():
            raise ApkModError(f"unknown file id: {file_id}")
        return path

    def name(self, file_id: str) -> str:
        return self.meta.get(file_id, {}).get("name", f"{file_id}.apk")


def _multipart(body: bytes, boundary: str) -> Dict[str, Tuple[Optional[str], bytes]]:
    parts: Dict[str, Tuple[Optional[str], bytes]] = {}
    for chunk in body.split(b"--" + boundary.encode()):
        chunk = chunk.strip(b"\r\n")
        if not chunk or chunk == b"--":
            continue
        head, _, content = chunk.partition(b"\r\n\r\n")
        headers = head.decode("utf-8", "replace")
        name = re.search(r'name="([^"]+)"', headers)
        if not name:
            continue
        filename = re.search(r'filename="([^"]*)"', headers)
        parts[name.group(1)] = (filename.group(1) if filename else None, content)
    return parts


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APK Modifyer</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e6e9ef;--mut:#8b93a7;--acc:#5eead4;--warn:#fbbf24;--bad:#f87171}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}
header{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:center;flex-wrap:wrap}
h1{font-size:17px;margin:0;letter-spacing:.3px}h1 span{color:var(--acc)}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-left:auto}
.chip{border:1px solid var(--line);border-radius:999px;padding:4px 10px;font-size:12px;color:var(--mut)}
.chip b{color:var(--fg);font-weight:600}.chip.on{border-color:#1f5c50}.chip.on b{color:var(--acc)}
main{padding:20px 22px;max-width:1080px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.card h2{font-size:13px;margin:0 0 10px;color:var(--mut);text-transform:uppercase;letter-spacing:.08em}
button,input,select{font:inherit;background:#0e1117;border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:8px 10px}
button{cursor:pointer}button:hover{border-color:var(--acc)}
button.primary{background:#123c34;border-color:#1f5c50;color:var(--acc)}
input[type=file]{padding:6px}
label{display:block;color:var(--mut);font-size:12px;margin:0 0 4px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
pre{background:#0b0e13;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;max-height:420px;margin:0;font-size:12.5px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px}
.tag{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:1px 7px;margin:2px 4px 2px 0;font-size:12px}
.warn{color:var(--warn)}.bad{color:var(--bad)}.ok{color:var(--acc)}
.note{color:var(--mut);font-size:12.5px}
a{color:var(--acc)}
.hidden{display:none}
</style></head>
<body>
<header>
  <h1>APK <span>Modifyer</span></h1>
  <div class="note">decode &middot; edit in place &middot; rebuild &middot; sign &middot; analyse</div>
  <div class="chips" id="chips"></div>
</header>
<main>
  <div class="card">
    <h2>1 &middot; Load an APK</h2>
    <div class="row">
      <div><label>apk file</label><input type="file" id="file" accept=".apk,.apks,.xapk"></div>
      <button class="primary" id="upload">Analyse</button>
      <div class="note" id="upload-state"></div>
    </div>
  </div>

  <div class="card hidden" id="summary">
    <h2>2 &middot; Summary</h2>
    <div id="summary-body"></div>
  </div>

  <div class="card hidden" id="tools">
    <h2>3 &middot; Edit</h2>
    <div class="row">
      <div style="min-width:260px"><label>permission to remove (comma separated)</label>
        <input id="perm" placeholder="android.permission.CAMERA" style="width:100%"></div>
      <button id="rm-perm">Remove permission</button>
      <div><label>new permission</label><input id="perm-add" placeholder="android.permission.VIBRATE"></div>
      <button id="add-perm">Add permission</button>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>resource string (exact)</label><input id="str-old"></div>
      <div><label>replace with</label><input id="str-new"></div>
      <button id="str-rep">Replace string</button>
      <button id="debug-on">Set debuggable</button>
      <button id="align">Re-align</button>
      <button id="sign">Sign (v1, new key)</button>
    </div>
    <div class="row" style="margin-top:10px">
      <label style="align-self:center"><input type="checkbox" id="auto-sign" checked> re-sign after each edit</label>
    </div>
    <div id="edit-out" class="note" style="margin-top:10px"></div>
  </div>

  <div class="card hidden" id="reports">
    <h2>4 &middot; Reports</h2>
    <div class="row" style="margin-bottom:10px">
      <button data-tab="analysis">Static analysis</button>
      <button data-tab="scan">Protection scan</button>
      <button data-tab="manifest">Manifest XML</button>
      <button data-tab="strings">Resource strings</button>
    </div>
    <pre id="report">pick a report</pre>
  </div>

  <div class="card">
    <h2>Notice</h2>
    <div class="note">For apps you own or are authorised to inspect. This tool reports protections &mdash;
    it does not defeat licence checks, payment gates or server-side entitlements.</div>
  </div>
</main>
<script>
let current=null;
const $=s=>document.querySelector(s);
async function j(url,opts){const r=await fetch(url,opts);const t=await r.text();try{return JSON.parse(t)}catch(e){if(!r.ok)throw new Error(t);return t}}
async function doctor(){
  const d=await j('/api/doctor');
  $('#chips').innerHTML=d.map(e=>`<div class="chip ${e.available?'on':''}"><b>${e.name}</b> ${e.available?'ready':'absent'}</div>`).join('');
}
function show(id){$(id).classList.remove('hidden')}
function rows(pairs){return '<table>'+pairs.map(([k,v])=>`<tr><th>${k}</th><td>${v}</td></tr>`).join('')+'</table>'}
async function load(id){
  current=id;
  const f=await j('/api/apk/'+id);const m=f.manifest||{};const s=f.signing||{};
  $('#summary-body').innerHTML=rows([
    ['file',f.name+' ('+Math.round(f.file_size/1024)+' KiB, '+f.entry_count+' entries)'],
    ['package',m.package||'-'],['version',(m.version_name||'-')+' ('+(m.version_code||'-')+')'],
    ['sdk','min '+(m.min_sdk||'-')+' / target '+(m.target_sdk||'-')],
    ['dex',(f.dex_files||[]).length+' file(s)'],['native',Object.keys(f.native_libraries||{}).join(', ')||'none'],
    ['signing',`v1 ${s.v1_jar_signing?'yes':'no'} &middot; v2 ${s.v2?'yes':'no'} &middot; v3 ${s.v3?'yes':'no'}`],
    ['permissions',(m.permissions||[]).map(p=>`<span class="tag">${p}</span>`).join('')||'none'],
    ['components',(m.activities||[]).length+' activities, '+(m.services||[]).length+' services, '+(m.receivers||[]).length+' receivers'],
    ['launcher',m.launcher_activity||'-'],['debuggable',String(m.debuggable)]
  ]);
  ['#summary','#tools','#reports'].forEach(show);
  $('#report').textContent='pick a report';
}
$('#upload').onclick=async()=>{
  const inp=$('#file');if(!inp.files.length){$('#upload-state').textContent='choose a file first';return}
  const fd=new FormData();fd.append('apk',inp.files[0]);
  $('#upload-state').textContent='working...';
  try{const r=await j('/api/upload',{method:'POST',body:fd});$('#upload-state').textContent='loaded '+r.id;await load(r.id)}
  catch(e){$('#upload-state').innerHTML='<span class=bad>'+e.message+'</span>'}
};
async function action(body){
  if(!current)return;
  $('#edit-out').textContent='working...';
  try{
    const r=await j('/api/apk/'+current+'/action',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    $('#edit-out').innerHTML=r.notes.map(n=>'<div>- '+n+'</div>').join('')+
      `<div>output: <a href="/api/download/${r.id}">${r.name}</a></div>`;
    if(body.keep)current=r.id; else current=r.id;
    await load(current);
  }catch(e){$('#edit-out').innerHTML='<span class=bad>'+e.message+'</span>'}
}
$('#rm-perm').onclick=()=>action({action:'remove-permission',permissions:$('#perm').value.split(',').map(s=>s.trim()).filter(Boolean),sign:$('#auto-sign').checked});
$('#add-perm').onclick=()=>action({action:'add-permission',permission:$('#perm-add').value.trim(),sign:$('#auto-sign').checked});
$('#str-rep').onclick=()=>action({action:'replace-string',old:$('#str-old').value,new:$('#str-new').value,sign:$('#auto-sign').checked});
$('#debug-on').onclick=()=>action({action:'set-debuggable',enabled:true,sign:$('#auto-sign').checked});
$('#align').onclick=()=>action({action:'align'});
$('#sign').onclick=()=>action({action:'sign'});
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=async()=>{
  if(!current)return;$('#report').textContent='loading...';
  try{
    if(b.dataset.tab==='analysis')$('#report').textContent=await (await fetch('/api/apk/'+current+'/analyze')).text();
    if(b.dataset.tab==='scan')$('#report').textContent=await (await fetch('/api/apk/'+current+'/scan')).text();
    if(b.dataset.tab==='manifest')$('#report').textContent=await (await fetch('/api/apk/'+current+'/manifest?xml=1')).text();
    if(b.dataset.tab==='strings'){
      const s=await j('/api/apk/'+current+'/strings');
      $('#report').textContent=s.strings.slice(0,600).map(x=>String(x.index).padStart(5)+'  '+x.value).join('\\n');
    }
  }catch(e){$('#report').textContent=e.message}
});
doctor();
</script></body></html>
"""


def build_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "apkmod"
        protocol_version = "HTTP/1.1"

        # -- plumbing ----------------------------------------------------
        def log_message(self, fmt, *args):  # quieter, but still visible
            print(f"[ui] {self.address_string()} {fmt % args}")

        def _send(self, body: bytes, ctype: str = "application/json", code: int = 200, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload, code: int = 200):
            self._send(json.dumps(payload, indent=2, default=str).encode(), code=code)

        def _text(self, text: str, code: int = 200):
            self._send(text.encode(), ctype="text/plain; charset=utf-8", code=code)

        def _error(self, exc: Exception, code: int = 400):
            self._json({"error": str(exc)}, code=code)

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        # -- routes ------------------------------------------------------
        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)
            try:
                if path == "/":
                    return self._send(PAGE.encode(), ctype="text/html; charset=utf-8")
                if path == "/api/doctor":
                    return self._json([s.as_dict() for s in registry.statuses()])
                parts = [p for p in path.split("/") if p]
                if parts[:2] == ["api", "apk"] and len(parts) >= 3:
                    file_id = parts[2]
                    target = parts[3] if len(parts) > 3 else "info"
                    apk = store.path(file_id)
                    if target == "info":
                        with ApkContainer(apk) as container:
                            facts = container.facts()
                        facts["name"] = store.name(file_id)
                        facts["id"] = file_id
                        return self._json(facts)
                    if target == "manifest":
                        xml = NativeEditor().manifest_xml(apk)
                        if query.get("xml"):
                            return self._text(xml)
                        return self._json({"xml": xml, "facts": NativeEditor().manifest_facts(apk)})
                    if target == "strings":
                        match = (query.get("match") or [""])[0].lower()
                        entries = NativeEditor().strings(apk)
                        if match:
                            entries = [e for e in entries if match in e[1].lower()]
                        return self._json(
                            {"count": len(entries), "strings": [{"index": i, "value": v, "used_by": u} for i, v, u in entries[:2000]]}
                        )
                    if target == "analyze":
                        return self._text(analyze_apk(apk).as_markdown())
                    if target == "scan":
                        return self._text(PatcherEngine().scan(apk).as_text())
                    if target == "verify":
                        from ..signing import verify_v1

                        return self._json(verify_v1(apk).__dict__)
                if parts[:2] == ["api", "download"] and len(parts) == 3:
                    apk = store.path(parts[2])
                    name = store.name(parts[2])
                    return self._send(
                        apk.read_bytes(),
                        ctype="application/vnd.android.package-archive",
                        extra={"Content-Disposition": f'attachment; filename="{name}"'},
                    )
                return self._json({"error": f"no route for {path}"}, code=404)
            except ApkModError as exc:
                return self._error(exc)
            except Exception as exc:  # keep the server alive on bad input
                return self._error(exc, code=500)

        def do_POST(self):
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            try:
                if parts == ["api", "upload"]:
                    ctype = self.headers.get("Content-Type", "")
                    match = re.search(r"boundary=(.+)", ctype)
                    if not match:
                        raise ApkModError("expected a multipart/form-data upload")
                    files = _multipart(self._body(), match.group(1).strip('"'))
                    if "apk" not in files:
                        raise ApkModError("upload field must be named 'apk'")
                    filename, data = files["apk"]
                    if not data:
                        raise ApkModError("empty upload")
                    file_id = store.put(data, filename or "upload.apk")
                    with ApkContainer(store.path(file_id)) as container:
                        facts = container.facts()
                    return self._json({"id": file_id, "name": filename, "manifest": facts.get("manifest", {})})
                if parts[:2] == ["api", "apk"] and len(parts) == 4 and parts[3] == "action":
                    file_id = parts[2]
                    payload = json.loads(self._body() or b"{}")
                    return self._json(self._action(store.path(file_id), store.name(file_id), payload, store))
                return self._json({"error": f"no route for {parsed.path}"}, code=404)
            except ApkModError as exc:
                return self._error(exc)
            except json.JSONDecodeError as exc:
                return self._error(exc)
            except Exception as exc:
                return self._error(exc, code=500)

        # -- actions -----------------------------------------------------
        def _action(self, apk: Path, name: str, payload: dict, store: Store) -> dict:
            action = payload.get("action")
            editor = NativeEditor()
            notes: list[str] = []
            stem = Path(name).stem

            if action == "remove-permission":
                permissions = payload.get("permissions") or []
                if not permissions:
                    raise ApkModError("no permissions given")
                out = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                result = editor.remove_permissions(apk, out, permissions)
                notes += result.notes
            elif action == "add-permission":
                permission = payload.get("permission")
                if not permission:
                    raise ApkModError("no permission given")
                out = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                result = editor.add_permission(apk, out, permission)
                notes += result.notes
            elif action == "replace-string":
                old, new = payload.get("old"), payload.get("new")
                if new is None:
                    raise ApkModError("no replacement string given")
                out = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                result = editor.replace_string(apk, out, old or "", new)
                notes += result.notes
            elif action == "set-debuggable":
                out = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                result = editor.set_debuggable(apk, out, bool(payload.get("enabled", True)))
                notes += result.notes
            elif action == "align":
                out = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                align(apk, out)
                notes.append("re-aligned (4-byte, .so page-aligned)")
            elif action == "sign":
                key_dir = store.root / "keys"
                key, cert = generate_key(key_dir, common_name="APK Modifyer UI")
                out = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                signed = sign_v1(apk, out, key.read_bytes(), cert.read_bytes())
                notes.append(f"v1 signed {signed.signed_entries} entries ({signed.subject})")
            else:
                raise ApkModError(f"unknown action '{action}'")

            data = out.read_bytes()
            out.unlink(missing_ok=True)
            new_name = f"{stem}-{'signed' if payload.get('sign') and action != 'sign' else action}.apk"
            new_id = store.put(data, new_name)

            if payload.get("sign") and action != "sign":
                key_dir = store.root / "keys"
                key = key_dir / "apkmod-key.pem"
                cert = key_dir / "apkmod-cert.pem"
                if not key.is_file():
                    key, cert = generate_key(key_dir)
                signed_path = store.root / f"tmp-{uuid.uuid4().hex[:8]}.apk"
                signed = sign_v1(store.path(new_id), signed_path, key.read_bytes(), cert.read_bytes())
                data = signed_path.read_bytes()
                signed_path.unlink(missing_ok=True)
                new_id = store.put(data, f"{stem}-{action}-signed.apk")
                notes.append(f"re-signed with a v1 signature ({signed.subject})")
            else:
                notes.append("not re-signed - install will fail until you sign it")

            return {"id": new_id, "name": store.name(new_id), "notes": notes, "size": len(data)}

    return Handler


def serve(host: str = "0.0.0.0", port: int = 8080, store: Optional[Store] = None) -> int:
    store = store or Store()
    handler = build_handler(store)
    httpd = ThreadingHTTPServer((host, port), handler)
    shown_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
    print(f"APK Modifyer UI on http://{shown_host}:{port}  (uploads in {store.root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
