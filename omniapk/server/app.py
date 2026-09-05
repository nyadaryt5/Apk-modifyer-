"""
OmniAPK Studio & AI Suite - FastAPI Web Server & REST / WebSocket API.
Serves responsive Desktop Linux & Mobile Android (Termux) Web Studio.
"""

import os
import shutil
import asyncio
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from omniapk.config import (
    BASE_DIR,
    WORKSPACE_DIR,
    UPLOAD_DIR,
    OUTPUT_DIR,
    DECOMPILE_DIR,
    SAMPLES_DIR,
    get_platform_info,
    AI_CONFIG_FILE
)
from omniapk.core.apk_packager import ApkPackager
from omniapk.core.apk_signer import ApkSigner
from omniapk.modules.apktool import ApktoolEngine
from omniapk.modules.apktool_m import ApktoolMEngine
from omniapk.modules.apk_editor import ApkResourceManager, PackageCloner
from omniapk.modules.lucky_patcher import LuckyPatcherEngine, AdRemover, BillingBypass, LicenseBypass
from omniapk.modules.jadx import JadxEngine
from omniapk.modules.frida import FridaScriptGenerator
from omniapk.modules.mt_manager import AntiSplitMerger, BatchRegexPatcher, ApkDiffer
from omniapk.modules.game_guardian import MemoryScanner, GameGuardianScriptBuilder
from omniapk.ai.router import AIRouter
from omniapk.ai.agent import OmniAgent
from omniapk.ai.tools import AIAgentTools

app = FastAPI(
    title="OmniAPK Studio & AI Engine",
    description="Unified Next-Gen APK Modding & Reverse Engineering Suite for Linux & Android",
    version="2.0.0"
)

# CORS configuration to allow local & proxy preview origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Instances
ai_router = AIRouter()
ai_agent = OmniAgent(ai_router)
global_memory_scanner = MemoryScanner()

# WebSockets Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# --- Models ---
class QuickEditRequest(BaseModel):
    apk_path: str
    package_name: Optional[str] = None
    debuggable: Optional[bool] = None
    remove_ad_perms: bool = True
    remove_dangerous_perms: bool = False
    remove_permissions: Optional[List[str]] = None
    add_permissions: Optional[List[str]] = None

class LuckyPatchRequest(BaseModel):
    apk_path: str
    remove_ads: bool = True
    bypass_billing: bool = True
    bypass_license: bool = True
    bypass_root: bool = True
    sign: bool = True

class AutonomousModRequest(BaseModel):
    apk_path: str
    prompt: str
    provider_preference: Optional[str] = None

class AIChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    provider_preference: Optional[str] = None
    model: Optional[str] = None

class FridaGenerateRequest(BaseModel):
    package_name: str
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    return_value: Optional[str] = None

class MemorySearchRequest(BaseModel):
    value: float
    value_type: str = "DWORD"
    is_refine: bool = False

class MemoryWriteRequest(BaseModel):
    address: int
    value: float
    value_type: str = "DWORD"

class SplitMergeRequest(BaseModel):
    apk_paths: List[str]

class BatchRegexRequest(BaseModel):
    apk_path: str
    pattern: str
    replacement: Optional[str] = None

class ApkDiffRequest(BaseModel):
    apk_a: str
    apk_b: str

# --- API Endpoints ---

@app.get("/api/system/info")
async def get_system_diagnostics():
    """Diagnostic system info, Linux vs Android/Termux, detected native tools."""
    return get_platform_info()

@app.post("/api/apk/upload")
async def upload_apk(file: UploadFile = File(...)):
    """Upload an APK file to workspace."""
    dest_path = UPLOAD_DIR / file.filename
    with dest_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    inspect_data = ApkPackager.inspect(dest_path)
    return {
        "success": True,
        "filename": file.filename,
        "path": str(dest_path),
        "info": inspect_data
    }

@app.get("/api/apk/list")
async def list_available_apks():
    """List loaded APKs across uploads, output, and samples."""
    files = []
    for folder, cat in [(UPLOAD_DIR, "upload"), (OUTPUT_DIR, "output"), (SAMPLES_DIR, "sample")]:
        if folder.exists():
            for p in folder.glob("*.apk"):
                try:
                    files.append({
                        "name": p.name,
                        "path": str(p),
                        "size": p.stat().st_size,
                        "category": cat
                    })
                except Exception:
                    pass
    return {"apks": sorted(files, key=lambda x: x["name"])}

@app.post("/api/apk/inspect")
async def inspect_apk_endpoint(data: Dict[str, str]):
    """Inspect internal contents and structure of APK."""
    apk_path = data.get("apk_path")
    if not apk_path or not Path(apk_path).exists():
        raise HTTPException(status_code=404, detail="APK file not found")
    return ApkPackager.inspect(apk_path)

@app.post("/api/apk/decompile")
async def decompile_apk_endpoint(data: Dict[str, Any]):
    """Apktool & JADX Decompile endpoint."""
    apk_path = data.get("apk_path")
    if not apk_path or not Path(apk_path).exists():
        raise HTTPException(status_code=404, detail="APK file not found")

    out_dir = DECOMPILE_DIR / Path(apk_path).stem
    apktool_res = ApktoolEngine.decompile(apk_path, out_dir)
    jadx_res = JadxEngine.decompile_apk_to_java(apk_path, out_dir / "java")

    return {
        "success": True,
        "apktool": apktool_res,
        "jadx": jadx_res,
        "project_dir": str(out_dir)
    }

@app.post("/api/apk/rebuild")
async def rebuild_apk_endpoint(data: Dict[str, Any]):
    """Recompile decompiled folder into signed APK."""
    project_dir = data.get("project_dir")
    if not project_dir or not Path(project_dir).exists():
        raise HTTPException(status_code=404, detail="Project directory not found")

    output_name = f"{Path(project_dir).name}_rebuilt.apk"
    out_apk = OUTPUT_DIR / output_name
    compile_res = ApktoolEngine.compile(project_dir, out_apk, zipalign=True)
    sign_res = ApkSigner.sign_apk(out_apk, out_apk)

    return {
        "success": True,
        "output_apk": str(out_apk),
        "filename": output_name,
        "size_bytes": out_apk.stat().st_size
    }

@app.post("/api/apk/quick_edit")
async def quick_edit_endpoint(req: QuickEditRequest):
    """Apktool M Quick Edit (Permissions, Debuggable, Package Name)."""
    if not Path(req.apk_path).exists():
        raise HTTPException(status_code=404, detail="APK not found")

    out_name = f"{Path(req.apk_path).stem}_quickedit.apk"
    out_apk = OUTPUT_DIR / out_name

    res = ApktoolMEngine.quick_edit_manifest(
        apk_path=req.apk_path,
        output_apk=out_apk,
        package_name=req.package_name,
        debuggable=req.debuggable,
        remove_permissions=req.remove_permissions,
        add_permissions=req.add_permissions,
        remove_ad_perms=req.remove_ad_perms,
        remove_dangerous_perms=req.remove_dangerous_perms,
        sign=True
    )
    return res

@app.post("/api/apk/lucky_patch")
async def lucky_patch_endpoint(req: LuckyPatchRequest):
    """Lucky Patcher Automated Suite."""
    if not Path(req.apk_path).exists():
        raise HTTPException(status_code=404, detail="APK not found")

    out_name = f"{Path(req.apk_path).stem}_luckypatched.apk"
    out_apk = OUTPUT_DIR / out_name

    res = LuckyPatcherEngine.apply_auto_patch(
        apk_path=req.apk_path,
        output_apk=out_apk,
        remove_ads=req.remove_ads,
        bypass_billing=req.bypass_billing,
        bypass_license=req.bypass_license,
        bypass_root_checks=req.bypass_root,
        sign=req.sign
    )
    return res

@app.post("/api/apk/split_merge")
async def split_merge_endpoint(req: SplitMergeRequest):
    """MT Manager Anti-Split APK Merger."""
    if not req.apk_paths:
        raise HTTPException(status_code=400, detail="No split APK paths provided")

    out_apk = OUTPUT_DIR / "merged_standalone.apk"
    res = AntiSplitMerger.merge_split_apks(req.apk_paths, out_apk, sign=True)
    return res

@app.post("/api/apk/batch_regex")
async def batch_regex_endpoint(req: BatchRegexRequest):
    """MT Manager Batch Multi-DEX Regex Patcher."""
    if not Path(req.apk_path).exists():
        raise HTTPException(status_code=404, detail="APK not found")

    if req.replacement is not None:
        out_apk = OUTPUT_DIR / f"{Path(req.apk_path).stem}_regex_patched.apk"
        res = BatchRegexPatcher.replace_all_dex(req.apk_path, req.pattern, req.replacement, out_apk, sign=True)
        return res
    else:
        matches = BatchRegexPatcher.search_all_dex(req.apk_path, req.pattern)
        return {"matches": matches, "count": len(matches)}

@app.post("/api/apk/diff")
async def apk_diff_endpoint(req: ApkDiffRequest):
    """MT Manager APK Diff Engine."""
    if not Path(req.apk_a).exists() or not Path(req.apk_b).exists():
        raise HTTPException(status_code=404, detail="One or both APKs not found")
    return ApkDiffer.compare_apks(req.apk_a, req.apk_b)

@app.post("/api/frida/generate")
async def frida_generate_endpoint(req: FridaGenerateRequest):
    """Frida Script Generator Suite."""
    scripts = {
        "ssl_unpinning": FridaScriptGenerator.get_universal_ssl_unpinning(),
        "root_bypass": FridaScriptGenerator.get_universal_root_bypass(),
        "billing_hook": FridaScriptGenerator.get_in_app_billing_bypass()
    }
    if req.class_name and req.method_name:
        scripts["custom_hook"] = FridaScriptGenerator.generate_method_hook(
            req.class_name, req.method_name, req.return_value
        )
    return scripts

@app.post("/api/game_guardian/search")
async def gg_memory_search(req: MemorySearchRequest):
    """Game Guardian Simulated RAM Memory Scanner."""
    if not req.is_refine:
        # If fresh search and memory empty, initialize simulated memory state
        if not any(global_memory_scanner.memory_space):
            global_memory_scanner.load_simulated_state({
                0x000100: 100,
                0x000250: 100,
                0x000480: 50,
                0x001000: 100,
                0x002040: 999
            }, req.value_type)

        matches = global_memory_scanner.search_exact(req.value, req.value_type)
    else:
        matches = global_memory_scanner.refine_search(req.value)

    return {
        "matches_count": len(matches),
        "addresses": [hex(a) for a in matches[:50]],
        "value_type": req.value_type
    }

@app.post("/api/game_guardian/edit")
async def gg_memory_edit(data: Dict[str, Any]):
    """Game Guardian Batch Edit Matches."""
    new_val = data.get("new_value", 999999)
    edited = global_memory_scanner.batch_edit_matches(new_val)
    return {"edited_count": edited, "new_value": new_val}

@app.post("/api/game_guardian/generate_lua")
async def gg_generate_lua(data: Dict[str, Any]):
    """Generate Game Guardian Lua script."""
    game_name = data.get("game_name", "TargetGame")
    searches = data.get("searches", [{"name": "Money", "target_val": 100, "new_val": 999999, "type": "DWORD"}])
    speed = float(data.get("speedhack", 1.0))
    lua_code = GameGuardianScriptBuilder.generate_lua_script(game_name, searches, speed)
    speed_hook = GameGuardianScriptBuilder.generate_speedhack_frida_script(speed)
    return {"lua_script": lua_code, "frida_speedhack": speed_hook}

@app.get("/api/ai/config")
async def get_ai_config():
    """Get active AI providers and settings."""
    if AI_CONFIG_FILE.exists():
        import json
        conf = json.loads(AI_CONFIG_FILE.read_text(encoding="utf-8"))
        # Mask keys for security
        masked_keys = {}
        for p, klist in conf.get("keys", {}).items():
            masked_keys[p] = [f"••••••••{k[-4:]}" if len(k) > 4 else "••••" for k in klist]
        return {
            "configured_providers": list(ai_router.providers.keys()),
            "priority_order": ai_router.priority_order,
            "models": conf.get("models", {}),
            "custom_endpoints": conf.get("custom_endpoints", {}),
            "keys_summary": {p: len(k) for p, k in conf.get("keys", {}).items()},
            "masked_keys": masked_keys
        }
    return {"configured_providers": list(ai_router.providers.keys())}

@app.post("/api/ai/config")
async def update_ai_config(conf: Dict[str, Any]):
    """Update AI providers, keys, and endpoints."""
    ai_router.save_config(conf)
    return {"success": True, "active_providers": list(ai_router.providers.keys())}

@app.post("/api/ai/chat")
async def ai_chat_endpoint(req: AIChatRequest):
    """Interactive Chat with Multi-Cloud AI Router."""
    res = await ai_router.chat(
        messages=req.messages,
        provider_preference=req.provider_preference,
        model=req.model,
        on_status_callback=lambda msg: asyncio.create_task(ws_manager.broadcast({"type": "ai_status", "message": msg}))
    )
    return res

@app.post("/api/ai/autonomous_mod")
async def autonomous_mod_endpoint(req: AutonomousModRequest):
    """Autonomous Prompt-Driven End-to-End Modding."""
    if not Path(req.apk_path).exists():
        raise HTTPException(status_code=404, detail="Target APK file not found")

    async def broadcast_event(event):
        await ws_manager.broadcast({"type": "agent_event", "data": event})

    # Run agent task
    result = await ai_agent.run_autonomous_mod_task(
        apk_path=req.apk_path,
        user_prompt=req.prompt,
        on_event_callback=lambda ev: asyncio.create_task(broadcast_event(ev)),
        provider_preference=req.provider_preference
    )
    return result

@app.get("/api/apk/download/{filename}")
async def download_apk(filename: str):
    """Download modded APK file."""
    for folder in [OUTPUT_DIR, UPLOAD_DIR, SAMPLES_DIR]:
        target = folder / filename
        if target.exists():
            return FileResponse(
                path=target,
                filename=filename,
                media_type="application/vnd.android.package-archive"
            )
    raise HTTPException(status_code=404, detail="File not found")

@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    """Real-time WebSocket event streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo heartbeat or client commands
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Mount static web frontend files
web_dir = BASE_DIR / "omniapk" / "web"
if web_dir.exists():
    app.mount("/", StaticFiles(directory=str(web_dir), html=True), name="web")
