#!/usr/bin/env python3
"""
OmniAPK Studio & AI Suite - Unified Interactive CLI.
Supports both Linux-based systems and Android (Termux) natively.
"""

import sys
import os
import argparse
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from omniapk.config import get_platform_info, DEFAULT_HOST, DEFAULT_PORT
from omniapk.core import ApkPackager, ApkSigner, DexParser, DexEditor, AndroidAppCompiler
from omniapk.modules.apktool import ApktoolEngine
from omniapk.modules.apktool_m import ApktoolMEngine
from omniapk.modules.lucky_patcher import LuckyPatcherEngine
from omniapk.modules.jadx import JadxEngine
from omniapk.modules.frida import FridaScriptGenerator
from omniapk.modules.mt_manager import AntiSplitMerger, BatchRegexPatcher, ApkDiffer
from omniapk.modules.game_guardian import MemoryScanner, GameGuardianScriptBuilder
from omniapk.ai.agent import OmniAgent
from omniapk.ai.router import AIRouter

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
except ImportError:
    class SimpleConsole:
        def print(self, *args, **kwargs):
            print(*args)
    console = SimpleConsole()

def cmd_inspect(args):
    """Inspect APK archive."""
    apk = Path(args.apk)
    if not apk.exists():
        console.print(f"[red]Error: APK file not found: {apk}[/red]")
        sys.exit(1)

    info = ApkPackager.inspect(apk)
    console.print(f"\n[bold cyan]⚡ OmniAPK Structural Inspection: {apk.name}[/bold cyan]")
    console.print(f"File Size: {info['size_bytes']:,} bytes ({info['size_bytes']/(1024*1024):.2f} MB)")
    console.print(f"Files Inside: {info['file_count']}")
    console.print(f"DEX Bytecode Files: {len(info['dex_files'])} ({', '.join([d['name'] for d in info['dex_files']])})")
    console.print(f"Native ABIs: {', '.join(info['abis']) if info['abis'] else 'None (Pure Java/Kotlin)'}")
    console.print(f"Signed: {'Yes' if info['is_signed'] else 'No'}\n")

def cmd_lucky_patch(args):
    """Apply Lucky Patcher pattern mods."""
    apk = Path(args.apk)
    out = Path(args.output or f"{apk.stem}_luckypatched.apk")

    console.print(f"[cyan]Applying Lucky Patcher Engine on {apk.name}...[/cyan]")
    res = LuckyPatcherEngine.apply_auto_patch(
        apk_path=apk,
        output_apk=out,
        remove_ads=not args.no_ads,
        bypass_billing=not args.no_billing,
        bypass_license=not args.no_license,
        bypass_root_checks=not args.no_root,
        sign=not args.no_sign
    )

    console.print(f"[bold green]✓ Lucky Patch Success![/bold green] Generated: {out} ({res['size_bytes']/(1024*1024):.2f} MB)")

def cmd_quick_mod(args):
    """Apktool M Quick Edit."""
    apk = Path(args.apk)
    out = Path(args.output or f"{apk.stem}_quickmod.apk")

    res = ApktoolMEngine.quick_edit_manifest(
        apk_path=apk,
        output_apk=out,
        package_name=args.package,
        debuggable=args.debuggable,
        remove_ad_perms=args.strip_ads,
        remove_dangerous_perms=args.strip_dangerous,
        sign=True
    )
    console.print(f"[bold green]✓ Quick Mod Completed![/bold green] Saved: {out}")

def cmd_decompile(args):
    """Apktool & JADX Decompilation."""
    apk = Path(args.apk)
    out = Path(args.output or f"decompiled_{apk.stem}")
    console.print(f"[cyan]Decompiling {apk.name} -> {out}...[/cyan]")
    ApktoolEngine.decompile(apk, out)
    JadxEngine.decompile_apk_to_java(apk, out / "java")
    console.print(f"[bold green]✓ Decompiled project to: {out}[/bold green]")

def cmd_split_merge(args):
    """MT Manager Anti-Split APK Merger."""
    out = Path(args.output or "merged_standalone.apk")
    console.print(f"[cyan]Merging {len(args.apks)} split APKs into standalone {out}...[/cyan]")
    res = AntiSplitMerger.merge_split_apks(args.apks, out, sign=True)
    console.print(f"[bold green]✓ Merged Standalone APK Generated: {out}[/bold green]")

def cmd_diff(args):
    """APK Differ."""
    diff = ApkDiffer.compare_apks(args.apk_a, args.apk_b)
    console.print(f"[bold cyan]📊 APK Differences ({diff['total_diff_count']} total changes):[/bold cyan]")
    console.print(f"Added Files: {len(diff['added_files'])}")
    console.print(f"Removed Files: {len(diff['removed_files'])}")
    console.print(f"Modified Files: {len(diff['modified_files'])} ({', '.join(diff['modified_files'][:5])}...)")

def cmd_frida_gen(args):
    """Generate Frida scripts."""
    script = FridaScriptGenerator.get_universal_ssl_unpinning() + "\n\n" + FridaScriptGenerator.get_universal_root_bypass()
    if args.class_name and args.method_name:
        script += "\n\n" + FridaScriptGenerator.generate_method_hook(args.class_name, args.method_name, args.return_val)
    if args.output:
        Path(args.output).write_text(script, encoding="utf-8")
        console.print(f"[green]Saved Frida script to {args.output}[/green]")
    else:
        print(script)

def cmd_gg_gen(args):
    """Generate Game Guardian Lua scripts."""
    searches = [{"name": "Value", "target_val": args.search, "new_val": args.set_value, "type": "DWORD"}]
    script = GameGuardianScriptBuilder.generate_lua_script(args.game, searches, args.speed)
    if args.output:
        Path(args.output).write_text(script, encoding="utf-8")
        console.print(f"[green]Saved Game Guardian script to {args.output}[/green]")
    else:
        print(script)

def cmd_build_android_app(args):
    """Compile launchable standalone Android APK."""
    out = Path(args.output or f"OmniAPK_Studio_v{args.version_name}.apk")
    console.print(f"[bold cyan]📱 Compiling OmniAPK Standalone Android App ({args.package})...[/bold cyan]")
    apk_path = AndroidAppCompiler.compile_apk(
        output_apk_path=out,
        package_name=args.package,
        app_name=args.name,
        version_name=args.version_name,
        version_code=args.version_code
    )
    console.print(f"[bold green]✓ Standalone Android APK Compiled Successfully![/bold green]")
    console.print(f"Output File: [bold cyan]{apk_path}[/bold cyan] ({apk_path.stat().st_size / (1024*1024):.2f} MB)")
    console.print(f"Signed with V1 + V2 Cryptographic Scheme (Installable on Android 5.0 - 15+)")

def cmd_sign(args):
    """Sign APK."""
    apk = Path(args.apk)
    out = Path(args.output or f"{apk.stem}_signed.apk")
    ApkSigner.sign_apk(apk, out)
    console.print(f"[bold green]✓ Signed APK: {out}[/bold green]")

def cmd_ai_mod(args):
    """Run Autonomous AI Agent Mod Task."""
    apk = Path(args.apk)
    if not apk.exists():
        console.print(f"[red]APK not found: {apk}[/red]")
        sys.exit(1)

    console.print(f"[bold cyan]🤖 Starting Autonomous AI Mod Agent...[/bold cyan]")
    console.print(f"Target: {apk.name}")
    console.print(f"Prompt: '{args.prompt}'\n")

    agent = OmniAgent()

    def on_event(ev):
        console.print(f"[dim][{ev.get('step','').upper()}][/dim] {ev.get('detail','')}")

    result = asyncio.run(agent.run_autonomous_mod_task(
        apk_path=apk,
        user_prompt=args.prompt,
        on_event_callback=on_event,
        provider_preference=args.provider
    ))

    console.print(f"\n[bold green]✓ Task Completed Successfully![/bold green]")
    console.print(f"Output APK: [bold cyan]{result['output_apk']}[/bold cyan]")
    console.print(f"AI Actions Applied:")
    for a in result.get("actions_taken", []):
        console.print(f" - {a}")

def cmd_serve(args):
    """Start Web Studio."""
    import uvicorn
    console.print(f"\n[bold cyan]⚡ Starting OmniAPK Studio Web Server on http://{args.host}:{args.port}[/bold cyan]")
    uvicorn.run("omniapk.server.app:app", host=args.host, port=args.port, reload=False)

def main():
    parser = argparse.ArgumentParser(
        prog="omniapk",
        description="OmniAPK Studio & AI Suite - 8-in-1 APK Modding & Reverse Engineering Suite for Linux & Android"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Inspect
    p_insp = subparsers.add_parser("inspect", help="Inspect APK structure and DEX")
    p_insp.add_argument("apk", help="Path to APK file")

    # Lucky Patch
    p_lp = subparsers.add_parser("lucky-patch", help="Apply Lucky Patcher automated mods")
    p_lp.add_argument("apk", help="Path to APK file")
    p_lp.add_argument("-o", "--output", help="Output APK path")
    p_lp.add_argument("--no-ads", action="store_true", help="Do not remove ads")
    p_lp.add_argument("--no-billing", action="store_true", help="Do not bypass billing")
    p_lp.add_argument("--no-license", action="store_true", help="Do not bypass license")
    p_lp.add_argument("--no-root", action="store_true", help="Do not bypass root checks")
    p_lp.add_argument("--no-sign", action="store_true", help="Do not sign output")

    # Quick Mod
    p_qm = subparsers.add_parser("quick-mod", help="Apktool M rapid manifest & permission mod")
    p_qm.add_argument("apk", help="Path to APK file")
    p_qm.add_argument("-o", "--output", help="Output APK path")
    p_qm.add_argument("--package", help="New package name")
    p_qm.add_argument("--debuggable", action="store_true", help="Force debuggable=true")
    p_qm.add_argument("--strip-ads", action="store_true", default=True, help="Strip ad permissions")
    p_qm.add_argument("--strip-dangerous", action="store_true", help="Strip dangerous telemetry permissions")

    # Decompile
    p_dec = subparsers.add_parser("decompile", help="Decompile APK to Smali and Java")
    p_dec.add_argument("apk", help="Path to APK file")
    p_dec.add_argument("-o", "--output", help="Output directory")

    # Split Merge
    p_sm = subparsers.add_parser("split-merge", help="Merge split APKs into standalone")
    p_sm.add_argument("apks", nargs="+", help="Split APK paths (base.apk split_config.*.apk)")
    p_sm.add_argument("-o", "--output", help="Output standalone APK path")

    # Diff
    p_diff = subparsers.add_parser("diff", help="Diff two APK files")
    p_diff.add_argument("apk_a", help="First APK path")
    p_diff.add_argument("apk_b", help="Second APK path")

    # Frida Gen
    p_fr = subparsers.add_parser("frida-gen", help="Generate Frida dynamic hooks")
    p_fr.add_argument("--class-name", help="Target Java Class")
    p_fr.add_argument("--method-name", help="Target Java Method")
    p_fr.add_argument("--return-val", help="Override return value")
    p_fr.add_argument("-o", "--output", help="Output .js file")

    # Game Guardian Gen
    p_gg = subparsers.add_parser("gg-gen", help="Generate Game Guardian Lua cheats")
    p_gg.add_argument("--game", default="TargetGame", help="Game Name")
    p_gg.add_argument("--search", type=int, default=100, help="Initial value")
    p_gg.add_argument("--set-value", type=int, default=999999, help="Modified value")
    p_gg.add_argument("--speed", type=float, default=1.0, help="Speedhack multiplier")
    p_gg.add_argument("-o", "--output", help="Output .lua file")

    # Build Android App
    p_build = subparsers.add_parser("build-android-app", help="Compile standalone launchable Android APK app")
    p_build.add_argument("-o", "--output", help="Output APK filename/path")
    p_build.add_argument("--package", default="com.omniapk.studio", help="Application package name")
    p_build.add_argument("--name", default="OmniAPK Studio", help="Application display label")
    p_build.add_argument("--version-name", default="2.0.0", help="Version name (e.g. 2.0.0)")
    p_build.add_argument("--version-code", type=int, default=200, help="Version code integer")

    # Sign
    p_sign = subparsers.add_parser("sign", help="Sign APK with V1+V2 scheme")
    p_sign.add_argument("apk", help="Path to APK file")
    p_sign.add_argument("-o", "--output", help="Output APK path")

    # AI Mod
    p_ai = subparsers.add_parser("ai-mod", help="Autonomous Prompt-Driven AI Mod Task")
    p_ai.add_argument("apk", help="Path to target APK")
    p_ai.add_argument("--prompt", required=True, help="Natural language modding instruction")
    p_ai.add_argument("--provider", help="AI provider preference (groq, openai, anthropic, gemini, etc.)")

    # Serve
    p_srv = subparsers.add_parser("serve", help="Start Web Studio & API Server")
    p_srv.add_argument("--host", default=DEFAULT_HOST, help="Host to bind (default: 0.0.0.0)")
    p_srv.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind (default: 8000)")

    args = parser.parse_args()

    if not args.command:
        # If no arguments provided, show help
        parser.print_help()
        return

    dispatch = {
        "inspect": cmd_inspect,
        "lucky-patch": cmd_lucky_patch,
        "quick-mod": cmd_quick_mod,
        "decompile": cmd_decompile,
        "split-merge": cmd_split_merge,
        "diff": cmd_diff,
        "frida-gen": cmd_frida_gen,
        "gg-gen": cmd_gg_gen,
        "build-android-app": cmd_build_android_app,
        "sign": cmd_sign,
        "ai-mod": cmd_ai_mod,
        "serve": cmd_serve,
    }

    if args.command in dispatch:
        dispatch[args.command](args)

if __name__ == "__main__":
    main()
