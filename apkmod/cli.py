"""``apkmod`` -- one command line for decompiling, editing, rebuilding and signing APKs.

Run ``apkmod --help`` for the command list, or ``apkmod doctor`` to see which
backends are wired up on this machine.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__, align, analyze, signing, smali
from .apk import ApkContainer
from .asn1 import ApkModError
from .engines import registry
from .engines.aee import EditResult, NativeEditor
from .engines.apktool import ApktoolEngine, install_apktool
from .engines.apktoolm import ApktoolMEngine
from .engines.patcher import PatcherEngine
from .util import eprint, human_size

__all__ = ["main", "build_parser"]

DESCRIPTION = (
    "APK Modifyer - one toolkit combining Apktool (decode/build), Apktool M (on-device), "
    "APK-Editor-style in-place editing, and protection analysis."
)

ETHICS_NOTE = (
    "Use this on apps you own or have permission to inspect. The toolkit reports protections; "
    "it does not defeat licence checks or alter paid entitlements."
)


# ==========================================================================
# helpers
# ==========================================================================
def _emit(payload, as_json: bool, text: str) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(text)


def _print_edit(result: EditResult) -> None:
    print(f"written: {result.path}  ({human_size(Path(result.path).stat().st_size)})")
    for note in result.notes:
        print(f"  - {note}")
    if result.signed:
        print("  - signed with a v1 (JAR) signature")
    if result.aligned_misalignments:
        print(f"  ! {result.aligned_misalignments} entr{'y is' if result.aligned_misalignments == 1 else 'ies are'} not aligned")


def _material(args) -> tuple[bytes, bytes]:
    return signing.load_material(
        key=getattr(args, "key", None),
        cert=getattr(args, "cert", None),
        keystore=getattr(args, "keystore", None),
        storepass=getattr(args, "storepass", "") or "",
        alias=getattr(args, "alias", None),
    )


def _maybe_sign(result: EditResult, args, editor: NativeEditor) -> EditResult:
    """If --sign was passed (or signing material is present), sign the result in place.

    The file named by ``-o`` is the final artifact, so a signed edit does not
    leave a confusing unsigned twin behind.
    """
    wants_sign = getattr(args, "sign", False)
    has_material = any(getattr(args, name, None) for name in ("key", "cert", "keystore"))
    if not (wants_sign or has_material):
        return result
    key_pem, cert_pem = _material(args)
    scratch = result.path.with_name(result.path.name + ".signing")
    signed = editor.sign(
        result.path, scratch, key_pem, cert_pem, name=getattr(args, "sig_name", "APKMOD") or "APKMOD"
    )
    scratch.replace(result.path)
    return EditResult(
        path=result.path,
        changed_entries=result.changed_entries + signed.changed_entries,
        notes=result.notes + signed.notes,
        signed=True,
        aligned_misalignments=signed.aligned_misalignments,
    )


def _finish_edit(result: EditResult, args, editor: NativeEditor) -> None:
    """Warn about the broken signature only when we are not about to fix it."""
    signing_now = getattr(args, "sign", False) or any(
        getattr(args, name, None) for name in ("key", "cert", "keystore")
    )
    if not signing_now and not getattr(args, "keep_signature", False):
        result.notes.append("v1 signature invalidated by this edit - re-sign before installing")
    _print_edit(_maybe_sign(result, args, editor))


# ==========================================================================
# commands
# ==========================================================================
def cmd_doctor(args) -> int:
    statuses = registry.statuses()
    if getattr(args, "json", False):
        print(json.dumps([s.as_dict() for s in statuses], indent=2, default=str))
        return 0
    print("\n\n".join(s.format() for s in statuses))
    ready = [s.name for s in statuses if s.available]
    print()
    print(f"ready: {', '.join(ready) if ready else 'none'}")
    signers = [s for s in signing.signer_statuses() if s.available]
    print(f"signing backends: {', '.join(s.name for s in signers) or 'native only'}")
    print(ETHICS_NOTE)
    return 0


def cmd_info(args) -> int:
    with ApkContainer(Path(args.apk)) as container:
        facts = container.facts()
    if getattr(args, "json", False):
        print(json.dumps(facts, indent=2, default=str))
        return 0
    manifest = facts.pop("manifest", {})
    print(f"file        : {facts['path']}")
    print(f"size        : {facts['file_size_human']} ({facts['entry_count']} entries)")
    print(f"package     : {manifest.get('package')}")
    print(f"version     : {manifest.get('version_name')} ({manifest.get('version_code')})")
    print(f"sdk         : min {manifest.get('min_sdk')} / target {manifest.get('target_sdk')}")
    print(f"dex         : {len(facts['dex_files'])} file(s)")
    libs = facts["native_libraries"]
    print(f"native      : {', '.join(sorted(libs)) or 'none'}")
    signing_info = facts["signing"]
    print(f"signing     : v1={signing_info['v1_jar_signing']} v2={signing_info['v2']} v3={signing_info['v3']}")
    for cert in signing_info["certificates"]:
        print(f"cert        : {cert['subject_cn'] or 'unknown'} sha256={cert['sha256'][:32]}...")
    print(f"permissions : {len(manifest.get('permissions', []))}")
    for key in ("activities", "services", "receivers", "providers"):
        print(f"  {key:<10}: {len(manifest.get(key, []))}")
    print("biggest     :")
    for entry in facts["biggest_entries"][:5]:
        print(f"  {human_size(entry['size']):>10}  {entry['name']}")
    return 0


def cmd_manifest(args) -> int:
    editor = NativeEditor()
    if getattr(args, "xml", False):
        print(editor.manifest_xml(Path(args.apk)))
        return 0
    facts = editor.manifest_facts(Path(args.apk))
    _emit(facts, getattr(args, "json", False), json.dumps(facts, indent=2, default=str))
    return 0


def cmd_strings(args) -> int:
    entries = NativeEditor().strings(Path(args.apk))
    if args.match:
        entries = [e for e in entries if args.match.lower() in e[1].lower()]
    entries = entries[: args.limit]
    if getattr(args, "json", False):
        print(json.dumps([{"index": i, "value": v, "used_by": u} for i, v, u in entries], indent=2))
        return 0
    for index, value, used in entries:
        where = f"  <- {used[0]}" if used else ""
        print(f"{index:>5}  {value!r}{where}")
    print(f"\n{len(entries)} string(s) shown")
    return 0


def cmd_decode(args) -> int:
    engine = ApktoolEngine()
    status = engine.status()
    if not status.available:
        raise ApkModError(
            "the apktool engine is not usable here:\n  " + "\n  ".join(status.notes or ["unknown"]) +
            f"\n{status.install_hint}"
        )
    out = engine.decode(Path(args.apk), Path(args.out), resources=not args.no_res, sources=not args.no_src)
    print(f"decoded -> {out}")
    print(f"  smali dirs: {', '.join(p.name for p in sorted(Path(out).iterdir()) if p.is_dir() and p.name.startswith('smali'))}")
    return 0


def cmd_build(args) -> int:
    engine = ApktoolEngine()
    out = engine.build(Path(args.project), Path(args.out))
    print(f"built -> {out}")
    print("  unsigned: run `apkmod sign` before installing")
    return 0


def cmd_install_apktool(args) -> int:
    jar = install_apktool(args.version)
    print(f"apktool jar -> {jar}")
    return 0


def cmd_align(args) -> int:
    result = align.align(Path(args.apk), Path(args.out), alignment=args.alignment, page_align_libs=not args.no_page_align)
    bad = align.verify_alignment(Path(args.out), page_align_libs=not args.no_page_align)
    print(f"aligned -> {result.path} ({result.entries} entries)")
    print(f"misaligned entries: {len(bad)}")
    for item in bad[:10]:
        print(f"  ! {item['name']} offset {item['offset']} (needs {item['required']})")
    return 0


def cmd_sign(args) -> int:
    keystore = getattr(args, "keystore", None)
    if keystore is None and not (args.key and args.cert):
        raise ApkModError("provide --key/--cert, or --keystore with --storepass")
    key_pem = cert_pem = None
    if args.key and args.cert:
        key_pem, cert_pem = signing.load_material(key=args.key, cert=args.cert)
    outcome = signing.sign(
        Path(args.apk),
        Path(args.out),
        engine=args.engine,
        key_pem=key_pem,
        cert_pem=cert_pem,
        keystore=keystore,
        storepass=args.storepass or "",
        alias=args.alias,
        digest=args.digest,
        signature_name=args.name,
    )
    print(f"signed -> {outcome.path}")
    print(f"  engine  : {outcome.engine}")
    print(f"  schemes : {', '.join(outcome.schemes) or 'none detected'}")
    print(f"  cert    : {outcome.subject or 'unknown'} ({(outcome.certificate_sha256 or '')[:32]}...)")
    for note in outcome.notes:
        print(f"  note    : {note}")
    check = signing.verify_v1(outcome.path)
    print(f"  verify  : {'OK' if check.ok else 'FAILED - ' + '; '.join(check.problems[:3])}")
    if outcome.engine == "native" and "v2" not in outcome.schemes:
        print("  hint    : v1 only - Android 11+ also wants v2/v3 (install build-tools for apksigner)")
    return 0 if check.ok else 1


def cmd_signers(args) -> int:
    statuses = signing.signer_statuses()
    if getattr(args, "json", False):
        print(json.dumps([s.as_dict() for s in statuses], indent=2))
        return 0
    for status in statuses:
        flag = "ready " if status.available else "absent"
        print(f"[{flag}] {status.name}")
        if status.version:
            print(f"         version : {status.version}")
        if status.location:
            print(f"         location: {status.location}")
        print(f"         schemes : {', '.join(status.schemes)}")
        print(f"         note    : {status.note}")
    return 0


def cmd_verify(args) -> int:
    result = signing.verify_v1(Path(args.apk))
    if getattr(args, "json", False):
        print(json.dumps(result.__dict__, indent=2))
        return 0 if result.ok else 1
    print(f"v1 signature : {'present' if result.signed else 'ABSENT'}")
    print(f"signature ok : {result.signature_valid}")
    print(f"entries      : {result.entries_checked} checked, {len(result.mismatched)} mismatched, {len(result.unsigned)} uncovered")
    if result.subject:
        print(f"certificate  : {result.subject} sha256={result.certificate_sha256[:32]}...")
    for problem in result.problems:
        print(f"  ! {problem}")
    for name in result.unsigned[:10]:
        print(f"  uncovered: {name}")
    return 0 if result.ok else 1


def cmd_genkey(args) -> int:
    key, cert = signing.generate_key(Path(args.out), common_name=args.cn)
    print(f"key  -> {key}")
    print(f"cert -> {cert}")
    print("use with: apkmod sign app.apk -o signed.apk --key <key> --cert <cert>")
    return 0


def cmd_remove_permission(args) -> int:
    editor = NativeEditor()
    result = editor.remove_permissions(Path(args.apk), Path(args.out), args.permission)
    _finish_edit(result, args, editor)
    return 0


def cmd_add_permission(args) -> int:
    editor = NativeEditor()
    result = editor.add_permission(Path(args.apk), Path(args.out), args.permission, tag=args.tag)
    _finish_edit(result, args, editor)
    return 0


def cmd_set_debuggable(args) -> int:
    editor = NativeEditor()
    result = editor.set_debuggable(Path(args.apk), Path(args.out), not args.off)
    _finish_edit(result, args, editor)
    return 0


def cmd_replace_string(args) -> int:
    editor = NativeEditor()
    chosen = [name for name, value in (("--res-name", args.res_name), ("--index", args.index), ("--old", args.old)) if value is not None]
    if not chosen:
        raise ApkModError("give one of --res-name NAME, --index N or --old TEXT, together with --new TEXT")
    if len(chosen) > 1:
        raise ApkModError(f"pick exactly one target, got {', '.join(chosen)}")

    if args.res_name is not None:
        res_type, _, entry = args.res_name.partition("/")
        if entry:  # "string/app_name"
            res_type, res_name = res_type, entry
        else:  # bare "app_name" implies the string type
            res_type, res_name = "string", res_type
        result = editor.replace_string(
            Path(args.apk), Path(args.out), "", args.new,
            res_name=res_name, res_type=res_type, res_config=args.config,
        )
    elif args.index is not None:
        result = editor.replace_string(Path(args.apk), Path(args.out), "", args.new, index=args.index)
    else:
        result = editor.replace_string(Path(args.apk), Path(args.out), args.old, args.new)
    _finish_edit(result, args, editor)
    return 0


def cmd_replace_file(args) -> int:
    editor = NativeEditor()
    if args.add:
        result = editor.add_file(Path(args.apk), Path(args.out), args.entry, Path(args.file))
    else:
        result = editor.replace_file(Path(args.apk), Path(args.out), args.entry, Path(args.file), compress=args.compress)
    _finish_edit(result, args, editor)
    return 0


def cmd_remove_entry(args) -> int:
    editor = NativeEditor()
    result = editor.remove_entries(Path(args.apk), Path(args.out), args.entry)
    _print_edit(_maybe_sign(result, args, editor))
    return 0


def cmd_analyze(args) -> int:
    report = analyze.analyze_apk(Path(args.apk))
    if getattr(args, "json", False):
        print(json.dumps(report.as_dict(), indent=2, default=str))
    elif getattr(args, "markdown", False):
        print(report.as_markdown())
    else:
        print(report.as_text())
    return 0


def cmd_scan(args) -> int:
    report = PatcherEngine().scan(Path(args.apk))
    if getattr(args, "json", False):
        print(json.dumps(report.as_dict(), indent=2, default=str))
    else:
        print(report.as_text())
    return 0


def cmd_smali_search(args) -> int:
    report = smali.search(Path(args.dir), args.pattern, ignore_case=not args.case_sensitive, limit=args.limit)
    for match in report.matches:
        print(match.format())
    print(f"\n{len(report.matches)} match(es) in {report.files_with_matches} of {report.files_scanned} file(s)")
    return 0


def cmd_smali_replace(args) -> int:
    report = smali.replace(
        Path(args.dir), args.pattern, args.replacement, ignore_case=not args.case_sensitive, dry_run=not args.apply
    )
    verb = "would change" if not args.apply else "changed"
    for match in report.matches[:50]:
        print(match.format())
    print(f"\n{verb} {len(report.matches)} line(s) across {report.files_with_matches} file(s)")
    if not args.apply:
        print("(dry run - pass --apply to write the changes)")
    return 0


def cmd_findings(args) -> int:
    findings = smali.signature_check_findings(Path(args.dir))
    _emit(findings, getattr(args, "json", False), json.dumps(findings, indent=2))
    return 0


def cmd_adb_push(args) -> int:
    engine = ApktoolMEngine()
    remote = engine.push(Path(args.apk))
    print(f"pushed -> {remote}")
    return 0


def cmd_adb_pull(args) -> int:
    engine = ApktoolMEngine()
    local = engine.pull(args.remote, Path(args.out))
    print(f"pulled -> {local}")
    return 0


def cmd_adb_launch(args) -> int:
    engine = ApktoolMEngine()
    print(f"launched {engine.launch(args.package)}")
    return 0


def cmd_serve(args) -> int:
    from .server.app import serve

    return serve(host=args.host, port=args.port)


# ==========================================================================
# parser
# ==========================================================================
def _add_signing_options(parser) -> None:
    group = parser.add_argument_group("signing")
    group.add_argument("--key", type=Path, help="PEM private key")
    group.add_argument("--cert", type=Path, help="PEM certificate")
    group.add_argument("--keystore", type=Path, help="PKCS#12 keystore")
    group.add_argument("--storepass", help="keystore password")
    group.add_argument("--alias", help="keystore alias (informational)")
    group.add_argument("--sig-name", default="APKMOD", help="META-INF block name (default APKMOD)")
    group.add_argument("--sign", action="store_true", help="re-sign the result")


# ==========================================================================
# diffing and bundles (MT Manager equivalents)
# ==========================================================================
def cmd_diff(args) -> int:
    from .engines.mtmanager import diff_apks

    diff = diff_apks(Path(args.left), Path(args.right), compare_content=not args.fast)
    _emit(diff.as_dict(), args.json, diff.format(include_identical=args.all, limit=args.limit))
    return 0


def cmd_bundle_unpack(args) -> int:
    from .engines.mtmanager import open_bundle

    parts, others = open_bundle(Path(args.bundle), Path(args.out))
    if args.json:
        print(json.dumps({"parts": [p.as_dict() for p in parts], "other_files": others}, indent=2))
    else:
        print(f"unpacked {len(parts)} APK(s) into {args.out}")
        for part in parts:
            tag = "base " if part.is_base else "split"
            print(f"  [{tag}] {part.name}  ({human_size(part.size)})")
        if others:
            print(f"  sidecar files: {', '.join(others)}")
    return 0


def cmd_bundle_pack(args) -> int:
    from .engines.mtmanager import rebuild_bundle, open_bundle

    source = Path(args.dir)
    # Re-read the directory as a bundle so the parts are discovered, not assumed.
    parts, _ = open_bundle(source, source)
    out = rebuild_bundle(parts, source, Path(args.out))
    print(f"wrote {out}  ({human_size(out.stat().st_size)})")
    return 0


# ==========================================================================
# JADX
# ==========================================================================
def cmd_decompile_java(args) -> int:
    from .engines.jadx import JadxEngine

    engine = JadxEngine(args.jadx)
    result = engine.decompile(
        Path(args.apk),
        Path(args.out),
        threads=args.threads,
        show_bad_code=args.show_bad_code,
        deobfuscate=args.deobf,
        include_resources=not args.no_res,
        timeout=args.timeout,
    )
    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    print(f"output: {result['output']}  ({result['java_files']} .java files)")
    for warning in result["warnings"][:20]:
        print(f"  ! {warning}")
    if result["note"]:
        print(f"  note: {result['note']}")
    return 0 if result["ok"] else 1


def cmd_java_search(args) -> int:
    from .engines.jadx import JadxEngine

    hits = JadxEngine(args.jadx).search(Path(args.dir), args.pattern, limit=args.limit)
    if args.json:
        print(json.dumps({"count": len(hits), "matches": hits}, indent=2))
    else:
        for hit in hits:
            print(f"{hit['file']}:{hit['line']}: {hit['text']}")
        print(f"{len(hits)} match(es)")
    return 0


# ==========================================================================
# Frida
# ==========================================================================
def cmd_frida_server(args) -> int:
    from .engines.frida import FridaEngine

    engine = FridaEngine()
    if args.action == "push":
        if not args.binary:
            eprint("error: --binary is required (the android frida-server build for your ABI)")
            return 2
        result = engine.push_server(Path(args.binary), serial=args.serial)
    else:
        result = engine.start_server(serial=args.serial, args=args.args or "")
    print(json.dumps(result, indent=2) if args.json else json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


def cmd_frida_ps(args) -> int:
    from .engines.frida import FridaEngine

    result = FridaEngine().list_processes(serial=args.serial, usb=not args.local)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for process in result["processes"]:
            print(f"{process['pid']:>7}  {process['name']}")
        print(f"{result['count']} process(es)")
    return 0


def cmd_frida_run(args) -> int:
    from .engines.frida import FridaEngine

    result = FridaEngine().run_script(
        Path(args.script),
        package=args.package,
        pid=args.pid,
        spawn=not args.attach,
        usb=not args.local,
        serial=args.serial,
        timeout=args.timeout,
        quiet=not args.interactive,
    )
    if result["stdout"]:
        print(result["stdout"])
    if result["stderr"]:
        eprint(result["stderr"])
    if args.json:
        print(json.dumps({k: v for k, v in result.items() if k != "stdout"}, indent=2))
    return 0 if result["ok"] else 1


# ==========================================================================
# AI
# ==========================================================================
def cmd_platform(args) -> int:
    from .platform_info import detect

    info = detect()
    _emit(info.as_dict(), args.json, info.format())
    return 0


def _ai_client(args):
    from .ai import AIClient, load_config

    config = load_config(args.config)
    if args.model:
        config.default_model = args.model
    if args.strategy:
        config.routing.strategy = args.strategy
    if args.max_wait:
        config.routing.max_wait_seconds = args.max_wait
    return AIClient(config)


def cmd_ai_doctor(args) -> int:
    from .ai import load_config

    config = load_config(args.config)
    usable = config.enabled_providers
    payload = config.as_dict()
    payload["usable_providers"] = [p.name for p in usable]
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"config: {config.path or '(none -- using environment only)'}")
    print(f"default model: {config.default_model or '(unset)'}")
    print(f"routing: strategy={config.routing.strategy} "
          f"max_wait={config.routing.max_wait_seconds}s "
          f"retry_on={config.routing.retry_statuses}")
    print()
    if not config.providers:
        print("no provider configured. Either export a key:")
        print("  export OPENAI_API_KEY=sk-...   # or ANTHROPIC_API_KEY, GEMINI_API_KEY, ...")
        print("or write ~/.apkmod/ai.json -- see the README for the full schema.")
    else:
        for provider in config.providers:
            flag = "ready " if provider.usable_keys else "no key"
            print(f"[{flag}] {provider.name} ({provider.kind})"
                  f"{' -> ' + provider.base_url if provider.base_url else ''}")
            print(f"         keys   : {len(provider.usable_keys)}")
            print(f"         models : {', '.join(provider.models) or '(unset)'}")
        print()
        print(f"{len(usable)} provider(s) usable, "
              f"{sum(len(p.usable_keys) for p in usable)} key(s) in the pool")
    for warning in config.warnings:
        print(f"warning: {warning}")
    return 0


def cmd_ai(args) -> int:
    import tempfile

    from .ai import Agent, ToolContext, work_dir

    client = _ai_client(args)
    session = Path(args.workdir) if args.workdir else work_dir() / "ai" / _session_id()
    session.mkdir(parents=True, exist_ok=True)

    apk = Path(args.apk) if args.apk else None
    if apk is not None and not apk.is_file():
        eprint(f"error: no such file: {apk}")
        return 2

    context = ToolContext(
        work_dir=session,
        apk=apk,
        decoded_dir=Path(args.decoded) if args.decoded else None,
        auto_confirm=args.yes,
    )
    events = []

    def on_event(kind, payload):
        events.append({"kind": kind, **payload})
        if args.verbose and not args.json:
            _print_ai_event(kind, payload)

    agent = Agent(
        client,
        context=context,
        max_iterations=args.max_steps,
        on_event=on_event,
    )
    result = agent.run(args.task, model=args.model)

    if args.json:
        payload = result.as_dict()
        payload["session"] = str(session)
        payload["events"] = events
        print(json.dumps(payload, indent=2, default=str))
    else:
        for step in result.steps:
            for call, outcome in zip(step.tool_calls, step.tool_results):
                status = outcome.get("status")
                print(f"  [{step.index}] {call['name']}({json.dumps(call['arguments'], ensure_ascii=False)[:120]}) -> {status}")
        print()
        print(result.text or "(no final answer)")
        print()
        print(
            f"steps={len(result.steps)} tool_calls={result.tool_call_count} "
            f"tokens={result.total_tokens} waited={result.waited_seconds:.1f}s "
            f"finished={result.finished}"
        )
        if result.pending_confirmations:
            print(
                f"{len(result.pending_confirmations)} change(s) were NOT applied; "
                "re-run with --yes to allow file modifications"
            )
        if result.error:
            eprint(f"error: {result.error}")
    if args.transcript:
        Path(args.transcript).write_text(
            json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
        )
    return 0 if result.finished == "complete" else 1


def _session_id() -> str:
    import time

    return time.strftime("%Y%m%d-%H%M%S")


def _print_ai_event(kind: str, payload: dict) -> None:
    if kind == "request":
        eprint(f"  -> {payload['endpoint']} ({payload['model']})")
    elif kind == "waited":
        eprint(f"  .. rate limited, waited {payload['waited_seconds']}s")
    elif kind == "error":
        eprint(f"  !! {payload['endpoint']}: {payload['status']} {payload['message'][:100]}")
    elif kind == "tool":
        eprint(f"  * {payload['name']}({json.dumps(payload['arguments'], ensure_ascii=False)[:140]})")
    elif kind == "tool_result":
        eprint(f"    = {payload['status']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apkmod", description=DESCRIPTION, epilog=ETHICS_NOTE)
    parser.add_argument("--version", action="version", version=f"apkmod {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("doctor", help="show which engines are usable here")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("info", help="summarise an APK")
    p.add_argument("apk")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("manifest", help="dump AndroidManifest.xml")
    p.add_argument("apk")
    p.add_argument("--xml", action="store_true", help="render readable XML instead of JSON facts")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("strings", help="list resource strings from resources.arsc")
    p.add_argument("apk")
    p.add_argument("--match", help="only strings containing this text")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("decode", help="decompile with Apktool (needs the jar + a JVM)")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--no-res", action="store_true")
    p.add_argument("--no-src", action="store_true")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("build", help="rebuild an Apktool project")
    p.add_argument("project")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("install-apktool", help="download an apktool jar into the cache")
    p.add_argument("version", nargs="?", default="2.11.1")
    p.set_defaults(func=cmd_install_apktool)

    p = sub.add_parser("align", help="zipalign (native)")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--alignment", type=int, default=4)
    p.add_argument("--no-page-align", action="store_true", help="do not page-align .so entries")
    p.set_defaults(func=cmd_align)

    p = sub.add_parser("sign", help="sign an APK (apksigner/uber-apk-signer when present, else native v1)")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--name", default="APKMOD", help="META-INF block name")
    p.add_argument("--digest", default="sha-256", choices=["sha-256", "sha-512"])
    p.add_argument(
        "--engine", default="auto", choices=["auto", "native", "apksigner", "uber"],
        help="auto prefers apksigner for v2/v3 coverage, then falls back to native v1",
    )
    _add_signing_options(p)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("signers", help="show which signing backends are available")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_signers)

    p = sub.add_parser("verify", help="verify a v1 signature")
    p.add_argument("apk")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("genkey", help="create a self-signed signing key with OpenSSL")
    p.add_argument("-o", "--out", default=".")
    p.add_argument("--cn", default="APK Modifyer")
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("remove-permission", help="strip <uses-permission> entries")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument(
        "-p", "--permission", action="append", required=True,
        help="e.g. android.permission.CAMERA (repeatable)",
    )
    p.add_argument("--keep-signature", action="store_true", help="do not warn about the broken signature")
    _add_signing_options(p)
    p.set_defaults(func=cmd_remove_permission)

    p = sub.add_parser("add-permission", help="declare a new permission")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("-p", "--permission", required=True, help="e.g. android.permission.VIBRATE")
    p.add_argument("--tag", default="uses-permission")
    p.add_argument("--keep-signature", action="store_true", help="do not warn about the broken signature")
    _add_signing_options(p)
    p.set_defaults(func=cmd_add_permission)

    p = sub.add_parser("set-debuggable", help="flip android:debuggable")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--off", action="store_true", help="set it to false instead of true")
    _add_signing_options(p)
    p.set_defaults(func=cmd_set_debuggable)

    p = sub.add_parser("replace-string", help="rewrite a resource string")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--res-name", help="resource name, e.g. app_name or string/app_name (recommended)")
    p.add_argument("--config", help="limit --res-name to one config, e.g. v21 or de")
    p.add_argument("--old", help="exact current value")
    p.add_argument("--new", required=True)
    p.add_argument("--index", type=int, help="string-pool index instead of --old")
    _add_signing_options(p)
    p.set_defaults(func=cmd_replace_string)

    p = sub.add_parser("replace-file", help="swap or inject an entry (assets, images, ...)")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--entry", required=True, help="path inside the APK, e.g. assets/config.json")
    p.add_argument("--file", required=True, type=Path)
    p.add_argument("--add", action="store_true", help="inject a new entry instead of replacing")
    p.add_argument("--compress", action="store_true", help="deflate the replacement")
    _add_signing_options(p)
    p.set_defaults(func=cmd_replace_file)

    p = sub.add_parser("remove-entry", help="drop entries from the archive")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--entry", action="append", required=True)
    _add_signing_options(p)
    p.set_defaults(func=cmd_remove_entry)

    p = sub.add_parser("analyze", help="full static analysis report")
    p.add_argument("apk")
    p.add_argument("--json", action="store_true")
    p.add_argument("--markdown", action="store_true")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("scan", help="anti-tamper / SDK inventory (analysis only)")
    p.add_argument("apk")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("smali-search", help="regex search a decoded smali tree")
    p.add_argument("dir")
    p.add_argument("pattern")
    p.add_argument("--case-sensitive", action="store_true")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_smali_search)

    p = sub.add_parser("smali-replace", help="regex replace across a decoded smali tree")
    p.add_argument("dir")
    p.add_argument("pattern")
    p.add_argument("replacement")
    p.add_argument("--case-sensitive", action="store_true")
    p.add_argument("--apply", action="store_true", help="write the changes (default is a dry run)")
    p.set_defaults(func=cmd_smali_replace)

    p = sub.add_parser("findings", help="where a decoded project checks its own integrity")
    p.add_argument("dir")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("adb-push", help="push an APK to the device for Apktool M")
    p.add_argument("apk")
    p.set_defaults(func=cmd_adb_push)

    p = sub.add_parser("adb-pull", help="pull a rebuilt APK back from the device")
    p.add_argument("remote")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(func=cmd_adb_pull)

    p = sub.add_parser("adb-launch", help="launch Apktool M on the device")
    p.add_argument("--package")
    p.set_defaults(func=cmd_adb_launch)

    p = sub.add_parser("serve", help="start the local web UI")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_serve)

    # ---------------- diffing and bundles (MT Manager equivalents) --------
    p = sub.add_parser("diff", help="compare two APKs entry by entry")
    p.add_argument("left")
    p.add_argument("right")
    p.add_argument("--all", action="store_true", help="also list unchanged entries")
    p.add_argument("--fast", action="store_true", help="trust the CRC, skip SHA-256 confirmation")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("bundle-unpack", help="unpack a split-APK bundle (xapk/apks)")
    p.add_argument("bundle")
    p.add_argument("--out", default="bundle")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_bundle_unpack)

    p = sub.add_parser("bundle-pack", help="repack an unpacked bundle directory")
    p.add_argument("dir")
    p.add_argument("--out", default="rebuilt.xapk")
    p.set_defaults(func=cmd_bundle_pack)

    # ---------------- JADX ------------------------------------------------
    p = sub.add_parser("decompile-java", help="decompile DEX to Java with JADX (needs jadx)")
    p.add_argument("apk")
    p.add_argument("--out", default="java")
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--show-bad-code", action="store_true")
    p.add_argument("--deobf", action="store_true", help="rename obfuscated identifiers")
    p.add_argument("--no-res", action="store_true")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--jadx", help="path to the jadx launcher")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_decompile_java)

    p = sub.add_parser("java-search", help="regex search decompiled Java sources")
    p.add_argument("dir")
    p.add_argument("pattern")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--jadx")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_java_search)

    # ---------------- Frida ----------------------------------------------
    p = sub.add_parser("frida-server", help="push or start frida-server on a device")
    p.add_argument("action", choices=["push", "start"])
    p.add_argument("--binary", help="local frida-server binary (for 'push')")
    p.add_argument("--serial", help="adb device serial")
    p.add_argument("--args", help="extra frida-server arguments (for 'start')")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_frida_server)

    p = sub.add_parser("frida-ps", help="list processes visible to frida")
    p.add_argument("--serial")
    p.add_argument("--local", action="store_true", help="this machine instead of USB")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_frida_ps)

    p = sub.add_parser("frida-run", help="run a Frida script against a package or pid")
    p.add_argument("--script", required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--package")
    group.add_argument("--pid", type=int)
    p.add_argument("--attach", action="store_true", help="attach instead of spawning")
    p.add_argument("--serial")
    p.add_argument("--local", action="store_true")
    p.add_argument("--interactive", action="store_true", help="do not pass -q")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_frida_run)

    # ---------------- platform and AI ------------------------------------
    p = sub.add_parser("platform", help="show the host platform and what it enables")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_platform)

    p = sub.add_parser("ai-doctor", help="show configured AI providers and routing")
    p.add_argument("--config", help="path to ai.json")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ai_doctor)

    p = sub.add_parser(
        "ai",
        help="run a task with the AI agent (multi-provider, auto-routing, waits on rate limits)",
    )
    p.add_argument("task", help="what you want done, in plain language")
    p.add_argument("--apk", help="APK to work on")
    p.add_argument("--decoded", help="decoded smali tree the agent may edit")
    p.add_argument("--workdir", help="session directory (default: ~/.apkmod/work/ai/<id>)")
    p.add_argument("--config", help="path to ai.json")
    p.add_argument("--model", help="override the model")
    p.add_argument("--strategy", choices=["priority", "round-robin", "lowest-latency"])
    p.add_argument("--max-wait", type=int, help="max seconds to wait out rate limits")
    p.add_argument("--max-steps", type=int, default=12)
    p.add_argument("--yes", action="store_true", help="allow file-modifying tools")
    p.add_argument("--transcript", help="write the full transcript to this file")
    p.add_argument("--verbose", action="store_true", help="stream routing and tool events")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ai)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args) or 0)
    except ApkModError as exc:
        eprint(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        eprint("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
