"""``apkmod`` -- one command line for decompiling, editing, rebuilding and signing APKs.

Run ``apkmod --help`` for the command list, or ``apkmod doctor`` to see which
backends are wired up on this machine.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

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
    key_pem, cert_pem = _material(args)
    result = signing.sign_v1(
        Path(args.apk), Path(args.out), key_pem, cert_pem, signature_name=args.name, digest=args.digest
    )
    print(f"signed -> {result.path}")
    print(f"  entries : {result.signed_entries}")
    print(f"  digest  : {result.digest_name}")
    print(f"  cert    : {result.subject or 'unknown'} ({result.certificate_sha256[:32]}...)")
    check = signing.verify_v1(result.path)
    print(f"  verify  : {'OK' if check.ok else 'FAILED - ' + '; '.join(check.problems[:3])}")
    return 0 if check.ok else 1


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
    if args.index is not None:
        result = editor.replace_string(Path(args.apk), Path(args.out), "", args.new, index=args.index)
    else:
        if not args.old:
            raise ApkModError("give --old TEXT (or --index N) together with --new TEXT")
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

    p = sub.add_parser("sign", help="sign an APK (native v1, or apksigner if present)")
    p.add_argument("apk")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--name", default="APKMOD", help="META-INF block name")
    p.add_argument("--digest", default="sha-256", choices=["sha-256", "sha-512"])
    _add_signing_options(p)
    p.set_defaults(func=cmd_sign)

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
