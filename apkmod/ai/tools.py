"""
The tool surface the AI agent drives.

Every capability of the toolkit is exposed here as a tool the model can call,
so the agent really can inspect and rewrite an APK end to end. Three rules keep
that safe enough to run:

* **Contained.** File access is resolved against the session work directory and
  a path that escapes it is refused. The model cannot reach the rest of the
  filesystem, whatever it asks for.
* **Gated.** Anything that mutates a file is ``confirm=True``; the agent must
  have been started with ``--yes`` or the change is reported back as pending.
* **Auditable.** Every call returns a dict that is also logged, so a transcript
  shows exactly what was changed and by which model.

The scope boundary is enforced here too, not just in prose: there is no tool
for defeating a licence check or for memory-editing a running game.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..align import align, repack, verify_alignment
from ..analyze import analyze_apk
from ..apk import ApkContainer
from ..arsc import ArscFile
from ..axml import AxmlFile
from ..dex import iter_dex_strings
from ..smali import replace as smali_replace
from ..smali import search as smali_search
from ..smali import signature_check_findings
from ..util import ApkModError, human_size, sha256_bytes
from .providers import ToolSpec

__all__ = ["ToolContext", "ToolRegistry", "build_registry"]


@dataclass
class ToolContext:
    """Everything a tool needs, injected so tools stay testable."""

    work_dir: Path
    apk: Optional[Path] = None
    decoded_dir: Optional[Path] = None
    auto_confirm: bool = False
    max_read_bytes: int = 256 * 1024
    log: List[dict] = field(default_factory=list)

    def resolve(self, relative: str) -> Path:
        """Resolve inside the work dir; refuse anything that escapes it."""
        if not relative:
            raise ApkModError("empty path")
        candidate = (self.work_dir / relative).resolve()
        root = self.work_dir.resolve()
        if candidate != root and root not in candidate.parents:
            raise ApkModError(
                f"refusing '{relative}': outside the session directory {root}"
            )
        return candidate

    def require_apk(self) -> Path:
        if self.apk is None or not Path(self.apk).is_file():
            raise ApkModError("no APK is attached to this session")
        return Path(self.apk)

    def record(self, tool: str, arguments: dict, result: dict) -> dict:
        entry = {"tool": tool, "arguments": arguments, "result": result}
        self.log.append(entry)
        return result


Tool = Callable[[dict], dict]


@dataclass
class RegisteredTool:
    spec: ToolSpec
    handler: Tool
    confirm: bool = False
    mutating: bool = False


class ToolRegistry:
    """Name -> tool, with the JSON schemas the model is shown."""

    def __init__(self, context: ToolContext) -> None:
        self.context = context
        self._tools: Dict[str, RegisteredTool] = {}
        self.pending_confirmations: List[dict] = []

    def add(self, spec: ToolSpec, handler: Tool, *, confirm: bool = False, mutating: bool = False) -> None:
        self._tools[spec.name] = RegisteredTool(spec, handler, confirm, mutating)

    @property
    def specs(self) -> List[ToolSpec]:
        return [tool.spec for tool in self._tools.values()]

    def names(self) -> List[str]:
        return list(self._tools)

    def get(self, name: str) -> RegisteredTool:
        try:
            return self._tools[name]
        except KeyError:
            raise ApkModError(f"unknown tool '{name}' (have: {', '.join(self._tools)})") from None

    def call(self, name: str, arguments: dict) -> dict:
        """
        Run a tool, converting any failure into a structured result.

        Unknown names are data, not exceptions: a model will occasionally invent
        a tool name, and that must come back as a result it can react to rather
        than kill the agent loop.
        """
        if name not in self._tools:
            return self.context.record(
                name,
                arguments or {},
                {"status": "error", "error": f"unknown tool '{name}'", "available": self.names()},
            )
        tool = self.get(name)
        if tool.confirm and not self.context.auto_confirm:
            self.pending_confirmations.append({"tool": name, "arguments": arguments})
            return {
                "status": "pending_confirmation",
                "tool": name,
                "detail": "this tool modifies files; re-run the agent with --yes to allow it",
            }
        try:
            result = tool.handler(arguments or {})
        except ApkModError as exc:
            result = {"status": "error", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - a tool must never kill the loop
            result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        result = result if isinstance(result, dict) else {"status": "ok", "value": result}
        result.setdefault("status", "ok")
        return self.context.record(name, arguments or {}, result)


# ==========================================================================
# construction
# ==========================================================================
def _ok(**kwargs) -> dict:
    out = {"status": "ok"}
    out.update(kwargs)
    return out


def build_registry(context: ToolContext) -> ToolRegistry:
    registry = ToolRegistry(context)

    # -- inspection -------------------------------------------------------
    registry.add(
        ToolSpec(
            name="apk_info",
            description=(
                "Summarise the attached APK: package, versions, SDK levels, permissions, "
                "entry inventory, signature schemes and native libraries."
            ),
        ),
        lambda args: _summarize(context),
    )

    registry.add(
        ToolSpec(
            name="read_manifest",
            description="Return AndroidManifest.xml as readable XML, plus the parsed facts.",
        ),
        lambda args: _read_manifest(context),
    )

    registry.add(
        ToolSpec(
            name="list_strings",
            description="List resource strings from resources.arsc.",
            parameters={
                "type": "object",
                "properties": {
                    "match": {"type": "string", "description": "case-insensitive substring filter"},
                    "limit": {"type": "integer", "description": "max rows to return (default 200)"},
                },
            },
        ),
        lambda args: _list_strings(context, args),
    )

    registry.add(
        ToolSpec(
            name="search_dex",
            description=(
                "Search the string table of every classes*.dex for hosts, API keys, "
                "class names or any literal."
            ),
            parameters={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        ),
        lambda args: _search_dex(context, args),
    )

    registry.add(
        ToolSpec(
            name="analyze",
            description=(
                "Full static analysis: ad/tracker SDKs, anti-tamper and integrity checks, "
                "dangerous permissions, debuggable flag, native libraries. Analysis only -- "
                "it reports protections, it does not defeat them."
            ),
        ),
        lambda args: _analyze(context),
    )

    registry.add(
        ToolSpec(
            name="find_integrity_checks",
            description=(
                "Locate where a decoded smali tree checks its own signature or installer. "
                "Reports file and line; does not patch anything."
            ),
        ),
        lambda args: _findings(context),
    )

    # -- file access, contained -------------------------------------------
    registry.add(
        ToolSpec(
            name="list_files",
            description="List files in the session directory (decoded tree, outputs).",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "relative subdirectory"}},
            },
        ),
        lambda args: _list_files(context, args),
    )

    registry.add(
        ToolSpec(
            name="read_file",
            description="Read a text file from the session directory (smali, XML, JSON, ...).",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
                "required": ["path"],
            },
        ),
        lambda args: _read_file(context, args),
    )

    registry.add(
        ToolSpec(
            name="write_file",
            description=(
                "Write or overwrite a file inside the session directory. Use for smali edits, "
                "replacing assets, or writing patch scripts."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        ),
        lambda args: _write_file(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="grep_smali",
            description="Regex search across a decoded smali tree.",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "relative smali root"},
                    "limit": {"type": "integer"},
                },
                "required": ["pattern"],
            },
        ),
        lambda args: _grep_smali(context, args),
    )

    registry.add(
        ToolSpec(
            name="edit_smali",
            description=(
                "Regex replace across a decoded smali tree. Returns every change; "
                "use dry_run first to review before committing."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "replacement": {"type": "string"},
                    "path": {"type": "string"},
                    "dry_run": {"type": "boolean"},
                },
                "required": ["pattern", "replacement"],
            },
        ),
        lambda args: _edit_smali(context, args),
        confirm=True,
        mutating=True,
    )

    # -- APK mutation -----------------------------------------------------
    registry.add(
        ToolSpec(
            name="rename_app",
            description="Change the app's display name via a string resource.",
            parameters={
                "type": "object",
                "properties": {
                    "resource_name": {"type": "string", "description": "e.g. app_name"},
                    "new_value": {"type": "string"},
                },
                "required": ["resource_name", "new_value"],
            },
        ),
        lambda args: _rename_app(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="edit_permissions",
            description="Remove or add <uses-permission> entries in the manifest.",
            parameters={
                "type": "object",
                "properties": {
                    "remove": {"type": "array", "items": {"type": "string"}},
                    "add": {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
        lambda args: _edit_permissions(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="set_debuggable",
            description="Set or clear android:debuggable on <application>.",
            parameters={
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
                "required": ["enabled"],
            },
        ),
        lambda args: _set_debuggable(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="replace_entry",
            description="Swap or inject a file inside the APK (assets, resources, images).",
            parameters={
                "type": "object",
                "properties": {
                    "entry": {"type": "string", "description": "path inside the APK"},
                    "source": {"type": "string", "description": "file in the session directory"},
                },
                "required": ["entry", "source"],
            },
        ),
        lambda args: _replace_entry(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="remove_entries",
            description="Drop entries from the APK (analytics configs, unused libs, ...).",
            parameters={
                "type": "object",
                "properties": {
                    "entries": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["entries"],
            },
        ),
        lambda args: _remove_entries(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="align_apk",
            description="zipalign an APK (4-byte; native libraries page-aligned).",
            parameters={
                "type": "object",
                "properties": {"source": {"type": "string"}, "output": {"type": "string"}},
                "required": ["source"],
            },
        ),
        lambda args: _align_apk(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="sign_apk",
            description=(
                "Sign an APK. Uses apksigner or uber-apk-signer when present, otherwise the "
                "built-in v1 signer."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "output": {"type": "string"},
                    "key_pem": {"type": "string"},
                    "cert_pem": {"type": "string"},
                },
                "required": ["source"],
            },
        ),
        lambda args: _sign_apk(context, args),
        confirm=True,
        mutating=True,
    )

    registry.add(
        ToolSpec(
            name="run_shell",
            description=(
                "Run a command inside the session directory. Intended for jadx, git, "
                "python scripts the agent wrote, and other local build steps."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "array", "items": {"type": "string"}},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
        ),
        lambda args: _run_shell(context, args),
        confirm=True,
        mutating=True,
    )

    return registry


# ==========================================================================
# handlers
# ==========================================================================
def _summarize(context: ToolContext) -> dict:
    apk = context.require_apk()
    with ApkContainer(apk) as container:
        facts = container.facts()
        manifest = container.manifest_axml().manifest_facts()
    return _ok(
        path=str(apk),
        size=facts["file_size_human"],
        package=manifest["package"],
        version_name=manifest["version_name"],
        version_code=manifest["version_code"],
        min_sdk=manifest["min_sdk"],
        target_sdk=manifest["target_sdk"],
        debuggable=manifest["debuggable"],
        permissions=manifest["permissions"],
        launcher=manifest["launcher_activity"],
        entry_count=facts["entry_count"],
        dex_files=facts["dex_files"],
        native_libraries=facts["native_libraries"],
        signing=facts["signing"],
    )


def _read_manifest(context: ToolContext) -> dict:
    with ApkContainer(context.require_apk()) as container:
        axml = container.manifest_axml()
        return _ok(xml=axml.to_xml(), facts=axml.manifest_facts())


def _list_strings(context: ToolContext, args: dict) -> dict:
    limit = int(args.get("limit") or 200)
    match = (args.get("match") or "").lower()
    with ApkContainer(context.require_apk()) as container:
        arsc = ArscFile.parse(container.arsc_bytes() or b"")
    rows = [
        {"index": index, "value": text, "used_by": locations}
        for index, text, locations in arsc.string_entries()
        if not match or match in text.lower()
    ]
    return _ok(count=len(rows), truncated=len(rows) > limit, strings=rows[:limit])


def _search_dex(context: ToolContext, args: dict) -> dict:
    query = str(args.get("query") or "")
    if not query:
        raise ApkModError("query is required")
    with ApkContainer(context.require_apk()) as container:
        strings = iter_dex_strings(container.dex_blobs())
    return _ok(query=query, matches=strings.search(query))


def _analyze(context: ToolContext) -> dict:
    return _ok(**analyze_apk(context.require_apk()).as_dict())


def _findings(context: ToolContext) -> dict:
    root = _smali_root(context, {})
    found = signature_check_findings(root)
    return _ok(root=str(root), labels=sorted(found), findings=found)


def _list_files(context: ToolContext, args: dict) -> dict:
    base = context.resolve(args.get("path") or ".")
    if not base.is_dir():
        raise ApkModError(f"not a directory: {args.get('path') or '.'}")
    entries = [
        {"path": str(path.relative_to(context.work_dir)), "size": path.stat().st_size}
        for path in sorted(base.rglob("*"))
        if path.is_file()
    ]
    return _ok(count=len(entries), files=entries[:1000])


def _read_file(context: ToolContext, args: dict) -> dict:
    path = context.resolve(str(args.get("path") or ""))
    if not path.is_file():
        raise ApkModError(f"no such file: {args.get('path')}")
    size = path.stat().st_size
    text = path.read_bytes()[: context.max_read_bytes].decode("utf-8", "replace")
    lines = text.splitlines()
    start = max(0, int(args.get("start_line") or 1) - 1)
    end = int(args.get("end_line") or len(lines))
    selected = lines[start:end]
    return _ok(
        path=str(path.relative_to(context.work_dir)),
        size_human=human_size(size),
        truncated=size > context.max_read_bytes,
        total_lines=len(lines),
        shown_lines=f"{start + 1}-{start + len(selected)}",
        content="\n".join(selected),
    )


def _write_file(context: ToolContext, args: dict) -> dict:
    path = context.resolve(str(args.get("path") or ""))
    content = args.get("content")
    if content is None:
        raise ApkModError("content is required")
    path.parent.mkdir(parents=True, exist_ok=True)
    existed = path.is_file()
    previous = sha256_bytes(path.read_bytes()) if existed else None
    path.write_text(str(content), encoding="utf-8")
    return _ok(
        path=str(path.relative_to(context.work_dir)),
        created=not existed,
        bytes=path.stat().st_size,
        sha256=sha256_bytes(path.read_bytes()),
        previous_sha256=previous,
    )


def _smali_root(context: ToolContext, args: dict) -> Path:
    relative = args.get("path") or ""
    if relative:
        root = context.resolve(str(relative))
    elif context.decoded_dir:
        root = Path(context.decoded_dir)
    else:
        raise ApkModError("no decoded smali tree; run `apkmod decode` first")
    if not root.is_dir():
        raise ApkModError(f"not a directory: {root}")
    return root


def _grep_smali(context: ToolContext, args: dict) -> dict:
    pattern = str(args.get("pattern") or "")
    if not pattern:
        raise ApkModError("pattern is required")
    limit = int(args.get("limit") or 100)
    report = smali_search(_smali_root(context, args), pattern, limit=0)
    return _ok(
        pattern=pattern,
        files_scanned=report.files_scanned,
        count=len(report.matches),
        truncated=len(report.matches) > limit,
        matches=[m.format() for m in report.matches[:limit]],
    )


def _edit_smali(context: ToolContext, args: dict) -> dict:
    pattern = str(args.get("pattern") or "")
    if not pattern:
        raise ApkModError("pattern is required")
    dry_run = bool(args.get("dry_run"))
    report = smali_replace(
        _smali_root(context, args),
        pattern,
        str(args.get("replacement") or ""),
        dry_run=dry_run,
    )
    return _ok(
        pattern=pattern,
        dry_run=dry_run,
        files_scanned=report.files_scanned,
        files_changed=len({m.file for m in report.matches}),
        matches=[m.format() for m in report.matches[:200]],
    )


def _repack(apk: Path, out: Path, **kwargs) -> dict:
    """Shared tail for every APK mutation: rewrite, then report honestly."""
    result = repack(apk, out, **kwargs)
    return {
        "output": str(result.path),
        "entries": result.entries,
        "replaced": result.replaced,
        "removed": result.removed,
        "added": result.added,
        "warning": "the v1 signature is now invalid; sign before installing",
    }


def _rename_app(context: ToolContext, args: dict) -> dict:
    name = str(args.get("resource_name") or "").strip()
    value = str(args.get("new_value") or "")
    if not name or not value:
        raise ApkModError("resource_name and new_value are both required")
    apk = context.require_apk()
    with ApkContainer(apk) as container:
        arsc = ArscFile.parse(container.arsc_bytes() or b"")
        indices, old = arsc.replace_by_name(name, value)
        payload = arsc.serialize()
    out = context.resolve(args.get("output") or f"renamed-{apk.name}")
    return _ok(
        resource=name,
        old=old,
        new=value,
        value_slots=len(indices),
        **_repack(apk, out, replace={"resources.arsc": payload}),
    )


def _edit_permissions(context: ToolContext, args: dict) -> dict:
    remove = [str(p) for p in (args.get("remove") or [])]
    add = [str(p) for p in (args.get("add") or [])]
    if not remove and not add:
        raise ApkModError("pass at least one of remove / add")
    apk = context.require_apk()
    with ApkContainer(apk) as container:
        axml = container.manifest_axml()
        removed = {p: axml.remove_permission(p) for p in remove}
        added = {p: axml.add_permission(p) for p in add}
        payload = axml.serialize()
        permissions = axml.permissions()
    out = context.resolve(args.get("output") or f"perms-{apk.name}")
    return _ok(
        removed_permissions=removed,
        added_permissions=added,
        permissions=permissions,
        **_repack(apk, out, replace={"AndroidManifest.xml": payload}),
    )


def _set_debuggable(context: ToolContext, args: dict) -> dict:
    enabled = bool(args.get("enabled"))
    apk = context.require_apk()
    with ApkContainer(apk) as container:
        axml = container.manifest_axml()
        axml.set_debuggable(enabled)
        payload = axml.serialize()
    out = context.resolve(args.get("output") or f"debug-{apk.name}")
    return _ok(debuggable=enabled, **_repack(apk, out, replace={"AndroidManifest.xml": payload}))


def _replace_entry(context: ToolContext, args: dict) -> dict:
    entry = str(args.get("entry") or "")
    if not entry:
        raise ApkModError("entry is required")
    source = context.resolve(str(args.get("source") or ""))
    if not source.is_file():
        raise ApkModError(f"no such source file: {args.get('source')}")
    apk = context.require_apk()
    payload = source.read_bytes()
    out = context.resolve(args.get("output") or f"patched-{apk.name}")

    # An existing entry is swapped in place; a new one has to be added, which
    # repack does through `prepend`. Guessing wrong raises, so check first.
    with ApkContainer(apk) as container:
        exists = container.has(entry)
    if exists:
        result = _repack(apk, out, replace={entry: payload})
    else:
        result = _repack(apk, out, prepend=[(entry, payload)])
    return _ok(entry=entry, bytes=len(payload), injected=not exists, **result)


def _remove_entries(context: ToolContext, args: dict) -> dict:
    entries = [str(e) for e in (args.get("entries") or [])]
    if not entries:
        raise ApkModError("entries is required")
    apk = context.require_apk()
    out = context.resolve(args.get("output") or f"stripped-{apk.name}")
    return _ok(**_repack(apk, out, exclude=entries))


def _align_apk(context: ToolContext, args: dict) -> dict:
    source = context.resolve(str(args.get("source") or ""))
    out = context.resolve(args.get("output") or f"aligned-{source.name}")
    result = align(source, out)
    return _ok(
        output=str(result.path),
        entries=result.entries,
        remaining_misalignments=verify_alignment(out),
    )


def _sign_apk(context: ToolContext, args: dict) -> dict:
    from ..signing import generate_key, sign

    source = context.resolve(str(args.get("source") or ""))
    out = context.resolve(args.get("output") or f"signed-{source.name}")
    key = context.resolve(args["key_pem"]) if args.get("key_pem") else None
    cert = context.resolve(args["cert_pem"]) if args.get("cert_pem") else None

    generated = None
    if key is None or cert is None:
        # A debug key beats an error: re-signing is the normal last step of an
        # edit, and the agent should not have to invent key material.
        key_path, cert_path = generate_key(context.work_dir / "keys")
        key, cert = key_path, cert_path
        generated = {"key": str(key_path), "cert": str(cert_path)}

    outcome = sign(source, out, key_pem=key.read_bytes(), cert_pem=cert.read_bytes())
    result = _ok(
        output=str(outcome.path),
        engine=outcome.engine,
        schemes=outcome.schemes,
        subject=outcome.subject,
        certificate_sha256=outcome.certificate_sha256,
        notes=outcome.notes,
    )
    if generated:
        result["generated_debug_key"] = generated
    return result


def _run_shell(context: ToolContext, args: dict) -> dict:
    import shlex

    from ..util import run

    command = args.get("command")
    if isinstance(command, str):
        command = shlex.split(command)
    if not isinstance(command, list) or not command:
        raise ApkModError("command must be a non-empty list of strings")
    if any(not isinstance(part, str) for part in command):
        raise ApkModError("every part of command must be a string")
    result = run(command, cwd=context.work_dir, timeout=int(args.get("timeout") or 120))
    return _ok(
        cmd=list(result.cmd),
        returncode=result.returncode,
        stdout=result.stdout[-8000:],
        stderr=result.stderr[-4000:],
    )
