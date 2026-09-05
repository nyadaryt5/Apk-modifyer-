"""
JADX adapter -- decompile DEX back to readable Java.

Apktool gives you smali, which is faithful but assembly-shaped. JADX gives you
Java you can actually read, which is what you want when tracing how a feature or
a protection works. This drives the real ``jadx`` binary; it does not
reimplement a decompiler.

Decompilation is lossy and JADX says so per class, so the result carries its
warnings rather than hiding them.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import List, Optional, Sequence

from ..util import ApkModError, cache_dir, find_binary, run
from .base import Engine, EngineStatus

__all__ = ["JadxEngine", "find_jadx", "JADX_RELEASE"]

JADX_RELEASE = "https://github.com/skylot/jadx/releases"
DEFAULT_VERSION = "1.5.1"


def find_jadx(explicit: Optional[str] = None) -> Optional[str]:
    """Locate a jadx launcher: explicit, JADX_HOME, cache, or PATH."""
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate)
        raise ApkModError(f"no jadx at {candidate}")
    for variable in ("JADX_HOME", "JADX_PATH"):
        import os

        value = os.environ.get(variable)
        if value:
            candidate = Path(value).expanduser()
            candidate = candidate / "bin" / "jadx" if candidate.is_dir() else candidate
            if candidate.is_file():
                return str(candidate)
    cached = find_binary(
        ["jadx", "jadx.bat"], extra_dirs=[str(cache_dir() / "jadx" / "bin"), str(cache_dir())]
    )
    return cached or shutil.which("jadx")


class JadxEngine(Engine):
    name = "jadx"
    label = "JADX"
    description = "Decompile DEX to readable Java, for tracing logic and protections."
    capabilities = ["decompile-java", "search-code", "export-sources"]

    def __init__(self, binary: Optional[str] = None) -> None:
        self._binary = binary

    def status(self) -> EngineStatus:
        binary = None
        try:
            binary = find_jadx(self._binary)
        except ApkModError as exc:
            return EngineStatus(
                name=self.name,
                label=self.label,
                available=False,
                description=self.description,
                capabilities=self.capabilities,
                notes=[str(exc)],
                install_hint=f"download from {JADX_RELEASE} (needs a JVM)",
            )
        if binary is None:
            return EngineStatus(
                name=self.name,
                label=self.label,
                available=False,
                description=self.description,
                capabilities=self.capabilities,
                notes=["the `jadx` launcher was not found"],
                install_hint=(
                    f"download jadx from {JADX_RELEASE}, or `apt install jadx`, "
                    "then put it on PATH or set JADX_HOME"
                ),
            )
        version = self._version(binary)
        return EngineStatus(
            name=self.name,
            label=self.label,
            available=True,
            description=self.description,
            version=version,
            location=binary,
            capabilities=self.capabilities,
        )

    @staticmethod
    def _version(binary: str) -> Optional[str]:
        result = run([binary, "--version"], timeout=60)
        if not result.ok:
            return None
        match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", result.output)
        return match.group(1) if match else result.output.strip()[:40]

    # -- operations -------------------------------------------------------
    def decompile(
        self,
        apk: Path,
        out_dir: Path,
        *,
        threads: int = 4,
        show_bad_code: bool = False,
        deobfuscate: bool = False,
        include_resources: bool = True,
        timeout: int = 900,
    ) -> dict:
        """
        Decompile an APK (or a bare .dex) into Java sources.

        JADX exits non-zero when some classes fail to decompile, which is normal
        for obfuscated code, so a non-zero exit is reported alongside whatever it
        did produce rather than treated as a hard failure.
        """
        binary = self._require()
        apk, out_dir = Path(apk), Path(out_dir)
        if not apk.is_file():
            raise ApkModError(f"no such file: {apk}")
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd: List[str] = [binary, "--output-dir", str(out_dir), "--threads", str(threads)]
        if show_bad_code:
            cmd.append("--show-bad-code")
        if deobfuscate:
            cmd.append("--deobf")
        if not include_resources:
            cmd.append("--no-res")
        cmd.append(str(apk))

        result = run(cmd, timeout=timeout)
        java = sorted(out_dir.rglob("*.java"))
        return {
            "ok": result.ok,
            "output": str(out_dir),
            "java_files": len(java),
            "warnings": _summarize(result.output),
            "returncode": result.returncode,
            "stderr_tail": result.stderr[-2000:],
            "note": (
                ""
                if result.ok
                else "jadx exited non-zero; obfuscated classes often partially fail "
                "and the sources produced are still usable"
            ),
        }

    def search(self, out_dir: Path, pattern: str, *, limit: int = 100) -> List[dict]:
        """Grep the decompiled sources. Cheaper than a smali search to read."""
        root = Path(out_dir)
        if not root.is_dir():
            raise ApkModError(f"no decompiled tree at {root}; run decompile first")
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ApkModError(f"bad regex: {exc}") from exc

        hits: List[dict] = []
        for path in sorted(root.rglob("*.java")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    hits.append(
                        {
                            "file": str(path.relative_to(root)),
                            "line": number,
                            "text": line.strip()[:300],
                        }
                    )
                    if len(hits) >= limit:
                        return hits
        return hits

    def _require(self) -> str:
        binary = find_jadx(self._binary)
        if not binary:
            raise ApkModError(
                "jadx is not installed; download it from "
                f"{JADX_RELEASE} or set JADX_HOME"
            )
        return binary


def _summarize(output: str, limit: int = 40) -> List[str]:
    """JADX's per-class warnings, deduplicated and bounded."""
    seen = []
    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        lowered = text.lower()
        if "warn" in lowered or "error" in lowered or "fail" in lowered:
            if text not in seen:
                seen.append(text)
        if len(seen) >= limit:
            break
    return seen
