"""Apktool adapter -- decode / build a full smali + resources project.

This one drives the real ``apktool`` jar through a JVM. Nothing is
reimplemented: when the jar is missing you get told how to get it rather than a
half-working approximation.
"""

from __future__ import annotations

import os
import re
import shutil
import sysconfig
from pathlib import Path
from typing import List, Optional, Sequence

from ..util import ApkModError, cache_dir, run
from .base import Engine, EngineStatus

__all__ = ["ApktoolEngine", "find_java", "find_apktool_jar"]

APKTOOL_RELEASE = "https://github.com/iBotPeaches/Apktool/releases/download/v{version}/apktool_{version}.jar"
DEFAULT_VERSION = "2.11.1"


def find_java() -> Optional[str]:
    """Locate a JVM: JAVA_HOME, PATH, then a pip-installed jdk4py runtime."""
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / "java"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("java")
    if found:
        return found
    patterns = [
        Path(sysconfig.get_paths()["purelib"]),
        Path(sysconfig.get_paths()["platlib"]),
    ]
    for base in patterns:
        for candidate in sorted(base.glob("jdk*/java-runtime/bin/java")):
            if candidate.is_file():
                return str(candidate)
    return None


def java_version(java: str) -> Optional[str]:
    result = run([java, "-version"])
    text = result.stdout + result.stderr
    match = re.search(r'version "([^"]+)"', text)
    return match.group(1) if match else None


def find_apktool_jar(explicit: Optional[Path] = None) -> Optional[str]:
    """Look for an apktool jar: explicit path, env var, cache, or a wrapper script."""
    if explicit:
        explicit = Path(explicit)
        if explicit.is_file():
            return str(explicit)
        raise ApkModError(f"no apktool jar at {explicit}")
    env = os.environ.get("APKMOD_APKTOOL_JAR")
    if env and Path(env).is_file():
        return env
    cached = sorted(cache_dir().glob("apktool*.jar"), key=lambda p: p.name, reverse=True)
    if cached:
        return str(cached[0])
    for candidate in ("/usr/local/bin/apktool", "/usr/bin/apktool"):
        if Path(candidate).is_file():
            return candidate
    wrapper = shutil.which("apktool")
    if wrapper:
        return wrapper
    return None


class ApktoolEngine(Engine):
    name = "apktool"
    label = "Apktool (desktop)"
    description = "Decompile to smali + resources and rebuild, via the Apktool jar."
    capabilities = ["decode", "build", "resources", "smali", "framework-install"]

    def __init__(self, jar: Optional[Path] = None) -> None:
        self.jar_override = jar

    # -- discovery --------------------------------------------------------
    def java(self) -> Optional[str]:
        return find_java()

    def jar(self) -> Optional[str]:
        try:
            return find_apktool_jar(self.jar_override)
        except ApkModError:
            return None

    def status(self) -> EngineStatus:
        notes: List[str] = []
        java = self.java()
        jar = self.jar()
        version = None
        if java is None:
            notes.append("no JVM found (JAVA_HOME, PATH, or pip install jdk4py)")
        else:
            version = java_version(java)
        if jar is None:
            notes.append("no apktool jar found")
        available = java is not None and jar is not None
        if available:
            probe = self._run(["--version"], timeout=60)
            if probe.ok:
                version = f"apktool {probe.stdout.strip()} on java {java_version(java) or '?'}"
            else:
                notes.append(f"apktool did not start: {probe.output[:160]}")
                available = False
        return EngineStatus(
            name=self.name,
            label=self.label,
            available=available,
            description=self.description,
            version=version,
            location=jar or java,
            capabilities=self.capabilities,
            notes=notes,
            install_hint=f"apkmod install-apktool [{DEFAULT_VERSION}]   # downloads the jar",
        )

    # -- execution --------------------------------------------------------
    def _run(self, args: Sequence[str], timeout: int = 1800):
        java = self.java()
        jar = self.jar()
        if java is None:
            raise ApkModError("no JVM available; install a JDK or `pip install jdk4py`")
        if jar is None:
            raise ApkModError(
                "no apktool jar available; run `apkmod install-apktool` or set APKMOD_APKTOOL_JAR"
            )
        if jar.endswith(".jar"):
            return run([java, "-jar", jar, *args], timeout=timeout)
        return run([jar, *args], timeout=timeout)

    def decode(
        self,
        apk: Path,
        out_dir: Path,
        *,
        resources: bool = True,
        sources: bool = True,
        force: bool = True,
        frame_path: Optional[Path] = None,
    ):
        args = ["d", str(apk), "-o", str(out_dir)]
        if force:
            args.append("--force")
        if not resources:
            args.append("--no-res")
        if not sources:
            args.append("--no-src")
        if frame_path:
            args += ["--frame-path", str(frame_path)]
        result = self._run(args)
        if not result.ok:
            raise ApkModError(f"apktool decode failed: {result.output[-800:]}")
        return out_dir

    def build(self, project: Path, out_apk: Path, *, use_aapt2: bool = True) -> Path:
        args = ["b", str(project), "-o", str(out_apk)]
        if use_aapt2:
            args.append("--use-aapt2")
        result = self._run(args)
        if not result.ok:
            raise ApkModError(f"apktool build failed: {result.output[-800:]}")
        return out_apk

    def install_framework(self, framework_apk: Path):
        result = self._run(["if", str(framework_apk)])
        if not result.ok:
            raise ApkModError(f"could not install framework: {result.output[-400:]}")
        return result.output


def install_apktool(version: str = DEFAULT_VERSION, dest: Optional[Path] = None) -> Path:
    """Download an apktool jar into the cache (needs outbound HTTPS to GitHub)."""
    dest_dir = Path(dest) if dest else cache_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f"apktool_{version}.jar"
    url = APKTOOL_RELEASE.format(version=version)
    if target.is_file():
        return target
    result = run(["curl", "-fSL", "--retry", "2", "-o", str(target), url], timeout=600)
    if not result.ok or not target.is_file() or target.stat().st_size < 1024:
        if target.exists():
            target.unlink()
        raise ApkModError(
            f"could not download {url}\n"
            f"({result.output.strip()[:200] or 'no output'})\n"
            "Download it manually and drop it in the cache, or set APKMOD_APKTOOL_JAR=/path/apktool.jar"
        )
    return target
