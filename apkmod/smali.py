"""Operations on a decoded smali tree (the output of ``apkmod decode``)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List

from .util import ApkModError

__all__ = ["search", "replace", "stats", "signature_check_findings"]

SIGNATURE_PATTERNS = {
    "reads PackageInfo signatures": r"getPackageInfo|GET_SIGNATURES|GET_SIGNING_CERTIFICATES|signingInfo",
    "compares a signature hash": r"MessageDigest|SHA-?1|SHA-?256|->digest\(",
    "checks the installer": r"getInstallerPackageName|getInstallSourceInfo|com/android/vending",
    "licence library": r"LicenseChecker|vending/licensing",
    "root / emulator detection": r"RootBeer|isEmulator|goldfish|ranchu|/system/xbin/su",
    "hooking detection": r"frida|xposed|substrate",
}


@dataclass
class Match:
    file: str
    line: int
    text: str

    def format(self) -> str:
        return f"{self.file}:{self.line}: {self.text.strip()}"


@dataclass
class SearchReport:
    pattern: str
    matches: List[Match] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def files_with_matches(self) -> int:
        return len({m.file for m in self.matches})


def _smali_files(root: Path) -> Iterable[Path]:
    root = Path(root)
    if not root.is_dir():
        raise ApkModError(f"not a directory: {root}")
    return sorted(root.rglob("*.smali"))


def search(root: Path, pattern: str, *, ignore_case: bool = True, limit: int = 0) -> SearchReport:
    """Regex search across every .smali file in a decoded project."""
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        raise ApkModError(f"bad regex: {exc}") from exc
    report = SearchReport(pattern=pattern)
    for path in _smali_files(root):
        report.files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                report.matches.append(Match(str(path), number, line))
                if limit and len(report.matches) >= limit:
                    return report
    return report


def replace(
    root: Path,
    pattern: str,
    replacement: str,
    *,
    ignore_case: bool = True,
    dry_run: bool = False,
) -> SearchReport:
    """Regex replace across a decoded tree. Returns what matched / would change."""
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        raise ApkModError(f"bad regex: {exc}") from exc
    report = SearchReport(pattern=pattern)
    for path in _smali_files(root):
        report.files_scanned += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        new_text, count = rx.subn(replacement, text)
        if not count:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                report.matches.append(Match(str(path), number, line))
        if not dry_run:
            path.write_text(new_text, encoding="utf-8")
    return report


def signature_check_findings(root: Path) -> dict:
    """Where the anti-tamper logic lives, so you know what you are dealing with."""
    findings: dict = {}
    for label, pattern in SIGNATURE_PATTERNS.items():
        report = search(root, pattern)
        if report.matches:
            findings[label] = {
                "hits": len(report.matches),
                "files": sorted({m.file for m in report.matches})[:20],
                "examples": [m.format() for m in report.matches[:8]],
            }
    return findings


def stats(root: Path) -> dict:
    files = list(_smali_files(root))
    classes = [f for f in files if "classes" not in f.name]
    return {
        "smali_files": len(files),
        "root": str(root),
        "total_lines": sum(len(f.read_text(encoding="utf-8", errors="replace").splitlines()) for f in files[:2000]),
        "smali_dirs": sorted({p.name for p in Path(root).iterdir() if p.is_dir() and p.name.startswith("smali")}),
    }
