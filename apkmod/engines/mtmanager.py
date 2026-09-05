"""
MT Manager adapter.

MT Manager's distinctive capabilities, minus the ones this toolkit already has
(smali editing lives in :mod:`apkmod.smali`, signing in :mod:`apkmod.signing`):

* **diff** -- compare two APKs entry by entry: what was added, removed, changed,
  and how big each change is. Implemented natively, so it works with no backend.
* **split APK handling** -- an XAPK/APKS is a zip of zips; this unpacks the
  base and config splits so they can be edited and reassembled.

The on-device app itself is not driven here; this is the equivalent
functionality on the desktop, which is where a diff is readable.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..util import ApkModError, find_binary, human_size, run
from .base import Engine, EngineStatus

__all__ = [
    "MTManagerEngine",
    "EntryDiff",
    "ApkDiff",
    "diff_apks",
    "open_bundle",
    "BundlePart",
]


@dataclass
class EntryDiff:
    name: str
    status: str  # added | removed | changed | identical
    old_size: int = 0
    new_size: int = 0
    old_crc: int = 0
    new_crc: int = 0
    old_sha256: str = ""
    new_sha256: str = ""

    @property
    def delta(self) -> int:
        return self.new_size - self.old_size

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "old_size": self.old_size,
            "new_size": self.new_size,
            "delta": self.delta,
            "old_sha256": self.old_sha256,
            "new_sha256": self.new_sha256,
        }

    def format(self) -> str:
        mark = {"added": "+", "removed": "-", "changed": "~", "identical": " "}[self.status]
        if self.status == "identical":
            return f"  {self.name}"
        if self.status == "added":
            return f"{mark} {self.name}  (+{human_size(self.new_size)})"
        if self.status == "removed":
            return f"{mark} {self.name}  (-{human_size(self.old_size)})"
        return (
            f"{mark} {self.name}  {human_size(self.old_size)} -> "
            f"{human_size(self.new_size)} ({self.delta:+d} bytes)"
        )


@dataclass
class ApkDiff:
    left: str
    right: str
    entries: List[EntryDiff] = field(default_factory=list)

    @property
    def added(self) -> List[EntryDiff]:
        return [e for e in self.entries if e.status == "added"]

    @property
    def removed(self) -> List[EntryDiff]:
        return [e for e in self.entries if e.status == "removed"]

    @property
    def changed(self) -> List[EntryDiff]:
        return [e for e in self.entries if e.status == "changed"]

    @property
    def identical(self) -> List[EntryDiff]:
        return [e for e in self.entries if e.status == "identical"]

    @property
    def changed_bytes(self) -> int:
        return sum(abs(e.delta) for e in self.entries if e.status != "identical")

    def interesting(self, *, include_identical: bool = False) -> List[EntryDiff]:
        rows = [e for e in self.entries if include_identical or e.status != "identical"]
        rank = {"removed": 0, "added": 1, "changed": 2, "identical": 3}
        return sorted(rows, key=lambda e: (rank[e.status], -abs(e.delta), e.name))

    def as_dict(self) -> dict:
        return {
            "left": self.left,
            "right": self.right,
            "counts": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
                "identical": len(self.identical),
            },
            "changed_bytes": self.changed_bytes,
            "entries": [e.as_dict() for e in self.entries],
        }

    def format(self, *, include_identical: bool = False, limit: int = 200) -> str:
        rows = self.interesting(include_identical=include_identical)
        head = (
            f"{Path(self.left).name} -> {Path(self.right).name}: "
            f"+{len(self.added)} -{len(self.removed)} ~{len(self.changed)} "
            f"={len(self.identical)}  ({human_size(self.changed_bytes)} changed)"
        )
        body = [e.format() for e in rows[:limit]]
        if len(rows) > limit:
            body.append(f"  ... and {len(rows) - limit} more")
        return "\n".join([head, *body])


def _digest(zf: zipfile.ZipFile, name: str) -> str:
    """SHA-256 of the *uncompressed* content, so recompression does not lie."""
    return hashlib.sha256(zf.read(name)).hexdigest()


def _inventory(path: Path) -> Dict[str, zipfile.ZipInfo]:
    if not Path(path).is_file():
        raise ApkModError(f"no such file: {path}")
    try:
        with zipfile.ZipFile(path) as zf:
            return {i.filename: i for i in zf.infolist()}
    except zipfile.BadZipFile as exc:
        raise ApkModError(f"{path} is not a readable zip/APK: {exc}") from exc


def diff_apks(left: Path, right: Path, *, compare_content: bool = True) -> ApkDiff:
    """
    Compare two APKs entry by entry.

    CRC from the central directory is enough to spot a change, but it is only
    32 bits and two builds of the same source differ in timestamps. So when
    ``compare_content`` is set (the default) a differing CRC is confirmed with a
    SHA-256 of the decompressed bytes, which is what you actually care about.
    """
    left, right = Path(left), Path(right)
    left_index, right_index = _inventory(left), _inventory(right)
    result = ApkDiff(left=str(left), right=str(right))

    with zipfile.ZipFile(left) as zleft, zipfile.ZipFile(right) as zright:
        for name in sorted(set(left_index) | set(right_index)):
            old, new = left_index.get(name), right_index.get(name)
            if old is None:
                result.entries.append(
                    EntryDiff(
                        name=name,
                        status="added",
                        new_size=new.file_size,
                        new_crc=new.CRC,
                        new_sha256=_digest(zright, name) if compare_content else "",
                    )
                )
            elif new is None:
                result.entries.append(
                    EntryDiff(
                        name=name,
                        status="removed",
                        old_size=old.file_size,
                        old_crc=old.CRC,
                        old_sha256=_digest(zleft, name) if compare_content else "",
                    )
                )
            else:
                differs = old.CRC != new.CRC or old.file_size != new.file_size
                if differs and compare_content:
                    differs = _digest(zleft, name) != _digest(zright, name)
                result.entries.append(
                    EntryDiff(
                        name=name,
                        status="changed" if differs else "identical",
                        old_size=old.file_size,
                        new_size=new.file_size,
                        old_crc=old.CRC,
                        new_crc=new.CRC,
                        old_sha256=_digest(zleft, name) if differs and compare_content else "",
                        new_sha256=_digest(zright, name) if differs and compare_content else "",
                    )
                )
    return result


# ==========================================================================
# split APK bundles
# ==========================================================================
@dataclass
class BundlePart:
    name: str  # e.g. base.apk, config.arm64_v8a.apk
    path: Path
    is_base: bool
    size: int

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": str(self.path),
            "is_base": self.is_base,
            "size": self.size,
            "size_human": human_size(self.size),
        }


def open_bundle(bundle: Path, out_dir: Path) -> Tuple[List[BundlePart], List[str]]:
    """
    Unpack an XAPK/APKS/XAPK-style bundle into its constituent APKs.

    Returns the parts plus any non-APK files that were alongside them (manifest
    JSON, icons, OBB files), which callers need in order to reassemble.
    """
    bundle, out_dir = Path(bundle), Path(out_dir)
    if not bundle.is_file():
        raise ApkModError(f"no such file: {bundle}")
    out_dir.mkdir(parents=True, exist_ok=True)

    parts: List[BundlePart] = []
    others: List[str] = []
    with zipfile.ZipFile(bundle) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = out_dir / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))
            if info.filename.lower().endswith(".apk"):
                parts.append(
                    BundlePart(
                        name=info.filename,
                        path=target,
                        is_base=Path(info.filename).stem.lower() in ("base", "split_config.base"),
                        size=info.file_size,
                    )
                )
            else:
                others.append(info.filename)
    if not parts:
        raise ApkModError(f"{bundle} contains no .apk members; is it really a bundle?")
    # base first, then config splits alphabetically
    parts.sort(key=lambda p: (not p.is_base, p.name))
    return parts, others


def rebuild_bundle(parts: List[BundlePart], others_dir: Optional[Path], out: Path) -> Path:
    """
    Reassemble parts (and any sidecar files) into a single bundle zip.

    ``others_dir`` is normally the directory the bundle was unpacked into, which
    still contains the parts themselves -- so they are skipped here, or every
    APK would be written twice.
    """
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = set()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as zf:
        for part in parts:
            if not Path(part.path).is_file():
                raise ApkModError(f"missing part: {part.path}")
            zf.write(part.path, part.name)
            written.add(part.name)
        if others_dir and Path(others_dir).is_dir():
            for path in sorted(Path(others_dir).rglob("*")):
                if not path.is_file():
                    continue
                arcname = str(path.relative_to(others_dir))
                if arcname in written:
                    continue
                zf.write(path, arcname)
                written.add(arcname)
    return out


# ==========================================================================
# engine
# ==========================================================================
class MTManagerEngine(Engine):
    name = "mtmanager"
    label = "MT Manager (native equivalents)"
    description = (
        "APK diffing and split-bundle handling, implemented natively. "
        "Smali regex editing and auto-signing come from the shared modules."
    )
    capabilities = ["diff-apks", "split-bundles", "regex-dex-edit", "auto-sign"]

    def status(self) -> EngineStatus:
        notes = [
            "diff and bundle handling are native Python -- always available",
            "regex smali editing is provided by `apkmod smali-search`/`smali-replace`",
            "auto-signing is provided by `apkmod sign`",
        ]
        return EngineStatus(
            name=self.name,
            label=self.label,
            available=True,
            description=self.description,
            capabilities=self.capabilities,
            notes=notes,
        )
