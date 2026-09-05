"""Small shared helpers: logging, shelling out, hashing, paths."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

__all__ = [
    "ApkModError",
    "ToolResult",
    "run",
    "sha256_file",
    "sha256_bytes",
    "human_size",
    "cache_dir",
    "work_dir",
    "find_binary",
    "read_bytes",
]


class ApkModError(Exception):
    """Raised for any user-facing failure. The CLI turns this into a clean exit."""


@dataclass
class ToolResult:
    """Result of shelling out to a backend tool (apktool, adb, apksigner...)."""

    cmd: Sequence[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    ok: bool = True

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


def run(
    cmd: Sequence[str | os.PathLike],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    input_data: bytes | None = None,
    env: dict | None = None,
) -> ToolResult:
    """Run a subprocess, never raising for a non-zero exit code."""
    argv = [str(c) for c in cmd]
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError as exc:
        return ToolResult(argv, 127, "", f"executable not found: {exc.filename}", ok=False)
    except subprocess.TimeoutExpired as exc:
        return ToolResult(argv, 124, "", f"timed out after {timeout}s: {exc}", ok=False)
    return ToolResult(
        argv,
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
        ok=proc.returncode == 0,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def read_bytes(path: Path) -> bytes:
    return Path(path).read_bytes()


def human_size(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(num) < 1024 or unit == "GiB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024
    return f"{num:.1f} GiB"


def _base_dir(env_var: str, default: str) -> Path:
    override = os.environ.get(env_var)
    path = Path(override).expanduser() if override else Path(default).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_dir() -> Path:
    """Where downloaded backends (apktool jar, signer jar) live."""
    return _base_dir("APKMOD_CACHE", "~/.apkmod/cache")


def work_dir() -> Path:
    """Scratch space for decoded trees and rebuilt APKs."""
    return _base_dir("APKMOD_WORK", "~/.apkmod/work")


def find_binary(names: Iterable[str], extra_dirs: Sequence[str] = ()) -> str | None:
    """Locate a binary on PATH, optionally searching extra directories first."""
    for directory in extra_dirs:
        for name in names:
            candidate = Path(directory) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def eprint(*args: object, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)
