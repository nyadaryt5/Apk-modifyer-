"""
Where this is running, and what that makes possible.

The toolkit runs on a Linux desktop and on Android itself (Termux), and the two
need genuinely different advice: a desktop has a JVM, a browser and adb, while a
phone has neither a desktop browser nor usually a JVM, but does have the device
itself -- so on-device editing beats pushing files back and forth.

Everything here is detection, never assumption. Each probe is a real check
(binary on PATH, path under the Termux prefix, root actually reachable), so the
output describes this machine rather than a guess about it.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .util import find_binary, run

__all__ = ["PlatformInfo", "detect", "describe"]

TERMUX_PREFIX = "/data/data/com.termux"


@dataclass
class PlatformInfo:
    system: str  # linux | android | darwin | windows | other
    family: str  # desktop | android | other
    release: str = ""
    machine: str = ""
    termux: bool = False
    root: bool = False
    binaries: dict = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def is_android(self) -> bool:
        return self.family == "android"

    def as_dict(self) -> dict:
        return {
            "system": self.system,
            "family": self.family,
            "release": self.release,
            "machine": self.machine,
            "termux": self.termux,
            "root": self.root,
            "binaries": self.binaries,
            "notes": self.notes,
        }

    def format(self) -> str:
        head = f"{self.system} ({self.family})"
        if self.release:
            head += f" {self.release}"
        head += f" / {self.machine}"
        lines = [head]
        if self.termux:
            lines.append("running inside Termux on Android")
        lines.append(f"root: {'yes' if self.root else 'no'}")
        present = [name for name, path in self.binaries.items() if path]
        missing = [name for name, path in self.binaries.items() if not path]
        lines.append(f"present: {', '.join(sorted(present)) or 'none'}")
        if missing:
            lines.append(f"missing: {', '.join(sorted(missing))}")
        for note in self.notes:
            lines.append(f"note: {note}")
        return "\n".join(lines)


def _is_termux() -> bool:
    prefix = os.environ.get("PREFIX", "")
    return prefix.startswith(TERMUX_PREFIX) or Path(TERMUX_PREFIX).is_dir()


def _is_android() -> bool:
    if _is_termux():
        return True
    # Android reports as Linux; the build fingerprint and these paths are the
    # reliable tells, since `uname` alone cannot distinguish the two.
    if Path("/system/build.prop").is_file() or Path("/system/bin/getprop").is_file():
        return True
    return platform.system().lower() == "android"


def _has_root() -> bool:
    """Check that root is actually reachable, not merely that `su` exists."""
    if shutil.which("su") is None:
        return False
    result = run(["su", "-c", "id -u"], timeout=10)
    return result.ok and result.stdout.strip().startswith("0")


def detect() -> PlatformInfo:
    system = platform.system().lower()
    android = _is_android()
    if android:
        family, name = "android", "android"
    elif system == "linux":
        family, name = "desktop", "linux"
    elif system == "darwin":
        family, name = "desktop", "macos"
    elif system == "windows":
        family, name = "desktop", "windows"
    else:
        family, name = "other", system or "unknown"

    info = PlatformInfo(
        system=name,
        family=family,
        release=platform.release(),
        machine=platform.machine(),
        termux=_is_termux(),
        root=_has_root(),
    )

    wanted = ["java", "adb", "openssl", "jadx", "frida", "frida-ps", "apktool", "aapt2"]
    info.binaries = {name: (find_binary([name]) or "") for name in wanted}

    _annotate(info)
    return info


def _annotate(info: PlatformInfo) -> None:
    if info.is_android:
        info.notes.append(
            "on Android the device is right here: prefer on-device editing "
            "(`apktool-m`) over pushing files to a PC"
        )
        if info.termux:
            info.notes.append(
                "Termux: `pkg install openjdk-17 openssl` enables the Apktool engine "
                "and the native signer"
            )
        if not info.binaries.get("java"):
            info.notes.append("no JVM found, so the desktop Apktool engine is unavailable here")
        if info.root:
            info.notes.append("root is available, so frida-server can be started on this device")
        else:
            info.notes.append(
                "no root: frida-server cannot run locally; use a PC with adb instead"
            )
    else:
        info.notes.append("desktop: use `adb` to reach a device for on-device workflows")
        if not info.binaries.get("adb"):
            info.notes.append("adb is missing, so device workflows (Apktool M, Frida) are unavailable")
        if not info.binaries.get("java"):
            info.notes.append("no JVM found; `pip install -e '.[apktool]'` installs one")


def describe(info: Optional[PlatformInfo] = None) -> str:
    return (info or detect()).format()
