"""Apktool M adapter -- the same workflow, driven on an Android device over adb.

Apktool M (``bin.mt.plus``) does its decompiling on the phone, so this adapter
handles the parts a desktop can do: finding the device, checking the app is
installed, pushing the APK in, launching it, and pulling the result back.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import List, Optional

from ..util import ApkModError, run
from .base import Engine, EngineStatus

__all__ = ["ApktoolMEngine"]

PACKAGES = ("bin.mt.plus", "bin.mt.plus.canary")
DEVICE_DIR = "/sdcard/Download"


def find_adb() -> Optional[str]:
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    extra = [str(Path(android_home) / "platform-tools")] if android_home else []
    for directory in extra:
        candidate = Path(directory) / "adb"
        if candidate.is_file():
            return str(candidate)
    return shutil.which("adb")


class ApktoolMEngine(Engine):
    name = "apktool-m"
    label = "Apktool M (on-device)"
    description = "Drive Apktool M on a connected Android device through adb."
    capabilities = ["adb push/pull", "launch on device", "device-side decode/build"]

    def __init__(self) -> None:
        self.adb = find_adb()

    def status(self) -> EngineStatus:
        notes: List[str] = []
        version = None
        if self.adb is None:
            notes.append("adb not found (install platform-tools or set ANDROID_HOME)")
        else:
            result = run([self.adb, "version"], timeout=20)
            match = re.search(r"Android Debug Bridge version ([\d.]+)", result.stdout)
            version = match.group(1) if match else (result.stdout.splitlines() or ["?"])[0]
            devices = self.devices()
            if not devices:
                notes.append("adb found but no device is authorised (adb devices)")
            else:
                notes.append(f"device(s): {', '.join(devices)}")
                installed = self.installed_package()
                notes.append(
                    f"Apktool M installed as {installed}" if installed else "Apktool M is not installed on the device"
                )
        return EngineStatus(
            name=self.name,
            label=self.label,
            available=self.adb is not None and bool(self.devices()) if self.adb else False,
            description=self.description,
            version=version,
            location=self.adb,
            capabilities=self.capabilities,
            notes=notes,
            install_hint="install platform-tools, enable USB debugging, then install Apktool M from F-Droid",
        )

    # -- adb helpers ------------------------------------------------------
    def _adb(self, args: List[str], timeout: int = 300):
        if self.adb is None:
            raise ApkModError("adb is not available")
        return run([self.adb, *args], timeout=timeout)

    def devices(self) -> List[str]:
        if self.adb is None:
            return []
        result = self._adb(["devices"], timeout=20)
        if not result.ok:
            return []
        return [
            line.split("\t")[0]
            for line in result.stdout.splitlines()[1:]
            if line.strip() and "device" in line and "offline" not in line
        ]

    def installed_package(self) -> Optional[str]:
        if not self.devices():
            return None
        result = self._adb(["shell", "pm", "list", "packages"], timeout=30)
        installed = {line.replace("package:", "").strip() for line in result.stdout.splitlines()}
        for package in PACKAGES:
            if package in installed:
                return package
        return None

    def push(self, local: Path, remote_dir: str = DEVICE_DIR) -> str:
        local = Path(local)
        if not local.is_file():
            raise ApkModError(f"no such file: {local}")
        remote = f"{remote_dir}/{local.name}"
        result = self._adb(["push", str(local), remote], timeout=600)
        if not result.ok:
            raise ApkModError(f"adb push failed: {result.output[:400]}")
        return remote

    def pull(self, remote: str, local: Path) -> Path:
        result = self._adb(["pull", remote, str(local)], timeout=600)
        if not result.ok:
            raise ApkModError(f"adb pull failed: {result.output[:400]}")
        return Path(local)

    def launch(self, package: Optional[str] = None) -> str:
        package = package or self.installed_package()
        if not package:
            raise ApkModError("Apktool M is not installed on the device")
        result = self._adb(["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"], timeout=60)
        if not result.ok:
            raise ApkModError(f"could not launch {package}: {result.output[:300]}")
        return package
