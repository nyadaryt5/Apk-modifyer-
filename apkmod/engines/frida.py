"""
Frida adapter -- dynamic instrumentation of a running app.

Static analysis tells you what an app *contains*; Frida tells you what it
*does*. This drives the real ``frida`` CLI and ``frida-server`` over adb. It
does not reimplement an instrumentation runtime, and it does not ship bypass
scripts -- the scope boundary in the README applies here exactly as it does to
the static engines.

Typical loop:

    apkmod frida-server push      # put frida-server on a rooted device
    apkmod frida-server start     # run it as root
    apkmod frida-ps               # what is running
    apkmod frida-run -p com.app -s hook.js
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import List, Optional

from ..util import ApkModError, cache_dir, find_binary, run
from .base import Engine, EngineStatus

__all__ = ["FridaEngine", "find_frida", "find_adb", "FRIDA_RELEASE"]

FRIDA_RELEASE = "https://github.com/frida/frida/releases"
DEVICE_SERVER_PATH = "/data/local/tmp/frida-server"


def find_frida(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate)
        raise ApkModError(f"no frida at {candidate}")
    import os

    for variable in ("FRIDA_HOME", "FRIDA_PATH"):
        value = os.environ.get(variable)
        if value:
            candidate = Path(value).expanduser()
            candidate = candidate / "frida" if candidate.is_dir() else candidate
            if candidate.is_file():
                return str(candidate)
    return find_binary(["frida"], extra_dirs=[str(cache_dir())]) or shutil.which("frida")


def find_frida_ps() -> Optional[str]:
    return shutil.which("frida-ps")


def find_adb() -> Optional[str]:
    import os

    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    extra = [str(Path(home) / "platform-tools")] if home else []
    return find_binary(["adb"], extra_dirs=extra) or shutil.which("adb")


class FridaEngine(Engine):
    name = "frida"
    label = "Frida"
    description = (
        "Dynamic instrumentation: attach to a running app and observe or steer it. "
        "Security testing on apps you own or are authorised to test."
    )
    capabilities = ["spawn", "attach", "run-script", "list-processes", "device-server"]

    def __init__(self, binary: Optional[str] = None) -> None:
        self._binary = binary

    def status(self) -> EngineStatus:
        notes: List[str] = []
        try:
            frida = find_frida(self._binary)
        except ApkModError as exc:
            return EngineStatus(
                name=self.name,
                label=self.label,
                available=False,
                description=self.description,
                capabilities=self.capabilities,
                notes=[str(exc)],
                install_hint=f"`pip install frida-tools`, or see {FRIDA_RELEASE}",
            )
        if frida is None:
            return EngineStatus(
                name=self.name,
                label=self.label,
                available=False,
                description=self.description,
                capabilities=self.capabilities,
                notes=["the `frida` CLI was not found"],
                install_hint="`pip install frida-tools` (also provides frida-ps)",
            )

        adb = find_adb()
        if adb is None:
            notes.append("adb not found -- USB/remote device control is unavailable")
        else:
            devices = self._adb_devices(adb)
            notes.append(f"adb devices: {', '.join(devices) if devices else 'none connected'}")
        if find_frida_ps() is None:
            notes.append("frida-ps not found -- process listing is unavailable")

        return EngineStatus(
            name=self.name,
            label=self.label,
            available=True,
            description=self.description,
            version=self._version(frida),
            location=frida,
            capabilities=self.capabilities,
            notes=notes,
        )

    @staticmethod
    def _version(frida: str) -> Optional[str]:
        result = run([frida, "--version"], timeout=60)
        if not result.ok:
            return None
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.output)
        return match.group(1) if match else result.output.strip()[:40]

    # -- device plumbing --------------------------------------------------
    @staticmethod
    def _adb_devices(adb: str) -> List[str]:
        result = run([adb, "devices"], timeout=30)
        out = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                out.append(parts[0])
        return out

    def push_server(self, local_server: Path, *, serial: Optional[str] = None) -> dict:
        """Copy a frida-server binary to the device. Needs adb and a rooted device."""
        adb = self._require_adb()
        local_server = Path(local_server).expanduser()
        if not local_server.is_file():
            raise ApkModError(
                f"no frida-server binary at {local_server}; download the android build "
                f"matching your device ABI from {FRIDA_RELEASE}"
            )
        push = [adb] + (["-s", serial] if serial else []) + ["push", str(local_server), DEVICE_SERVER_PATH]
        result = run(push, timeout=300)
        if not result.ok:
            raise ApkModError(f"adb push failed: {result.output}")
        chmod = [adb] + (["-s", serial] if serial else []) + ["shell", "chmod", "755", DEVICE_SERVER_PATH]
        run(chmod, timeout=60)
        return {"ok": True, "device_path": DEVICE_SERVER_PATH, "size": local_server.stat().st_size}

    def start_server(self, *, serial: Optional[str] = None, args: str = "") -> dict:
        """Start frida-server on the device (backgrounded). Requires root."""
        adb = self._require_adb()
        shell = f"nohup {DEVICE_SERVER_PATH} {args} >/dev/null 2>&1 &".strip()
        command = [adb] + (["-s", serial] if serial else []) + ["shell", f"su -c '{shell}'"]
        result = run(command, timeout=60)
        return {
            "ok": result.ok,
            "command": " ".join(command),
            "output": result.output[-500:],
            "note": "" if result.ok else "starting frida-server needs root on the device",
        }

    # -- instrumentation --------------------------------------------------
    def list_processes(self, *, serial: Optional[str] = None, usb: bool = True, timeout: int = 60) -> dict:
        ps = find_frida_ps()
        if ps is None:
            raise ApkModError("frida-ps is not installed (`pip install frida-tools`)")
        cmd = [ps] + (["-U"] if usb else []) + (["-D", serial] if serial else [])
        result = run(cmd, timeout=timeout)
        if not result.ok:
            raise ApkModError(f"frida-ps failed: {result.output}")
        rows = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                rows.append({"pid": int(parts[0]), "name": parts[1]})
        return {"ok": True, "count": len(rows), "processes": rows}

    def run_script(
        self,
        script: Path,
        *,
        package: Optional[str] = None,
        pid: Optional[int] = None,
        spawn: bool = True,
        usb: bool = True,
        serial: Optional[str] = None,
        timeout: int = 120,
        quiet: bool = True,
    ) -> dict:
        """
        Run a Frida script against a process.

        Either ``package`` (spawn or attach by name) or ``pid`` must be given.
        """
        frida = self._require()
        script = Path(script).expanduser()
        if not script.is_file():
            raise ApkModError(f"no such script: {script}")
        if not package and pid is None:
            raise ApkModError("give either a package name or a pid")

        cmd: List[str] = [frida]
        if usb:
            cmd.append("-U")
        if serial:
            cmd += ["-D", serial]
        cmd += ["-l", str(script)]
        if pid is not None:
            cmd += ["-p", str(pid)]
        elif spawn:
            cmd += ["-f", package, "--no-pause"]
        else:
            cmd += ["-n", package]
        if quiet:
            cmd.append("-q")

        result = run(cmd, timeout=timeout)
        return {
            "ok": result.ok,
            "command": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout[-8000:],
            "stderr": result.stderr[-2000:],
        }

    # -- helpers ----------------------------------------------------------
    def _require(self) -> str:
        frida = find_frida(self._binary)
        if not frida:
            raise ApkModError("frida is not installed; `pip install frida-tools`")
        return frida

    @staticmethod
    def _require_adb() -> str:
        adb = find_adb()
        if not adb:
            raise ApkModError("adb is not installed; install Android platform-tools")
        return adb
