"""Engine registry: every adapter, one lookup.

The seven tool families this toolkit combines, as adapters behind one
interface:

======================  =====================================================
``apktool``             decode/build smali + resources via the Apktool jar
``apktool-m``           the same workflow driven on an Android device (adb)
``aee``                 in-place APK editing, native Python, no decompile
``patcher``             analysis of what a build protects and how
``jadx``                decompile DEX back to readable Java
``frida``               dynamic instrumentation of a running app
``mtmanager``           APK diffing and split-bundle handling, native
======================  =====================================================
"""

from __future__ import annotations

from typing import Dict, List

from ..util import ApkModError
from .aee import NativeEditor
from .apktool import ApktoolEngine
from .apktoolm import ApktoolMEngine
from .base import Engine, EngineStatus
from .frida import FridaEngine
from .jadx import JadxEngine
from .mtmanager import MTManagerEngine
from .patcher import PatcherEngine

__all__ = ["registry", "status_all", "get"]


class Registry:
    def __init__(self) -> None:
        self._engines: Dict[str, Engine] = {
            "apktool": ApktoolEngine(),
            "apktool-m": ApktoolMEngine(),
            "aee": NativeEditor(),
            "patcher": PatcherEngine(),
            "jadx": JadxEngine(),
            "frida": FridaEngine(),
            "mtmanager": MTManagerEngine(),
        }

    @property
    def names(self) -> List[str]:
        return list(self._engines)

    def get(self, name: str) -> Engine:
        try:
            return self._engines[name]
        except KeyError:
            raise ApkModError(f"unknown engine '{name}' (have: {', '.join(self._engines)})") from None

    def statuses(self) -> List[EngineStatus]:
        return [engine.status() for engine in self._engines.values()]


registry = Registry()


def status_all() -> List[EngineStatus]:
    return registry.statuses()


def get(name: str) -> Engine:
    return registry.get(name)
