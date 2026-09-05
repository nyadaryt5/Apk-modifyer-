"""The engine layer.

The point of this toolkit is that the four tool families people normally juggle
separately show up as four adapters behind one interface:

======================  =====================================================
``apktool``             decode/build smali + resources via the Apktool jar
``apktool-m``           the same workflow driven on an Android device (adb)
``aee``                 in-place APK editing, native Python, no decompile
``patcher``             analysis of what a build protects and how
======================  =====================================================

Every engine reports a :class:`EngineStatus` so ``apkmod doctor`` can say
exactly what is usable right now and what is missing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = ["Engine", "EngineStatus"]


@dataclass
class EngineStatus:
    name: str
    label: str
    available: bool
    description: str = ""
    version: Optional[str] = None
    location: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    install_hint: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "available": self.available,
            "description": self.description,
            "version": self.version,
            "location": self.location,
            "capabilities": self.capabilities,
            "notes": self.notes,
            "install_hint": self.install_hint,
        }

    def format(self) -> str:
        flag = "ready " if self.available else "absent"
        head = f"[{flag}] {self.label} ({self.name})"
        lines = [head]
        if self.version:
            lines.append(f"         version : {self.version}")
        if self.location:
            lines.append(f"         location: {self.location}")
        lines.append(f"         provides: {', '.join(self.capabilities) or '-'}")
        for note in self.notes:
            lines.append(f"         note    : {note}")
        if not self.available and self.install_hint:
            lines.append(f"         install : {self.install_hint}")
        return "\n".join(lines)


class Engine(ABC):
    name = "engine"
    label = "Engine"
    description = ""
    capabilities: List[str] = []

    @abstractmethod
    def status(self) -> EngineStatus:
        """Probe the environment and report what this engine can do."""
