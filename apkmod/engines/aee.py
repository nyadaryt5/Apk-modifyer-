"""Native in-place editor -- the "APK Editor / AEE" mode.

Every operation here rewrites only the entries it has to touch, keeps the rest
of the archive byte-for-byte, and re-aligns the result. No JVM, no decompile,
so it works anywhere Python does -- including on a phone via Termux.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..align import repack, verify_alignment
from ..apk import ApkContainer
from ..arsc import ArscFile
from ..axml import AxmlFile
from ..signing import sign_v1
from ..util import ApkModError
from .base import Engine, EngineStatus

__all__ = ["NativeEditor", "EditResult"]


@dataclass
class EditResult:
    path: Path
    changed_entries: List[str]
    notes: List[str]
    signed: bool = False
    aligned_misalignments: int = 0

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "changed_entries": self.changed_entries,
            "notes": self.notes,
            "signed": self.signed,
            "alignment_problems": self.aligned_misalignments,
        }


class NativeEditor(Engine):
    name = "aee"
    label = "Native in-place editor (APK Editor mode)"
    description = "Edit manifest / resources / files inside an APK without decompiling it."
    capabilities = [
        "manifest read/write",
        "permission add/remove",
        "resource string rewrite",
        "file replace/inject/remove",
        "zipalign",
        "v1 signing",
    ]

    def status(self) -> EngineStatus:
        return EngineStatus(
            name=self.name,
            label=self.label,
            available=True,  # pure Python: always ready
            description=self.description,
            version="native",
            location="apkmod.axml / apkmod.arsc / apkmod.align / apkmod.signing",
            capabilities=self.capabilities,
            notes=["no external tools required"],
        )

    # -- manifest ---------------------------------------------------------
    def manifest_xml(self, apk: Path) -> str:
        with ApkContainer(apk) as container:
            return container.manifest_axml().to_xml()

    def manifest_facts(self, apk: Path) -> dict:
        with ApkContainer(apk) as container:
            return container.manifest_axml().manifest_facts()

    def _patch_manifest(self, apk: Path, out: Path, mutate) -> EditResult:
        with ApkContainer(apk) as container:
            axml = container.manifest_axml()
            notes = mutate(axml)
            blob = axml.serialize()
            result = repack(apk, out, replace={"AndroidManifest.xml": blob})
        return EditResult(
            path=result.path,
            changed_entries=["AndroidManifest.xml"],
            notes=list(notes or []),
            aligned_misalignments=len(verify_alignment(result.path)),
        )

    def remove_permissions(self, apk: Path, out: Path, permissions: Sequence[str]) -> EditResult:
        removed: Dict[str, int] = {}

        def mutate(axml: AxmlFile) -> List[str]:
            for permission in permissions:
                removed[permission] = axml.remove_permission(permission)
            return [
                f"removed {count} x {permission}" if count else f"not present: {permission}"
                for permission, count in removed.items()
            ]

        return self._patch_manifest(apk, out, mutate)

    def add_permission(self, apk: Path, out: Path, permission: str, tag: str = "uses-permission") -> EditResult:
        def mutate(axml: AxmlFile) -> List[str]:
            added = axml.add_permission(permission, tag=tag)
            return [f"added {permission}" if added else f"already declared: {permission}"]

        return self._patch_manifest(apk, out, mutate)

    def set_debuggable(self, apk: Path, out: Path, enabled: bool) -> EditResult:
        def mutate(axml: AxmlFile) -> List[str]:
            changed = axml.set_debuggable(enabled)
            return [f"debuggable={enabled}" if changed else "no <application> element found"]

        return self._patch_manifest(apk, out, mutate)

    # -- resources --------------------------------------------------------
    def strings(self, apk: Path) -> List[Tuple[int, str, List[str]]]:
        with ApkContainer(apk) as container:
            blob = container.arsc_bytes()
        if blob is None:
            raise ApkModError("this APK has no resources.arsc")
        return ArscFile.parse(blob).string_entries()

    def replace_string(self, apk: Path, out: Path, old: str, new: str, *, index: Optional[int] = None) -> EditResult:
        with ApkContainer(apk) as container:
            blob = container.arsc_bytes()
            if blob is None:
                raise ApkModError("this APK has no resources.arsc")
            table = ArscFile.parse(blob)
            if index is not None:
                previous = table.replace_string(index, new)
                notes = [f"string #{index}: {previous!r} -> {new!r}"]
            else:
                count = table.replace_all(old, new)
                if not count:
                    raise ApkModError(f"no resource string equals {old!r}")
                notes = [f"replaced {count} occurrence(s) of {old!r} with {new!r}"]
            payload = table.serialize()
        result = repack(apk, out, replace={"resources.arsc": payload})
        return EditResult(
            path=result.path,
            changed_entries=["resources.arsc"],
            notes=notes,
            aligned_misalignments=len(verify_alignment(result.path)),
        )

    # -- raw entries ------------------------------------------------------
    def replace_file(self, apk: Path, out: Path, entry: str, source: Path, *, compress: bool = False) -> EditResult:
        source = Path(source)
        if not source.is_file():
            raise ApkModError(f"no such file: {source}")
        data = source.read_bytes()
        with ApkContainer(apk) as container:
            if not container.has(entry):
                raise ApkModError(f"{entry} is not in the APK (use --add to inject a new entry)")
            if compress:
                # forcing compression changes the alignment story, so rebuild fully
                with zipfile.ZipFile(out, "w") as zout:
                    for info in container.zip.infolist():
                        payload = data if info.filename == entry else container.read(info.filename)
                        method = zipfile.ZIP_DEFLATED if info.filename == entry else info.compress_type
                        zout.writestr(info.filename, payload, compress_type=method)
                return EditResult(
                    path=Path(out),
                    changed_entries=[entry],
                    notes=[f"replaced {entry} (recompressed)", "alignment is not preserved in this mode"],
                )
            result = repack(apk, out, replace={entry: data})
        return EditResult(
            path=result.path,
            changed_entries=[entry],
            notes=[f"replaced {entry} ({len(data)} bytes)"],
            aligned_misalignments=len(verify_alignment(result.path)),
        )

    def add_file(self, apk: Path, out: Path, entry: str, source: Path) -> EditResult:
        """Inject a new entry (assets are the common case) and keep alignment."""
        source = Path(source)
        if not source.is_file():
            raise ApkModError(f"no such file: {source}")
        data = source.read_bytes()
        with zipfile.ZipFile(apk) as zin, zipfile.ZipFile(out, "w") as zout:
            from ..align import _write  # local import keeps the helper private

            names = set(zin.namelist())
            if entry in names:
                raise ApkModError(f"{entry} already exists (use replace-file)")
            for info in zin.infolist():
                _write(
                    zout,
                    info.filename,
                    zin.read(info.filename),
                    alignment=4 if info.compress_type == zipfile.ZIP_STORED else None,
                    compress_type=info.compress_type,
                    date_time=info.date_time,
                    external_attr=info.external_attr,
                    create_system=info.create_system,
                )
            _write(zout, entry, data, alignment=None, compress_type=zipfile.ZIP_DEFLATED)
        return EditResult(
            path=Path(out),
            changed_entries=[entry],
            notes=[f"added {entry} ({len(data)} bytes)"],
            aligned_misalignments=len(verify_alignment(out)),
        )

    def remove_entries(self, apk: Path, out: Path, entries: Sequence[str]) -> EditResult:
        with ApkContainer(apk) as container:
            missing = [e for e in entries if not container.has(e)]
            if missing:
                raise ApkModError(f"not in the APK: {', '.join(missing)}")
        result = repack(apk, out, exclude=set(entries))
        return EditResult(
            path=result.path,
            changed_entries=list(entries),
            notes=[f"removed {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}"],
            aligned_misalignments=len(verify_alignment(result.path)),
        )

    # -- signing ----------------------------------------------------------
    def sign(self, apk: Path, out: Path, key_pem: bytes, cert_pem: bytes, *, name: str = "APKMOD") -> EditResult:
        signed = sign_v1(apk, out, key_pem, cert_pem, signature_name=name)
        return EditResult(
            path=signed.path,
            changed_entries=[signed.signature_name, "META-INF/MANIFEST.MF"],
            notes=[
                f"v1 signed {signed.signed_entries} entries with {signed.digest_name}",
                f"certificate: {signed.subject or 'unknown'} ({signed.certificate_sha256[:16]}...)",
            ],
            signed=True,
            aligned_misalignments=len(verify_alignment(signed.path)),
        )
