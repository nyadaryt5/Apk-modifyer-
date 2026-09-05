"""Native zipalign + APK repacker (no Android SDK required).

zipalign works by padding the *local file header's* extra field so that each
uncompressed entry's data starts on an N-byte boundary. That is exactly what
this does, so mmap-able entries (``.so``, ``resources.arsc``, assets) stay
page-aligned like the real tool produces.
"""

from __future__ import annotations

import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .util import ApkModError

__all__ = ["repack", "align", "verify_alignment", "local_data_offsets", "ALIGNMENT_EXTRA_FIELD"]

ALIGNMENT_EXTRA_FIELD = 0xD935
PAGE_ALIGN_SUFFIXES = (".so",)


@dataclass
class RepackResult:
    path: Path
    entries: int
    replaced: List[str]
    removed: List[str]
    added: List[str]


def _alignment_for(name: str, compress_type: int, alignment: int, page_align_libs: bool) -> Optional[int]:
    """Uncompressed entries get aligned; deflated ones do not need it."""
    if compress_type != zipfile.ZIP_STORED:
        return None
    if page_align_libs and name.endswith(PAGE_ALIGN_SUFFIXES):
        return 4096
    return alignment


def _padding_extra(header_len: int, alignment: int) -> bytes:
    """Extra-field bytes that push the payload to an ``alignment`` boundary."""
    pad = (alignment - (header_len % alignment)) % alignment
    if pad < 4:  # a well-formed extra field needs >= 4 bytes
        pad += alignment
    return struct.pack("<HH", ALIGNMENT_EXTRA_FIELD, pad - 4) + b"\x00" * (pad - 4)


def repack(
    src: Path,
    dst: Path,
    *,
    alignment: int = 4,
    page_align_libs: bool = True,
    replace: Optional[Dict[str, bytes]] = None,
    exclude: Iterable[str] = (),
    prepend: Optional[Sequence[Tuple[str, bytes]]] = None,
) -> RepackResult:
    """Rewrite ``src`` into ``dst``, aligning stored entries.

    ``replace`` swaps entry contents, ``exclude`` drops entries, and
    ``prepend`` writes extra entries first (used for META-INF signature files).
    """
    replace = dict(replace or {})
    excluded = set(exclude)
    prepend = list(prepend or [])
    src, dst = Path(src), Path(dst)
    replaced: List[str] = []
    removed: List[str] = []

    with zipfile.ZipFile(src) as zin:
        infos = zin.infolist()
        present = {i.filename for i in infos}
        missing = [name for name in replace if name not in present]
        if missing:
            raise ApkModError(f"cannot replace {', '.join(missing)}: not present in {src.name}")
        with zipfile.ZipFile(dst, "w", allowZip64=True) as zout:
            for name, data in prepend:
                _write(zout, name, data, alignment=4, compress_type=zipfile.ZIP_STORED)
            for info in infos:
                if info.is_dir():
                    continue
                if info.filename in excluded:
                    removed.append(info.filename)
                    continue
                if info.filename in replace:
                    data = replace[info.filename]
                    replaced.append(info.filename)
                else:
                    data = zin.read(info.filename)
                _write(
                    zout,
                    info.filename,
                    data,
                    alignment=_alignment_for(info.filename, info.compress_type, alignment, page_align_libs),
                    compress_type=info.compress_type,
                    date_time=info.date_time,
                    external_attr=info.external_attr,
                    create_system=info.create_system,
                )

    with zipfile.ZipFile(dst) as check:
        entry_count = len(check.infolist())

    return RepackResult(
        path=dst,
        entries=entry_count,
        replaced=replaced,
        removed=removed,
        added=[n for n, _ in prepend],
    )


def _write(
    zout: zipfile.ZipFile,
    name: str,
    data: bytes,
    *,
    alignment: Optional[int],
    compress_type: int = zipfile.ZIP_DEFLATED,
    date_time: Optional[tuple] = None,
    external_attr: int = 0,
    create_system: int = 0,
) -> None:
    info = zipfile.ZipInfo(name, date_time=date_time or (1980, 1, 1, 0, 0, 0))
    info.compress_type = compress_type
    info.external_attr = external_attr
    info.create_system = create_system
    info.file_size = len(data)
    # ZipInfo.__init__ does not define CRC, but FileHeader() reads it; zipfile
    # recomputes and patches this field when the entry is actually written.
    info.CRC = zlib.crc32(data)
    info.compress_size = len(data)
    if alignment:
        base = zout.fp.tell() + len(info.FileHeader(zip64=info.file_size > 0xFFFFFFFF))
        info.extra = _padding_extra(base, alignment)
    zout.writestr(info, data)


def align(src: Path, dst: Path, *, alignment: int = 4, page_align_libs: bool = True) -> RepackResult:
    """Standalone ``zipalign`` equivalent."""
    return repack(src, dst, alignment=alignment, page_align_libs=page_align_libs)


def local_data_offsets(path: Path) -> List[Tuple[str, int, int]]:
    """(entry name, data offset, alignment requirement) read from local headers."""
    out: List[Tuple[str, int, int]] = []
    raw = Path(path).read_bytes()
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            off = info.header_offset
            name_len, extra_len = struct.unpack_from("<HH", raw, off + 26)
            data_off = off + 30 + name_len + extra_len
            required = 4096 if info.filename.endswith(PAGE_ALIGN_SUFFIXES) and info.compress_type == zipfile.ZIP_STORED else (
                4 if info.compress_type == zipfile.ZIP_STORED else 0
            )
            out.append((info.filename, data_off, required))
    return out


def verify_alignment(path: Path, *, page_align_libs: bool = True) -> List[dict]:
    """Return every stored entry whose payload is not on its required boundary."""
    bad: List[dict] = []
    for name, offset, required in local_data_offsets(path):
        if not required or not page_align_libs and required == 4096:
            continue
        if offset % required:
            bad.append({"name": name, "offset": offset, "required": required, "mod": offset % required})
    return bad
