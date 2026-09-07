"""
BIFROST SDK — VA -> file-offset mapping for analyzed images.

The analyzer works on two shapes of source:

  * module dumps — raw bytes of a loaded image, `base` carries the load
    address, so file offset == va - base, linear for the whole file.
  * on-disk binaries — a PE needs its section table to translate a virtual
    address back to a file offset (headers and sections don't line up).

Everything here is read-only and stateless apart from a tiny per-file
section cache. Errors are return values, never raises — callers render
them as user-facing messages.
"""

from __future__ import annotations

import os

_PE_MACHINE_X64 = 0x8664
_PE_MACHINE_X86 = 0x14C

_cache: dict[str, tuple | None] = {}


def _load_pe_map(path: str) -> tuple | None:
    """(image_base, machine, [(va, fileoff, vsize), ...]) or None."""
    if path in _cache:
        return _cache[path]
    result = None
    try:
        import pefile  # lazy: only PE files touch this

        pe = pefile.PE(path, fast_load=True)
        try:
            machine = pe.FILE_HEADER.Machine
            image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)
            sections = []
            for section in pe.sections:
                va = image_base + section.VirtualAddress
                sections.append((va, section.PointerToRawData, max(
                    section.Misc_VirtualSize, section.SizeOfRawData
                )))
            sections.sort(key=lambda s: s[0])
            result = (image_base, machine, sections)
        finally:
            pe.close()
    except Exception:
        result = None
    if len(_cache) > 16:  # cap: analyzed files pile up across sessions
        _cache.clear()
    _cache[path] = result
    return result


def _arch_for_machine(machine: int | None) -> str:
    if machine == _PE_MACHINE_X86:
        return "x86"
    if machine == _PE_MACHINE_X64:
        return "x86_64"
    return "x86_64"  # unknown/ELF/etc — assume x64, caller sees garbage if wrong


def va_to_window(file_path: str, base: int | None, va: int, length: int) -> dict:
    """Map a VA to a readable file window of *length* bytes.

    *base* is the image base for raw module dumps (None for on-disk PEs).
    Returns {'ok': True, 'offset', 'arch', 'file_base', 'length'} where
    the window starts at file offset *offset* and decoding with ip=va
    yields true addresses. On failure: {'ok': False, 'error'}.
    """
    try:
        size = os.path.getsize(file_path)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}

    if base:
        if va < base:
            return {"ok": False, "error": f"address {va:#x} before image base"}
        offset = va - base
        if offset >= size:
            return {"ok": False, "error": f"address {va:#x} outside image bounds"}
        room = size - offset
        return {"ok": True, "offset": offset, "arch": "x86_64", "length": min(length, room)}

    pe_map = _load_pe_map(file_path)
    if pe_map is not None:
        image_base, machine, sections = pe_map
        for sva, fileoff, vsize in sections:
            if sva <= va < sva + vsize:
                delta = va - sva
                room = size - (fileoff + delta)
                if room <= 0:
                    return {"ok": False, "error": f"address {va:#x} past end of file"}
                return {
                    "ok": True, "offset": fileoff + delta,
                    "arch": _arch_for_machine(machine),
                    "length": min(length, room),
                }
        return {"ok": False, "error": f"address {va:#x} is not in any section"}
    return {"ok": False, "error": "unsupported image: needs a module base "
            "(raw dump) or a PE with section headers"}
