"""BIFROST SDK -- JSON signature packs + health checking.

A pack is plain JSON (shippable, per-game, no recompile)::

    {"name": "cs2-client", "module": "client.dll",
     "entries": [
       {"name": "EntityList",
        "pattern": "48 8B 0D ?? ?? ?? ?? 48 89 7C 24 20",
        "rip": {"offset": 3, "insn_len": 7},
        "expect": "unique"},
       {"name": "SomeByte", "pattern": "90 90 CC", "expect": "any"}
     ]}

`rescan_pack` resolves every entry against a live process (module scan)
or a file on disk (disk mode -- no game running) and reports per entry:

    ok        exactly 1 hit (or >=1 when expect == "any")
    broken    0 hits -- pattern died this patch
    ambiguous 2+ hits when unique expected -- needs a longer pattern

RIP-relative entries resolve to the absolute address (live) or the VA
given image_base (disk, default 0 = raw file offsets + relative resolve).
"""

from __future__ import annotations

import os
import struct


# ------------------------------------------------------------------
# Pack validation
# ------------------------------------------------------------------

def validate_pack(pack: dict) -> tuple[bool, str]:
    """Structural check. Returns (ok, message)."""
    if not isinstance(pack, dict):
        return False, "pack must be an object"
    entries = pack.get("entries")
    if not isinstance(entries, list) or not entries:
        return False, "pack.entries must be a non-empty array"
    if len(entries) > 500:
        return False, "pack capped at 500 entries"
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            return False, f"entry {i} must be an object"
        if not e.get("name") or not isinstance(e.get("name"), str):
            return False, f"entry {i} needs a string name"
        pat = e.get("pattern")
        if not isinstance(pat, str) or not pat.strip():
            return False, f"entry {e.get('name')!r} needs a pattern string"
        toks = pat.split()
        if len(toks) > 128:
            return False, f"entry {e.get('name')!r}: pattern capped at 128 bytes"
        for t in toks:
            if t in ("?", "??", "**"):
                continue
            try:
                int(t, 16)
            except ValueError:
                return False, f"entry {e.get('name')!r}: bad token {t!r}"
        rip = e.get("rip")
        if rip is not None:
            if not isinstance(rip, dict):
                return False, f"entry {e.get('name')!r}: rip must be {{offset, insn_len}}"
            try:
                off = int(rip.get("offset", 3))
                ln = int(rip.get("insn_len", 7))
            except (TypeError, ValueError):
                return False, f"entry {e.get('name')!r}: rip offset/insn_len must be ints"
            if off < 0 or ln < off + 4:
                return False, f"entry {e.get('name')!r}: rip insn_len must cover offset+4"
        if e.get("expect", "unique") not in ("unique", "any"):
            return False, f"entry {e.get('name')!r}: expect must be unique|any"
    return True, "ok"


# ------------------------------------------------------------------
# Disk-mode reader (no process needed)
# ------------------------------------------------------------------

class FileReader:
    """Minimal reader over a file on disk for PatternScanner.

    VA space = image_base + file offset. No `handle` attribute on purpose:
    the scanner then takes its section-walk path and falls back to a flat
    region scan, which is exactly what we want for files.
    """

    def __init__(self, path: str, image_base: int = 0):
        with open(path, "rb") as f:
            self._data = f.read()
        self._base = image_base
        self.handle = None

    def read_bytes(self, address: int, size: int) -> bytes:
        off = address - self._base
        if off < 0 or off + size > len(self._data):
            raise RuntimeError(f"read past end of file (off {off:#x}, size {size})")
        return self._data[off:off + size]

    def module_base(self, module_name: str = "") -> int:
        return self._base

    def module_size(self, module_name: str = "") -> int:
        return len(self._data)

    def get_module_sections(self, module_name: str = "") -> list:
        return []

    def resolve_rip_relative(self, pattern_addr: int, rip_offset_pos: int = 3,
                             insn_len: int = 7) -> int:
        raw = self.read_bytes(pattern_addr + rip_offset_pos, 4)
        rel = struct.unpack("<i", raw)[0]
        return pattern_addr + insn_len + rel

    def close(self):
        pass


# ------------------------------------------------------------------
# Resolve + rescan
# ------------------------------------------------------------------

def resolve_entry(scanner, entry: dict, module: str = "") -> dict:
    """Resolve one pack entry. Returns {name,status,hits,resolved}."""
    from .scanner import PatternScanner  # noqa: F401 (type cue only)

    name = entry.get("name", "?")
    pattern = entry["pattern"]
    expect = entry.get("expect", "unique")
    rip = entry.get("rip")

    try:
        if module or not getattr(scanner.reader, "handle", None):
            # FileReader has no handle: scan_module falls back to a flat
            # region walk, while scan_all refuses without VirtualQueryEx.
            hits = scanner.scan_module(module or "file", pattern,
                                       return_first=False, max_results=3)
        else:
            hits = scanner.scan_all(pattern, return_first=False, max_results=3,
                                    executable_only=False)
    except Exception as exc:
        return {"name": name, "status": "error", "hits": [], "resolved": None,
                "detail": str(exc)}

    addrs = [h.address for h in hits]
    if not addrs:
        return {"name": name, "status": "broken", "hits": [], "resolved": None}
    if expect == "unique" and len(addrs) > 1:
        return {"name": name, "status": "ambiguous", "hits": addrs, "resolved": None}

    resolved = None
    if rip:
        try:
            resolved = scanner.reader.resolve_rip_relative(
                addrs[0], int(rip.get("offset", 3)), int(rip.get("insn_len", 7)))
        except Exception as exc:
            return {"name": name, "status": "error", "hits": addrs, "resolved": None,
                    "detail": f"rip resolve failed: {exc}"}
    else:
        resolved = addrs[0]
    return {"name": name, "status": "ok", "hits": addrs, "resolved": resolved}


def rescan_pack(pack: dict, *, pid: int = 0, module: str = "",
                file: str = "", image_base: int = 0) -> dict:
    """Validate + resolve every entry. Exactly one of pid / file required."""
    ok, msg = validate_pack(pack)
    if not ok:
        return {"error": msg, "code": "BAD_PACK"}
    if bool(pid) == bool(file):
        return {"error": "give exactly one of pid / file", "code": "BAD_ARGS"}

    from .scanner import PatternScanner

    reader = None
    try:
        if file:
            if not os.path.isfile(file):
                return {"error": f"file not found: {file}", "code": "NO_FILE"}
            reader = FileReader(file, image_base=image_base)
            default_module = ""
        else:
            try:
                from .stealth import StealthReader
                from .stealth.config import AccessMethod, StealthConfig
                reader = StealthReader(pid=pid,
                                       config=StealthConfig(method=AccessMethod.HIJACK))
            except Exception:
                from .memory import MemoryReader
                reader = MemoryReader(pid=pid)
            default_module = module or pack.get("module", "")

        scanner = PatternScanner(reader)
        results = []
        for entry in pack["entries"]:
            mod = "" if file else entry.get("module", default_module)
            results.append(resolve_entry(scanner, entry, module=mod))
        broken = sum(1 for r in results if r["status"] == "broken")
        ambiguous = sum(1 for r in results if r["status"] == "ambiguous")
        errors = sum(1 for r in results if r["status"] == "error")
        healthy = len(results) - broken - ambiguous - errors
        return {
            "pack": pack.get("name", ""),
            "total": len(results),
            "healthy": healthy,
            "broken": broken,
            "ambiguous": ambiguous,
            "errors": errors,
            "results": results,
        }
    except Exception as exc:
        return {"error": str(exc), "code": "RESCAN_FAILED"}
    finally:
        if reader:
            try:
                reader.close()
            except Exception:
                pass
