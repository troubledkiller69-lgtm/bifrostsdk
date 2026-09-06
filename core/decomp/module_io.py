"""
BIFROST SDK — raw module image saver.

Streams a target module's memory image to disk so it can be handed to the
analyzer. Reads chunked through whatever ReaderProtocol implementation the
caller attached (stealth or direct) with cooperative cancellation between
chunks.

Guard pages inside a module image are normal on Windows (e.g. the loader
lock page). Reads that fail per-chunk are zero-filled and counted — the
dump stays analyzable, and the caller is told how much is missing.
"""

from __future__ import annotations

import os

_CHUNK_SIZE = 0x4000  # 16 KB — small enough for slow driver reads to cancel

ImageStats = dict  # {base, size, bytes_read, chunks, missing_chunks, path}


def resolve_module_image(reader, module_name: str) -> tuple[int, int]:
    """Return (base, size) for *module_name* via the reader.

    Falls back to the PE SizeOfImage when the reader only knows the base
    (MemoryReader caches size from EnumProcessModules, stealth readers read
    it from the in-memory optional header — both should be fine).
    """
    name_lower = (module_name or "").lower()
    if not name_lower:
        raise ValueError("module name required")

    base = reader.module_base(module_name)
    size = 0
    try:
        size = reader.module_size(module_name)
    except Exception:
        size = 0
    if size <= 0:
        # Last resort: list_modules often carries sizes even when the
        # dedicated getter is unavailable.
        for mod in reader.list_modules() or []:
            if (mod.get("name") or "").lower() == name_lower:
                size = mod.get("size") or 0
                break
    if base <= 0:
        raise RuntimeError(f"Module '{module_name}' has no resolvable base")
    if size <= 0:
        raise RuntimeError(f"Module '{module_name}' has no resolvable size")
    return base, size


def dump_module(
    reader,
    module_name: str,
    target_path: str,
    cancel_check=None,
    base: int | None = None,
    size: int | None = None,
) -> ImageStats:
    """Dump *module_name* from *reader* into *target_path* (raw image).

    *cancel_check* is called between chunks; returning True aborts with the
    partial file left in place (deleted by the caller if unwanted).

    Returns stats dict; raises on hard failures (attach-side errors surface
    from the reader itself).
    """
    if base is None or size is None:
        base, size = resolve_module_image(reader, module_name)

    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)

    stats: ImageStats = {
        "base": base,
        "size": size,
        "bytes_read": 0,
        "chunks": 0,
        "missing_chunks": 0,
        "path": target_path,
    }
    with open(target_path, "wb") as out:
        for chunk_start in range(base, base + size, _CHUNK_SIZE):
            chunk = min(_CHUNK_SIZE, base + size - chunk_start)
            try:
                data = reader.read_bytes(chunk_start, chunk)
                if len(data) != chunk:  # short read — pad, don't corrupt offset
                    data = data + b"\x00" * (chunk - len(data))
                    stats["missing_chunks"] += 1
                out.write(data)
            except Exception:
                out.write(b"\x00" * chunk)
                stats["missing_chunks"] += 1
            stats["chunks"] += 1
            stats["bytes_read"] += chunk
            if cancel_check and cancel_check():
                break
    stats["complete"] = stats["bytes_read"] >= size and stats["missing_chunks"] == 0
    return stats
