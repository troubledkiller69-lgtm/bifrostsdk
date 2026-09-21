"""BIFROST SDK -- offsets.json drift helpers (frozen-safe).

Pure logic shared by the `compare_dumps.py` CLI and `core/dump_history.py`.
Lives in core (not scripts/) so the PyInstaller backend can import it --
scripts/ is never bundled into api_server.exe.
"""

from __future__ import annotations

import json
from pathlib import Path


def norm_hex(value) -> int | None:
    """Normalize an offset to int. Accepts '0x18' / '18' / 24 / None."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"not a hex/int value: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 16)
        except ValueError:
            raise ValueError(f"not a hex/int value: {value!r}")
    raise ValueError(f"not a hex/int value: {value!r}")


def find_offsets_json(output_dir: str | Path) -> Path | None:
    """Locate offsets.json in a dump dir (itself, then one level deep)."""
    base = Path(output_dir)
    if not base.is_dir():
        return None
    candidates = [base / "offsets.json"]
    for sub in sorted(base.iterdir()):
        if sub.is_dir():
            candidates.append(sub / "offsets.json")
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def load_offsets(path: str | Path) -> dict:
    """Load an offsets.json file; raises ValueError on parse failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot parse {path}: {e}") from e
    return data


def hex_str(value: int | None) -> str:
    return "null" if value is None else f"0x{value:X}"


def field_snapshot(cls_rec: dict) -> dict[str, tuple[int | None, int | None, str]]:
    """Class record -> {field: (normalized_offset, size, type)}. Skips junk."""
    snap = {}
    fields = cls_rec.get("fields", {}) if isinstance(cls_rec, dict) else {}
    for name, fld in fields.items():
        if not isinstance(fld, dict):
            snap[name] = (None, None, "")
            continue
        try:
            off = norm_hex(fld.get("offset"))
        except ValueError:
            off = None
        size = fld.get("size")
        snap[name] = (
            off,
            size if isinstance(size, int) else None,
            str(fld.get("type", "")),
        )
    return snap


def diff_classes(old: dict, new: dict) -> dict:
    """Full per-class comparison. Returns categorized class names + changes.

    changes maps class name -> list of (field, old_repr, new_repr) strings
    ready to print. Field rename shows up as a removal + addition in that
    class (offset moves to a different name), which counts as changed.
    """
    old_offsets = old.get("offsets", {}) if isinstance(old.get("offsets"), dict) else {}
    new_offsets = new.get("offsets", {}) if isinstance(new.get("offsets"), dict) else {}

    removed = sorted(set(old_offsets) - set(new_offsets))
    added = sorted(set(new_offsets) - set(old_offsets))
    changed: dict[str, list[str]] = {}
    unchanged: list[str] = []

    for cls_name in sorted(set(old_offsets) & set(new_offsets)):
        old_snap = field_snapshot(old_offsets[cls_name])
        new_snap = field_snapshot(new_offsets[cls_name])
        lines = []

        for fld in sorted(set(old_snap) & set(new_snap)):
            o_off, o_size, _ = old_snap[fld]
            n_off, n_size, _ = new_snap[fld]
            if (o_off, o_size) != (n_off, n_size):
                if o_off != n_off:
                    lines.append(f"{cls_name}.{fld}: {hex_str(o_off)} → {hex_str(n_off)}")
                else:
                    lines.append(
                        f"{cls_name}.{fld}: offset {hex_str(o_off)} unchanged, "
                        f"size {o_size} → {n_size}"
                    )

        for fld in sorted(set(old_snap) - set(new_snap)):
            lines.append(f"{cls_name}.{fld}: {hex_str(old_snap[fld][0])} → <removed>")
        for fld in sorted(set(new_snap) - set(old_snap)):
            lines.append(f"{cls_name}.{fld}: <added> → {hex_str(new_snap[fld][0])}")

        if lines:
            changed[cls_name] = lines
        else:
            unchanged.append(cls_name)

    return {"removed": removed, "added": added, "changed": changed, "unchanged": unchanged}
