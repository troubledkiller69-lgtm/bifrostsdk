"""compare_dumps.py — offset-drift watcher between two dump outputs.

Usage:
    python scripts/compare_dumps.py <old_dir> <new_dir>

Loads offsets.json from both dirs (resolved one level deep via
scripts/shared.find_offsets_json — see shared.py's docstring for the assumed
file shape) and diffs per class:

    * removed   — class present in old dump, gone from new
    * added     — class present in new dump only
    * changed   — any field offset differs, or a field name was added/removed
    * unchanged — class name in both, no field differences

Offsets may be hex strings ("0x18"), plain ints, or null (AS3-style runtime
layouts); all normalize through int(x, 16) for strings. Null == null is not a
change; null -> value (or the reverse) is.

Exit codes:
    0 = no drift (additions of brand-new classes alone are fine — that's a
        normal dump growing)
    1 = changed/removed field offsets, removed classes, or field renames
    2 = missing offsets.json or unparseable JSON in either dir
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from shared import find_offsets_json, load_offsets, norm_hex, out  # noqa: E402


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


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        out(f"usage: {Path(sys.argv[0]).name} <old_dir> <new_dir>")
        return 2
    old_dir, new_dir = argv

    old_path = find_offsets_json(old_dir)
    new_path = find_offsets_json(new_dir)
    if old_path is None:
        out(f"[compare] no offsets.json under {old_dir}")
        return 2
    if new_path is None:
        out(f"[compare] no offsets.json under {new_dir}")
        return 2
    out(f"[compare] old: {old_path}")
    out(f"[compare] new: {new_path}")
    try:
        old = load_offsets(old_path)
        new = load_offsets(new_path)
    except ValueError as e:
        out(f"[compare] {e}")
        return 2

    result = diff_classes(old, new)
    removed = result["removed"]
    added = result["added"]
    changed = result["changed"]
    unchanged = result["unchanged"]
    changed_fields = sum(len(lines) for lines in changed.values())

    out("")
    out(f"removed classes : {len(removed)}")
    out(f"added classes   : {len(added)}")
    out(f"changed classes : {len(changed)}")
    out(f"unchanged       : {len(unchanged)}")
    out(f"changed fields  : {changed_fields}")
    out("")

    for cls_name in sorted(changed):
        for line in changed[cls_name]:
            out(f"  ~ {line}")
    for name in removed:
        out(f"  - {name} (removed)")
    for name in added:
        out(f"  + {name} (added)")

    if changed_fields or removed:
        out("")
        out(f"DRIFT: {changed_fields} changed fields across {len(changed)} classes")
        return 1
    out("")
    out("No drift")
    return 0


if __name__ == "__main__":
    sys.exit(main())
