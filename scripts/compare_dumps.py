"""compare_dumps.py — offset-drift watcher between two dump outputs.

Usage:
    python scripts/compare_dumps.py <old_dir> <new_dir>

Loads offsets.json from both dirs (itself, then one level deep) and diffs
per class:

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

Diff logic lives in core/offset_diff.py (shared with the frozen backend's
dump_history) — this file is the CLI wrapper only.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from core.offset_diff import (  # noqa: E402
    diff_classes,
    find_offsets_json,
    hex_str,
    load_offsets,
)
from scripts.shared import out  # noqa: E402


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
