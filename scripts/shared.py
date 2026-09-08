"""Shared helpers for scripts/verify_output.py and scripts/compare_dumps.py.

Assumed offsets.json shape (matches contracts/sdk_output_schema.json and what
core/generator/SDKGenerator.generate_json emits):

    {
      "_meta": {
        "generator": "BIFROST SDK",
        "engine": "Source Engine",
        "timestamp": "...",
        "total_classes": 2779,
        "total_fields": 16428,
        ...optional keys...
      },
      "offsets": {
        "Engine.ClassName": {
          "size": "0x1A0",            # hex string canonical, or int
          "super": "Engine.Parent",   # "" for root classes
          "fields": {
            "m_SomeField": {
              "offset": "0x18",       # hex string, int, or null (AS3-style)
              "size": 4,              # int or null
              "type": "IntProperty"   # engine-native type name
            }
          }
        }
      }
    }
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Dump reports use '→' etc; Windows consoles default to cp1252 and choke.
# Best-effort UTF-8 with replace — degrades to '?' instead of crashing.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PROJECT_ROOT / "contracts" / "sdk_output_schema.json"


def find_offsets_json(output_dir: str) -> Path | None:
    """Locate offsets.json in a dump output dir.

    Checks the dir itself first, then one level deep (dump layouts commonly
    nest per-engine or per-module output under the given dir). Returns the
    first hit or None.
    """
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


def norm_hex(value) -> int | None:
    """Normalize an offset/size to int. Accepts '0x18' / '18' / 24 / None."""
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
        return int(s, 16)
    raise ValueError(f"not a hex/int value: {value!r}")


def out(*parts: str) -> None:
    print(" ".join(parts))
    sys.stdout.flush()
