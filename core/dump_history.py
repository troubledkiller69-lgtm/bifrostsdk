"""Dump history — archive every successful offsets.json, diff any two.

Layout: output/<game>/.history/<UTC-timestamp>.json (plus _meta with engine).
Keeps the newest 20 per game, prunes the rest. compare reuses
core/offset_diff.diff_classes (same logic as scripts/compare_dumps.py,
frozen-safe) so CLI and GUI agree.
"""
from __future__ import annotations

import datetime
import json
import os

_HISTORY_DIR = ".history"
_KEEP = 20


def _history_dir(output_dir: str) -> str:
    return os.path.join(os.path.abspath(output_dir), _HISTORY_DIR)


def archive_dump(output_dir: str, engine: str = "") -> dict:
    """Copy output_dir/offsets.json into .history/. Returns {archived, path}
    or {archived: False, reason} — never raises (history must not break dumps)."""
    try:
        src = os.path.join(os.path.abspath(output_dir), "offsets.json")
        if not os.path.isfile(src):
            return {"archived": False, "reason": "no offsets.json"}
        hdir = _history_dir(output_dir)
        os.makedirs(hdir, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # live result payload also lands here so history entries are
        # self-describing without re-reading the full offsets
        try:
            with open(src, "r", encoding="utf-8") as f:
                data = json.load(f)
            meta = data.get("_meta", {}) if isinstance(data, dict) else {}
        except Exception:
            meta = {}
        dest = os.path.join(hdir, f"{stamp}.json")
        with open(src, "rb") as fsrc, open(dest, "wb") as fdst:
            fdst.write(fsrc.read())
        # sidecar with engine + class/field counts for the picker UI
        classes = fields = 0
        try:
            offs = data.get("offsets", {}) if isinstance(data, dict) else {}
            classes = len(offs)
            fields = sum(len(v.get("fields", {})) for v in offs.values()
                         if isinstance(v, dict))
        except Exception:
            pass
        with open(dest + ".meta.json", "w", encoding="utf-8") as f:
            json.dump({"engine": engine or meta.get("engine", ""),
                       "classes": classes, "fields": fields,
                       "stamp": stamp, "game": os.path.basename(os.path.abspath(output_dir))}, f)
        # prune oldest
        snaps = sorted(f for f in os.listdir(hdir)
                       if f.endswith(".json") and not f.endswith(".meta.json"))
        for old in snaps[:-_KEEP]:
            for p in (os.path.join(hdir, old), os.path.join(hdir, old + ".meta.json")):
                try:
                    os.remove(p)
                except OSError:
                    pass
        return {"archived": True, "path": dest, "stamp": stamp,
                "classes": classes, "fields": fields}
    except Exception as exc:
        return {"archived": False, "reason": str(exc)}


def list_history(project_root: str) -> dict:
    """{games: {<game>: [{stamp, path, engine, classes, fields}]}} newest last."""
    games = {}
    output_root = os.path.join(os.path.abspath(project_root), "output")
    if not os.path.isdir(output_root):
        return {"games": {}}
    for game in sorted(os.listdir(output_root)):
        hdir = os.path.join(output_root, game, _HISTORY_DIR)
        if not os.path.isdir(hdir):
            continue
        entries = []
        for f in sorted(os.listdir(hdir)):
            if not f.endswith(".json") or f.endswith(".meta.json"):
                continue
            entry = {"stamp": f[:-5], "path": os.path.join(hdir, f),
                     "engine": "", "classes": 0, "fields": 0}
            try:
                with open(os.path.join(hdir, f + ".meta.json"), "r", encoding="utf-8") as mf:
                    entry.update(json.load(mf))
            except Exception:
                pass
            entries.append(entry)
        if entries:
            games[game] = entries
    return {"games": games}


def diff_snapshots(old_path: str, new_path: str) -> dict:
    """Diff two offsets.json files (history entries or live dirs)."""
    from .offset_diff import diff_classes, find_offsets_json, load_offsets

    old_json = old_path if str(old_path).endswith(".json") else find_offsets_json(old_path)
    new_json = new_path if str(new_path).endswith(".json") else find_offsets_json(new_path)
    if not old_json or not os.path.isfile(old_json):
        return {"error": f"no offsets.json at {old_path}", "code": "NO_SNAPSHOT"}
    if not new_json or not os.path.isfile(new_json):
        return {"error": f"no offsets.json at {new_path}", "code": "NO_SNAPSHOT"}
    try:
        old = load_offsets(old_json)
        new = load_offsets(new_json)
    except ValueError as exc:
        return {"error": str(exc), "code": "BAD_SNAPSHOT"}
    result = diff_classes(old, new)
    changed_fields = sum(len(v) for v in result["changed"].values())
    return {
        "old": str(old_json), "new": str(new_json),
        "removed": result["removed"], "added": result["added"],
        "changed": result["changed"], "unchanged_count": len(result["unchanged"]),
        "changed_fields": changed_fields,
        "drift": bool(changed_fields or result["removed"]),
    }
