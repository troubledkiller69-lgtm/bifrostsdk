"""verify_output.py — CLI validator for a dump's output directory.

Usage:
    python scripts/verify_output.py [output_dir] [--headers <hdr_dir>]

Checks offsets.json (default: ./output/, found one level deep if nested)
against contracts/sdk_output_schema.json, then reports:

    * total classes / total fields (from _meta, cross-checked against data)
    * top-level keys present
    * schema status (jsonschema when installed, manual structural fallback
      otherwise — the fallback mirrors the schema's required shape so the
      tool works on a stdlib-only box)
    * zero-field classes and duplicate field names per class

Headers mode (`--headers <dir>`): globs *.h and sanity-checks each file —
balanced braces, at least one struct/class declaration, and suspicious
lines (empty struct bodies, member lines with no type).

Exit codes: 0 clean, 1 any validation problem, 2 no offsets.json found.

Zero-field classes are REPORTED but not fatal: real engine dumps legitimately
contain fieldless classes (the live CS2 dump has 597 out of 2779). Fatal
problems are schema violations, name collisions, and _meta count mismatches.
Pass --strict to treat zero-field classes and header oddities as fatal.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from shared import PROJECT_ROOT, SCHEMA_PATH, find_offsets_json, load_offsets, out  # noqa: E402


# ---------------------------------------------------------------------------
# Schema loading / validation
# ---------------------------------------------------------------------------

def load_schema() -> dict | None:
    """Load contracts/sdk_output_schema.json. None when missing."""
    try:
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def schema_errors_jsonschema(data: dict, schema: dict) -> list[str]:
    """Validate via jsonschema; returns a list of human-readable problems."""
    from jsonschema import Draft7Validator

    validator = Draft7Validator(schema)
    problems = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        where = ".".join(str(p) for p in err.path) or "<root>"
        problems.append(f"{where}: {err.message}")
    return problems


# Manual fallback — mirrors the schema's required shape without jsonschema.
_MANUAL_RULES = (
    ("_meta", dict, "top-level _meta must be an object"),
    ("offsets", dict, "top-level offsets must be an object"),
    ("_meta.generator", str, "_meta.generator must be a string"),
    ("_meta.engine", str, "_meta.engine must be a string"),
    ("_meta.timestamp", str, "_meta.timestamp must be a string"),
    ("_meta.total_classes", int, "_meta.total_classes must be an integer"),
    ("_meta.total_fields", int, "_meta.total_fields must be an integer"),
)


def schema_errors_manual(data: dict, schema: dict | None) -> list[str]:
    """Structural validation for when jsonschema is not importable."""
    problems = []
    for path, kind, msg in _MANUAL_RULES:
        node = data
        ok = True
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                ok = False
                break
            node = node[part]
        if not ok or (kind is not None and not isinstance(node, kind)):
            problems.append(f"{path}: {msg}")

    if not isinstance(data.get("offsets"), dict):
        return problems

    for cls_name, cls_rec in data["offsets"].items():
        where = f"offsets.{cls_name}"
        if not isinstance(cls_rec, dict):
            problems.append(f"{where}: class record must be an object")
            continue
        for key, kind in (("size", (str, int)), ("super", str), ("fields", dict)):
            if key not in cls_rec:
                problems.append(f"{where}: missing required key '{key}'")
            elif not isinstance(cls_rec[key], kind):
                problems.append(f"{where}.{key}: wrong type (expected {kind})")
        fields = cls_rec.get("fields")
        if not isinstance(fields, dict):
            continue
        for fld_name, fld_rec in fields.items():
            fwhere = f"{where}.fields.{fld_name}"
            if not isinstance(fld_rec, dict):
                problems.append(f"{fwhere}: field record must be an object")
                continue
            for key in ("offset", "size", "type"):
                if key not in fld_rec:
                    problems.append(f"{fwhere}: missing required key '{key}'")
            if "type" in fld_rec and not isinstance(fld_rec["type"], str):
                problems.append(f"{fwhere}.type: must be a string")
    return problems


def validate_against_schema(data: dict) -> tuple[str, list[str]]:
    """Return (mode, problems). mode is 'jsonschema', 'manual', or 'skipped'."""
    schema = load_schema()
    if schema is None:
        return ("skipped", ["contracts/sdk_output_schema.json not found"])
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return ("manual", schema_errors_manual(data, schema))
    return ("jsonschema", schema_errors_jsonschema(data, schema))


# ---------------------------------------------------------------------------
# Content checks
# ---------------------------------------------------------------------------

def _collision_key(name: str) -> str:
    """Name collisions = keys differing only by case or surrounding space."""
    return re.sub(r"\s+", " ", name).strip().lower()


def structural_findings(data: dict) -> tuple[list[str], list[str]]:
    """Cross-check content. Returns (zero_field_classes, collisions)."""
    offsets = data.get("offsets", {})
    zero_field = []
    collisions = []
    for cls_name in sorted(offsets):
        fields = offsets[cls_name].get("fields", {}) if isinstance(offsets[cls_name], dict) else {}
        if not fields:
            zero_field.append(cls_name)
        seen = {}
        for fld_name in fields:
            k = _collision_key(fld_name)
            if k in seen:
                collisions.append(f"{cls_name}: '{fld_name}' collides with '{seen[k]}'")
            else:
                seen[k] = fld_name
    return zero_field, collisions


# ---------------------------------------------------------------------------
# Headers sanity check
# ---------------------------------------------------------------------------

_RE_EMPTY_STRUCT = re.compile(r"^\s*(struct|class)\s+[\w:<>]+\s*\{\s*\}\s*;?")
_RE_ONE_TOKEN_MEMBER = re.compile(r"^\s+[\w:~]*\s*;")  # "Foo;" or ";" — no type


def check_headers(hdr_dir: str, problems: list[str]) -> tuple[int, int]:
    """Sanity-check *.h files. Returns (files_checked, files_with_problems)."""
    d = Path(hdr_dir)
    files = sorted(d.glob("*.h")) if d.is_dir() else []
    checked = 0
    bad_files = 0
    for path in files:
        checked += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            problems.append(f"[headers] {path.name}: unreadable ({e})")
            bad_files += 1
            continue
        code_lines = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith("//") and not ln.strip().startswith("#")
        ]
        braces = sum(1 for ln in code_lines if "{" in ln) - sum(1 for ln in code_lines if "}" in ln)
        if braces != 0:
            problems.append(f"[headers] {path.name}: unbalanced braces (net {'+' if braces > 0 else ''}{braces})")
            bad_files += 1
        decls = sum(1 for ln in code_lines if re.match(r"^\s*(struct|class)\s+\w", ln))
        if decls == 0:
            problems.append(f"[headers] {path.name}: no struct/class declaration found")
            bad_files += 1
        file_bad = False
        for idx, ln in enumerate(code_lines, start=1):
            if _RE_EMPTY_STRUCT.search(ln):
                problems.append(f"[headers] {path.name}:{idx}: empty struct/class body — {ln.strip()}")
                file_bad = True
            elif _RE_ONE_TOKEN_MEMBER.match(ln):
                problems.append(f"[headers] {path.name}:{idx}: field with no type — {ln.strip()}")
                file_bad = True
        if file_bad:
            bad_files += 1
    return checked, bad_files


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    output_dir = "output"
    headers_dir = None
    i = 0
    while i < len(argv):
        if argv[i] == "--headers":
            if i + 1 >= len(argv):
                out("--headers requires a directory argument")
                return 1
            headers_dir = argv[i + 1]
            i += 2
        elif argv[i].startswith("-"):
            out(f"unknown option: {argv[i]}")
            return 1
        else:
            output_dir = argv[i]
            i += 1

    problems: list[str] = []
    strict = "--strict" in argv
    argv = [a for a in argv if a != "--strict"]
    json_path = find_offsets_json(output_dir)
    if json_path is None:
        out(f"[verify] no offsets.json found under {output_dir}")
        return 2

    out(f"[verify] {json_path}")
    try:
        data = load_offsets(json_path)
    except ValueError as e:
        out(f"[verify] {e}")
        return 1

    top_keys = sorted(data.keys())
    offsets = data.get("offsets", {}) if isinstance(data.get("offsets"), dict) else {}
    classes = len(offsets)
    fields = sum(
        len(c.get("fields", {})) for c in offsets.values()
        if isinstance(c, dict)
    )
    meta = data.get("_meta", {}) if isinstance(data.get("_meta"), dict) else {}
    meta_classes = meta.get("total_classes", "?")
    meta_fields = meta.get("total_fields", "?")
    mode, schema_problems = validate_against_schema(data)
    problems += schema_problems

    zero_field, collisions = structural_findings(data)
    problems += collisions
    meta_mismatch = False

    if isinstance(meta_classes, int) and meta_classes != classes:
        problems.append(
            f"_meta.total_classes says {meta_classes} but offsets has {classes}"
        )
        meta_mismatch = True
    if isinstance(meta_fields, int) and meta_fields != fields:
        problems.append(
            f"_meta.total_fields says {meta_fields} but offsets has {fields}"
        )
        meta_mismatch = True

    out(f"[verify] total classes: {classes} (meta: {meta_classes})")
    out(f"[verify] total fields: {fields} (meta: {meta_fields})")
    out(f"[verify] top-level keys: {', '.join(top_keys)}")
    if schema_problems:
        out(f"[verify] schema ({mode}): FAIL — {len(schema_problems)} violation(s)")
    else:
        out(f"[verify] schema ({mode}): OK")

    if zero_field:
        out(f"[verify] zero-field classes: {len(zero_field)}")
        for name in zero_field[:5]:
            out(f"    ! {name}")
        if len(zero_field) > 5:
            out(f"    ... and {len(zero_field) - 5} more")
    else:
        out("[verify] zero-field classes: 0")
    if collisions:
        out(f"[verify] field name collisions: {len(collisions)}")

    if headers_dir:
        checked, bad_files = check_headers(headers_dir, problems)
        out(f"[verify] headers: {checked} file(s) checked, {bad_files} with problems")
    else:
        bad_files = 0

    fatal = (
        bool(schema_problems)
        or bool(collisions)
        or meta_mismatch
        or (headers_dir is not None and bad_files > 0)
    )
    if strict:
        fatal = fatal or bool(zero_field)

    if problems:
        out(f"[verify] {len(problems)} problem(s) found")
        for p in problems[:20]:
            out(f"    ! {p}")
        if len(problems) > 20:
            out(f"    ... and {len(problems) - 20} more")
        if not fatal:
            out("[verify] all problems are informational (pass --strict to fail on them)")
        return 1 if fatal else 0
    out("[verify] OK — output is clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
