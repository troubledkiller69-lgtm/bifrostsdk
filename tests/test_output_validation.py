"""
Tests for scripts/verify_output.py and scripts/compare_dumps.py.

Both scripts are plain stdlib CLI tools (jsonschema optional) exposing
main(argv) -> int. We import them via importlib (scripts/ is not a package)
and assert on return codes + captured output — no subprocess spawning, no
network. Fixtures build schema-valid minimal dumps in tmp_path mirroring the
shape from contracts/sdk_output_schema.json.

Coverage:
    verify_output  — clean dump exits 0; missing offsets.json exits 2;
                     zero-field class reported (informational, exit 0);
                     case-collision duplicate exits 1; schema violation
                     exits 1; manual (jsonschema-free) fallback agrees.
    compare_dumps  — identical dumps exit 0; changed field exits 1 with both
                     hex values + class.field in the report; removed class
                     exits 1; added class alone exits 0; missing file exits
                     2; int-form offsets normalize against hex-string ones.
"""

from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


def _load_script(name: str):
    path = SCRIPTS_DIR / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


verify_mod = _load_script("verify_output.py")
compare_mod = _load_script("compare_dumps.py")

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

FIELD_A = {"offset": "0x18", "size": 4, "type": "IntProperty"}
FIELD_B = {"offset": 0x20, "size": 8, "type": "DoubleProperty"}


def make_dump(tmp_path: Path, *, classes=None, meta_counts=None, name="offsets.json"):
    """Write a schema-minimal offsets.json into tmp_path; return its path."""
    offsets = classes if classes is not None else {
        "Game.Pawn": {
            "size": "0x100",
            "super": "Game.Actor",
            "fields": {"Health": FIELD_A, "Armor": FIELD_B},
        },
        "Game.Actor": {
            "size": "0x80",
            "super": "",
            "fields": {"Location": {"offset": "0x10", "size": 12, "type": "Vector"}},
        },
    }
    n_fields = sum(len(c["fields"]) for c in offsets.values())
    dump = {
        "_meta": {
            "generator": "BIFROST SDK",
            "engine": "unreal5",
            "timestamp": "2026-09-07T12:00:00Z",
            "total_classes": meta_counts[0] if meta_counts else len(offsets),
            "total_fields": meta_counts[1] if meta_counts else n_fields,
        },
        "offsets": offsets,
    }
    p = tmp_path / name
    p.write_text(json.dumps(dump), encoding="utf-8")
    return p


def dump_dir(tmp_path: Path, *, classes=None, meta_counts=None, sub=None) -> Path:
    """A directory (optionally nested one level) containing offsets.json."""
    d = tmp_path / (sub or "outdir")
    d.mkdir(parents=True, exist_ok=True)
    make_dump(d, classes=classes, meta_counts=meta_counts)
    return d


# ---------------------------------------------------------------------------
# verify_output.py
# ---------------------------------------------------------------------------

class TestVerifyOutput:
    def test_clean_dump_exits_zero(self, tmp_path, capsys):
        d = dump_dir(tmp_path)
        rc = verify_mod.main([str(d)])
        captured = capsys.readouterr().out
        assert rc == 0
        assert "total classes: 2" in captured
        assert "total fields: 3" in captured
        assert "schema (jsonschema): OK" in captured
        assert "OK — output is clean" in captured

    def test_missing_offsets_exits_2(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        rc = verify_mod.main([str(empty)])
        assert rc == 2
        assert "no offsets.json found" in capsys.readouterr().out

    def test_zero_field_class_reported_but_not_fatal(self, tmp_path, capsys):
        classes = {
            "Game.Pawn": {
                "size": "0x100", "super": "Game.Actor",
                "fields": {"Health": FIELD_A},
            },
            "Game.Interface": {
                "size": "0x8", "super": "", "fields": {},
            },
        }
        d = dump_dir(tmp_path, classes=classes)
        rc = verify_mod.main([str(d)])
        captured = capsys.readouterr().out
        assert rc == 0, captured  # informational, like real engine dumps
        assert "zero-field classes: 1" in captured
        assert "! Game.Interface" in captured

    def test_zero_field_class_fatal_with_strict(self, tmp_path, capsys):
        classes = {
            "Game.Pawn": {
                "size": "0x100", "super": "", "fields": {"Health": FIELD_A},
            },
            "Game.Interface": {"size": "0x8", "super": "", "fields": {}},
        }
        d = dump_dir(tmp_path, classes=classes)
        rc = verify_mod.main([str(d), "--strict"])
        assert rc == 1
        assert "informational" not in capsys.readouterr().out

    def test_field_name_collision_exits_1(self, tmp_path, capsys):
        # JSON keys are unique, but names differing only by case are C++
        # member collisions once headers are generated.
        classes = {
            "Game.Pawn": {
                "size": "0x100", "super": "",
                "fields": {"Health": FIELD_A, "health": FIELD_B},
            },
        }
        d = dump_dir(tmp_path, classes=classes)
        rc = verify_mod.main([str(d)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "collides with" in captured

    def test_schema_violation_exits_1(self, tmp_path, capsys):
        classes = {
            "Game.Pawn": {
                "size": "0x100", "super": "",
                "fields": {"Health": {"offset": "not_hex", "size": 4,
                                      "type": "IntProperty"}},
            },
        }
        d = dump_dir(tmp_path, classes=classes)
        rc = verify_mod.main([str(d)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "schema (jsonschema): FAIL" in captured

    def test_meta_count_mismatch_exits_1(self, tmp_path, capsys):
        d = dump_dir(tmp_path, meta_counts=(99, 1))
        rc = verify_mod.main([str(d)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "total_classes says 99 but offsets has 2" in captured

    def test_nested_offsets_found_one_level_deep(self, tmp_path, capsys):
        d = dump_dir(tmp_path, sub="cs2")
        rc = verify_mod.main([str(tmp_path)])
        assert rc == 0
        assert "total classes: 2" in capsys.readouterr().out

    def test_manual_fallback_agrees_on_clean_and_broken(self, tmp_path):
        clean = {
            "_meta": {"generator": "BIFROST SDK", "engine": "source",
                      "timestamp": "t", "total_classes": 1, "total_fields": 1},
            "offsets": {"A": {"size": "0x10", "super": "",
                              "fields": {"x": {"offset": "0x0", "size": 4,
                                               "type": "IntProperty"}}}},
        }
        broken = deepcopy(clean)
        del broken["offsets"]["A"]["fields"]["x"]["offset"]
        schema = {"$defs": {}}  # content unused by the manual walk
        assert verify_mod.schema_errors_manual(clean, schema) == []
        assert verify_mod.schema_errors_manual(broken, schema) != []

    def test_headers_check_flags_bad_file(self, tmp_path, capsys):
        hdrs = tmp_path / "hdrs"
        hdrs.mkdir()
        (hdrs / "good.h").write_text(
            "class GoodClass\n{\npublic:\n    int32 m_x; // 0x0\n};\n",
            encoding="utf-8",
        )
        (hdrs / "bad.h").write_text(
            "class EmptyClass {};\nstruct LoneField {\n    ; // no type\n};\n",
            encoding="utf-8",
        )
        d = dump_dir(tmp_path)
        rc = verify_mod.main([str(d), "--headers", str(hdrs)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "bad.h:1: empty struct/class body" in captured
        assert "bad.h:3: field with no type" in captured

    def test_headers_balance_ok(self, tmp_path, capsys):
        hdrs = tmp_path / "hdrs"
        hdrs.mkdir()
        (hdrs / "ok.h").write_text(
            "class OkClass\n{\npublic:\n    int32 m_x; // 0x0\n};\n"
            "static_assert(sizeof(OkClass) == 4);\n",
            encoding="utf-8",
        )
        d = dump_dir(tmp_path)
        rc = verify_mod.main([str(d), "--headers", str(hdrs)])
        assert rc == 0


# ---------------------------------------------------------------------------
# compare_dumps.py
# ---------------------------------------------------------------------------

class TestCompareDumps:
    def test_identical_dumps_exit_zero(self, tmp_path, capsys):
        old = dump_dir(tmp_path / "old", sub="cs2")
        new = dump_dir(tmp_path / "new", sub="cs2")
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        captured = capsys.readouterr().out
        assert rc == 0
        assert "No drift" in captured
        assert "unchanged       : 2" in captured

    def test_changed_offset_exits_1_with_hexes(self, tmp_path, capsys):
        old = dump_dir(tmp_path / "old", sub="cs2")
        classes = {
            "Game.Pawn": {
                "size": "0x100", "super": "Game.Actor",
                "fields": {"Health": {"offset": "0x1C", "size": 4,
                                      "type": "IntProperty"},
                           "Armor": FIELD_B},
            },
            "Game.Actor": {
                "size": "0x80", "super": "",
                "fields": {"Location": {"offset": "0x10", "size": 12,
                                        "type": "Vector"}},
            },
        }
        new = dump_dir(tmp_path / "new", sub="cs2", classes=classes)
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "Game.Pawn.Health: 0x18 → 0x1C" in captured
        assert "DRIFT: 1 changed fields across 1 classes" in captured

    def test_int_offset_normalizes_against_hex_string(self, tmp_path, capsys):
        # New dump stores offsets as plain ints; old as hex strings. Identical
        # values must NOT register as drift.
        old = dump_dir(tmp_path / "old", sub="cs2")
        classes = {
            "Game.Pawn": {
                "size": "0x100", "super": "Game.Actor",
                "fields": {"Health": {"offset": 0x18, "size": 4,
                                      "type": "IntProperty"},
                           "Armor": FIELD_B},
            },
            "Game.Actor": {
                "size": "0x80", "super": "",
                "fields": {"Location": {"offset": 0x10, "size": 12,
                                        "type": "Vector"}},
            },
        }
        new = dump_dir(tmp_path / "new", sub="cs2", classes=classes)
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        assert rc == 0
        assert "No drift" in capsys.readouterr().out

    def test_removed_class_exits_1(self, tmp_path, capsys):
        old = dump_dir(tmp_path / "old", sub="cs2")
        classes = {"Game.Pawn": {
            "size": "0x100", "super": "",
            "fields": {"Health": FIELD_A, "Armor": FIELD_B},
        }}
        new = dump_dir(tmp_path / "new", sub="cs2", classes=classes)
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "- Game.Actor (removed)" in captured
        assert "DRIFT: 0 changed fields across 0 classes" in captured

    def test_added_class_alone_exits_zero(self, tmp_path, capsys):
        old_classes = {"Game.Actor": {
            "size": "0x80", "super": "",
            "fields": {"Location": {"offset": "0x10", "size": 12,
                                    "type": "Vector"}},
        }}
        old = dump_dir(tmp_path / "old", sub="cs2", classes=old_classes)
        new = dump_dir(tmp_path / "new", sub="cs2")
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        captured = capsys.readouterr().out
        assert rc == 0  # dump growth = no drift
        assert "+ Game.Pawn (added)" in captured
        assert "No drift" in captured

    def test_field_removed_within_class_exits_1(self, tmp_path, capsys):
        classes = {"Game.Pawn": {
            "size": "0x100", "super": "",
            "fields": {"Armor": FIELD_B},  # Health dropped
        }}
        old = dump_dir(tmp_path / "old", sub="cs2")
        new = dump_dir(tmp_path / "new", sub="cs2", classes=classes)
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "Game.Pawn.Health: 0x18 → <removed>" in captured

    def test_missing_offsets_exits_2(self, tmp_path, capsys):
        good = dump_dir(tmp_path / "good", sub="cs2")
        empty = tmp_path / "empty"
        empty.mkdir()
        rc = compare_mod.main([str(good.parent), str(empty)])
        assert rc == 2
        assert "no offsets.json under" in capsys.readouterr().out

    def test_unparseable_json_exits_2(self, tmp_path, capsys):
        old = dump_dir(tmp_path / "old", sub="cs2")
        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / "offsets.json").write_text("{ not json", encoding="utf-8")
        rc = compare_mod.main([str(old.parent), str(bad)])
        assert rc == 2
        assert "cannot parse" in capsys.readouterr().out

    def test_class_name_change_reads_as_removed_plus_added(self, tmp_path, capsys):
        actor = {
            "Game.Actor": {
                "size": "0x80", "super": "",
                "fields": {"Location": {"offset": "0x10", "size": 12,
                                        "type": "Vector"}},
            },
        }
        old = dump_dir(tmp_path / "old", sub="cs2", classes=actor)
        renamed = {
            "Game.ActorNew": {
                "size": "0x80", "super": "",
                "fields": {"Location": {"offset": "0x10", "size": 12,
                                        "type": "Vector"}},
            },
            "Game.Pawn": {  # genuinely new class — additions alone are fine
                "size": "0x100", "super": "Game.ActorNew",
                "fields": {"Health": FIELD_A, "Armor": FIELD_B},
            },
        }
        new = dump_dir(tmp_path / "new", sub="cs2", classes=renamed)
        rc = compare_mod.main([str(old.parent), str(new.parent)])
        captured = capsys.readouterr().out
        assert rc == 1
        assert "- Game.Actor (removed)" in captured
        assert "+ Game.ActorNew (added)" in captured
        assert "+ Game.Pawn (added)" in captured
