"""
Tests for contracts/sdk_output_schema.json — engine-agnostic dump output validation.

These tests give us confidence that every engine produces well-formed output
even when no live game is available. The schema enforces structural shape;
correctness against real game memory is Tier 2/3 of the validation strategy
(see docs/superpowers/specs/ or the most recent plan file).
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

# jsonschema is already a dependency via contracts/validate.py
from jsonschema import Draft7Validator, ValidationError, validate

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "contracts"
    / "sdk_output_schema.json"
)


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def valid_dump() -> dict:
    """A minimal well-formed dump matching what core/generator/__init__.py emits."""
    return {
        "_meta": {
            "generator": "BIFROST SDK",
            "engine": "unreal5",
            "timestamp": "2026-05-29T14:32:00Z",
            "total_classes": 2,
            "total_fields": 3,
        },
        "offsets": {
            "Engine.Pawn": {
                "size": "0x440",
                "super": "Engine.Actor",
                "fields": {
                    "Health": {"offset": "0x18", "size": 4, "type": "IntProperty"},
                    "MaxHealth": {"offset": "0x1C", "size": 4, "type": "IntProperty"},
                },
            },
            "Engine.Actor": {
                "size": "0x400",
                "super": "",
                "fields": {
                    "Location": {"offset": "0x10", "size": 12, "type": "StructProperty"},
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Schema loads / basic shape
# ---------------------------------------------------------------------------

class TestSchemaIntegrity:
    def test_schema_file_exists(self):
        assert SCHEMA_PATH.exists()

    def test_schema_is_valid_draft07(self, schema):
        # If the schema itself is malformed, jsonschema raises here.
        Draft7Validator.check_schema(schema)

    def test_schema_has_top_level_required(self, schema):
        assert schema["required"] == ["_meta", "offsets"]


# ---------------------------------------------------------------------------
# Valid dumps pass
# ---------------------------------------------------------------------------

class TestValidDumpsPass:
    def test_unreal_minimal_dump_passes(self, schema, valid_dump):
        validate(instance=valid_dump, schema=schema)  # should not raise

    def test_optional_meta_fields_are_accepted(self, schema, valid_dump):
        valid_dump["_meta"]["verified_against_live_process"] = True
        valid_dump["_meta"]["bridge_version"] = "abc123"
        valid_dump["_meta"]["dumper_version"] = "3.0.0"
        validate(instance=valid_dump, schema=schema)

    def test_empty_offsets_passes(self, schema, valid_dump):
        valid_dump["offsets"] = {}
        valid_dump["_meta"]["total_classes"] = 0
        valid_dump["_meta"]["total_fields"] = 0
        validate(instance=valid_dump, schema=schema)


# ---------------------------------------------------------------------------
# Malformed dumps fail with useful errors
# ---------------------------------------------------------------------------

class TestMalformedDumpsRejected:
    def test_missing_meta_key_rejected(self, schema, valid_dump):
        del valid_dump["_meta"]["engine"]
        with pytest.raises(ValidationError) as exc_info:
            validate(instance=valid_dump, schema=schema)
        assert "engine" in str(exc_info.value)

    def test_missing_offsets_key_rejected(self, schema, valid_dump):
        del valid_dump["offsets"]
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_total_classes_wrong_type_rejected(self, schema, valid_dump):
        valid_dump["_meta"]["total_classes"] = "two"
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_negative_total_classes_rejected(self, schema, valid_dump):
        valid_dump["_meta"]["total_classes"] = -1
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_class_missing_size_rejected(self, schema, valid_dump):
        del valid_dump["offsets"]["Engine.Pawn"]["size"]
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_class_missing_fields_rejected(self, schema, valid_dump):
        del valid_dump["offsets"]["Engine.Pawn"]["fields"]
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_class_extra_key_rejected(self, schema, valid_dump):
        # additionalProperties: false on the class record — catches typos
        valid_dump["offsets"]["Engine.Pawn"]["typo_key"] = "junk"
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_field_missing_offset_rejected(self, schema, valid_dump):
        del valid_dump["offsets"]["Engine.Pawn"]["fields"]["Health"]["offset"]
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_field_offset_garbage_string_rejected(self, schema, valid_dump):
        valid_dump["offsets"]["Engine.Pawn"]["fields"]["Health"]["offset"] = "not_hex"
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_field_size_negative_rejected(self, schema, valid_dump):
        valid_dump["offsets"]["Engine.Pawn"]["fields"]["Health"]["size"] = -1
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)

    def test_top_level_extra_key_rejected(self, schema, valid_dump):
        # Top-level additionalProperties: false — catches accidental new keys
        valid_dump["bonus_data"] = {"sneaky": True}
        with pytest.raises(ValidationError):
            validate(instance=valid_dump, schema=schema)


# ---------------------------------------------------------------------------
# Engine identifiers — all known engines validate
# ---------------------------------------------------------------------------

class TestKnownEngines:
    @pytest.mark.parametrize("engine", [
        "unreal5", "unity_mono", "unity_il2cpp",
        "source", "blizzard",
    ])
    def test_known_engine_validates(self, schema, valid_dump, engine):
        valid_dump["_meta"]["engine"] = engine
        validate(instance=valid_dump, schema=schema)

    def test_unknown_engine_still_accepted(self, schema, valid_dump):
        # engine field is intentionally not enum-constrained — new engines
        # shouldn't trigger schema failures during early integration.
        valid_dump["_meta"]["engine"] = "experimental_godot_v5"
        validate(instance=valid_dump, schema=schema)
