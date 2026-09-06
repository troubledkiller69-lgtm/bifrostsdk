"""Tests for contracts/validate.py — protocol validation and command allow-list."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contracts.validate import (
    KNOWN_COMMANDS,
    KNOWN_STREAMING,
    load_protocol,
    validate_command,
    validate_protocol_document,
)


class TestValidateCommand:
    """Test the command allow-list validator."""

    def test_known_command_accepted(self):
        ok, msg = validate_command("ping", {})
        assert ok is True

    def test_known_streaming_accepted(self):
        ok, msg = validate_command("dump", {"pid": 1234})
        assert ok is True
        assert "streaming" in msg

    def test_unknown_command_rejected(self):
        ok, msg = validate_command("drop_database", {})
        assert ok is False
        assert "Unknown" in msg

    def test_empty_command_rejected(self):
        ok, msg = validate_command("", {})
        assert ok is False

    def test_all_listed_commands_accepted(self):
        for cmd in KNOWN_COMMANDS:
            ok, _ = validate_command(cmd, {})
            assert ok, f"KNOWN_COMMANDS entry '{cmd}' was rejected"

    def test_all_streaming_commands_accepted(self):
        for cmd in KNOWN_STREAMING:
            ok, _ = validate_command(cmd, {})
            assert ok, f"KNOWN_STREAMING entry '{cmd}' was rejected"


class TestProtocolDocument:
    """Test the protocol document structure validation."""

    def test_protocol_loads(self):
        proto = load_protocol()
        assert isinstance(proto, dict)
        assert "protocol" in proto

    def test_protocol_validates(self):
        ok, msg = validate_protocol_document()
        assert ok, f"Protocol validation failed: {msg}"

    def test_protocol_version_is_1_1_or_newer(self):
        proto = load_protocol()
        version = proto["protocol"]["version"]
        assert version.startswith("1.1") or version.startswith("1.2") or version.startswith("1.3"), (
            f"Expected 1.1+, got {version}"
        )


class TestCommandListSync:
    """Verify KNOWN_COMMANDS and KNOWN_STREAMING match bifrost_protocol.json.

    This catches drift between the Python allow-list and the protocol document.
    Council finding T5: this was previously undetected.
    """

    def test_known_commands_match_protocol_json(self):
        proto = load_protocol()
        json_commands = set(proto.get("commands", {}).keys())
        python_commands = set(KNOWN_COMMANDS)
        assert python_commands == json_commands, (
            f"KNOWN_COMMANDS drift detected!\n"
            f"  In Python but not JSON: {python_commands - json_commands}\n"
            f"  In JSON but not Python: {json_commands - python_commands}"
        )

    def test_known_streaming_match_protocol_json(self):
        proto = load_protocol()
        json_streaming = set(proto.get("streaming_commands", {}).keys())
        python_streaming = set(KNOWN_STREAMING)
        assert python_streaming == json_streaming, (
            f"KNOWN_STREAMING drift detected!\n"
            f"  In Python but not JSON: {python_streaming - json_streaming}\n"
            f"  In JSON but not Python: {json_streaming - python_streaming}"
        )
