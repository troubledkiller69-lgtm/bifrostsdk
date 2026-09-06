"""Tests for core/scanner.py — pattern compilation and matching logic."""

from __future__ import annotations

import re

import pytest

from core.scanner import PatternScanner


class TestCompilePattern:
    """Test the pure _compile_pattern function."""

    def test_simple_pattern(self):
        regex = PatternScanner._compile_pattern("48 8B 05")
        assert regex.match(b"\x48\x8B\x05")

    def test_wildcard_double_question(self):
        regex = PatternScanner._compile_pattern("48 ?? 05")
        assert regex.match(b"\x48\xFF\x05")
        assert regex.match(b"\x48\x00\x05")

    def test_wildcard_single_question(self):
        regex = PatternScanner._compile_pattern("48 ? 05")
        assert regex.match(b"\x48\xAA\x05")

    def test_wildcard_asterisk(self):
        regex = PatternScanner._compile_pattern("48 ** 05")
        assert regex.match(b"\x48\x01\x05")

    def test_no_match_wrong_bytes(self):
        regex = PatternScanner._compile_pattern("48 8B 05")
        assert not regex.match(b"\x49\x8B\x05")

    def test_empty_pattern_raises(self):
        # An empty string should produce an empty-token list
        regex = PatternScanner._compile_pattern("")
        # Empty regex matches empty bytes
        assert regex.match(b"")

    def test_pattern_with_extra_spaces(self):
        regex = PatternScanner._compile_pattern("  48   8B   05  ")
        assert regex.match(b"\x48\x8B\x05")

    def test_all_wildcards(self):
        regex = PatternScanner._compile_pattern("?? ?? ??")
        assert regex.match(b"\x00\x00\x00")
        assert regex.match(b"\xFF\xFF\xFF")

    def test_long_pattern(self):
        pat = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20"
        regex = PatternScanner._compile_pattern(pat)
        data = b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20"
        assert regex.match(data)

    def test_pattern_finds_in_buffer(self):
        """Verify that a compiled pattern can find a match inside a larger buffer."""
        regex = PatternScanner._compile_pattern("AA BB CC")
        data = b"\x00\x00\xAA\xBB\xCC\x00\x00"
        match = regex.search(data)
        assert match is not None
        assert match.start() == 2
