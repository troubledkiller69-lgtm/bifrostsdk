"""Tests for core/signature_generator.py — byte classification and window selection."""

from __future__ import annotations

import pytest

from core.signature_generator import ByteClass, SignatureGenerator


class TestClassifyBytes:
    """Test the _classify_bytes pure function."""

    def _make_gen(self):
        """Create a SignatureGenerator with mocked reader/scanner (not needed for pure fns)."""
        gen = object.__new__(SignatureGenerator)
        return gen

    def test_single_entity_padding_detection(self):
        gen = self._make_gen()
        result = gen._classify_bytes([b"\x00\xCC\x48\x8B"])
        assert result[0] == ByteClass.PADDING  # 0x00
        assert result[1] == ByteClass.PADDING  # 0xCC
        assert result[2] == ByteClass.STABLE   # 0x48

    def test_multi_entity_stable_bytes(self):
        gen = self._make_gen()
        # Two entities with identical bytes at each position
        result = gen._classify_bytes([b"\x48\x8B\x05", b"\x48\x8B\x05"])
        assert all(c == ByteClass.STABLE for c in result)

    def test_multi_entity_variable_bytes(self):
        gen = self._make_gen()
        # Byte 1 differs between entities
        result = gen._classify_bytes([b"\x48\xAA\x05", b"\x48\xBB\x05"])
        assert result[0] == ByteClass.STABLE
        assert result[1] == ByteClass.VARIABLE
        assert result[2] == ByteClass.STABLE

    def test_empty_buffers_returns_empty(self):
        gen = self._make_gen()
        result = gen._classify_bytes([b"", b""])
        assert result == []

    def test_mismatched_lengths_uses_minimum(self):
        gen = self._make_gen()
        result = gen._classify_bytes([b"\x48\x8B", b"\x48"])
        assert len(result) == 1  # min length


class TestBestWindow:
    """Test the _best_window pure function."""

    def _make_gen(self):
        gen = object.__new__(SignatureGenerator)
        return gen

    def test_all_concrete_window(self):
        gen = self._make_gen()
        # All concrete bytes (no None/wildcards)
        pattern = [0x48, 0x8B, 0x05, 0x00, 0x90, 0x64, 0xA0, 0xFF]
        result = gen._best_window(pattern, 4)
        assert result is not None
        pat_str, ratio = result
        assert ratio == 1.0  # all concrete

    def test_mixed_window_selects_densest(self):
        gen = self._make_gen()
        # First 4 have 2 concrete, last 4 have 4 concrete
        pattern = [None, None, 0x48, 0x8B, 0x05, 0x00, 0x90, 0x64]
        result = gen._best_window(pattern, 4)
        assert result is not None
        _, ratio = result
        assert ratio >= 0.75  # should pick window with most concrete bytes

    def test_all_wildcards_returns_zero_ratio(self):
        gen = self._make_gen()
        pattern = [None, None, None, None]
        result = gen._best_window(pattern, 4)
        assert result is not None
        _, ratio = result
        assert ratio == 0.0

    def test_window_larger_than_pattern_returns_none(self):
        gen = self._make_gen()
        result = gen._best_window([0x48, 0x8B], 8)
        assert result is None

    def test_exact_size_window(self):
        gen = self._make_gen()
        pattern = [0x48, 0x8B, 0x05, None]
        result = gen._best_window(pattern, 4)
        assert result is not None
        _, ratio = result
        assert ratio == 0.75
