"""
BIFROST SDK -- AOB Signature Generator
Given known-good entity addresses, reads surrounding bytes from multiple
entities, classifies each byte position as stable or variable, and generates
AOB patterns at different quality levels.

Two strategies:
  1. generate_from_addresses  -- compare raw bytes across entities
  2. generate_from_field_anchors -- use known field values as anchors
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from .memory import MemoryReader
from .scanner import PatternScanner


# ------------------------------------------------------------------
# Byte classification
# ------------------------------------------------------------------

class ByteClass(Enum):
    STABLE = auto()       # Same value in every entity
    VARIABLE = auto()     # Differs across entities
    PADDING = auto()      # 0x00 or 0xCC -- likely padding
    POINTER_LIKE = auto() # Looks like a memory address


@dataclass
class SignatureCandidate:
    """A generated AOB pattern with quality metadata."""
    pattern: str                # e.g. "00 90 64 ?? ?? A0"
    strategy: str               # "tight" | "balanced" | "loose"
    length: int                 # number of bytes
    concrete_ratio: float       # fraction of non-wildcard bytes
    scan_matches: int = 0       # how many hits in the full process scan
    score: float = 0.0          # overall quality score (higher = better)


class SignatureGenerator:
    """
    Build AOB signatures from known-good entity addresses.

    Usage::

        gen = SignatureGenerator(reader, scanner)
        candidates = gen.generate_from_addresses(entity_addrs)
        best = candidates[0]  # sorted by score descending
    """

    # Candidate window sizes to try (bytes)
    WINDOW_SIZES = [16, 24, 32, 48]

    def __init__(self, reader: MemoryReader, scanner: PatternScanner):
        self.reader = reader
        self.scanner = scanner

    # ------------------------------------------------------------------
    # Primary: multi-entity comparison
    # ------------------------------------------------------------------

    def generate_from_addresses(
        self,
        addresses: list[int],
        read_size: int = 0x100,
        anchor_offset: int = 0,
    ) -> list[SignatureCandidate]:
        """
        Read *read_size* bytes from each address, classify each byte, and
        return scored signature candidates sorted best-first.

        Parameters
        ----------
        addresses : known-good entity base addresses (at least 1)
        read_size : how many bytes to read from each entity
        anchor_offset : byte offset within the entity to center signatures on
        """
        if not addresses:
            return []

        # 1. Read raw bytes from every entity
        buffers: list[bytes] = []
        for addr in addresses:
            try:
                buf = self.reader.read_bytes(addr + anchor_offset, read_size)
                buffers.append(buf)
            except Exception:
                continue

        if not buffers:
            return []

        # 2. Classify each byte position
        classifications = self._classify_bytes(buffers)

        # 3. Build candidate signatures at 3 strategy levels
        strategies = {
            "tight":    self._build_tight(buffers[0], classifications),
            "balanced": self._build_balanced(buffers[0], classifications),
            "loose":    self._build_loose(buffers[0], classifications),
        }

        # 4. For each strategy, find the best window
        candidates: list[SignatureCandidate] = []
        for strategy_name, full_pattern_bytes in strategies.items():
            for window_size in self.WINDOW_SIZES:
                best = self._best_window(full_pattern_bytes, window_size)
                if best is None:
                    continue

                pattern_str, concrete_ratio = best
                if concrete_ratio < 0.3:
                    continue  # too many wildcards

                candidates.append(SignatureCandidate(
                    pattern=pattern_str,
                    strategy=strategy_name,
                    length=window_size,
                    concrete_ratio=concrete_ratio,
                ))

        # 5. Score candidates by scanning the process for false positives
        for cand in candidates:
            cand.scan_matches = self._count_matches(cand.pattern)
            # Prefer: high concrete ratio, low match count (ideally = expected),
            # longer patterns, balanced strategy
            strategy_bonus = {"balanced": 0.2, "tight": 0.1, "loose": 0.0}
            expected = len(addresses)
            if cand.scan_matches > 0:
                uniqueness = expected / cand.scan_matches
            else:
                uniqueness = 0.0
            cand.score = (
                uniqueness * 0.5
                + cand.concrete_ratio * 0.3
                + (cand.length / 48.0) * 0.1
                + strategy_bonus.get(cand.strategy, 0)
            )

        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    # ------------------------------------------------------------------
    # Alternative: field-anchor approach
    # ------------------------------------------------------------------

    def generate_from_field_anchors(
        self,
        addresses: list[int],
        field_offsets: dict[str, tuple[int, str, int]],
        validation_fn=None,
    ) -> list[SignatureCandidate]:
        """
        Use known field values as anchors.  Find the densest cluster of
        fields that validate, then build a signature centered on that region.

        *validation_fn(name, value) -> bool* checks whether a read value is
        plausible for the named field (e.g., x_position is a float in range).
        """
        if not addresses or not field_offsets:
            return []

        # Default validator: accept everything
        if validation_fn is None:
            validation_fn = lambda name, val: True

        # Find which offsets validate across entities
        validated_offsets: list[int] = []
        for name, (offset, type_name, size) in field_offsets.items():
            ok_count = 0
            for addr in addresses:
                try:
                    if type_name == "float":
                        val = self.reader.read_float(addr + offset)
                    else:
                        val = self.reader.read_int32(addr + offset)
                    if validation_fn(name, val):
                        ok_count += 1
                except Exception:
                    pass
            if ok_count == len(addresses):
                validated_offsets.append(offset)

        if len(validated_offsets) < 3:
            return []

        # Find densest cluster of validated offsets
        validated_offsets.sort()
        best_start, best_count = 0, 0
        for i, off in enumerate(validated_offsets):
            window_end = off + 48
            count = sum(1 for o in validated_offsets if off <= o < window_end)
            if count > best_count:
                best_start = off
                best_count = count

        # Read that region from all entities and generate via standard path
        return self.generate_from_addresses(
            addresses,
            read_size=64,
            anchor_offset=best_start,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _classify_bytes(self, buffers: list[bytes]) -> list[ByteClass]:
        """Classify each byte position across all entity buffers."""
        length = min(len(b) for b in buffers)
        result: list[ByteClass] = []

        for i in range(length):
            values = {b[i] for b in buffers}

            if len(buffers) == 1:
                # Single entity: heuristic classification
                val = buffers[0][i]
                if val in (0x00, 0xCC):
                    result.append(ByteClass.PADDING)
                elif i % 4 == 0 and i + 4 <= length:
                    # Check if this starts a pointer-like 4-byte value
                    as_uint = int.from_bytes(buffers[0][i:i+4], "little", signed=False)
                    if 0x10000 < as_uint < 0x7FFFFFFFFFFF:
                        result.append(ByteClass.POINTER_LIKE)
                    else:
                        result.append(ByteClass.STABLE)
                else:
                    result.append(ByteClass.STABLE)
            else:
                # Multi-entity: compare across all
                if len(values) == 1:
                    val = values.pop()
                    if val in (0x00, 0xCC):
                        result.append(ByteClass.PADDING)
                    else:
                        result.append(ByteClass.STABLE)
                else:
                    # Check if the variation looks pointer-like
                    if i % 4 == 0 and i + 4 <= length:
                        is_ptr = True
                        for b in buffers:
                            as_uint = int.from_bytes(b[i:i+4], "little", signed=False)
                            if not (0x10000 < as_uint < 0x7FFFFFFFFFFF):
                                is_ptr = False
                                break
                        if is_ptr:
                            result.append(ByteClass.POINTER_LIKE)
                        else:
                            result.append(ByteClass.VARIABLE)
                    else:
                        result.append(ByteClass.VARIABLE)

        return result

    def _build_tight(
        self, reference: bytes, classes: list[ByteClass]
    ) -> list[Optional[int]]:
        """
        Tight strategy: only wildcard VARIABLE and POINTER_LIKE bytes.
        Most specific -- breaks fastest on updates.
        """
        result: list[Optional[int]] = []
        for i, bc in enumerate(classes):
            if bc in (ByteClass.VARIABLE, ByteClass.POINTER_LIKE):
                result.append(None)  # wildcard
            else:
                result.append(reference[i])
        return result

    def _build_balanced(
        self, reference: bytes, classes: list[ByteClass]
    ) -> list[Optional[int]]:
        """
        Balanced strategy: also wildcard bytes adjacent to VARIABLE bytes.
        Good middle ground between specificity and resilience.
        """
        result = self._build_tight(reference, classes)
        length = len(result)

        # Expand wildcards to neighbors of variable bytes
        expanded = list(result)
        for i in range(length):
            if result[i] is None:
                if i > 0:
                    expanded[i - 1] = None
                if i < length - 1:
                    expanded[i + 1] = None
        return expanded

    def _build_loose(
        self, reference: bytes, classes: list[ByteClass]
    ) -> list[Optional[int]]:
        """
        Loose strategy: wildcard everything except runs of 3+ consecutive
        STABLE bytes.  Most resilient -- survives more changes.
        """
        length = len(classes)
        result: list[Optional[int]] = [None] * length

        # Find runs of stable bytes
        i = 0
        while i < length:
            if classes[i] == ByteClass.STABLE:
                run_start = i
                while i < length and classes[i] in (ByteClass.STABLE, ByteClass.PADDING):
                    i += 1
                run_len = i - run_start
                if run_len >= 3:
                    for j in range(run_start, i):
                        result[j] = reference[j]
            else:
                i += 1

        return result

    def _best_window(
        self,
        pattern_bytes: list[Optional[int]],
        window_size: int,
    ) -> Optional[tuple[str, float]]:
        """
        Slide a window across the full pattern and return the sub-region
        with the highest concrete byte ratio.

        Returns (pattern_string, concrete_ratio) or None.
        """
        if len(pattern_bytes) < window_size:
            return None

        best_ratio = 0.0
        best_start = 0

        for start in range(len(pattern_bytes) - window_size + 1):
            window = pattern_bytes[start : start + window_size]
            concrete = sum(1 for b in window if b is not None)
            ratio = concrete / window_size
            if ratio > best_ratio:
                best_ratio = ratio
                best_start = start

        # NOTE: do not filter low ratios here. The caller (_generate_pattern)
        # applies its own >= 0.3 cutoff. Keeping this helper a pure function
        # (returns the best window for any non-too-short input) lets unit
        # tests verify the windowing logic separately from the threshold.

        window = pattern_bytes[best_start : best_start + window_size]
        tokens: list[str] = []
        for b in window:
            if b is None:
                tokens.append("??")
            else:
                tokens.append(f"{b:02X}")

        return " ".join(tokens), best_ratio

    def _count_matches(self, pattern: str) -> int:
        """Scan all RW memory for *pattern* and return the hit count."""
        try:
            hits = self.scanner.scan_all(
                pattern,
                return_first=False,
                max_results=200,
                executable_only=False,
            )
            return len(hits)
        except Exception:
            return 0
