from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from core.generator import SDKField, SDKClass, SDKPackage
from engines.unreal.dumper import UnrealDumper
from engines.unreal.structs import UE5_DEFAULT, UE5Profile
from engines.unreal.names import GNamesResolver
from engines.unreal.objects import GObjectsWalker, UObjectEntry
from engines.unreal.properties import PropertyReader
from tests.test_unreal_mock import MockMemoryReader, FakeNamePool, setup_mock_ue_environment


def test_unreal_dumper_direct_offset_stale_fallback():
    """Verify that if direct offsets fail verification, we trigger fallback to pattern scanning."""
    reader = MockMemoryReader()
    scanner = MagicMock()

    profile = UE5Profile(
        gnames_direct_offset=0x1000,
        gobjects_direct_offset=0x2000
    )

    exe_base = 0x140000000
    gnames_addr = exe_base + 0x1000
    gobjects_addr = exe_base + 0x2000

    # Initialize correct memory at another location (representing pattern-scanned values)
    scanned_gnames = exe_base + 0x5000
    scanned_gobjects = exe_base + 0x6000
    setup_mock_ue_environment(reader, profile, scanned_gnames, scanned_gobjects)

    # Set up stale garbage values at the direct offset addresses
    reader.write_ptr(gnames_addr, 0x12345) # invalid, resolves to nothing
    reader.write_ptr(gobjects_addr, 0x54321) # invalid, resolves to count 0

    # Configure scanner mock to return the scanned addresses
    # find_pool() extracts the pattern string from PatternDef and passes
    # rip_offset/insn_len as kwargs — mock needs to accept both.
    gnames_pat_str = profile.gnames_pattern.pattern if hasattr(profile.gnames_pattern, 'pattern') else profile.gnames_pattern
    gobjects_pat_str = profile.gobjects_pattern.pattern if hasattr(profile.gobjects_pattern, 'pattern') else profile.gobjects_pattern
    scanner.find_address.side_effect = lambda mod, pat, **kw: (
        scanned_gnames if pat == gnames_pat_str else (
            scanned_gobjects if pat == gobjects_pat_str else 0
        )
    )

    dumper = UnrealDumper(reader, profile=profile, target_module="Game.exe")
    dumper.scanner = scanner

    # Validate should succeed via pattern scanning after failing direct verification
    assert dumper.validate() is True
    assert dumper.get_gnames_address() == scanned_gnames
    assert dumper.get_gobjects_address() == scanned_gobjects
