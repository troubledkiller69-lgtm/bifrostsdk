"""
BIFROST SDK — UE5 Dumper Mock Tests (Marvel Rivals Profile)
Tests the full validation pipeline with a mock memory reader that simulates
UE5's in-memory layout, focusing on the bugs fixed in this patch:
    1. Direct offset pointer dereference (LEA vs MOV style)
    2. FNamePool verification with non-zero header_offset
    3. GObjects verification depending on GNames being resolved
    4. Pattern scanning with PatternDef (per-pattern RIP metadata)
    5. Case-insensitive module matching
"""

import struct
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from engines.unreal.dumper import UnrealDumper
from engines.unreal.names import GNamesResolver
from engines.unreal.objects import GObjectsWalker, UObjectEntry
from engines.unreal.structs import (
    UE5Profile, UE5_DEFAULT, UE5_MARVEL_RIVALS,
    FNamePoolConfig, FNameConfig, GObjectsConfig, UObjectConfig,
    PatternDef,
)
from core.generator import SDKPackage


# ======================================================================
# Helpers
# ======================================================================

class MockMemory(dict):
    """Simple memory-as-dict simulation."""

    def write_uint8(self, addr, val):
        self[addr] = struct.pack("B", val)

    def write_uint16(self, addr, val):
        self[addr] = struct.pack("<H", val)

    def write_int32(self, addr, val):
        self[addr] = struct.pack("<i", val)

    def write_uint32(self, addr, val):
        self[addr] = struct.pack("<I", val)

    def write_uint64(self, addr, val):
        self[addr] = struct.pack("<Q", val)

    def write_ptr(self, addr, val):
        self.write_uint64(addr, val)

    def write_string(self, addr, s: str):
        self[addr] = s.encode("utf-8")


class MockReader:
    """Mock MemoryReader with dict-backed memory."""

    def __init__(self, mem: MockMemory):
        self._mem = mem
        self._modules = {}
        self.handle = None  # No handle = driver mode for scanner

    def add_module(self, name, base, size):
        self._modules[name.lower()] = {"name": name, "base": base, "size": size}

    def _find_bytes(self, addr, size):
        """Find the memory region covering this address."""
        # Check exact key first
        if addr in self._mem:
            data = self._mem[addr]
            return data[:size]

        # Check if addr falls within a larger write
        for base, data in sorted(self._mem.items()):
            if isinstance(data, bytes) and base <= addr < base + len(data):
                offset = addr - base
                return data[offset:offset + size]

        return b"\x00" * size

    def read_bytes(self, addr, size):
        return self._find_bytes(addr, size)

    def read_ptr(self, addr):
        return struct.unpack("<Q", self.read_bytes(addr, 8))[0]

    def read_int32(self, addr):
        return struct.unpack("<i", self.read_bytes(addr, 4))[0]

    def read_uint16(self, addr):
        return struct.unpack("<H", self.read_bytes(addr, 2))[0]

    def read_uint32(self, addr):
        return struct.unpack("<I", self.read_bytes(addr, 4))[0]

    def read_uint64(self, addr):
        return struct.unpack("<Q", self.read_bytes(addr, 8))[0]

    def read_uint8(self, addr):
        return struct.unpack("B", self.read_bytes(addr, 1))[0]

    def read_string(self, addr, max_len=256, encoding="utf-8"):
        raw = self.read_bytes(addr, max_len)
        null = raw.find(b"\x00")
        if null != -1:
            raw = raw[:null]
        return raw.decode(encoding, errors="replace")

    def read_wstring(self, addr, max_len=256):
        raw = self.read_bytes(addr, max_len * 2)
        result = []
        for i in range(0, len(raw), 2):
            ch = struct.unpack_from("<H", raw, i)[0]
            if ch == 0:
                break
            result.append(chr(ch))
        return "".join(result)

    def module_base(self, name):
        key = name.lower()
        if key in self._modules:
            return self._modules[key]["base"]
        raise RuntimeError(f"Module '{name}' not found")

    def module_size(self, name):
        key = name.lower()
        if key in self._modules:
            return self._modules[key]["size"]
        raise RuntimeError(f"Module '{name}' not found")

    def list_modules(self):
        return [
            {"name": m["name"], "base": m["base"], "size": m["size"]}
            for m in self._modules.values()
        ]

    def get_module_sections(self, name):
        return []

    def resolve_rip_relative(self, pattern_addr, rip_offset_pos=3, insn_len=7):
        raw = self.read_bytes(pattern_addr + rip_offset_pos, 4)
        rel = struct.unpack("<i", raw)[0]
        return pattern_addr + insn_len + rel

    def close(self):
        pass


def _build_fname_entry_default(name_str: str) -> bytes:
    """Build a default UE5 FNameEntry: [uint16 header][string bytes]."""
    name_bytes = name_str.encode("utf-8")
    length = len(name_bytes)
    # Default: len_shift=6, wide_bit_mask=0x1, no wide
    header = (length << 6) & 0xFFFF
    return struct.pack("<H", header) + name_bytes


def _build_fname_entry_marvel(name_str: str) -> bytes:
    """Build a Marvel Rivals FNameEntry: [4 bytes pad][uint16 header][string bytes]."""
    name_bytes = name_str.encode("utf-8")
    length = len(name_bytes)
    # Marvel Rivals: header_offset=4, string_offset=6, len_shift=1
    header = (length << 1) & 0xFFFF
    return b"\x00\x00\x00\x00" + struct.pack("<H", header) + name_bytes


def _align(size, stride):
    return (size + stride - 1) & ~(stride - 1)


# ======================================================================
# Test: PatternDef basics
# ======================================================================

class TestPatternDef:
    """Verify PatternDef dataclass and unpacking."""

    def test_default_rip_params(self):
        p = PatternDef("48 8D 05 ?? ?? ?? ?? EB 16")
        assert p.pattern == "48 8D 05 ?? ?? ?? ?? EB 16"
        assert p.rip_offset == 3
        assert p.insn_len == 7

    def test_custom_rip_params(self):
        p = PatternDef("E8 ?? ?? ?? ?? 48 8B C3", rip_offset=1, insn_len=5)
        assert p.rip_offset == 1
        assert p.insn_len == 5

    def test_unpack_from_resolver(self):
        p = PatternDef("89 0D ?? ?? ?? ??", rip_offset=2, insn_len=6)
        pat_str, rip_off, insn_len = GNamesResolver._unpack_pattern(p)
        assert pat_str == "89 0D ?? ?? ?? ??"
        assert rip_off == 2
        assert insn_len == 6

    def test_unpack_raw_string(self):
        pat_str, rip_off, insn_len = GNamesResolver._unpack_pattern("48 8D 05 ?? ??")
        assert pat_str == "48 8D 05 ?? ??"
        assert rip_off == 3
        assert insn_len == 7


# ======================================================================
# Test: GNames verification with Default profile
# ======================================================================

class TestGNamesVerifyDefault:
    """Test GNames verification with the default UE5 profile."""

    def _build_pool(self, mem, reader, names=None):
        """Build a minimal FNamePool at a known address."""
        if names is None:
            names = ["None", "ByteProperty", "IntProperty"]

        POOL_ADDR = 0x1000000
        BLOCK_ADDR = 0x2000000

        cfg = UE5_DEFAULT.fname_pool

        # Write block[0] pointer at pool + blocks_offset
        mem.write_ptr(POOL_ADDR + cfg.blocks_offset, BLOCK_ADDR)
        # Write current_block = 0, current_byte_cursor
        mem.write_uint32(POOL_ADDR + cfg.current_block, 0)

        # Write entries sequentially in the block
        offset = 0
        for name_str in names:
            entry_bytes = _build_fname_entry_default(name_str)
            entry_size = _align(len(entry_bytes), cfg.stride)
            # Write entry at block + offset
            mem[BLOCK_ADDR + offset] = entry_bytes
            offset += entry_size

        mem.write_uint32(POOL_ADDR + cfg.current_byte_cursor, offset)
        return POOL_ADDR

    def test_verify_valid_pool(self):
        mem = MockMemory()
        reader = MockReader(mem)
        scanner = MagicMock()
        resolver = GNamesResolver(reader, scanner, UE5_DEFAULT)

        pool_addr = self._build_pool(mem, reader)
        assert resolver.verify_address(pool_addr) is True

    def test_verify_null_address(self):
        mem = MockMemory()
        reader = MockReader(mem)
        scanner = MagicMock()
        resolver = GNamesResolver(reader, scanner, UE5_DEFAULT)
        assert resolver.verify_address(0) is False

    def test_verify_bad_block_pointer(self):
        mem = MockMemory()
        reader = MockReader(mem)
        scanner = MagicMock()
        resolver = GNamesResolver(reader, scanner, UE5_DEFAULT)

        # Pool with null block[0] pointer
        POOL_ADDR = 0x1000000
        mem.write_ptr(POOL_ADDR + UE5_DEFAULT.fname_pool.blocks_offset, 0)
        assert resolver.verify_address(POOL_ADDR) is False


# ======================================================================
# Test: GNames verification with Marvel Rivals profile
# ======================================================================

class TestGNamesVerifyMarvel:
    """Test GNames verification with the Marvel Rivals profile (header_offset=4)."""

    def _build_pool_marvel(self, mem, names=None):
        """Build a Marvel Rivals FNamePool."""
        if names is None:
            names = ["None", "ByteProperty", "IntProperty"]

        POOL_ADDR = 0x3000000
        BLOCK_ADDR = 0x4000000

        cfg = UE5_MARVEL_RIVALS.fname_pool

        mem.write_ptr(POOL_ADDR + cfg.blocks_offset, BLOCK_ADDR)
        mem.write_uint32(POOL_ADDR + cfg.current_block, 0)

        offset = 0
        for name_str in names:
            entry_bytes = _build_fname_entry_marvel(name_str)
            entry_size = _align(len(entry_bytes), cfg.stride)
            mem[BLOCK_ADDR + offset] = entry_bytes
            offset += entry_size

        mem.write_uint32(POOL_ADDR + cfg.current_byte_cursor, offset)
        return POOL_ADDR

    def test_verify_marvel_pool(self):
        mem = MockMemory()
        reader = MockReader(mem)
        scanner = MagicMock()
        resolver = GNamesResolver(reader, scanner, UE5_MARVEL_RIVALS)

        pool_addr = self._build_pool_marvel(mem)
        assert resolver.verify_address(pool_addr) is True

    def test_resolve_names_marvel(self):
        mem = MockMemory()
        reader = MockReader(mem)
        scanner = MagicMock()
        resolver = GNamesResolver(reader, scanner, UE5_MARVEL_RIVALS)

        pool_addr = self._build_pool_marvel(mem)
        resolver.set_pool_address(pool_addr)

        assert resolver.resolve(0).lower() == "none"


# ======================================================================
# Test: Direct offset with pointer dereference (Bug 1)
# ======================================================================

class TestDirectOffsetDereference:
    """Verify that validate() tries both inline and dereferenced addresses."""

    def _build_environment(self, deref_mode=True):
        """Build a mock environment where direct offsets require dereference."""
        mem = MockMemory()
        reader = MockReader(mem)

        EXE_BASE = 0x140000000
        reader.add_module("Marvel-Win64-Shipping.exe", EXE_BASE, 0x10000000)

        # Build a valid FNamePool
        POOL_ADDR = 0x200000000
        BLOCK_ADDR = 0x210000000

        cfg = UE5_MARVEL_RIVALS.fname_pool
        mem.write_ptr(POOL_ADDR + cfg.blocks_offset, BLOCK_ADDR)
        mem.write_uint32(POOL_ADDR + cfg.current_block, 0)

        # Write "None" entry in Marvel Rivals format
        entry = _build_fname_entry_marvel("None")
        mem[BLOCK_ADDR] = entry
        entry2 = _build_fname_entry_marvel("ByteProperty")
        offset2 = _align(len(entry), cfg.stride)
        mem[BLOCK_ADDR + offset2] = entry2
        mem.write_uint32(POOL_ADDR + cfg.current_byte_cursor, offset2 + _align(len(entry2), cfg.stride))

        # Set up direct offset
        gnames_offset = UE5_MARVEL_RIVALS.gnames_direct_offset
        if deref_mode:
            # MOV-style: offset points to a POINTER to the pool
            mem.write_ptr(EXE_BASE + gnames_offset, POOL_ADDR)
        else:
            # LEA-style: offset IS the pool (would need POOL_ADDR == EXE_BASE + offset)
            # This test focuses on deref mode
            pass

        # Build a valid GObjects array
        GOBJECTS_ADDR = 0x220000000
        CHUNKS_ADDR = 0x230000000
        CHUNK0_ADDR = 0x240000000

        obj_cfg = UE5_MARVEL_RIVALS.gobjects
        mem.write_ptr(GOBJECTS_ADDR + obj_cfg.objects_offset, CHUNKS_ADDR)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.num_elements_offset, 500)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.max_elements_offset, 65536)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.num_chunks_offset, 1)

        # Write chunk[0] pointer
        mem.write_ptr(CHUNKS_ADDR, CHUNK0_ADDR)

        # Write a valid UObject in chunk[0][0]
        OBJ_ADDR = 0x250000000
        uobj_cfg = UE5_MARVEL_RIVALS.uobject
        mem.write_ptr(CHUNK0_ADDR + obj_cfg.item_object_offset, OBJ_ADDR)

        # UObject fields — name = FName(0) = "None"
        mem.write_int32(OBJ_ADDR + uobj_cfg.internal_index, 0)
        mem.write_ptr(OBJ_ADDR + uobj_cfg.class_private, 0x260000000)
        mem.write_ptr(OBJ_ADDR + uobj_cfg.outer_private, 0)
        # FName at name_private: ComparisonIndex=0, Number=0
        mem.write_int32(OBJ_ADDR + uobj_cfg.name_private, 0)
        mem.write_int32(OBJ_ADDR + uobj_cfg.name_private + 4, 0)

        # GObjects direct offset
        gobjects_offset = UE5_MARVEL_RIVALS.gobjects_direct_offset
        if deref_mode:
            mem.write_ptr(EXE_BASE + gobjects_offset, GOBJECTS_ADDR)

        return mem, reader

    def test_validate_with_dereference(self):
        """Direct offsets point to pointers — validate must dereference to find the pool."""
        mem, reader = self._build_environment(deref_mode=True)

        # Create a profile with direct offsets matching our layout
        profile = UE5_MARVEL_RIVALS

        dumper = UnrealDumper(
            reader,
            output_dir="test_output",
            profile=profile,
            target_module="Marvel-Win64-Shipping.exe",
        )

        result = dumper.validate()
        assert result is True, f"validate() should succeed with deref. Errors: {dumper.progress.errors}"

    def test_gnames_address_resolved(self):
        """After validate, the GNames address should be set correctly."""
        mem, reader = self._build_environment(deref_mode=True)
        dumper = UnrealDumper(reader, profile=UE5_MARVEL_RIVALS, target_module="Marvel-Win64-Shipping.exe")
        dumper.validate()
        assert dumper.get_gnames_address() != 0

    def test_gobjects_address_resolved(self):
        """After validate, the GObjects address should be set correctly."""
        mem, reader = self._build_environment(deref_mode=True)
        dumper = UnrealDumper(reader, profile=UE5_MARVEL_RIVALS, target_module="Marvel-Win64-Shipping.exe")
        dumper.validate()
        assert dumper.get_gobjects_address() != 0


# ======================================================================
# Test: Case-insensitive module matching (Bug 5)
# ======================================================================

class TestModuleMatching:
    """Test that _detect_target_module handles case mismatches."""

    def test_exact_case_match(self):
        mem = MockMemory()
        reader = MockReader(mem)
        reader.add_module("Marvel-Win64-Shipping.exe", 0x140000000, 0x1000)

        dumper = UnrealDumper(reader, target_module="Marvel-Win64-Shipping.exe")
        module = dumper._detect_target_module()
        assert module == "Marvel-Win64-Shipping.exe"

    def test_case_insensitive_match(self):
        mem = MockMemory()
        reader = MockReader(mem)
        reader.add_module("marvel-win64-shipping.exe", 0x140000000, 0x1000)

        dumper = UnrealDumper(reader, target_module="Marvel-Win64-Shipping.exe")
        module = dumper._detect_target_module()
        assert module.lower() == "marvel-win64-shipping.exe"

    def test_substring_fuzzy_match(self):
        mem = MockMemory()
        reader = MockReader(mem)
        reader.add_module("MarvelRivals.exe", 0x140000000, 0x1000)

        # The UI might pass a different name than what pymem sees
        dumper = UnrealDumper(reader, target_module="marvelrivals.exe")
        module = dumper._detect_target_module()
        assert module == "MarvelRivals.exe"

    def test_auto_detect_largest_exe(self):
        mem = MockMemory()
        reader = MockReader(mem)
        reader.add_module("small.exe", 0x10000, 0x100)
        reader.add_module("BigGame.exe", 0x140000000, 0x10000000)
        reader.add_module("helper.dll", 0x7FF000000, 0x500)

        dumper = UnrealDumper(reader, target_module=None)
        module = dumper._detect_target_module()
        assert module == "BigGame.exe"


# ======================================================================
# Test: GObjects depends on GNames (Bug 3)
# ======================================================================

class TestGObjectsDependsOnGNames:
    """Verify GObjects verification works when GNames is already resolved."""

    def test_gobjects_verify_with_resolved_gnames(self):
        """GObjects.verify_address should find valid names when GNames pool is set."""
        mem = MockMemory()
        reader = MockReader(mem)

        # Build a minimal GNames pool (default profile for simplicity)
        POOL_ADDR = 0x1000000
        BLOCK_ADDR = 0x2000000
        cfg = UE5_DEFAULT.fname_pool

        mem.write_ptr(POOL_ADDR + cfg.blocks_offset, BLOCK_ADDR)
        mem.write_uint32(POOL_ADDR + cfg.current_block, 0)

        entry = _build_fname_entry_default("None")
        mem[BLOCK_ADDR] = entry
        entry2 = _build_fname_entry_default("CoreUObject")
        offset2 = _align(len(entry), cfg.stride)
        mem[BLOCK_ADDR + offset2] = entry2
        mem.write_uint32(POOL_ADDR + cfg.current_byte_cursor, offset2 + _align(len(entry2), cfg.stride))

        # Set up GNames resolver with pool address
        scanner = MagicMock()
        names = GNamesResolver(reader, scanner, UE5_DEFAULT)
        names.set_pool_address(POOL_ADDR)

        # Verify GNames works
        assert names.resolve(0).lower() == "none"

        # Build a GObjects array
        GOBJECTS_ADDR = 0x5000000
        CHUNKS_ADDR = 0x6000000
        CHUNK0_ADDR = 0x7000000

        obj_cfg = UE5_DEFAULT.gobjects
        uobj_cfg = UE5_DEFAULT.uobject

        mem.write_ptr(GOBJECTS_ADDR + obj_cfg.objects_offset, CHUNKS_ADDR)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.num_elements_offset, 200)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.max_elements_offset, 65536)
        mem.write_ptr(CHUNKS_ADDR, CHUNK0_ADDR)

        # Write a valid UObject with FName pointing to "None" (index 0)
        OBJ_ADDR = 0x8000000
        mem.write_ptr(CHUNK0_ADDR + obj_cfg.item_object_offset, OBJ_ADDR)
        mem.write_int32(OBJ_ADDR + uobj_cfg.internal_index, 0)
        mem.write_ptr(OBJ_ADDR + uobj_cfg.class_private, 0x9000000)
        mem.write_ptr(OBJ_ADDR + uobj_cfg.outer_private, 0)
        mem.write_int32(OBJ_ADDR + uobj_cfg.name_private, 0)  # FName index 0 = "None"
        mem.write_int32(OBJ_ADDR + uobj_cfg.name_private + 4, 0)

        # Create walker with the resolved GNames
        walker = GObjectsWalker(reader, scanner, names, UE5_DEFAULT)

        # Should succeed because GNames can resolve names
        assert walker.verify_address(GOBJECTS_ADDR) is True

    def test_gobjects_verify_without_gnames_fails(self):
        """GObjects.verify_address should fail when GNames pool is NOT set."""
        mem = MockMemory()
        reader = MockReader(mem)
        scanner = MagicMock()

        # GNames resolver with NO pool address
        names = GNamesResolver(reader, scanner, UE5_DEFAULT)
        assert names.pool_address == 0  # Not set

        # Build a GObjects array
        GOBJECTS_ADDR = 0x5000000
        CHUNKS_ADDR = 0x6000000
        CHUNK0_ADDR = 0x7000000

        obj_cfg = UE5_DEFAULT.gobjects
        uobj_cfg = UE5_DEFAULT.uobject

        mem.write_ptr(GOBJECTS_ADDR + obj_cfg.objects_offset, CHUNKS_ADDR)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.num_elements_offset, 200)
        mem.write_int32(GOBJECTS_ADDR + obj_cfg.max_elements_offset, 65536)
        mem.write_ptr(CHUNKS_ADDR, CHUNK0_ADDR)

        OBJ_ADDR = 0x8000000
        mem.write_ptr(CHUNK0_ADDR + obj_cfg.item_object_offset, OBJ_ADDR)
        mem.write_int32(OBJ_ADDR + uobj_cfg.internal_index, 0)
        mem.write_ptr(OBJ_ADDR + uobj_cfg.class_private, 0x9000000)
        mem.write_ptr(OBJ_ADDR + uobj_cfg.outer_private, 0)
        mem.write_int32(OBJ_ADDR + uobj_cfg.name_private, 0)
        mem.write_int32(OBJ_ADDR + uobj_cfg.name_private + 4, 0)

        walker = GObjectsWalker(reader, scanner, names, UE5_DEFAULT)

        # Should fail — names resolve to "FName_0" which starts with "FName_"
        assert walker.verify_address(GOBJECTS_ADDR) is False
