from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from core.generator import SDKField, SDKClass, SDKPackage
from core.scanner import ScanResult
from engines.blizzard.dumper import BlizzardDumper
from engines.blizzard.structs import BlizzardEntity, HeroDefinition, PlayerState, ViewMatrix


class MockMemoryReader:
    def __init__(self):
        self.memory = {}
        self.modules = [{"name": "Overwatch.exe", "base": 0x140000000, "size": 0x1000000}]
        self.module_bases = {"overwatch.exe": 0x140000000}
        self.module_sizes = {"overwatch.exe": 0x1000000}

    def list_modules(self) -> list[dict]:
        return self.modules

    def module_base(self, name: str) -> int:
        return self.module_bases[name.lower()]

    def module_size(self, name: str) -> int:
        return self.module_sizes[name.lower()]

    def read_bytes(self, addr: int, size: int) -> bytes:
        res = bytearray(size)
        for i in range(size):
            res[i] = self.memory.get(addr + i, 0)
        return bytes(res)

    def write_bytes(self, addr: int, data: bytes):
        for i, b in enumerate(data):
            self.memory[addr + i] = b

    def write_ptr(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<Q", val))

    def write_uint64(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<Q", val))

    def write_uint32(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<I", val))

    def write_int32(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<i", val))

    def write_string(self, addr: int, val: str):
        self.write_bytes(addr, val.encode("utf-8") + b"\x00")

    def read_ptr(self, addr: int) -> int:
        return struct.unpack("<Q", self.read_bytes(addr, 8))[0]

    def read_uint64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read_bytes(addr, 8))[0]

    def read_uint32(self, addr: int) -> int:
        return struct.unpack("<I", self.read_bytes(addr, 4))[0]

    def read_int32(self, addr: int) -> int:
        return struct.unpack("<i", self.read_bytes(addr, 4))[0]

    def read_string(self, addr: int, max_len: int = 128) -> str:
        data = self.read_bytes(addr, max_len)
        null_idx = data.find(b"\x00")
        if null_idx != -1:
            data = data[:null_idx]
        return data.decode("utf-8", errors="ignore")

    def resolve_rip_relative(self, pattern_addr: int, rip_offset_pos: int = 3, insn_len: int = 7) -> int:
        raw = self.read_bytes(pattern_addr + rip_offset_pos, 4)
        rel = struct.unpack("<i", raw)[0]
        return pattern_addr + insn_len + rel


def test_blizzard_dumper_mock():
    reader = MockMemoryReader()
    exe_base = 0x140000000

    # Set up global pointer addresses
    em_ptr_addr = exe_base + 0x1000
    cr_ptr_addr = exe_base + 0x2000
    hd_ptr_addr = exe_base + 0x3000
    vm_ptr_addr = exe_base + 0x4000

    # Write target global pointer values in mock memory
    # 1. EntityManager
    reader.write_ptr(em_ptr_addr, 0x500000)
    # 2. ComponentRegistry
    cr_addr = 0x600000
    reader.write_uint32(cr_ptr_addr, 2)  # count
    reader.write_uint32(cr_ptr_addr + 4, 4)  # capacity
    cr_buckets_ptr = 0x700000
    reader.write_ptr(cr_ptr_addr + 8, cr_buckets_ptr)

    # 3. Component Meta Entry 0
    entry0_addr = 0x800000
    reader.write_ptr(cr_buckets_ptr, entry0_addr)
    reader.write_uint64(entry0_addr, 0xABC)  # type_hash
    reader.write_uint64(entry0_addr + 0x08, 0x900000)  # vtable
    reader.write_uint32(entry0_addr + 0x10, 0x50)  # comp_size
    entry0_name_ptr = 0x950000
    reader.write_ptr(entry0_addr + 0x18, entry0_name_ptr)
    reader.write_string(entry0_name_ptr, "MovementComponent")

    # 4. HeroDatabase
    hd_addr = 0x1000000
    reader.write_ptr(hd_ptr_addr, hd_addr)
    reader.write_uint32(hd_addr, 5)  # count
    reader.write_ptr(hd_addr + 8, 0x1010000)  # array ptr

    # 5. ViewMatrix
    reader.write_ptr(vm_ptr_addr, 0x1020000)

    # Setup scanner mock behavior
    scanner_mock = MagicMock()
    # Mocking scan_module calls:
    # We return hits with instructions that resolve to our test globals
    def mock_scan_module(module, pattern, **kwargs):
        if "48 8D 0D" in pattern: # entity_manager
            # Write relative offset to em_ptr_addr
            # em_ptr_addr = hit_addr + insn_len + rel -> rel = em_ptr_addr - hit_addr - insn_len
            hit_addr = exe_base + 0x500
            rel = em_ptr_addr - hit_addr - 7
            reader.write_bytes(hit_addr + 3, struct.pack("<i", rel))
            return [ScanResult(address=hit_addr)]
        elif "48 8B 0D" in pattern: # component_registry (global-load shape)
            hit_addr = exe_base + 0x600
            rel = cr_ptr_addr - hit_addr - 7
            reader.write_bytes(hit_addr + 3, struct.pack("<i", rel))
            return [ScanResult(address=hit_addr)]
        elif "48 8B 05" in pattern and "48 85 C0 74" in pattern: # hero_database
            hit_addr = exe_base + 0x700
            rel = hd_ptr_addr - hit_addr - 7
            reader.write_bytes(hit_addr + 3, struct.pack("<i", rel))
            return [ScanResult(address=hit_addr)]
        elif "48 8B 05" in pattern and "48 8D 4C 24" in pattern: # view_matrix
            hit_addr = exe_base + 0x800
            rel = vm_ptr_addr - hit_addr - 7
            reader.write_bytes(hit_addr + 3, struct.pack("<i", rel))
            return [ScanResult(address=hit_addr)]
        elif "01 00 00 00" in pattern: # RTTI Complete Object Locator
            # We don't need real RTTI hits for now, as we default component name to name_ptr
            return []
        return []

    scanner_mock.scan_module.side_effect = mock_scan_module

    # Instantiate dumper
    with patch("core.scanner.PatternScanner", return_value=scanner_mock):
        dumper = BlizzardDumper(reader, "output")

        # Validate
        assert dumper.validate() is True

        # Dump
        packages = dumper.dump()
        assert len(packages) == 1
        pkg = packages[0]
        assert pkg.name == "Blizzard"

        # Check classes
        classes_by_name = {c.name: c for c in pkg.classes}
        assert "MovementComponent" in classes_by_name
        assert "HeroDefinition" in classes_by_name
        assert "PlayerState" in classes_by_name
        assert "ViewMatrix" in classes_by_name
        assert "Entity" in classes_by_name
        assert "Globals" in classes_by_name

        # Verify component fields
        move_comp = classes_by_name["MovementComponent"]
        assert move_comp.size == 0x50

        # Verify globals
        globals_cls = classes_by_name["Globals"]
        fields_by_name = {f.name: f for f in globals_cls.fields}
        assert "EntityManager" in fields_by_name
        assert "ComponentRegistry" in fields_by_name
        assert "HeroDatabase" in fields_by_name
        assert "ViewMatrix" in fields_by_name
