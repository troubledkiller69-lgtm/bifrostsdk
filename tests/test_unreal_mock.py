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


class MockMemoryReader:
    def __init__(self):
        self.memory = {}
        self.modules = [{"name": "Game.exe", "base": 0x140000000, "size": 0x1000000}]
        self.module_bases = {"game.exe": 0x140000000}

    def list_modules(self) -> list[dict]:
        return self.modules

    def module_base(self, name: str) -> int:
        return self.module_bases[name.lower()]

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

    def write_int32(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<i", val))

    def write_uint32(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<I", val))

    def write_uint16(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<H", val))

    def write_uint8(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<B", val))

    def read_ptr(self, addr: int) -> int:
        return struct.unpack("<Q", self.read_bytes(addr, 8))[0]

    def read_int32(self, addr: int) -> int:
        return struct.unpack("<i", self.read_bytes(addr, 4))[0]

    def read_uint32(self, addr: int) -> int:
        return struct.unpack("<I", self.read_bytes(addr, 4))[0]

    def read_uint16(self, addr: int) -> int:
        return struct.unpack("<H", self.read_bytes(addr, 2))[0]

    def read_uint8(self, addr: int) -> int:
        return struct.unpack("<B", self.read_bytes(addr, 1))[0]


class FakeNamePool:
    def __init__(self, reader: MockMemoryReader, pool_addr: int, profile: UE5Profile):
        self.reader = reader
        self.pool_addr = pool_addr
        self.profile = profile
        self.block_addr = 0x200000000
        self.current_offset = 0
        self.names_map = {} # comparison_idx -> string
        
        # Set up the blocks pointer table in memory
        cfg = profile.fname_pool
        # Write block 0 pointer
        reader.write_ptr(pool_addr + cfg.blocks_offset, self.block_addr)
        # Write current block and cursor
        reader.write_uint32(pool_addr + cfg.current_block, 0)
        reader.write_uint32(pool_addr + cfg.current_byte_cursor, 0x10000)

    def add_name(self, name: str) -> int:
        cfg = self.profile.fname_pool
        # Allocate entry
        # Aligned to stride
        entry_offset = self.current_offset
        entry_addr = self.block_addr + entry_offset
        
        name_bytes = name.encode("utf-8")
        length = len(name_bytes)
        
        # Write header
        header = (length << cfg.len_shift) & 0xFFFF
        self.reader.write_uint16(entry_addr + cfg.header_offset, header)
        
        # Write string
        self.reader.write_bytes(entry_addr + cfg.string_offset, name_bytes)
        
        # Advance cursor with stride alignment
        entry_size = cfg.string_offset + length
        entry_size = (entry_size + cfg.stride - 1) & ~(cfg.stride - 1)
        self.current_offset += entry_size
        
        comparison_idx = entry_offset // cfg.stride
        self.names_map[comparison_idx] = name
        return comparison_idx


def setup_mock_ue_environment(reader, profile, gnames_addr, gobjects_addr):
    # Initialize NamePool helper
    pool = FakeNamePool(reader, gnames_addr, profile)
    
    # Register core names
    name_none = pool.add_name("None") # index 0 must be None for verify_address
    name_class = pool.add_name("Class")
    name_scriptstruct = pool.add_name("ScriptStruct")
    name_pawn = pool.add_name("Pawn")
    name_actor = pool.add_name("Actor")
    name_health = pool.add_name("Health")
    name_location = pool.add_name("Location")
    name_int_prop = pool.add_name("IntProperty")
    name_struct_prop = pool.add_name("StructProperty")
    name_engine_pkg = pool.add_name("Engine")

    # Set up global object array
    # write NumElements = 500 (must be > 100 for verify_address)
    reader.write_int32(gobjects_addr + profile.gobjects.num_elements_offset, 500)
    # write Objects pointer
    chunks_base = 0x300000000
    reader.write_ptr(gobjects_addr + profile.gobjects.objects_offset, chunks_base)
    # write chunk 0 pointer
    chunk0_addr = 0x300100000
    reader.write_ptr(chunks_base, chunk0_addr)

    # Create UObjects
    # 1. Class Actor
    actor_addr = 0x400000000
    # write FUObjectItem entry for Actor
    reader.write_ptr(chunk0_addr + 0 * profile.gobjects.item_size + profile.gobjects.item_object_offset, actor_addr)
    # Actor UObjectBase fields
    reader.write_int32(actor_addr + profile.uobject.internal_index, 0)
    reader.write_ptr(actor_addr + profile.uobject.class_private, 0) # class_private of Class is not verified heavily
    # write Outer
    reader.write_ptr(actor_addr + profile.uobject.outer_private, 0) # Outer is 0 for package-level
    # write Name
    reader.write_int32(actor_addr + profile.uobject.name_private + profile.fname.comparison_index_offset, name_actor)
    # write class private for Actor (it should point to Class UObject)
    class_class_addr = 0x400200000
    reader.write_ptr(actor_addr + profile.uobject.class_private, class_class_addr)
    reader.write_int32(class_class_addr + profile.uobject.name_private + profile.fname.comparison_index_offset, name_class)

    # Actor UStruct fields
    reader.write_ptr(actor_addr + profile.ustruct.super_struct, 0)
    reader.write_int32(actor_addr + profile.ustruct.properties_size, 0x400)
    # properties chain for Actor: Location
    prop_location_addr = 0x500000000
    reader.write_ptr(actor_addr + profile.ustruct.child_properties, prop_location_addr)
    # FProperty Location fields
    class_struct_prop_addr = 0x600000000
    reader.write_ptr(prop_location_addr + profile.ffield.class_private, class_struct_prop_addr)
    reader.write_int32(class_struct_prop_addr + profile.ffield_class.name + profile.fname.comparison_index_offset, name_struct_prop)
    reader.write_ptr(prop_location_addr + profile.ffield.next, 0) # end of list
    reader.write_int32(prop_location_addr + profile.ffield.name + profile.fname.comparison_index_offset, name_location)
    reader.write_int32(prop_location_addr + profile.fproperty.array_dim, 1)
    reader.write_int32(prop_location_addr + profile.fproperty.element_size, 12)
    reader.write_int32(prop_location_addr + profile.fproperty.offset_internal, 0x10)

    # 2. Class Pawn (inherits from Actor)
    pawn_addr = 0x400100000
    reader.write_ptr(chunk0_addr + 1 * profile.gobjects.item_size + profile.gobjects.item_object_offset, pawn_addr)
    reader.write_int32(pawn_addr + profile.uobject.internal_index, 1)
    reader.write_ptr(pawn_addr + profile.uobject.class_private, class_class_addr)
    reader.write_ptr(pawn_addr + profile.uobject.outer_private, 0)
    reader.write_int32(pawn_addr + profile.uobject.name_private + profile.fname.comparison_index_offset, name_pawn)
    # Pawn UStruct fields
    reader.write_ptr(pawn_addr + profile.ustruct.super_struct, actor_addr)
    reader.write_int32(pawn_addr + profile.ustruct.properties_size, 0x440)
    # properties chain for Pawn: Health
    prop_health_addr = 0x500100000
    reader.write_ptr(pawn_addr + profile.ustruct.child_properties, prop_health_addr)
    # FProperty Health fields
    class_int_prop_addr = 0x600100000
    reader.write_ptr(prop_health_addr + profile.ffield.class_private, class_int_prop_addr)
    reader.write_int32(class_int_prop_addr + profile.ffield_class.name + profile.fname.comparison_index_offset, name_int_prop)
    reader.write_ptr(prop_health_addr + profile.ffield.next, 0)
    reader.write_int32(prop_health_addr + profile.ffield.name + profile.fname.comparison_index_offset, name_health)
    reader.write_int32(prop_health_addr + profile.fproperty.array_dim, 1)
    reader.write_int32(prop_health_addr + profile.fproperty.element_size, 4)
    reader.write_int32(prop_health_addr + profile.fproperty.offset_internal, 0x18)

    return pool


def test_unreal_dumper_mock_validation():
    reader = MockMemoryReader()
    scanner = MagicMock()

    profile = UE5Profile(
        gnames_direct_offset=0x1000,
        gobjects_direct_offset=0x2000
    )

    exe_base = 0x140000000
    gnames_addr = exe_base + 0x1000
    gobjects_addr = exe_base + 0x2000

    setup_mock_ue_environment(reader, profile, gnames_addr, gobjects_addr)

    dumper = UnrealDumper(reader, profile=profile, target_module="Game.exe")
    dumper.scanner = scanner

    assert dumper.validate() is True


def test_unreal_dumper_full_dump():
    reader = MockMemoryReader()
    scanner = MagicMock()
    # Use deepcopy / separate profile instance
    profile = UE5Profile(
        gnames_direct_offset=0x1000,
        gobjects_direct_offset=0x2000
    )

    exe_base = 0x140000000
    gnames_addr = exe_base + 0x1000
    gobjects_addr = exe_base + 0x2000

    setup_mock_ue_environment(reader, profile, gnames_addr, gobjects_addr)

    # Let's run dumper
    dumper = UnrealDumper(reader, profile=profile, target_module="Game.exe")
    dumper.scanner = scanner
    
    assert dumper.validate() is True
    packages = dumper.dump()
    
    assert len(packages) == 1
    pkg = packages[0]
    # Default package name since outer was 0 is "Unknown"
    assert pkg.name == "Unknown"
    assert len(pkg.classes) == 2
    
    classes_by_name = {c.name: c for c in pkg.classes}
    assert "UActor" in classes_by_name
    assert "UPawn" in classes_by_name
    
    actor_class = classes_by_name["UActor"]
    assert actor_class.size == 0x400
    assert len(actor_class.fields) == 1
    assert actor_class.fields[0].name == "Location"
    assert actor_class.fields[0].offset == 0x10
    
    pawn_class = classes_by_name["UPawn"]
    assert pawn_class.size == 0x440
    assert pawn_class.super_name == "UActor"
    assert len(pawn_class.fields) == 1
    assert pawn_class.fields[0].name == "Health"
    assert pawn_class.fields[0].offset == 0x18
