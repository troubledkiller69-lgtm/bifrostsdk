from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from core.generator import SDKField, SDKClass, SDKPackage
from engines.unity.il2cpp import IL2CPPDumper
from engines.unity.structs import IL2CPPConfig


class MockMemoryReader:
    def __init__(self):
        self.memory = {}
        self.modules = [{"name": "GameAssembly.dll", "base": 0x140000000, "size": 0x1000000}]
        self.module_bases = {"gameassembly.dll": 0x140000000}

    def list_modules(self) -> list[dict]:
        return self.modules

    def module_base(self, name: str) -> int:
        return self.module_bases[name.lower()]

    def module_size(self, name: str) -> int:
        return 0x1000000

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

    def write_uint16(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<H", val))

    def write_uint8(self, addr: int, val: int):
        self.write_bytes(addr, struct.pack("<B", val))

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

    def read_uint16(self, addr: int) -> int:
        return struct.unpack("<H", self.read_bytes(addr, 2))[0]

    def read_uint8(self, addr: int) -> int:
        return struct.unpack("<B", self.read_bytes(addr, 1))[0]

    def read_string(self, addr: int, max_len: int = 128) -> str:
        data = self.read_bytes(addr, max_len)
        null_idx = data.find(b"\x00")
        if null_idx != -1:
            data = data[:null_idx]
        return data.decode("utf-8", errors="ignore")

    def close(self):
        pass


def test_unity_il2cpp_dumper_mock():
    reader = MockMemoryReader()
    cfg = IL2CPPConfig()

    ga_base = 0x140000000
    s_type_info_table_ptr_addr = ga_base + 0x20000
    type_info_table_addr = 0x300000000

    # Write table address to global pointer s_TypeInfoTable
    reader.write_ptr(s_type_info_table_ptr_addr, type_info_table_addr)

    # Class pointer at type_index 0 in table
    class_addr = 0x400000000
    reader.write_ptr(type_info_table_addr, class_addr)

    # fields pointer in Il2CppClass at offset 0x80
    fields_ptr = 0x500000000
    reader.write_ptr(class_addr + 0x80, fields_ptr)

    # FieldInfo at fields_ptr
    # name_ptr at fields_ptr + 0
    field_name_ptr = 0x600000000
    reader.write_ptr(fields_ptr, field_name_ptr)
    reader.write_string(field_name_ptr, "health")

    # type_ptr at fields_ptr + 8
    field_type_ptr = 0x700000000
    reader.write_ptr(fields_ptr + 8, field_type_ptr)
    # type_enum at type_ptr + 0x0A
    reader.write_uint8(field_type_ptr + 0x0A, 0x08)  # IL2CPP_TYPE_I4 (int32_t)

    # offset at fields_ptr + 0x18
    reader.write_int32(fields_ptr + 0x18, 0x1C)

    # Setup scanner mock behavior
    scanner_mock = MagicMock()
    scanner_mock.find_address.return_value = s_type_info_table_ptr_addr

    with patch("engines.base.PatternScanner", return_value=scanner_mock):
        dumper = IL2CPPDumper(reader, "output", config=cfg)

        assert dumper.validate() is True

        # Pre-populate parsed metadata
        dumper._type_defs = [{
            "index": 0,
            "name": "PlayerController",
            "namespace": "Game",
            "field_start": 0,
            "field_count": 1,
        }]
        dumper._field_defs = [{
            "index": 0,
            "name": "health",
            "type_index": 0,
        }]

        # Mock loading and parsing methods
        dumper._find_metadata_path = MagicMock(return_value="fake_metadata_path")
        dumper._load_metadata_from_disk = MagicMock(return_value=True)
        dumper._parse_metadata = MagicMock()

        packages = dumper.dump()

        assert len(packages) == 1
        pkg = packages[0]
        assert pkg.name == "Game"
        assert len(pkg.classes) == 1

        cls = pkg.classes[0]
        assert cls.name == "PlayerController"
        assert cls.full_name == "Game.PlayerController"
        assert len(cls.fields) == 1

        fld = cls.fields[0]
        assert fld.name == "health"
        assert fld.offset == 0x1C
        assert fld.type_name == "int32_t"
