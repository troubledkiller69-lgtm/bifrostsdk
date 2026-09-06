from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from core.generator import SDKField, SDKClass, SDKPackage
from core.scanner import ScanResult
from engines.unity.mono import MonoDumper
from engines.unity.structs import MonoConfig


class MockMemoryReader:
    def __init__(self):
        self.memory = {}
        self.modules = [{"name": "mono.dll", "base": 0x140000000, "size": 0x1000000}]
        self.module_bases = {"mono.dll": 0x140000000}

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


def test_unity_mono_dumper_mock():
    reader = MockMemoryReader()
    cfg = MonoConfig()

    # Base domain global pointer
    mono_base = 0x140000000
    root_domain_ptr_addr = mono_base + 0x10000
    domain_addr = 0x200000000

    # Write root domain pointer value
    reader.write_ptr(root_domain_ptr_addr, domain_addr)

    # domain_assemblies GSList at domain + 0xC8
    asm_list_addr = 0x300000000
    reader.write_ptr(domain_addr + 0xC8, asm_list_addr)

    # GSList node 0: data = assembly_addr, next = 0
    assembly_addr = 0x400000000
    reader.write_ptr(asm_list_addr, assembly_addr)
    reader.write_ptr(asm_list_addr + 8, 0) # end list

    # MonoAssembly -> MonoImage* image at 0x60
    image_addr = 0x500000000
    reader.write_ptr(assembly_addr + 0x60, image_addr)

    # MonoImage.name at 0x18
    name_str_addr = 0x550000000
    reader.write_ptr(image_addr + 0x18, name_str_addr)
    reader.write_string(name_str_addr, "Assembly-CSharp")

    # MonoImage.class_cache GHashTable at 0x3A0
    # table_size (int32) at 0x3A0, table_ptr (pointer) at 0x3A0 + 8
    reader.write_int32(image_addr + 0x3A0, 1) # table_size
    class_cache_table_ptr = 0x600000000
    reader.write_ptr(image_addr + 0x3A8, class_cache_table_ptr)

    # Bucket 0: points to MonoClass pointer
    klass_addr = 0x700000000
    reader.write_ptr(class_cache_table_ptr, klass_addr)

    # MonoClass fields
    # name_ptr at klass_addr + monoclass_name (0x48)
    klass_name_ptr = 0x750000000
    reader.write_ptr(klass_addr + cfg.monoclass_name, klass_name_ptr)
    reader.write_string(klass_name_ptr, "PlayerController")

    # namespace_ptr at klass_addr + monoclass_namespace (0x50)
    klass_ns_ptr = 0x760000000
    reader.write_ptr(klass_addr + cfg.monoclass_namespace, klass_ns_ptr)
    reader.write_string(klass_ns_ptr, "Game.Logic")

    # parent at klass_addr + monoclass_parent (0x30)
    reader.write_ptr(klass_addr + cfg.monoclass_parent, 0)

    # instance_size at klass_addr + monoclass_instance_size (0x18)
    reader.write_int32(klass_addr + cfg.monoclass_instance_size, 0x100)

    # fields_ptr at klass_addr + monoclass_fields (0x98)
    fields_arr_ptr = 0x800000000
    reader.write_ptr(klass_addr + cfg.monoclass_fields, fields_arr_ptr)

    # field_count at klass_addr + monoclass_field_count (0x100)
    reader.write_uint16(klass_addr + cfg.monoclass_field_count, 1)

    # Field 0 at fields_arr_ptr
    # name_ptr at field_addr + field_name (0x00)
    field_name_ptr = 0x850000000
    reader.write_ptr(fields_arr_ptr + cfg.field_name, field_name_ptr)
    reader.write_string(field_name_ptr, "health")

    # offset at field_addr + field_offset (0x18)
    reader.write_int32(fields_arr_ptr + cfg.field_offset, 0x18)

    # type_ptr at field_addr + field_type (0x08)
    field_type_ptr = 0x860000000
    reader.write_ptr(fields_arr_ptr + cfg.field_type, field_type_ptr)
    # MonoType.type enum (uint8) at type_ptr + 0x10
    reader.write_uint8(field_type_ptr + 0x10, 0x08)  # MONO_TYPE_I4 (int32_t)

    # Mock Scanner
    scanner_mock = MagicMock()
    # Mocking scanner.find_address to return our root_domain_ptr_addr
    scanner_mock.find_address.return_value = root_domain_ptr_addr

    with patch("engines.base.PatternScanner", return_value=scanner_mock):
        dumper = MonoDumper(reader, "output", config=cfg)

        assert dumper.validate() is True
        packages = dumper.dump()

        assert len(packages) == 1
        pkg = packages[0]
        assert pkg.name == "Assembly-CSharp"
        assert len(pkg.classes) == 1

        cls = pkg.classes[0]
        assert cls.name == "PlayerController"
        assert cls.full_name == "Game.Logic.PlayerController"
        assert cls.size == 0x100
        assert len(cls.fields) == 1

        fld = cls.fields[0]
        assert fld.name == "health"
        assert fld.offset == 0x18
        assert fld.type_name == "int32_t"
