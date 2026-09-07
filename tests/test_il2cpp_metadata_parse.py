"""
Metadata table parse regression tests (IL2CPP dumper).

The field-definitions header pair is a FIXED index (11, byte 0x60), not
"the pair after typeDefinitions" — reading the images pair produced
nonsense field counts (PG3D: 423 fields for 21329 types).
"""
import struct

from engines.unity.il2cpp import IL2CPPDumper
from engines.unity.structs import IL2CPPConfig

MAGIC = b"\xAF\x1B\xB1\xFA"


def _build_blob():
    """Hand-built v29-shaped metadata: 1 type def, 2 field defs."""
    strings = b"Cls\0FieldOne\0FieldTwo\0"
    str_off = 0x100

    fd_off = 0x200
    fd_size = 0x0C
    fd_table = b"".join([
        struct.pack("<ii", 4, 0) + b"\x00" * (fd_size - 8),   # "FieldOne" (index 4)
        struct.pack("<ii", 13, 0) + b"\x00" * (fd_size - 8),  # "FieldTwo"
    ])

    td_off = 0x300
    td_size = 0x80
    td = bytearray(td_size)
    struct.pack_into("<ii", td, 0x00, 0, 0)   # name=Cls, namespace=empty
    struct.pack_into("<i", td, 0x28, 0)       # field_start = 0
    struct.pack_into("<H", td, 0x68, 2)       # field_count = 2

    body = bytearray(td_off + td_size)
    body[0:4] = MAGIC
    struct.pack_into("<i", body, 0x04, 29)                    # version
    struct.pack_into("<ii", body, 0x18, str_off, len(strings))  # strings pair
    struct.pack_into("<ii", body, 0x60, fd_off, len(fd_table))  # fields pair
    struct.pack_into("<ii", body, 0xA0, td_off, td_size)      # typedefs pair
    body[str_off:str_off + len(strings)] = strings
    body[fd_off:fd_off + len(fd_table)] = fd_table
    body[td_off:td_off + td_size] = td
    return bytes(body)


def _make_dumper(blob):
    dumper = IL2CPPDumper.__new__(IL2CPPDumper)
    dumper.config = IL2CPPConfig()
    dumper._type_defs = []
    dumper._field_defs = []
    dumper._strings = b""
    dumper._metadata = blob
    dumper._metadata_version = struct.unpack_from("<i", blob, 4)[0]
    return dumper


def test_field_definitions_parsed_from_fixed_pair():
    dumper = _make_dumper(_build_blob())
    dumper._parse_metadata()

    assert len(dumper._type_defs) == 1
    assert dumper._type_defs[0]["name"] == "Cls"
    assert dumper._type_defs[0]["field_count"] == 2

    names = [f["name"] for f in dumper._field_defs]
    assert names == ["FieldOne", "FieldTwo"], f"got {names}"
