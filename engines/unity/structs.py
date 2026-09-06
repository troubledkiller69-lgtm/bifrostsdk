"""
BIFROST SDK — Unity Engine Struct Definitions
Internal struct layouts for both Mono and IL2CPP runtimes.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ======================================================================
# Mono Runtime Structs
# ======================================================================

@dataclass
class MonoConfig:
    """Configuration for Mono runtime SDK dumping."""
    # Common Mono DLL names
    mono_dll_names: list[str] = field(default_factory=lambda: [
        "mono.dll",
        "mono-2.0-bdwgc.dll",
        "mono-2.0-sgen.dll",
    ])

    # Mono internal struct offsets (MonoClass)
    # These vary between Mono versions, the defaults are for modern Unity Mono
    monoclass_name: int = 0x48          # const char* name
    monoclass_namespace: int = 0x50     # const char* name_space
    monoclass_parent: int = 0x30        # MonoClass* parent
    monoclass_nested_in: int = 0x38     # MonoClass* nested_in
    monoclass_fields: int = 0xA0        # MonoClassField* fields
    monoclass_field_count: int = 0x100  # uint16_t field_count (inside runtime_info or bitfield)
    monoclass_methods: int = 0x98       # MonoMethod** methods
    monoclass_method_count: int = 0x0   # varies
    monoclass_instance_size: int = 0x6C # int32 instance_size
    monoclass_vtable_size: int = 0x5C   # int32 vtable_size
    monoclass_token: int = 0x58         # uint32 type_token
    monoclass_flags: int = 0x24         # uint32 flags
    monoclass_type: int = 0x2C          # MonoType this_arg or byval_arg

    # MonoClassField offsets
    field_type: int = 0x00              # MonoType* type
    field_name: int = 0x08              # const char* name
    field_parent: int = 0x10            # MonoClass* parent
    field_offset: int = 0x18            # int32 offset
    field_size: int = 0x20              # size of MonoClassField struct

    # MonoType offsets
    type_data: int = 0x00               # void* data (MonoClass* for VALUETYPE/CLASS)
    type_attrs: int = 0x08              # uint16 attrs


@dataclass
class MonoExports:
    """Expected Mono export function names."""
    get_root_domain: str = "mono_get_root_domain"
    domain_get_assemblies: str = "mono_domain_get_assemblies"  # not always exported
    assembly_foreach: str = "mono_assembly_foreach"
    assembly_get_image: str = "mono_assembly_get_image"
    image_get_name: str = "mono_image_get_name"
    image_get_table_info: str = "mono_image_get_table_info"
    table_info_get_rows: str = "mono_table_info_get_rows"
    class_get: str = "mono_class_get"
    class_from_name: str = "mono_class_from_name"
    class_get_name: str = "mono_class_get_name"
    class_get_namespace: str = "mono_class_get_namespace"
    class_get_parent: str = "mono_class_get_parent"
    class_get_fields: str = "mono_class_get_fields"
    class_get_methods: str = "mono_class_get_methods"
    class_num_fields: str = "mono_class_num_fields"
    class_num_methods: str = "mono_class_num_methods"
    class_instance_size: str = "mono_class_instance_size"
    field_get_name: str = "mono_field_get_name"
    field_get_offset: str = "mono_field_get_offset"
    field_get_type: str = "mono_field_get_type"
    type_get_name: str = "mono_type_get_name"
    type_get_type: str = "mono_type_get_type"
    method_get_name: str = "mono_method_get_name"


# ======================================================================
# IL2CPP Structs
# ======================================================================

@dataclass
class IL2CPPConfig:
    """Configuration for IL2CPP SDK dumping."""
    # Key DLL
    game_assembly_dll: str = "GameAssembly.dll"
    unity_player_dll: str = "UnityPlayer.dll"

    # global-metadata.dat path (relative to game dir)
    metadata_filename: str = "global-metadata.dat"

    # Metadata header magic
    metadata_magic: int = 0xFAB11BAF
    metadata_magic_bytes: bytes = b"\xAF\x1B\xB1\xFA"

    # Il2CppGlobalMetadataHeader offsets (version 29+)
    header_sanity: int = 0x00       # int32 sanity (magic)
    header_version: int = 0x04      # int32 version
    header_string_offset: int = 0x18        # int32
    header_string_count: int = 0x1C         # int32
    header_string_literal_offset: int = 0x20
    header_type_definitions_offset: int = 0xA0  # varies per version
    header_type_definitions_count: int = 0xA4

    # Il2CppTypeDefinition layout (metadata version 29)
    typedef_name_index: int = 0x00          # StringIndex
    typedef_namespace_index: int = 0x04     # StringIndex
    typedef_parent_index: int = 0x14        # TypeIndex
    typedef_field_start: int = 0x28         # FieldIndex
    typedef_field_count: int = 0x68         # uint16
    typedef_method_start: int = 0x2C        # MethodIndex
    typedef_method_count: int = 0x6A        # uint16
    typedef_instance_size: int = 0x5C       # int32 (from bitfield area, varies)
    typedef_token: int = 0x58               # uint32 token
    typedef_size: int = 0x80                # sizeof(Il2CppTypeDefinition) — varies

    # Il2CppFieldDefinition
    field_def_name_index: int = 0x00        # StringIndex
    field_def_type_index: int = 0x04        # TypeIndex
    field_def_token: int = 0x08             # uint32 customAttributeIndex (or token)
    field_def_size: int = 0x0C

    # Memory patterns for finding il2cpp exports
    il2cpp_domain_get_assemblies_pattern: str = "48 83 EC 28 48 85 C9 75"
    il2cpp_class_get_fields_pattern: str = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B F2 48 8B D9 48 85 D2"

    # Export names from GameAssembly.dll
    export_domain_get: str = "il2cpp_domain_get"
    export_domain_get_assemblies: str = "il2cpp_domain_get_assemblies"
    export_class_from_name: str = "il2cpp_class_from_name"
    export_class_get_fields: str = "il2cpp_class_get_fields"
    export_field_get_offset: str = "il2cpp_field_get_offset"
    export_type_get_name: str = "il2cpp_type_get_name"
