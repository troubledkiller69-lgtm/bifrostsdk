"""
BIFROST SDK — Source Engine Struct Definitions
RecvTable / RecvProp / ClientClass layouts for NetVar dumping.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceConfig:
    """Configuration for Source Engine NetVar dumping."""
    # Module names
    client_dll: str = "client.dll"
    engine_dll: str = "engine.dll"
    engine2_dll: str = "engine2.dll"  # Source 2

    # ClientClass linked list
    # Pattern to find the head of the linked list
    # Typically: first ClientClass is reachable from CreateInterface or
    # a global pointer in client.dll
    client_class_pattern: str = "44 54 5F ?? ?? 48 89 05"

    # Source 1 ClientClass layout
    cc_create_fn: int = 0x00        # void* m_pCreateFn
    cc_create_event_fn: int = 0x08  # void* m_pCreateEventFn
    cc_network_name: int = 0x10     # const char* m_pNetworkName
    cc_recv_table: int = 0x18       # RecvTable* m_pRecvTable
    cc_next: int = 0x20             # ClientClass* m_pNext
    cc_class_id: int = 0x28         # int m_ClassID

    # RecvTable layout
    rt_props: int = 0x00            # RecvProp* m_pProps
    rt_num_props: int = 0x08        # int m_nProps
    rt_decoder: int = 0x10          # void* m_pDecoder
    rt_name: int = 0x18             # const char* m_pNetTableName

    # RecvProp layout
    rp_var_name: int = 0x00         # const char* m_pVarName
    rp_recv_type: int = 0x08        # int m_RecvType (SendPropType)
    rp_flags: int = 0x0C            # int m_Flags
    rp_string_buffer_size: int = 0x10   # int
    rp_inside_array: int = 0x14     # bool
    rp_extra_data: int = 0x18       # const void*
    rp_array_prop: int = 0x20       # RecvProp* m_pArrayProp
    rp_array_length_proxy: int = 0x28   # ArrayLengthRecvProxy
    rp_proxy_fn: int = 0x30         # RecvVarProxy
    rp_data_table: int = 0x38       # RecvTable* m_pDataTable
    rp_offset: int = 0x40           # int m_Offset  ← THE MONEY OFFSET
    rp_element_stride: int = 0x44   # int m_ElementStride
    rp_num_elements: int = 0x48     # int m_nElements
    rp_parent_array_prop_name: int = 0x50  # const char*
    rp_size: int = 0x58             # sizeof(RecvProp)

    # SendPropType enum
    prop_type_names: dict[int, str] = field(default_factory=lambda: {
        0: "DPT_Int",
        1: "DPT_Float",
        2: "DPT_Vector",
        3: "DPT_VectorXY",
        4: "DPT_String",
        5: "DPT_Array",
        6: "DPT_DataTable",
        7: "DPT_Int64",
    })


@dataclass
class Source2Config:
    """Configuration for Source 2 engine (Dota 2, CS2, Deadlock)."""
    # Source 2 uses a different schema system
    client_dll: str = "client.dll"
    schema_system_dll: str = "schemasystem.dll"

    # SchemaSystem patterns (multiple for resilience across CS2 updates)
    schema_system_patterns: list[str] = field(default_factory=lambda: [
        "4C 8D 35 ?? ?? ?? ?? 0F 28 45",
        "48 89 05 ?? ?? ?? ?? 4C 8D 45 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ??",
        "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05",
        "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 05",
    ])

    # SchemaSystem → TypeScope array
    type_scopes_size_offset: int = 0x190   # int32 — number of registered scopes
    type_scopes_offset: int = 0x198        # CSchemaSystemTypeScope** — pointer array

    # SchemaSystemTypeScope
    scope_name_offset: int = 0x08       # char m_szName[256] — inline string
    class_bindings_offset: int = 0x560  # CUtlTSHash<CSchemaClassBinding*>
    enum_bindings_offset: int = 0x2E50  # CUtlTSHash<CSchemaEnumBinding*>
    scope_declared_classes_offset: int = 0x4C8  # CSchemaDeclaredClassEntry* (fallback)
    scope_num_classes_offset: int = 0x456       # uint16_t (fallback)

    # CSchemaDeclaredClassEntry (24 bytes each)
    declared_class_entry_size: int = 0x18
    declared_class_ptr_offset: int = 0x10   # → CSchemaDeclaredClassData_t*

    # SchemaClassBinding
    binding_name_offset: int = 0x08     # const char*
    binding_module_offset: int = 0x10   # const char*
    binding_size_offset: int = 0x20     # int32 size
    binding_field_count_offset: int = 0x24  # uint16
    binding_fields_offset: int = 0x30   # SchemaClassFieldData*

    # SchemaClassFieldData
    field_name_offset: int = 0x00       # const char*
    field_type_offset: int = 0x08       # SchemaType*
    field_offset_offset: int = 0x10     # int32 offset
    field_metadata_offset: int = 0x18   # SchemaMetadataEntryData*
    field_size: int = 0x20

    # SchemaType
    type_size_offset: int = 0x14        # int32 size within SchemaType
