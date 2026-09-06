"""
BIFROST SDK — Unreal Engine 5 Internal Struct Definitions
Mirrors the in-memory layout of UE5's reflection system objects.
Offsets are configurable via profiles for different UE5 versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ======================================================================
# FName / FNamePool
# ======================================================================

@dataclass
class FNamePoolConfig:
    """Configurable offsets for the FNamePool (chunked name table)."""
    # FNamePool layout
    lock_size: int = 8              # FRWLock at offset 0
    current_block: int = 8          # uint32 CurrentBlock
    current_byte_cursor: int = 12   # uint32 CurrentByteCursor
    blocks_offset: int = 16         # void* Blocks[FNameMaxBlocks]

    # FNameEntry layout
    header_offset: int = 0          # offset from entry start to header
    header_size: int = 2            # uint16 Header (bIsWide : 1, Len : 15)  or (Len:6, pad:10) varies
    wide_bit_mask: int = 0x1        # bit 0 = bIsWide
    len_shift: int = 6              # shift right by 6 to get length in UE5
    len_mask: int = 0xFFFF          # after shift, mask for length
    string_offset: int = 2          # offset from entry start to string

    # FNamePool constants
    block_offset_bits: int = 16
    block_size: int = 0x1FFFE       # stride = 2 * (1 << (BlockOffsetBits-1)) = 131070
    max_blocks: int = 8192
    stride: int = 2                 # entries are aligned to boundaries
    comparison_index_shift: int = 0 # shift applied to ComparisonIndex to get the index


@dataclass
class FNameConfig:
    """FName in-object layout."""
    comparison_index_offset: int = 0    # int32 ComparisonIndex (FNameEntryId)
    number_offset: int = 4              # int32 Number
    size: int = 8                       # total FName size


# ======================================================================
# GObjects / FUObjectArray
# ======================================================================

@dataclass
class GObjectsConfig:
    """Configurable offsets for the chunked FUObjectArray."""
    # FChunkedFixedUObjectArray
    objects_offset: int = 0         # FUObjectItem** Objects
    pre_alloc_offset: int = 8       # FUObjectItem* PreAllocatedObjects  (unused by us)
    max_elements_offset: int = 16   # int32 MaxElements
    num_elements_offset: int = 20   # int32 NumElements
    max_chunks_offset: int = 24     # int32 MaxChunks
    num_chunks_offset: int = 28     # int32 NumChunks

    # FUObjectItem
    item_size: int = 24             # sizeof(FUObjectItem) — object ptr + flags + cluster + serial
    item_object_offset: int = 0     # UObject* Object within FUObjectItem

    # Chunk
    elements_per_chunk: int = 65536  # 64 * 1024


# ======================================================================
# UObject hierarchy
# ======================================================================

@dataclass
class UObjectConfig:
    """Offsets within UObjectBase / UObject."""
    vtable: int = 0x0000
    object_flags: int = 0x0008
    internal_index: int = 0x000C
    class_private: int = 0x0010
    name_private: int = 0x0018
    outer_private: int = 0x0020
    size: int = 0x0028


@dataclass
class UFieldConfig:
    """UField : UObject."""
    next: int = 0x0028              # UField* Next (UE4-style, UE5 may not use)
    size: int = 0x0030


@dataclass
class UStructConfig:
    """UStruct : UField."""
    super_struct: int = 0x0040      # UStruct* SuperStruct
    children: int = 0x0048          # UField* Children (legacy, UE4)
    child_properties: int = 0x0050  # FField* ChildProperties (UE5)
    properties_size: int = 0x0058   # int32 PropertiesSize
    min_alignment: int = 0x005C     # int32 MinAlignment
    size: int = 0x00B0              # approximate total


@dataclass
class UClassConfig:
    """UClass : UStruct — adds class-specific fields."""
    class_flags: int = 0x00B0       # EClassFlags
    class_cast_flags: int = 0x00B8  # EClassCastFlags
    class_default_object: int = 0x0110  # UObject* ClassDefaultObject
    size: int = 0x0230


@dataclass
class UEnumConfig:
    """UEnum : UField"""
    names_array: int = 0x0040       # TArray<TPair<FName, int64>> Names


# ======================================================================
# FField / FProperty (UE5's property system)
# ======================================================================

@dataclass
class FFieldConfig:
    """FField — base of UE5's property system (replaces UProperty)."""
    vtable: int = 0x0000
    class_private: int = 0x0008     # FFieldClass* ClassPrivate
    owner: int = 0x0010             # FFieldVariant Owner
    next: int = 0x0020              # FField* Next
    name: int = 0x0028              # FName NamePrivate
    flags: int = 0x0030             # EObjectFlags FlagsPrivate
    size: int = 0x0038


@dataclass
class FPropertyConfig:
    """FProperty : FField — concrete property with offset/size info."""
    array_dim: int = 0x0038         # int32 ArrayDim
    element_size: int = 0x003C      # int32 ElementSize
    property_flags: int = 0x0040    # EPropertyFlags (uint64)
    offset_internal: int = 0x004C   # int32 Offset_Internal  ← THE MONEY OFFSET
    size: int = 0x0078


@dataclass
class FBoolPropertyConfig:
    """Extra fields for FBoolProperty."""
    field_size: int = 0x0078        # uint8
    byte_offset: int = 0x0079      # uint8
    byte_mask: int = 0x007A        # uint8
    field_mask: int = 0x007B       # uint8


# ======================================================================
# FFieldClass (used to identify property types)
# ======================================================================

@dataclass
class FFieldClassConfig:
    """FFieldClass — runtime type info for FField subclasses."""
    name: int = 0x0000              # FName Id
    unique_id: int = 0x0008         # uint64 CastFlags
    size: int = 0x0038


# ======================================================================
# Pattern definition (pattern + RIP resolution metadata)
# ======================================================================

@dataclass
class PatternDef:
    """
    AOB pattern bundled with RIP-relative resolution parameters.

    Different x86-64 instructions encode the RIP-relative offset at different
    positions within the instruction:
        LEA/MOV reg, [rip+disp32]:  48 8D/8B 05 xx xx xx xx  → rip_offset=3, insn_len=7
        CALL rel32:                 E8 xx xx xx xx            → rip_offset=1, insn_len=5
        MOV [rip+disp32], reg:      89 0D xx xx xx xx         → rip_offset=2, insn_len=6
        LEA reg, [rip+disp32]:      48 8D 0D xx xx xx xx      → rip_offset=3, insn_len=7
        LEA reg, [rip+disp32]:      48 8D 35 xx xx xx xx      → rip_offset=3, insn_len=7
        LEA reg, [rip+disp32]:      48 8D 1D xx xx xx xx      → rip_offset=3, insn_len=7
    """
    pattern: str
    rip_offset: int = 3   # byte position of the 4-byte RIP-relative displacement
    insn_len: int = 7     # total length of the instruction containing the displacement


# ======================================================================
# Aggregate profile
# ======================================================================

@dataclass
class UE5Profile:
    """Complete offset profile for a UE5 game."""
    name: str = "UE5 Default"
    fname_pool: FNamePoolConfig = field(default_factory=FNamePoolConfig)
    fname: FNameConfig = field(default_factory=FNameConfig)
    gobjects: GObjectsConfig = field(default_factory=GObjectsConfig)
    uobject: UObjectConfig = field(default_factory=UObjectConfig)
    ufield: UFieldConfig = field(default_factory=UFieldConfig)
    ustruct: UStructConfig = field(default_factory=UStructConfig)
    uclass: UClassConfig = field(default_factory=UClassConfig)
    uenum: UEnumConfig = field(default_factory=UEnumConfig)
    ffield: FFieldConfig = field(default_factory=FFieldConfig)
    fproperty: FPropertyConfig = field(default_factory=FPropertyConfig)
    fbool_property: FBoolPropertyConfig = field(default_factory=FBoolPropertyConfig)
    ffield_class: FFieldClassConfig = field(default_factory=FFieldClassConfig)

    # Common pattern signatures (game-specific, override as needed)
    # Use PatternDef to bundle pattern + RIP resolution params.
    # Plain strings are also accepted (default rip_offset=3, insn_len=7).
    gnames_pattern: PatternDef = field(default_factory=lambda: PatternDef("48 8D 05 ?? ?? ?? ?? EB 16"))
    gobjects_pattern: PatternDef = field(default_factory=lambda: PatternDef("48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1"))

    # Direct offsets from module base (bypass pattern scanning entirely)
    # Set these to non-zero values to skip pattern scanning and use hardcoded offsets.
    # These are typically sourced from community dumps (UnknownCheats, Dumper-7, etc.)
    #
    # IMPORTANT: These offsets may point to either:
    #   a) The structure itself (LEA-style — pool is inline in .data)
    #   b) A pointer TO the structure (MOV-style — must dereference once)
    # The dumper tries both interpretations automatically.
    gnames_direct_offset: int = 0   # offset from exe base to FNamePool (or ptr to it)
    gobjects_direct_offset: int = 0 # offset from exe base to FUObjectArray (or ptr to it)

    # Alternative patterns for different UE5 versions
    gnames_patterns_alt: list = field(default_factory=lambda: [
        # UE5.1+ / UE5.4 variations — each with correct RIP metadata
        PatternDef("48 8D 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8B C8 48 8B 44 24"),
        PatternDef("48 8D 35 ?? ?? ?? ?? EB 16"),                           # LEA RSI
        PatternDef("48 8D 05 ?? ?? ?? ?? 48 89 45 ?? EB"),                  # LEA RAX
        PatternDef("E8 ?? ?? ?? ?? 48 8B C3 48 89 1D", rip_offset=1, insn_len=5),  # CALL
        PatternDef("48 8D 05 ?? ?? ?? ?? 48 83 C4 ?? 5F C3 48 89 5C 24"),
        PatternDef("48 8D 05 ?? ?? ?? ?? EB 13 48 8D 05 ?? ?? ?? ?? 48 89 05"),
        PatternDef("48 8D 1D ?? ?? ?? ?? 48 89 1D ?? ?? ?? ?? 48 8B 5C 24"),
        PatternDef("48 8D 0D ?? ?? ?? ?? 8B FA 75 0F"),                     # LEA RCX
        PatternDef("48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B E8 C6 05"),   # LEA RCX
    ])
    gobjects_patterns_alt: list = field(default_factory=lambda: [
        # Common UE5 variations
        PatternDef("48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1"),
        PatternDef("48 8B 05 ?? ?? ?? ?? 48 63 C9 48 8D 14 40"),
        PatternDef("89 0D ?? ?? ?? ?? 48 8B DF", rip_offset=2, insn_len=6),  # MOV [rip+xx], ECX
        PatternDef("48 8B 15 ?? ?? ?? ?? 33 F6 48 8D 0C C2"),               # MOV RDX
        PatternDef("48 8B 05 ?? ?? ?? ?? 48 8B 1C C8 81 4B 08"),
        PatternDef("48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 1C D1"),
        PatternDef("48 8B 05 ?? ?? ?? ?? 48 8B 14 C8 4B 8D 0C 40 4C 8D 2C CA"),
        PatternDef("4C 8B 0D ?? ?? ?? ?? 8B D0"),                           # MOV R9
    ])


# Preset profiles for common configurations
UE5_DEFAULT = UE5Profile()

UE5_MARVEL_RIVALS = UE5Profile(
    name="UE5 Marvel Rivals",
    fname_pool=FNamePoolConfig(
        header_offset=4,
        string_offset=6,
        len_shift=1,
        stride=4,
        comparison_index_shift=0
    ),
    uobject=UObjectConfig(outer_private=0x28),
    uenum=UEnumConfig(names_array=0x40),
    ustruct=UStructConfig(
        super_struct=0x48,
        child_properties=0x58,
        properties_size=0x60
    ),
    fproperty=FPropertyConfig(
        array_dim=0x30,
        element_size=0x34,
        property_flags=0x38,
        offset_internal=0x44,
        size=0x70
    ),
    fbool_property=FBoolPropertyConfig(
        field_size=0x70,
        byte_offset=0x71,
        byte_mask=0x72,
        field_mask=0x73
    ),
    ffield=FFieldConfig(
        class_private=0x08,
        next=0x18,
        name=0x20
    ),
    # Direct offsets from exe base (community-sourced, May 30 2026 build)
    # These bypass pattern scanning entirely — update after game patches.
    # These point to the POINTER to the pool (dereference once to get actual address).
    gnames_direct_offset=0xEC29B80,
    gobjects_direct_offset=0xECE19E0,
    # Fallback patterns (used only if direct offsets fail)
    gnames_pattern=PatternDef("48 8D 0D ?? ?? ?? ?? 8B FA 75 0F"),   # LEA RCX, [rip+xx]
    gobjects_pattern=PatternDef("48 8B 05 ?? ?? ?? ?? 48 8B 14 C8 4B 8D 0C 40 4C 8D 2C CA"),
)
