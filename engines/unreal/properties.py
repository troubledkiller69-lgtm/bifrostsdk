"""
BIFROST SDK — UE5 FProperty Reader
Walks the FField/FProperty chain attached to UStruct/UClass objects
and extracts field names, types, offsets, and sizes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.memory import MemoryReader
from core.generator import SDKField
from .structs import UE5Profile
from .names import GNamesResolver


# FFieldClass name → C++ type hint mapping
PROPERTY_TYPE_MAP: dict[str, str] = {
    "BoolProperty": "bool",
    "ByteProperty": "uint8_t",
    "Int8Property": "int8_t",
    "Int16Property": "int16_t",
    "UInt16Property": "uint16_t",
    "IntProperty": "int32_t",
    "UInt32Property": "uint32_t",
    "Int64Property": "int64_t",
    "UInt64Property": "uint64_t",
    "FloatProperty": "float",
    "DoubleProperty": "double",
    "NameProperty": "FName",
    "StrProperty": "FString",
    "TextProperty": "FText",
    "ObjectProperty": "UObject*",
    "WeakObjectProperty": "TWeakObjectPtr<UObject>",
    "LazyObjectProperty": "TLazyObjectPtr<UObject>",
    "SoftObjectProperty": "TSoftObjectPtr<UObject>",
    "ClassProperty": "UClass*",
    "InterfaceProperty": "FScriptInterface",
    "StructProperty": "STRUCT",
    "ArrayProperty": "TArray<>",
    "MapProperty": "TMap<>",
    "SetProperty": "TSet<>",
    "DelegateProperty": "FDelegate",
    "MulticastDelegateProperty": "FMulticastDelegate",
    "MulticastInlineDelegateProperty": "FMulticastInlineDelegate",
    "MulticastSparseDelegateProperty": "FMulticastSparseDelegate",
    "EnumProperty": "ENUM",
    "FieldPathProperty": "FFieldPath",
}


class PropertyReader:
    """
    Read FProperty chains from UE5 UStruct/UClass objects.
    
    UE5 uses FField* ChildProperties (at UStruct + child_properties_offset).
    Each FField has:
        - FFieldClass* ClassPrivate  (tells us the property type)
        - FField* Next               (linked list)
        - FName NamePrivate
    FProperty adds:
        - int32 ArrayDim
        - int32 ElementSize
        - int32 Offset_Internal      ← the SDK offset we want
    """

    def __init__(self, reader: MemoryReader, names: GNamesResolver, profile: UE5Profile):
        self.reader = reader
        self.names = names
        self.profile = profile
        self._field_class_cache: dict[int, str] = {}

    def _read_field_class_name(self, ffield_addr: int) -> str:
        """Read the FFieldClass name from an FField's ClassPrivate pointer."""
        cfg = self.profile.ffield
        class_ptr = self.reader.read_ptr(ffield_addr + cfg.class_private)
        if class_ptr == 0:
            return "Unknown"

        if class_ptr in self._field_class_cache:
            return self._field_class_cache[class_ptr]

        # FFieldClass has FName at offset 0
        try:
            name = self.names.resolve_fname_at(class_ptr + self.profile.ffield_class.name)
            self._field_class_cache[class_ptr] = name
            return name
        except Exception:
            return "Unknown"

    def read_properties(self, struct_addr: int) -> list[SDKField]:
        """
        Walk the FProperty chain starting from UStruct.ChildProperties
        and return a list of SDKField objects.
        """
        cfg_struct = self.profile.ustruct
        cfg_field = self.profile.ffield
        cfg_prop = self.profile.fproperty
        cfg_bool = self.profile.fbool_property

        fields: list[SDKField] = []

        # Read ChildProperties pointer
        try:
            child_ptr = self.reader.read_ptr(struct_addr + cfg_struct.child_properties)
        except Exception:
            return fields

        current = child_ptr
        depth = 0
        max_props = 2048  # safety limit

        while current != 0 and depth < max_props:
            depth += 1
            try:
                # Read FField base
                field_name = self.names.resolve_fname_at(current + cfg_field.name)
                field_type = self._read_field_class_name(current)

                # Read FProperty specifics
                array_dim = self.reader.read_int32(current + cfg_prop.array_dim)
                element_size = self.reader.read_int32(current + cfg_prop.element_size)
                offset = self.reader.read_int32(current + cfg_prop.offset_internal)

                # Sanity checks
                if offset < 0 or offset > 0x10000:
                    current = self.reader.read_ptr(current + cfg_field.next)
                    continue
                if element_size < 0 or element_size > 0x1000:
                    element_size = 0

                total_size = element_size * max(array_dim, 1)

                # Map type
                cpp_type = PROPERTY_TYPE_MAP.get(field_type, field_type)

                # Handle bool properties specially
                bit_offset = -1
                if field_type == "BoolProperty":
                    try:
                        field_mask = self.reader.read_uint8(current + cfg_bool.field_mask)
                        byte_mask = self.reader.read_uint8(current + cfg_bool.byte_mask)
                        byte_off = self.reader.read_uint8(current + cfg_bool.byte_offset)
                        # If field_mask != 0xFF, it's a bitfield
                        if field_mask != 0xFF:
                            # Calculate bit position
                            bit_offset = 0
                            m = field_mask
                            while m > 1:
                                m >>= 1
                                bit_offset += 1
                        total_size = 1
                    except Exception:
                        pass

                # Handle struct properties — try to resolve inner struct name
                comment = ""
                if field_type == "StructProperty":
                    try:
                        # FStructProperty has UScriptStruct* at fproperty.size + 0x00
                        inner_struct = self.reader.read_ptr(current + cfg_prop.size)
                        if inner_struct:
                            inner_name = self.names.resolve_fname_at(
                                inner_struct + self.profile.uobject.name_private
                            )
                            cpp_type = f"F{inner_name}" if inner_name else "STRUCT"
                            comment = f"StructProperty({inner_name})"
                    except Exception:
                        pass

                # Handle object properties — try to resolve target class
                if field_type == "ObjectProperty":
                    try:
                        target_class = self.reader.read_ptr(current + cfg_prop.size)
                        if target_class:
                            target_name = self.names.resolve_fname_at(
                                target_class + self.profile.uobject.name_private
                            )
                            cpp_type = f"class U{target_name}*" if target_name else "UObject*"
                            comment = f"ObjectProperty({target_name})"
                    except Exception:
                        pass

                # Handle array properties — try to resolve inner type
                if field_type == "ArrayProperty":
                    try:
                        inner_prop = self.reader.read_ptr(current + cfg_prop.size)
                        if inner_prop:
                            inner_type = self._read_field_class_name(inner_prop)
                            inner_cpp = PROPERTY_TYPE_MAP.get(inner_type, inner_type)
                            cpp_type = f"TArray<{inner_cpp}>"
                            comment = f"ArrayProperty<{inner_type}>"
                    except Exception:
                        pass

                fields.append(SDKField(
                    name=field_name,
                    type_name=cpp_type,
                    offset=offset,
                    size=total_size,
                    array_dim=array_dim if array_dim > 1 else 1,
                    bit_offset=bit_offset,
                    comment=comment,
                ))

                # Next in linked list
                current = self.reader.read_ptr(current + cfg_field.next)

            except Exception:
                break

        return fields

    def read_super_struct(self, struct_addr: int) -> int:
        """Return the SuperStruct pointer of a UStruct."""
        try:
            return self.reader.read_ptr(struct_addr + self.profile.ustruct.super_struct)
        except Exception:
            return 0

    def read_struct_size(self, struct_addr: int) -> int:
        """Return PropertiesSize of a UStruct."""
        try:
            return self.reader.read_int32(struct_addr + self.profile.ustruct.properties_size)
        except Exception:
            return 0
