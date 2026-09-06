"""
BIFROST SDK — Unity Mono Runtime SDK Dumper
Reads class/field metadata from Mono-based Unity games by calling
Mono API exports or reading internal structures directly.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from collections import defaultdict
from typing import Optional

from core.memory import ReaderProtocol
from core.scanner import PatternScanner
from core.generator import SDKPackage, SDKClass, SDKField
from engines.base import BaseDumper

from .structs import MonoConfig, MonoExports


class MonoDumper(BaseDumper):
    """
    SDK dumper for Unity games using the Mono runtime.

    Strategy:
        1. Find mono.dll (or variant) in the target process
        2. Locate MonoImage for each loaded assembly
        3. Walk classes via the metadata tables
        4. For each class, read fields with names, types, offsets
    
    Two approaches are supported:
        A. Direct memory read of MonoClass/MonoClassField structs
        B. Calling Mono exports via CreateRemoteThread (if available)
    
    This implementation uses approach A (direct reads) for safety.
    """

    ENGINE_NAME = "Unity (Mono)"

    def __init__(
        self,
        reader: ReaderProtocol,
        output_dir: str = "output",
        config: MonoConfig | None = None,
        stealth_config=None,
        **kwargs,
    ):
        super().__init__(reader, output_dir, stealth_config=stealth_config, **kwargs)
        self.config = config or MonoConfig()
        self._mono_module: str = ""
        self._mono_base: int = 0
        self._root_domain: int = 0

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Check that mono.dll (or variant) is loaded."""
        modules = self.reader.list_modules()
        module_names = {m["name"].lower(): m for m in modules}

        for dll_name in self.config.mono_dll_names:
            if dll_name.lower() in module_names:
                self._mono_module = dll_name
                self._mono_base = module_names[dll_name.lower()]["base"]
                self._update_progress(
                    "validating",
                    f"Found {dll_name} at 0x{self._mono_base:X}",
                )
                return True

        self._log_error("No Mono runtime DLL found")
        return False

    # ------------------------------------------------------------------
    # Internal helpers — read Mono structs directly from memory
    # ------------------------------------------------------------------

    def _read_mono_string(self, addr: int, max_len: int = 256) -> str:
        """Read a C string pointer."""
        if addr == 0:
            return ""
        try:
            return self.reader.read_string(addr, max_len)
        except Exception:
            return ""

    def _read_class_name(self, class_addr: int) -> str:
        cfg = self.config
        name_ptr = self.reader.read_ptr(class_addr + cfg.monoclass_name)
        return self._read_mono_string(name_ptr)

    def _read_class_namespace(self, class_addr: int) -> str:
        cfg = self.config
        ns_ptr = self.reader.read_ptr(class_addr + cfg.monoclass_namespace)
        return self._read_mono_string(ns_ptr)

    def _read_class_parent(self, class_addr: int) -> int:
        return self.reader.read_ptr(class_addr + self.config.monoclass_parent)

    def _read_instance_size(self, class_addr: int) -> int:
        try:
            return self.reader.read_int32(class_addr + self.config.monoclass_instance_size)
        except Exception:
            return 0

    def _read_field_count(self, class_addr: int) -> int:
        """Read field count — this is tricky as it moves between Mono versions."""
        cfg = self.config
        try:
            # Try reading at the configured offset
            count = self.reader.read_uint16(class_addr + cfg.monoclass_field_count)
            if 0 < count < 2000:
                return count
            # Fallback: try nearby offsets
            for delta in range(-8, 8, 2):
                count = self.reader.read_uint16(class_addr + cfg.monoclass_field_count + delta)
                if 0 < count < 2000:
                    return count
        except Exception:
            pass
        return 0

    def _read_fields(self, class_addr: int) -> list[SDKField]:
        """Read MonoClassField array from a MonoClass."""
        cfg = self.config
        fields_ptr = self.reader.read_ptr(class_addr + cfg.monoclass_fields)
        if fields_ptr == 0:
            return []

        field_count = self._read_field_count(class_addr)
        if field_count <= 0:
            return []

        result: list[SDKField] = []

        for i in range(field_count):
            field_addr = fields_ptr + i * cfg.field_size

            try:
                # Read field name
                name_ptr = self.reader.read_ptr(field_addr + cfg.field_name)
                name = self._read_mono_string(name_ptr)
                if not name:
                    continue

                # Read field offset
                offset = self.reader.read_int32(field_addr + cfg.field_offset)

                # Read field type
                type_ptr = self.reader.read_ptr(field_addr + cfg.field_type)
                type_name = "void*"
                if type_ptr:
                    try:
                        # MonoType.data contains class pointer or primitive type
                        type_enum = self.reader.read_uint8(type_ptr + 0x10)  # MonoType.type enum
                        type_name = self._mono_type_to_string(type_enum, type_ptr)
                    except Exception:
                        pass

                # Estimate size from type
                size = self._estimate_size(type_name)

                result.append(SDKField(
                    name=name,
                    type_name=type_name,
                    offset=offset,
                    size=size,
                ))

            except Exception:
                continue

        return result

    def _mono_type_to_string(self, type_enum: int, type_ptr: int) -> str:
        """Convert MonoTypeEnum to a C++ type string."""
        MONO_TYPES = {
            0x00: "void",       # MONO_TYPE_END
            0x01: "void",       # MONO_TYPE_VOID
            0x02: "bool",       # MONO_TYPE_BOOLEAN
            0x03: "char",       # MONO_TYPE_CHAR
            0x04: "int8_t",     # MONO_TYPE_I1
            0x05: "uint8_t",    # MONO_TYPE_U1
            0x06: "int16_t",    # MONO_TYPE_I2
            0x07: "uint16_t",   # MONO_TYPE_U2
            0x08: "int32_t",    # MONO_TYPE_I4
            0x09: "uint32_t",   # MONO_TYPE_U4
            0x0A: "int64_t",    # MONO_TYPE_I8
            0x0B: "uint64_t",   # MONO_TYPE_U8
            0x0C: "float",      # MONO_TYPE_R4
            0x0D: "double",     # MONO_TYPE_R8
            0x0E: "MonoString*",  # MONO_TYPE_STRING
            0x0F: "void*",      # MONO_TYPE_PTR
            0x10: "void*",      # MONO_TYPE_BYREF
            0x11: "VALUETYPE",  # MONO_TYPE_VALUETYPE
            0x12: "CLASS*",     # MONO_TYPE_CLASS
            0x14: "MonoArray*", # MONO_TYPE_ARRAY
            0x15: "void*",      # MONO_TYPE_GENERICINST
            0x16: "void*",      # MONO_TYPE_TYPEDBYREF
            0x18: "intptr_t",   # MONO_TYPE_I
            0x19: "uintptr_t",  # MONO_TYPE_U
            0x1D: "MonoArray*", # MONO_TYPE_SZARRAY
            0x1C: "void*",      # MONO_TYPE_MVAR
        }

        type_str = MONO_TYPES.get(type_enum, f"UnknownType_{type_enum:#x}")

        # For CLASS and VALUETYPE, try to resolve the actual class name
        if type_enum in (0x11, 0x12):
            try:
                # MonoType.data.klass is at type_ptr + 0x00
                klass_ptr = self.reader.read_ptr(type_ptr + 0x00)
                if klass_ptr:
                    class_name = self._read_class_name(klass_ptr)
                    if class_name:
                        prefix = "" if type_enum == 0x11 else ""
                        type_str = f"{prefix}{class_name}*" if type_enum == 0x12 else class_name
            except Exception:
                pass

        return type_str

    def _estimate_size(self, type_name: str) -> int:
        """Estimate field size from type name."""
        SIZE_MAP = {
            "bool": 1, "char": 2, "int8_t": 1, "uint8_t": 1,
            "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4,
            "int64_t": 8, "uint64_t": 8, "float": 4, "double": 8,
            "intptr_t": 8, "uintptr_t": 8, "void": 0,
        }
        if type_name in SIZE_MAP:
            return SIZE_MAP[type_name]
        if type_name.endswith("*"):
            return 8  # pointer
        return 4  # default guess

    # ------------------------------------------------------------------
    # Assembly / Image discovery
    # ------------------------------------------------------------------

    def _find_assemblies(self) -> list[dict]:
        """
        Find loaded Mono assemblies by scanning for the root domain
        and walking the assembly list.
        
        Falls back to pattern scanning if export-based approach fails.
        """
        assemblies = []

        # Strategy: find mono_get_root_domain export, call it,
        # then walk domain->domain_assemblies GSList
        # Since we can't safely call functions, we pattern scan for
        # the root domain global and read it directly.

        # Pattern for root domain global (common in mono.dll):
        # "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8" (MOV RCX, [root_domain])
        patterns = [
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8",
            "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48",
            "48 89 05 ?? ?? ?? ??",  # MOV [root_domain], RAX
        ]

        for pat in patterns:
            addr = self.scanner.find_address(self._mono_module, pat)
            if addr:
                self._root_domain = addr
                break

        if self._root_domain == 0:
            self._log_error("Could not find Mono root domain")
            return assemblies

        # Walk domain->domain_assemblies (GSList* at domain + ~0xC8)
        # GSList: data, next
        try:
            domain_addr = self.reader.read_ptr(self._root_domain)
            if not domain_addr:
                return assemblies
            # Common offset for domain_assemblies in modern Mono
            for asm_list_offset in (0xC8, 0xD0, 0xD8, 0xE0):
                asm_list = self.reader.read_ptr(domain_addr + asm_list_offset)
                if asm_list and asm_list < 0x7FFFFFFFFFFF:
                    # Walk GSList
                    current = asm_list
                    depth = 0
                    while current and depth < 500:
                        depth += 1
                        try:
                            data = self.reader.read_ptr(current)  # assembly pointer
                            next_node = self.reader.read_ptr(current + 8)

                            if data:
                                # MonoAssembly -> MonoImage* image at offset 0x60 (common)
                                for img_offset in (0x60, 0x58, 0x68):
                                    image = self.reader.read_ptr(data + img_offset)
                                    if image and image < 0x7FFFFFFFFFFF:
                                        # MonoImage.name is typically at offset 0x18 or 0x20
                                        for name_off in (0x18, 0x20, 0x10):
                                            name_ptr = self.reader.read_ptr(image + name_off)
                                            if name_ptr:
                                                name = self._read_mono_string(name_ptr)
                                                if name and len(name) > 1 and len(name) < 200:
                                                    assemblies.append({
                                                        "assembly": data,
                                                        "image": image,
                                                        "name": name,
                                                    })
                                                    break
                                        if assemblies and assemblies[-1]["assembly"] == data:
                                            break

                            current = next_node
                        except Exception:
                            break

                    if assemblies:
                        break

        except Exception as e:
            self._log_error(f"Error walking assemblies: {e}")

        return assemblies

    # ------------------------------------------------------------------
    # Class enumeration (via metadata tables)
    # ------------------------------------------------------------------

    def _enumerate_classes(self, image_addr: int) -> list[int]:
        """
        Enumerate all MonoClass pointers from a MonoImage's class cache.
        
        MonoImage has a class_cache (GHashTable) that maps tokens to classes.
        We walk the hash table to find all loaded classes.
        """
        classes: list[int] = []

        # The MonoImage.class_cache is a MonoInternalHashTable at various offsets
        # Common offsets: 0x3A0, 0x3B0, 0x4A0 (depends on Mono version)
        for cache_offset in (0x3A0, 0x3B0, 0x3C0, 0x4A0, 0x4B0):
            try:
                # MonoInternalHashTable: size (int32), table (MonoClass**)
                table_size = self.reader.read_int32(image_addr + cache_offset)
                if table_size <= 0 or table_size > 100000:
                    continue

                table_ptr = self.reader.read_ptr(image_addr + cache_offset + 8)
                if table_ptr == 0:
                    continue

                # Walk hash table buckets
                for bucket in range(table_size):
                    try:
                        entry = self.reader.read_ptr(table_ptr + bucket * 8)
                        depth = 0
                        while entry and depth < 100:
                            depth += 1
                            # Verify it looks like a MonoClass
                            name = self._read_class_name(entry)
                            if name and len(name) > 0 and len(name) < 200:
                                classes.append(entry)
                            # next_class_cache is typically the first field
                            # or at a known offset in the hash chain
                            try:
                                entry = self.reader.read_ptr(entry + 0x108)  # next in cache chain
                            except Exception:
                                break
                    except Exception:
                        continue

                if classes:
                    break

            except Exception:
                continue

        return classes

    # ------------------------------------------------------------------
    # Dump
    # ------------------------------------------------------------------

    def dump(self) -> list[SDKPackage]:
        """Full Mono SDK dump."""
        self._update_progress("dumping", "Finding assemblies...", 0)
        assemblies = self._find_assemblies()

        if not assemblies:
            self._log_error("No assemblies found — trying fallback class scan")
            return self._dump_fallback()

        self._update_progress(
            "dumping",
            f"Found {len(assemblies)} assemblies",
            10,
        )

        packages: list[SDKPackage] = []
        total_asm = len(assemblies)

        for idx, asm_info in enumerate(assemblies):
            pct = 10 + (idx / total_asm) * 80
            asm_name = asm_info["name"]
            self._update_progress("dumping", f"Dumping {asm_name}...", pct)

            pkg = SDKPackage(name=asm_name)

            # Enumerate classes in this image
            class_addrs = self._enumerate_classes(asm_info["image"])
            self._update_progress(
                "dumping",
                f"{asm_name}: {len(class_addrs)} classes",
                pct,
            )

            for class_addr in class_addrs:
                try:
                    name = self._read_class_name(class_addr)
                    namespace = self._read_class_namespace(class_addr)
                    if not name:
                        continue

                    # Read parent
                    parent_addr = self._read_class_parent(class_addr)
                    parent_name = ""
                    if parent_addr:
                        parent_name = self._read_class_name(parent_addr)

                    # Read size
                    instance_size = self._read_instance_size(class_addr)

                    # Read fields
                    fields = self._read_fields(class_addr)

                    full_name = f"{namespace}.{name}" if namespace else name
                    self.progress.classes_found += 1
                    self.progress.fields_found += len(fields)

                    pkg.classes.append(SDKClass(
                        name=name,
                        full_name=full_name,
                        super_name=parent_name,
                        size=instance_size,
                        fields=fields,
                        package=asm_name,
                    ))

                except Exception:
                    continue

            packages.append(pkg)

        self._update_progress(
            "dumping",
            f"Done — {self.progress.classes_found} classes, "
            f"{self.progress.fields_found} fields",
            100,
        )
        return packages

    def _dump_fallback(self) -> list[SDKPackage]:
        """
        Last-resort class scan via MonoClass structure patterns.

        The previous stub returned an empty package, which produced a
        "successful" dump with zero classes — indistinguishable from a real
        failure. This version raises so the bridge surfaces the error to the
        UI instead of silently writing an empty SDK.
        """
        self._update_progress("dumping", "Fallback: scanning for class structures...", 0)
        raise RuntimeError(
            "Mono assembly enumeration failed and the fallback class scan is "
            "not implemented for this Mono version. Try Il2CppDumper for "
            "metadata-based recovery instead."
        )
