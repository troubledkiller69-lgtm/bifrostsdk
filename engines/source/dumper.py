"""
BIFROST SDK — Source Engine SDK Dumper
Walks the ClientClass linked list and RecvTable hierarchy to dump NetVar offsets.
Supports both Source 1 (CS:GO, TF2, L4D2) and Source 2 (CS2, Dota 2, Deadlock).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from core.memory import ReaderProtocol
from core.scanner import PatternScanner
from core.generator import SDKPackage, SDKClass, SDKField
from engines.base import BaseDumper

from .structs import SourceConfig, Source2Config


class SourceDumper(BaseDumper):
    """
    Source Engine NetVar / Schema offset dumper.

    Source 1 strategy:
        1. Find the ClientClass linked list head in client.dll
        2. Walk ClientClass -> RecvTable -> RecvProp chains
        3. Recursively flatten DataTable props for nested offsets

    Source 2 strategy:
        1. Find SchemaSystem in schemasystem.dll
        2. Walk TypeScopes -> ClassBindings -> FieldData
    """

    ENGINE_NAME = "Source Engine"

    def __init__(
        self,
        reader: ReaderProtocol,
        output_dir: str = "output",
        config: SourceConfig | None = None,
        s2_config: Source2Config | None = None,
        stealth_config=None,
        **kwargs,
    ):
        super().__init__(reader, output_dir, stealth_config=stealth_config, **kwargs)
        self.config = config or SourceConfig()
        self.s2_config = s2_config or Source2Config()
        self._is_source2 = False
        self._client_base: int = 0

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Detect whether this is a Source 1 or Source 2 game."""
        modules = self.reader.list_modules()
        module_names = {m["name"].lower(): m for m in modules}

        # Check for Source 2
        if self.s2_config.schema_system_dll.lower() in module_names:
            self._is_source2 = True
            self._update_progress("validating", "Detected Source 2 engine")
            return True

        # Check for Source 1
        if self.config.client_dll.lower() in module_names:
            self._client_base = module_names[self.config.client_dll.lower()]["base"]
            self._update_progress(
                "validating",
                f"Detected Source 1 — client.dll at 0x{self._client_base:X}",
            )
            return True

        # Check engine2.dll for Source 2
        if self.config.engine2_dll.lower() in module_names:
            self._is_source2 = True
            self._update_progress("validating", "Detected Source 2 (engine2.dll)")
            return True

        self._log_error("No Source engine modules found")
        return False

    # ------------------------------------------------------------------
    # Source 1: ClientClass / RecvTable / RecvProp
    # ------------------------------------------------------------------

    def _find_client_class_head(self) -> int:
        """
        Find the first ClientClass in the linked list.
        
        Common approach: scan client.dll for a pattern that references
        the first ClientClass, or find it via the CreateInterface export.
        """
        cfg = self.config

        # Try pattern scanning for the head pointer
        # Common patterns near the head of the list:
        patterns = [
            "44 54 5F ?? ?? 48 89 05",
            "48 89 1D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 05",
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 8B 41",  # walk pattern
        ]

        for pat in patterns:
            hits = self.scanner.scan_module(cfg.client_dll, pat, return_first=True)
            if hits:
                # Resolve the pointer
                addr = self.reader.resolve_rip_relative(hits[0].address)
                if addr:
                    try:
                        first_cc = self.reader.read_ptr(addr)
                        if first_cc and first_cc < 0x7FFFFFFFFFFF:
                            return first_cc
                    except Exception as e:
                        self._log_warn(f"Pattern resolve failed: {e}")
                        continue

        # Fallback: scan for a known class name string reference
        # like "DT_BaseEntity" and work backwards to find the ClientClass
        string_patterns = [
            "44 54 5F 42 61 73 65 45 6E 74 69 74 79",  # "DT_BaseEntity"
        ]
        for pat in string_patterns:
            hits = self.scanner.scan_module(cfg.client_dll, pat, return_first=True)
            if hits:
                str_addr = hits[0].address
                # Search for a pointer to this string (the network name field)
                # This is hacky but effective
                ptr_bytes = str_addr.to_bytes(8, "little")
                ptr_pat = " ".join(f"{b:02X}" for b in ptr_bytes)
                ptr_hits = self.scanner.scan_module(cfg.client_dll, ptr_pat, return_first=True)
                if ptr_hits:
                    # This should be ClientClass.m_pNetworkName
                    cc_addr = ptr_hits[0].address - cfg.cc_network_name
                    return cc_addr

        return 0

    def _walk_recv_table(
        self,
        table_addr: int,
        base_offset: int = 0,
    ) -> list[SDKField]:
        """
        Recursively walk a RecvTable and its nested DataTable props.
        Returns flattened SDKField list with accumulated offsets.
        """
        cfg = self.config
        fields: list[SDKField] = []

        try:
            props_ptr = self.reader.read_ptr(table_addr + cfg.rt_props)
            num_props = self.reader.read_int32(table_addr + cfg.rt_num_props)
        except Exception as e:
            self._log_warn(f"RecvTable read at 0x{table_addr:X}: {e}")
            return fields

        if props_ptr == 0 or num_props <= 0 or num_props > 2000:
            return fields

        for i in range(num_props):
            prop_addr = props_ptr + i * cfg.rp_size

            try:
                # Read prop name
                name_ptr = self.reader.read_ptr(prop_addr + cfg.rp_var_name)
                name = self.reader.read_string(name_ptr) if name_ptr else ""
                if not name:
                    continue

                # Read type and offset
                prop_type = self.reader.read_int32(prop_addr + cfg.rp_recv_type)
                offset = self.reader.read_int32(prop_addr + cfg.rp_offset)

                # If this is a DataTable (type 6), recurse into it
                if prop_type == 6:  # DPT_DataTable
                    dt_ptr = self.reader.read_ptr(prop_addr + cfg.rp_data_table)
                    if dt_ptr:
                        nested = self._walk_recv_table(dt_ptr, base_offset + offset)
                        fields.extend(nested)
                    continue

                # Skip baseclass entries
                if name == "baseclass":
                    continue

                # Map type
                type_name = cfg.prop_type_names.get(prop_type, f"DPT_{prop_type}")
                cpp_type = self._source_type_to_cpp(prop_type)

                total_offset = base_offset + offset
                size = self._estimate_prop_size(prop_type)

                fields.append(SDKField(
                    name=name,
                    type_name=cpp_type,
                    offset=total_offset,
                    size=size,
                    comment=type_name,
                ))

            except Exception as e:
                self._log_warn(f"Prop {i} read failed: {e}")
                continue

        return fields

    def _source_type_to_cpp(self, prop_type: int) -> str:
        """Map Source SendPropType to C++ type."""
        TYPE_MAP = {
            0: "int32_t",       # DPT_Int
            1: "float",         # DPT_Float
            2: "Vector",        # DPT_Vector
            3: "Vector2D",      # DPT_VectorXY
            4: "char*",         # DPT_String
            5: "void*",         # DPT_Array
            6: "void*",         # DPT_DataTable
            7: "int64_t",       # DPT_Int64
        }
        return TYPE_MAP.get(prop_type, "void*")

    def _estimate_prop_size(self, prop_type: int) -> int:
        SIZE_MAP = {0: 4, 1: 4, 2: 12, 3: 8, 4: 8, 5: 8, 6: 8, 7: 8}
        return SIZE_MAP.get(prop_type, 4)

    def _dump_source1(self) -> list[SDKPackage]:
        """Source 1 NetVar dump via ClientClass linked list."""
        self._update_progress("dumping", "Finding ClientClass head...", 0)
        head = self._find_client_class_head()

        if head == 0:
            self._log_error("Could not find ClientClass linked list head")
            return []

        self._update_progress("dumping", f"ClientClass head at 0x{head:X}", 10)

        cfg = self.config
        pkg = SDKPackage(name="netvars")
        current = head
        depth = 0
        max_classes = 5000

        while current and depth < max_classes:
            depth += 1
            try:
                # Read class name
                name_ptr = self.reader.read_ptr(current + cfg.cc_network_name)
                class_name = self.reader.read_string(name_ptr) if name_ptr else ""
                if not class_name:
                    current = self.reader.read_ptr(current + cfg.cc_next)
                    continue

                # Read RecvTable
                recv_table = self.reader.read_ptr(current + cfg.cc_recv_table)
                fields: list[SDKField] = []
                if recv_table:
                    fields = self._walk_recv_table(recv_table)

                # Read table name for display
                table_name_ptr = self.reader.read_ptr(recv_table + cfg.rt_name) if recv_table else 0
                table_name = self.reader.read_string(table_name_ptr) if table_name_ptr else class_name

                self.progress.classes_found += 1
                self.progress.fields_found += len(fields)

                pkg.classes.append(SDKClass(
                    name=table_name,
                    full_name=f"Source.{table_name}",
                    super_name="",
                    size=max(f.offset + f.size for f in fields) if fields else 0,
                    fields=fields,
                    package="netvars",
                ))

                if depth % 50 == 0:
                    pct = min(10 + depth * 0.5, 90)
                    self._update_progress(
                        "dumping",
                        f"Walking classes: {depth} — {class_name}",
                        pct,
                    )

                # Next in linked list
                current = self.reader.read_ptr(current + cfg.cc_next)

            except Exception as e:
                self._log_warn(f"Class walk failed at depth {depth}: {e}")
                break

        self._update_progress("dumping", f"Done — {depth} classes", 100)
        return [pkg]

    # ------------------------------------------------------------------
    # Source 2: SchemaSystem
    # ------------------------------------------------------------------

    def _read_utl_ts_hash(self, utl_ts_hash_addr: int) -> list[int]:
        """
        Extracts an array of pointers (e.g., SchemaClassBinding*) from a CUtlTSHash.
        """
        elements = []
        
        # 1. Read counts from UtlMemoryPool (located at the start of CUtlTSHash)
        try:
            blocks_allocated = self.reader.read_int32(utl_ts_hash_addr + 0x0C)
            peak_allocated = self.reader.read_int32(utl_ts_hash_addr + 0x10)
        except Exception as e:
            self._log_warn(f"CUtlTSHash header read at 0x{utl_ts_hash_addr:X}: {e}")
            return []
        
        # 2. Iterate allocated elements inside the buckets
        buckets_offset = 0x60
        bucket_size = 0x18
        bucket_count = 256
        
        for i in range(bucket_count):
            if len(elements) >= blocks_allocated:
                break
                
            bucket_addr = utl_ts_hash_addr + buckets_offset + (i * bucket_size)
            try:
                node_ptr = self.reader.read_ptr(bucket_addr + 0x10)
            except Exception as e:
                self._log_warn(f"Bucket {i} read failed: {e}")
                continue
            
            while node_ptr != 0:
                try:
                    data_ptr = self.reader.read_ptr(node_ptr + 0x10)
                    if data_ptr != 0:
                        elements.append(data_ptr)
                        
                    if len(elements) >= blocks_allocated:
                        break
                        
                    node_ptr = self.reader.read_ptr(node_ptr + 0x08)
                except Exception as e:
                    self._log_warn(f"Node walk failed at 0x{node_ptr:X}: {e}")
                    break

        # 3. Iterate unallocated elements (free blocks list)
        try:
            blob_ptr = self.reader.read_ptr(utl_ts_hash_addr + 0x20)
        except Exception as e:
            self._log_warn(f"Free list read at 0x{utl_ts_hash_addr + 0x20:X}: {e}")
            blob_ptr = 0
            
        unallocated_elements = []
        
        while blob_ptr != 0:
            try:
                data_ptr = self.reader.read_ptr(blob_ptr + 0x10)
                if data_ptr != 0:
                    unallocated_elements.append(data_ptr)
                    
                if len(unallocated_elements) >= peak_allocated:
                    break
                    
                blob_ptr = self.reader.read_ptr(blob_ptr)
            except Exception as e:
                self._log_warn(f"Free block walk failed: {e}")
                break

        # 4. Combine lists and remove duplicate pointers
        return list(set(elements + unallocated_elements))

    def _dump_source2(self) -> list[SDKPackage]:
        """Source 2 SDK dump via SchemaSystem."""
        cfg = self.s2_config
        self._update_progress("dumping", "Finding SchemaSystem...", 0)

        # Find SchemaSystem global pointer address
        schema_ptr_addr = None
        patterns = cfg.schema_system_patterns
        for i, pattern in enumerate(patterns):
            self._log(f"Trying SchemaSystem pattern {i+1}/{len(patterns)}...")
            schema_ptr_addr = self.scanner.find_address(
                cfg.schema_system_dll,
                pattern,
            )
            if schema_ptr_addr:
                self._log(f"SchemaSystem found with pattern {i+1}")
                break

        if not schema_ptr_addr:
            self._log_error("SchemaSystem not found with any pattern — CS2 may have updated")
            return []

        # Check if the pattern uses LEA (Load Effective Address)
        # If it's an LEA instruction (e.g. 4C 8D or 48 8D), the resolved address IS the object.
        # If it's a MOV/CMP instruction (e.g. 48 89 or 48 8B), the resolved address is a POINTER to the object.
        if "8D" in patterns[i]:
            schema_system = schema_ptr_addr
        else:
            schema_system = self.reader.read_ptr(schema_ptr_addr)
            
        if not schema_system:
            self._log_error(f"SchemaSystem global at 0x{schema_ptr_addr:X} is null")
            return []

        self._log(f"SchemaSystem object at 0x{schema_system:X} (resolved from 0x{schema_ptr_addr:X})")
        self._update_progress("dumping", f"SchemaSystem at 0x{schema_system:X}", 10)

        # Read TypeScope array from SchemaSystem
        num_scopes = self.reader.read_int32(schema_system + cfg.type_scopes_size_offset)
        scope_array_ptr = self.reader.read_ptr(schema_system + cfg.type_scopes_offset)

        self._log(f"TypeScopes: count={num_scopes}, array=0x{scope_array_ptr:X}")

        if num_scopes <= 0 or num_scopes > 64 or not scope_array_ptr:
            self._log_error(f"Invalid scope data: count={num_scopes}, ptr=0x{scope_array_ptr:X}")
            return []

        packages: list[SDKPackage] = []

        for i in range(num_scopes):
            try:
                scope_ptr = self.reader.read_ptr(scope_array_ptr + i * 8)
                if not scope_ptr:
                    continue

                # Scope name is an inline char[256] at offset 0x008
                scope_name = self.reader.read_string(scope_ptr + cfg.scope_name_offset)
                if not scope_name:
                    scope_name = f"scope_{i}"

                # SchemaSystemTypeScope has a CUtlTSHash for class bindings
                ts_hash_addr = scope_ptr + cfg.class_bindings_offset
                class_bindings = self._read_utl_ts_hash(ts_hash_addr)
                num_classes = len(class_bindings)
                
                self._log(f"Scope '{scope_name}': {num_classes} classes (CUtlTSHash=0x{ts_hash_addr:X})")

                pkg = SDKPackage(name=scope_name)

                if class_bindings:
                    for binding_ptr in class_bindings:
                        if not binding_ptr:
                            continue
                        self._read_schema_class(binding_ptr, pkg, cfg)

                if pkg.classes:
                    packages.append(pkg)

                pct = 10 + int(80 * (i + 1) / num_scopes)
                self._update_progress("dumping", f"Scope {i+1}/{num_scopes}: {scope_name}", pct)

            except Exception as e:
                self._log_warn(f"Scope {i} failed: {e}")
                continue

        self._update_progress(
            "dumping",
            f"Done — {self.progress.classes_found} classes",
            100,
        )
        return packages

    def _read_schema_class(self, binding_ptr: int, pkg: SDKPackage, cfg: Source2Config):
        """Read a SchemaClassBinding and its fields."""
        try:
            # Read class name
            name_ptr = self.reader.read_ptr(binding_ptr + cfg.binding_name_offset)
            name = self.reader.read_string(name_ptr) if name_ptr else ""
            if not name:
                return

            # Read size
            class_size = self.reader.read_int32(binding_ptr + cfg.binding_size_offset)

            # Read fields
            field_count = self.reader.read_uint16(binding_ptr + cfg.binding_field_count_offset)
            fields_ptr = self.reader.read_ptr(binding_ptr + cfg.binding_fields_offset)

            fields: list[SDKField] = []
            if fields_ptr and field_count > 0 and field_count < 2000:
                for k in range(field_count):
                    fd_addr = fields_ptr + k * cfg.field_size

                    fd_name_ptr = self.reader.read_ptr(fd_addr + cfg.field_name_offset)
                    fd_name = self.reader.read_string(fd_name_ptr) if fd_name_ptr else ""
                    fd_offset = self.reader.read_int32(fd_addr + cfg.field_offset_offset)

                    # Try to read type name
                    type_ptr = self.reader.read_ptr(fd_addr + cfg.field_type_offset)
                    type_name = "void*"
                    if type_ptr:
                        try:
                            type_name_ptr = self.reader.read_ptr(type_ptr + 0x08)
                            if type_name_ptr:
                                type_name = self.reader.read_string(type_name_ptr)
                        except Exception:
                            pass

                    fd_size = 4
                    if type_ptr:
                        try:
                            fd_size = self.reader.read_int32(type_ptr + cfg.type_size_offset)
                            if fd_size <= 0 or fd_size > 0x1000:
                                fd_size = 4
                        except Exception:
                            pass

                    if fd_name:
                        fields.append(SDKField(
                            name=fd_name,
                            type_name=type_name,
                            offset=fd_offset,
                            size=fd_size,
                        ))

            self.progress.classes_found += 1
            self.progress.fields_found += len(fields)

            pkg.classes.append(SDKClass(
                name=name,
                full_name=f"Source2.{name}",
                super_name="",
                size=class_size,
                fields=fields,
                package=pkg.name,
            ))

        except Exception as e:
            self._log_warn(f"Class binding 0x{binding_ptr:X}: {e}")

    # ------------------------------------------------------------------
    # Dump (dispatch)
    # ------------------------------------------------------------------

    def dump(self) -> list[SDKPackage]:
        if self._is_source2:
            return self._dump_source2()
        return self._dump_source1()
