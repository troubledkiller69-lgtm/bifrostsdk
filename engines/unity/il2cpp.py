"""
BIFROST SDK — Unity IL2CPP SDK Dumper
Parses global-metadata.dat and GameAssembly.dll to extract class/field offsets
from IL2CPP-compiled Unity games.
"""

from __future__ import annotations

import os
import struct
from collections import defaultdict
from typing import Optional

from core.memory import ReaderProtocol
from core.scanner import PatternScanner
from core.generator import SDKPackage, SDKClass, SDKField
from engines.base import BaseDumper

from .structs import IL2CPPConfig


class IL2CPPDumper(BaseDumper):
    """
    SDK dumper for Unity games compiled with IL2CPP.

    Strategy:
        1. Locate GameAssembly.dll in the target process
        2. Find and read global-metadata.dat (from disk or memory)
        3. Parse metadata tables: TypeDefinitions, FieldDefinitions, strings
        4. For field offsets, read them from memory via GameAssembly's
           Il2CppClass/FieldInfo runtime structures
    
    The metadata file contains names and structure, but actual offsets
    are only available at runtime from the Il2CppClass instances.
    """

    ENGINE_NAME = "Unity (IL2CPP)"

    def __init__(
        self,
        reader: ReaderProtocol,
        output_dir: str = "output",
        config: IL2CPPConfig | None = None,
        game_dir: str | None = None,
        stealth_config=None,
        **kwargs,
    ):
        super().__init__(reader, output_dir, stealth_config=stealth_config, **kwargs)
        self.config = config or IL2CPPConfig()
        self._game_dir = game_dir
        self._ga_base: int = 0
        self._ga_size: int = 0
        self._type_info_table: int | None = None
        self._metadata: bytes = b""
        self._metadata_version: int = 0
        self._strings: bytes = b""
        self._type_defs: list[dict] = []
        self._field_defs: list[dict] = []

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Verify GameAssembly.dll is loaded."""
        modules = self.reader.list_modules()
        for m in modules:
            if m["name"].lower() == self.config.game_assembly_dll.lower():
                self._ga_base = m["base"]
                self._ga_size = m["size"]
                self._update_progress(
                    "validating",
                    f"Found {self.config.game_assembly_dll} at 0x{self._ga_base:X}",
                )
                return True
        self._log_error(f"{self.config.game_assembly_dll} not found")
        return False

    # ------------------------------------------------------------------
    # Metadata loading
    # ------------------------------------------------------------------

    def _guess_game_dir(self) -> Optional[str]:
        """Directory of the target executable, when resolvable.

        run_dump never passes game_dir, so disk metadata search previously
        never ran at all — the only anchor we reliably have at dump time is
        the process we're attached to.
        """
        pid = getattr(self.reader, "pid", None)
        if not pid:
            return None
        try:
            import psutil
            exe = psutil.Process(pid).exe()
            return os.path.dirname(exe) if exe else None
        except Exception:
            return None

    def _find_metadata_paths(self) -> list[str]:
        """Ordered disk candidates for global-metadata.dat.

        Roots: the configured game_dir (when given) and the target's exe
        directory. Walks each depth-limited — the canonical Unity IL2CPP
        layout is <game>/<game>_Data/il2cpp_data/Metadata/global-metadata.dat.
        Canonical-looking hits sort first.
        """
        roots: list[str] = []
        if self._game_dir:
            roots.append(self._game_dir)
        exe_dir = self._guess_game_dir()
        if exe_dir:
            roots.append(exe_dir)

        found: list[str] = []
        seen: set[str] = set()
        for root in roots:
            try:
                for dirpath, dirnames, filenames in os.walk(root):
                    rel = os.path.relpath(dirpath, root)
                    depth = 0 if rel == "." else rel.count(os.sep) + 1
                    if depth >= 6:
                        dirnames[:] = []
                        continue
                    for f in filenames:
                        if f.lower() == self.config.metadata_filename.lower():
                            full = os.path.abspath(os.path.join(dirpath, f))
                            if full.lower() not in seen:
                                seen.add(full.lower())
                                found.append(full)
            except Exception:
                continue

        found.sort(key=lambda p: (
            0 if "il2cpp_data" in p.lower() else 1, p.lower()))
        return found

    def _load_metadata_from_disk(self, path: str) -> bool:
        """Read and parse global-metadata.dat from disk."""
        try:
            with open(path, "rb") as f:
                self._metadata = f.read()

            # Verify magic
            if self._metadata[:4] != self.config.metadata_magic_bytes:
                self._log_error("Invalid metadata magic")
                return False

            # Read version
            self._metadata_version = struct.unpack_from("<i", self._metadata, 4)[0]
            self._update_progress(
                "loading",
                f"Metadata version {self._metadata_version}, size {len(self._metadata)} bytes",
            )

            return True
        except Exception as e:
            self._log_error(f"Failed to read metadata: {e}")
            return False

    def _load_metadata_from_memory(self) -> bool:
        """
        Find global-metadata.dat mapped in memory by scanning for its magic.
        Falls back if disk path is unavailable.
        """
        hits = self.scanner.scan_all(
            "AF 1B B1 FA",  # metadata magic in little-endian
            return_first=True,
        )
        if not hits:
            self._log_error("Could not find metadata magic in memory")
            return False

        addr = hits[0].address
        try:
            # Read enough header to get size info, then read the full blob
            header = self.reader.read_bytes(addr, 0x200)
            version = struct.unpack_from("<i", header, 4)[0]
            self._metadata_version = version

            # Estimate total size from string table end
            str_offset = struct.unpack_from("<i", header, 0x18)[0]
            str_count = struct.unpack_from("<i", header, 0x1C)[0]
            estimated_size = str_offset + str_count + 0x100000  # generous padding

            self._metadata = self.reader.read_bytes(addr, min(estimated_size, 64 * 1024 * 1024))
            return True
        except Exception as e:
            self._log_error(f"Failed to read metadata from memory: {e}")
            return False

    # ------------------------------------------------------------------
    # Metadata parsing
    # ------------------------------------------------------------------

    def _parse_metadata(self):
        """Parse the loaded metadata blob."""
        cfg = self.config
        meta = self._metadata

        # Read string table
        str_offset = struct.unpack_from("<i", meta, cfg.header_string_offset)[0]
        str_count = struct.unpack_from("<i", meta, cfg.header_string_count)[0]
        self._strings = meta[str_offset:str_offset + str_count]

        # Read type definitions
        try:
            td_offset = struct.unpack_from("<i", meta, cfg.header_type_definitions_offset)[0]
            td_count = struct.unpack_from("<i", meta, cfg.header_type_definitions_count)[0]
            td_size = cfg.typedef_size

            num_types = td_count // td_size if td_size > 0 else 0

            for i in range(num_types):
                off = td_offset + i * td_size
                if off + td_size > len(meta):
                    break

                name_idx = struct.unpack_from("<i", meta, off + cfg.typedef_name_index)[0]
                ns_idx = struct.unpack_from("<i", meta, off + cfg.typedef_namespace_index)[0]
                field_start = struct.unpack_from("<i", meta, off + cfg.typedef_field_start)[0]

                # field_count might be uint16
                try:
                    field_count = struct.unpack_from("<H", meta, off + cfg.typedef_field_count)[0]
                except Exception:
                    field_count = 0

                self._type_defs.append({
                    "index": i,
                    "name": self._read_metadata_string(name_idx),
                    "namespace": self._read_metadata_string(ns_idx),
                    "field_start": field_start,
                    "field_count": field_count,
                })

        except Exception as e:
            self._log_error(f"Error parsing type definitions: {e}")

        # Read field definitions
        # The field pair is a fixed header index (11), not "the pair after
        # typeDefinitions" — that was the images table, which produced a
        # nonsense field count (PG3D showed 423 fields for 21329 types).
        try:
            fd_offset = struct.unpack_from("<i", meta, cfg.header_field_definitions_offset)[0]
            fd_count = struct.unpack_from("<i", meta, cfg.header_field_definitions_count)[0]
            fd_size = cfg.field_def_size

            num_fields = fd_count // fd_size if fd_size > 0 else 0

            for i in range(num_fields):
                off = fd_offset + i * fd_size
                if off + fd_size > len(meta):
                    break

                name_idx = struct.unpack_from("<i", meta, off + cfg.field_def_name_index)[0]
                type_idx = struct.unpack_from("<i", meta, off + cfg.field_def_type_index)[0]

                self._field_defs.append({
                    "index": i,
                    "name": self._read_metadata_string(name_idx),
                    "type_index": type_idx,
                })

        except Exception as e:
            self._log_error(f"Error parsing field definitions: {e}")

    def _read_metadata_string(self, index: int) -> str:
        """Read a null-terminated string from the metadata string table."""
        if index < 0 or index >= len(self._strings):
            return ""
        end = self._strings.find(b"\x00", index)
        if end == -1:
            end = min(index + 256, len(self._strings))
        return self._strings[index:end].decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Runtime offset reading
    # ------------------------------------------------------------------

    def _find_runtime_class(self, type_index: int) -> int:
        """
        Return the runtime Il2CppClass* for a type definition index.

        GameAssembly.dll contains a global array (Il2CppClass** s_TypeInfoTable)
        indexed by TypeDefinitionIndex. The table base is resolved ONCE per
        dump — the old code re-scanned GameAssembly for the pattern on every
        type, which stalled 21k-type dumps for minutes between progress
        events. A miss means the patterns don't match this build; every
        type falls back to metadata-only names instead of re-scanning.
        """
        if self._type_info_table is None:
            patterns = [
                # MOV RAX, [s_TypeInfoTable]; MOV RCX, [RAX+RCX*8]
                "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8",
                "4C 8B 05 ?? ?? ?? ?? 4D 8B 04 C0",
            ]
            table_addr = 0
            for pat in patterns:
                addr = self.scanner.find_address(self.config.game_assembly_dll, pat)
                if addr:
                    try:
                        table_addr = self.reader.read_ptr(addr) or 0
                    except Exception:
                        table_addr = 0
                    if table_addr:
                        break
            self._type_info_table = table_addr
            if table_addr:
                self._update_progress(
                    "dumping", f"Runtime type table at 0x{table_addr:X}", 30)
            else:
                self._log_error(
                    "s_TypeInfoTable pattern not found; using metadata-only "
                    "field names (offsets will need runtime resolution)")

        if not self._type_info_table:
            return 0
        try:
            class_ptr = self.reader.read_ptr(self._type_info_table + type_index * 8)
        except Exception:
            return 0
        # Readable, kernel-space-excluding sanity gate — keeps bogus table
        # entries from sending _read_runtime_fields off reading garbage.
        if not class_ptr or class_ptr > 0x7FFFFFFFFFFF:
            return 0
        try:
            self.reader.read_ptr(class_ptr)
        except Exception:
            return 0
        return class_ptr

    def _read_runtime_fields(self, class_addr: int, field_count: int) -> list[SDKField]:
        """
        Read field offsets from the runtime Il2CppClass -> FieldInfo array.
        
        Il2CppClass:
            FieldInfo* fields; // at offset ~0x80
        FieldInfo:
            const char* name;      // 0x00
            Il2CppType* type;      // 0x08
            Il2CppClass* parent;   // 0x10
            int32_t offset;        // 0x18
            uint32_t token;        // 0x1C
            // size = 0x20
        """
        fields: list[SDKField] = []

        # Il2CppClass.fields offset (varies, common: 0x80)
        for fields_offset in (0x80, 0x88, 0x78, 0x90):
            fields_ptr = self.reader.read_ptr(class_addr + fields_offset)
            if fields_ptr and fields_ptr < 0x7FFFFFFFFFFF:
                break
        else:
            return fields

        FIELD_INFO_SIZE = 0x20

        for i in range(field_count):
            fi_addr = fields_ptr + i * FIELD_INFO_SIZE
            try:
                name_ptr = self.reader.read_ptr(fi_addr + 0x00)
                name = self.reader.read_string(name_ptr) if name_ptr else f"field_{i}"
                offset = self.reader.read_int32(fi_addr + 0x18)

                # Try to get type name
                type_ptr = self.reader.read_ptr(fi_addr + 0x08)
                type_name = "void*"
                if type_ptr:
                    try:
                        # Il2CppType.type is at offset 0x0A (uint8)
                        type_enum = self.reader.read_uint8(type_ptr + 0x0A)
                        type_name = self._il2cpp_type_to_string(type_enum)
                    except Exception:
                        pass

                fields.append(SDKField(
                    name=name,
                    type_name=type_name,
                    offset=offset,
                    size=self._estimate_size(type_name),
                ))
            except Exception:
                continue

        return fields

    def _il2cpp_type_to_string(self, type_enum: int) -> str:
        """Map IL2CPP type enum to C++ type string."""
        IL2CPP_TYPES = {
            0x01: "void", 0x02: "bool", 0x03: "char16_t",
            0x04: "int8_t", 0x05: "uint8_t",
            0x06: "int16_t", 0x07: "uint16_t",
            0x08: "int32_t", 0x09: "uint32_t",
            0x0A: "int64_t", 0x0B: "uint64_t",
            0x0C: "float", 0x0D: "double",
            0x0E: "Il2CppString*", 0x11: "VALUETYPE",
            0x12: "CLASS*", 0x14: "Il2CppArray*",
            0x15: "GENERIC*", 0x18: "intptr_t", 0x19: "uintptr_t",
            0x1D: "Il2CppArray*",
        }
        return IL2CPP_TYPES.get(type_enum, f"void* /*type {type_enum:#x}*/")

    def _estimate_size(self, type_name: str) -> int:
        SIZE_MAP = {
            "bool": 1, "char16_t": 2, "int8_t": 1, "uint8_t": 1,
            "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4,
            "int64_t": 8, "uint64_t": 8, "float": 4, "double": 8,
            "intptr_t": 8, "uintptr_t": 8, "void": 0,
        }
        if type_name in SIZE_MAP:
            return SIZE_MAP[type_name]
        if "*" in type_name:
            return 8
        return 4

    # ------------------------------------------------------------------
    # Dump
    # ------------------------------------------------------------------

    def dump(self) -> list[SDKPackage]:
        """Full IL2CPP SDK dump."""
        # Step 1: Load metadata
        self._update_progress("dumping", "Loading metadata...", 0)

        # Disk candidates first (magic-validated per file) so a protected
        # build that hides metadata from memory scans still dumps; memory
        # scan is the fallback, not the primary path.
        loaded = False
        for path in self._find_metadata_paths():
            self._update_progress("dumping", f"Trying {path}")
            if self._load_metadata_from_disk(path):
                loaded = True
                break
        if not loaded:
            self._log_error("Metadata not found on disk; scanning memory...")
            loaded = self._load_metadata_from_memory()
        if not loaded:
            self._log_error("Failed to load metadata from any source")
            return []

        # Step 2: Parse metadata
        self._update_progress("dumping", "Parsing metadata tables...", 15)
        self._parse_metadata()

        self._update_progress(
            "dumping",
            f"Found {len(self._type_defs)} types, {len(self._field_defs)} fields",
            30,
        )

        # Step 3: Build packages from type definitions
        packages_map: dict[str, SDKPackage] = defaultdict(lambda: SDKPackage(name=""))
        total = len(self._type_defs)

        for idx, td in enumerate(self._type_defs):
            if idx % 200 == 0:
                pct = 30 + (idx / total) * 60 if total > 0 else 30
                self._update_progress("dumping", f"Processing type {idx}/{total}", pct)

            name = td["name"]
            namespace = td["namespace"]
            if not name:
                continue

            pkg_name = namespace if namespace else "Global"
            if packages_map[pkg_name].name == "":
                packages_map[pkg_name] = SDKPackage(name=pkg_name)

            # Build SDKClass from metadata
            fields: list[SDKField] = []
            field_start = td["field_start"]
            field_count = td["field_count"]

            # Try to get runtime offsets if we have a class pointer
            runtime_class = self._find_runtime_class(td["index"])
            if runtime_class:
                fields = self._read_runtime_fields(runtime_class, field_count)
            else:
                # Fall back to metadata-only (offsets will be 0)
                for fi in range(field_count):
                    fd_idx = field_start + fi
                    if fd_idx < len(self._field_defs):
                        fd = self._field_defs[fd_idx]
                        fields.append(SDKField(
                            name=fd["name"],
                            type_name="void*",
                            offset=0,  # unknown without runtime
                            size=0,
                        ))

            self.progress.classes_found += 1
            self.progress.fields_found += len(fields)

            packages_map[pkg_name].classes.append(SDKClass(
                name=name,
                full_name=f"{namespace}.{name}" if namespace else name,
                super_name="",
                size=0,
                fields=fields,
                package=pkg_name,
            ))

        self._update_progress(
            "dumping",
            f"Done — {self.progress.classes_found} classes, "
            f"{self.progress.fields_found} fields",
            100,
        )

        return list(packages_map.values())
