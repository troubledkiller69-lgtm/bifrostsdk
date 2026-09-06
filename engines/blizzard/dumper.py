"""
BIFROST SDK — Blizzard Engine Dumper (Overwatch 2)
Dumps entity/component offsets from OW2's custom ECS architecture.

Strategy:
  1. Pattern scan for EntityManager, ComponentRegistry, HeroDatabase globals
  2. Walk the ComponentRegistry to enumerate all component types
  3. For each component type, read its field layout via RTTI
  4. Walk the HeroDatabase for hero-specific offsets
  5. Generate SDK headers with all offsets

Unlike UE5/Unity, Blizzard's engine has no public reflection system.
We rely on RTTI scanning + vtable analysis + known structure offsets.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

from ..base import BaseDumper, DumpProgress
from core.generator import SDKPackage, SDKClass, SDKField
from .structs import (
    PATTERNS,
    BlizzardEntity,
    BlizzardComponent,
    HeroDefinition,
    PlayerState,
    ViewMatrix,
    HERO_HASHES,
)


@dataclass
class BlizzardClass:
    """A discovered class/component type."""
    name: str
    type_hash: int
    vtable_addr: int
    size: int
    fields: dict[str, dict] = field(default_factory=dict)  # name -> {offset, size, type}
    parent: str = ""


class BlizzardDumper(BaseDumper):
    """
    Dump Overwatch 2's ECS component offsets via pattern scanning + RTTI walk.
    """

    ENGINE_NAME = "Blizzard (Overwatch 2)"
    GAME_MODULE = "Overwatch.exe"

    def __init__(self, reader, output_dir: str, stealth_config=None, **kwargs):
        super().__init__(reader, output_dir, stealth_config=stealth_config, **kwargs)
        self._entity_manager: int = 0
        self._component_registry: int = 0
        self._hero_database: int = 0
        self._view_matrix_ptr: int = 0
        self._classes: list[BlizzardClass] = []
        self._rtti_cache: dict[int, str] = {}

    def validate(self) -> bool:
        """Verify the game module is loaded."""
        try:
            modules = self.reader.list_modules()
            for m in modules:
                if m["name"].lower() == self.GAME_MODULE.lower():
                    return True
        except Exception:
            pass
        return False

    def dump(self) -> list[SDKPackage]:
        """Perform the full SDK dump."""
        self._classes = []
        self._rtti_cache = {}

        # Phase 1: Find global pointers
        self._update_progress("dumping", "Locating globals...", 10)
        self._resolve_globals()

        # Phase 2: Walk RTTI for class enumeration
        self._update_progress("dumping", "Walking type descriptors...", 30)
        self._walk_rtti()

        # Phase 3: Dump component registry
        self._update_progress("dumping", "Enumerating ECS components...", 50)
        self._dump_component_registry()

        # Phase 4: Hero database
        self._update_progress("dumping", "Reading hero definitions...", 70)
        self._dump_hero_database()

        # Phase 5: Known critical offsets (view matrix, player state, etc.)
        self._update_progress("dumping", "Resolving gameplay offsets...", 85)
        self._dump_known_structures()

        # Phase 6: Organize into SDKPackage format
        self._update_progress("dumping", "Structuring packages...", 95)
        sdk_classes = []
        
        # Add discovered classes
        for cls in self._classes:
            fields = []
            for f_name, f_data in cls.fields.items():
                fields.append(SDKField(
                    name=f_name,
                    type_name=f_data.get("type", "void*"),
                    offset=f_data.get("offset", 0),
                    size=f_data.get("size", 4),
                ))
            sdk_classes.append(SDKClass(
                name=cls.name,
                full_name=f"Blizzard.{cls.name}",
                super_name=cls.parent,
                size=cls.size,
                fields=fields,
                package="Blizzard",
            ))

        # Add global pointers as a Globals class
        globals_fields = []
        if self._entity_manager:
            globals_fields.append(SDKField(name="EntityManager", type_name="void*", offset=self._entity_manager, size=8))
        if self._component_registry:
            globals_fields.append(SDKField(name="ComponentRegistry", type_name="void*", offset=self._component_registry, size=8))
        if self._hero_database:
            globals_fields.append(SDKField(name="HeroDatabase", type_name="void*", offset=self._hero_database, size=8))
        if self._view_matrix_ptr:
            globals_fields.append(SDKField(name="ViewMatrix", type_name="void*", offset=self._view_matrix_ptr, size=8))

        if globals_fields:
            sdk_classes.append(SDKClass(
                name="Globals",
                full_name="Blizzard.Globals",
                size=0,
                fields=globals_fields,
                package="Blizzard",
            ))

        self.progress.classes_found = len(sdk_classes)
        self.progress.fields_found = sum(len(c.fields) for c in sdk_classes)

        return [SDKPackage(name="Blizzard", classes=sdk_classes)]

    # ------------------------------------------------------------------
    # Phase 1: Global pointer resolution
    # ------------------------------------------------------------------

    def _resolve_globals(self):
        """Pattern scan for global singleton pointers.

        Each entry maps the target attribute to (pattern_key, rip_offset_pos,
        insn_len). The disp32 position varies per pattern shape:
          - 48 8D 0D / 48 8B 05 forms: disp at byte 3, 7-byte instruction
          - patterns WITHOUT a direct rip-relative global (prologue+call
            shapes) are excluded here — resolving them yields garbage and
            silently corrupts the dump.
        """
        from core.scanner import PatternScanner
        scanner = PatternScanner(self.reader)

        resolvers = [
            ("_entity_manager", "entity_manager", 3, 7),
            ("_component_registry", "component_registry", 3, 7),
            ("_hero_database", "hero_database", 3, 7),
            ("_view_matrix_ptr", "view_matrix", 3, 7),
        ]

        for attr, pattern_key, rip_pos, insn_len in resolvers:
            hits = scanner.scan_module(self.GAME_MODULE, PATTERNS[pattern_key], return_first=True)
            if hits:
                resolved = self.reader.resolve_rip_relative(hits[0].address, rip_pos, insn_len)
                setattr(self, attr, resolved)
                self._log(f"{pattern_key}: 0x{resolved:X}")
            else:
                self._log_warn(f"Pattern miss for {pattern_key} — needs a per-patch refresh")

    # ------------------------------------------------------------------
    # Phase 2: RTTI walk
    # ------------------------------------------------------------------

    def _walk_rtti(self):
        """
        Walk MSVC RTTI structures to enumerate classes.
        Scans .rdata section for type_info vtables and builds a class map.
        """
        from core.scanner import PatternScanner
        scanner = PatternScanner(self.reader)

        # Find .rdata section bounds
        try:
            base = self.reader.module_base(self.GAME_MODULE)
            size = self.reader.module_size(self.GAME_MODULE)
        except RuntimeError:
            self._log_error("Could not locate game module for RTTI scan")
            return

        # Scan for RTTI Complete Object Locator signatures
        # Pattern: the COL has a fixed signature value of 0x00000001 at offset 0
        # followed by offsets into the type descriptor
        rtti_pattern = "01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"
        hits = scanner.scan_module(self.GAME_MODULE, rtti_pattern, return_first=False, max_results=2000)

        for hit in hits:
            try:
                # Read the type descriptor offset
                td_rva = self.reader.read_uint32(hit.address + 12)
                if td_rva == 0:
                    continue

                td_addr = base + td_rva

                # Type descriptor starts with vtable ptr, then spare, then mangled name
                # Skip vtable (8) + spare (8) = name at +16
                name = self.reader.read_string(td_addr + 16, 128)
                if not name or not name.startswith(".?AV"):
                    continue

                # Demangle: .?AVClassName@@  ->  ClassName
                demangled = name[4:].rstrip("@")
                if demangled:
                    self._rtti_cache[td_addr] = demangled
                    self.progress.classes_found += 1

            except Exception:
                continue

    # ------------------------------------------------------------------
    # Phase 3: Component registry dump
    # ------------------------------------------------------------------

    def _dump_component_registry(self):
        """
        Walk the component registry to enumerate all ECS component types.
        The registry is typically a hash map: type_hash -> ComponentMeta*
        """
        if not self._component_registry:
            self._log_error("ComponentRegistry not found — skipping")
            return

        try:
            # Registry structure: { count: u32, capacity: u32, buckets_ptr: u64 }
            count = self.reader.read_uint32(self._component_registry)
            capacity = self.reader.read_uint32(self._component_registry + 4)
            buckets_ptr = self.reader.read_uint64(self._component_registry + 8)

            if count == 0 or count > 10000 or buckets_ptr == 0:
                self._log_error(f"Invalid registry state: count={count}")
                return

            self._log(f"Component types registered: {count}")

            # Walk buckets (each is a linked list entry or direct slot)
            for i in range(min(capacity, 4096)):
                entry_ptr = self.reader.read_uint64(buckets_ptr + i * 8)
                if entry_ptr == 0:
                    continue

                # Each entry: { type_hash: u64, vtable: u64, size: u32, name_ptr: u64 }
                type_hash = self.reader.read_uint64(entry_ptr)
                vtable = self.reader.read_uint64(entry_ptr + 0x08)
                comp_size = self.reader.read_uint32(entry_ptr + 0x10)
                name_ptr = self.reader.read_uint64(entry_ptr + 0x18)

                if vtable == 0 or comp_size == 0:
                    continue

                name = ""
                if name_ptr:
                    try:
                        name = self.reader.read_string(name_ptr, 64)
                    except Exception:
                        name = f"Component_0x{type_hash:X}"

                if not name:
                    name = f"Component_0x{type_hash:X}"

                cls = BlizzardClass(
                    name=name,
                    type_hash=type_hash,
                    vtable_addr=vtable,
                    size=comp_size,
                )

                # Try to read field info from vtable RTTI
                self._resolve_fields_from_vtable(cls)
                self._classes.append(cls)

        except Exception as e:
            self._log_error(f"Component registry walk failed: {e}")

    def _resolve_fields_from_vtable(self, cls: BlizzardClass):
        """Attempt to extract field layout from RTTI metadata near the vtable."""
        try:
            # MSVC vtable layout: vtable[-1] = pointer to RTTI Complete Object Locator
            col_ptr = self.reader.read_uint64(cls.vtable_addr - 8)
            if col_ptr == 0:
                return

            # Check if this COL is in our RTTI cache
            td_rva = self.reader.read_uint32(col_ptr + 12)
            base = self.reader.module_base(self.GAME_MODULE)
            td_addr = base + td_rva

            if td_addr in self._rtti_cache:
                cls.name = self._rtti_cache[td_addr]

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Phase 4: Hero database
    # ------------------------------------------------------------------

    def _dump_hero_database(self):
        """Read the hero definition table."""
        if not self._hero_database:
            self._log_error("HeroDatabase not found — skipping")
            return

        try:
            # Database structure: { count: u32, array_ptr: u64 }
            db_ptr = self.reader.read_uint64(self._hero_database)
            if db_ptr == 0:
                return

            count = self.reader.read_uint32(db_ptr)
            array_ptr = self.reader.read_uint64(db_ptr + 8)

            if count == 0 or count > 100 or array_ptr == 0:
                return

            self._log(f"Heroes in database: {count}")

            hero_class = BlizzardClass(
                name="HeroDefinition",
                type_hash=0,
                vtable_addr=0,
                size=0x60,
                fields={},
            )

            for field_name, offset in HeroDefinition.OFFSETS.items():
                hero_class.fields[field_name] = {
                    "offset": offset,
                    "size": 8 if "ptr" in field_name else 4,
                    "type": "ptr" if "ptr" in field_name else "float" if field_name.startswith("max_") else "u32",
                }
                self.progress.fields_found += 1

            self._classes.append(hero_class)

        except Exception as e:
            self._log_error(f"Hero database read failed: {e}")

    # ------------------------------------------------------------------
    # Phase 5: Known structures
    # ------------------------------------------------------------------

    def _dump_known_structures(self):
        """Add known hardcoded offset structures."""
        # PlayerState
        ps_class = BlizzardClass(
            name="PlayerState",
            type_hash=0,
            vtable_addr=0,
            size=0x70,
        )
        for name, offset in PlayerState.OFFSETS.items():
            size = 12 if name in ("position", "rotation", "velocity") else 4
            type_name = "Vec3" if size == 12 else "float" if "charge" in name or "health" in name else "u32"
            ps_class.fields[name] = {"offset": offset, "size": size, "type": type_name}
            self.progress.fields_found += 1
        self._classes.append(ps_class)

        # ViewMatrix
        vm_class = BlizzardClass(
            name="ViewMatrix",
            type_hash=0,
            vtable_addr=0,
            size=0x50,
        )
        for name, offset in ViewMatrix.OFFSETS.items():
            size = 64 if name == "matrix" else 4
            vm_class.fields[name] = {"offset": offset, "size": size, "type": "float[16]" if size == 64 else "float"}
            self.progress.fields_found += 1
        self._classes.append(vm_class)

        # BlizzardEntity
        ent_class = BlizzardClass(
            name="Entity",
            type_hash=0,
            vtable_addr=0,
            size=0x60,
        )
        for name, offset in BlizzardEntity.OFFSETS.items():
            ent_class.fields[name] = {"offset": offset, "size": 8, "type": "u64"}
            self.progress.fields_found += 1
        self._classes.append(ent_class)
