"""
BIFROST SDK — Unreal Engine 5 SDK Dumper
Orchestrates the full UE5 SDK dump pipeline:
    1. Pattern scan for GNames + GObjects
    2. Walk the global object array
    3. For each UClass/UScriptStruct, read FProperty chain
    4. Build SDK packages → generate C++ headers + JSON
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Optional

from core.memory import MemoryReader
from core.scanner import PatternScanner
from core.generator import SDKPackage, SDKClass, SDKField
from engines.base import BaseDumper

from .structs import UE5Profile, UE5_DEFAULT
from .names import GNamesResolver
from .objects import GObjectsWalker, UObjectEntry
from .properties import PropertyReader


class UnrealDumper(BaseDumper):
    """
    Full UE5 SDK offset dumper.

    Usage:
        reader = MemoryReader("MarvelRivals_Win64_Shipping.exe")
        dumper = UnrealDumper(reader, profile=UE5_DEFAULT)
        result = dumper.dump_and_generate()
    """

    ENGINE_NAME = "Unreal Engine 5"

    def __init__(
        self,
        reader,
        output_dir: str = "output",
        profile: UE5Profile | None = None,
        target_module: str | None = None,
        stealth_config=None,
        **kwargs,
    ):
        super().__init__(reader, output_dir, stealth_config=stealth_config, **kwargs)
        self.profile = profile or UE5_DEFAULT
        self._target_module = target_module  # exe name to scan in, auto-detected if None
        self._names: Optional[GNamesResolver] = None
        self._objects: Optional[GObjectsWalker] = None
        self._props: Optional[PropertyReader] = None

    # ------------------------------------------------------------------
    # Engine detection
    # ------------------------------------------------------------------

    def _detect_target_module(self) -> str:
        """
        Resolve the target module name to a real entry in the live module list.

        When the caller supplied a `target_module` hint (from the UI), we run a
        4-tier match against the actual modules in memory:

            Tier 1 — exact match on the user's string
            Tier 2 — case-insensitive exact (e.g. 'marvelrivals.exe' → 'MarvelRivals.exe')
            Tier 3 — substring match on the base name, picking the largest module
                     when multiple candidates match
            Tier 4 — blind-trust the user input (enumeration failed OR no match)

        Module enumeration is wrapped in try/except so anti-cheat-induced
        exceptions degrade gracefully to Tier 4 — preserving the prior
        "blindly trust" behavior whenever live enumeration is not safe.

        When no hint is provided, fall back to the previous heuristic: largest
        `.exe` module in the process, then first module overall.
        """
        # ---------------- Hinted path ----------------
        if self._target_module:
            try:
                modules = self.reader.list_modules() or []
            except Exception as e:
                self._log(
                    f"[VALIDATE] Module enumeration failed ({e}); "
                    f"blindly trusting target_module '{self._target_module}'."
                )
                return self._target_module

            wanted = self._target_module
            wanted_lower = wanted.lower()

            # Tier 1: exact match
            for m in modules:
                if m["name"] == wanted:
                    return m["name"]

            # Tier 2: case-insensitive exact match — return the REAL casing
            for m in modules:
                if m["name"].lower() == wanted_lower:
                    self._log(
                        f"[VALIDATE] Resolved '{wanted}' to '{m['name']}' "
                        f"(case-insensitive match)."
                    )
                    return m["name"]

            # Tier 3: substring on base name (strip .exe), largest-wins tiebreak
            wanted_base = wanted_lower.removesuffix(".exe") if hasattr(str, "removesuffix") \
                else (wanted_lower[:-4] if wanted_lower.endswith(".exe") else wanted_lower)
            substring_hits = [
                m for m in modules
                if wanted_base and wanted_base in m["name"].lower().replace(".exe", "")
            ]
            if substring_hits:
                # Pick the largest (most likely the main executable, not a helper DLL).
                # Ties are accepted — first-seen wins.
                best = max(substring_hits, key=lambda m: m.get("size", 0))
                self._log(
                    f"[VALIDATE] Resolved '{wanted}' to '{best['name']}' "
                    f"via substring match (1 of {len(substring_hits)} candidates, "
                    f"size={best.get('size', 0)})."
                )
                return best["name"]

            # Tier 4: no match — blind trust + warn
            self._log(
                f"[VALIDATE] No module matched '{wanted}' "
                f"(checked {len(modules)} modules); blindly trusting the user input."
            )
            return wanted

        # ---------------- Auto-detect path (no hint) ----------------
        modules = self.reader.list_modules()
        exe_modules = [m for m in modules if m["name"].lower().endswith(".exe")]
        if exe_modules:
            # Pick the largest exe module (usually the game)
            biggest = max(exe_modules, key=lambda m: m["size"])
            return biggest["name"]

        # Fallback: first module
        if modules:
            return modules[0]["name"]

        raise RuntimeError("No modules found in target process")

    def validate(self) -> bool:
        """
        Validate that the process is a UE5 game by trying to find
        GNames and GObjects via direct offsets or pattern scanning.

        Strategy:
            1. Try direct offsets (community-sourced, fastest)
               - First try as direct address (LEA-style, pool inline in .data)
               - Then try as pointer (MOV-style, dereference once)
            2. Pattern scan (fallback)
            3. GNames MUST be fully resolved before GObjects verification,
               because GObjects verification reads object names via GNames.
        """
        try:
            module = self._detect_target_module()
            self._log(f"[VALIDATE] Profile: {self.profile.name}")
            self._log(f"[VALIDATE] Target module: {module}")
            self._log(f"[VALIDATE] Direct offsets: GNames=0x{self.profile.gnames_direct_offset:X}, GObjects=0x{self.profile.gobjects_direct_offset:X}")

            self._names = GNamesResolver(self.reader, self.scanner, self.profile)
            self._objects = GObjectsWalker(self.reader, self.scanner, self._names, self.profile)
            self._props = PropertyReader(self.reader, self._names, self.profile)

            found_names = False
            found_objects = False

            # ---- Phase 1: Resolve GNames FIRST ----
            # (GObjects verification depends on GNames being functional)

            # Strategy 1A: Direct offsets for GNames
            if self.profile.gnames_direct_offset != 0:
                try:
                    exe_base = self.reader.module_base(module)
                    self._log(f"[VALIDATE] Module base: 0x{exe_base:X}")
                    gnames_addr = exe_base + self.profile.gnames_direct_offset
                    self._log(f"[VALIDATE] Trying GNames at 0x{gnames_addr:X} (base + 0x{self.profile.gnames_direct_offset:X})")

                    # Try 1: Address IS the pool (LEA-style, inline in .data)
                    if self._names.verify_address(gnames_addr, log_fn=self._log):
                        self._names.set_pool_address(gnames_addr)
                        found_names = True
                        self._log(f"[VALIDATE] GNames via direct offset (inline): 0x{gnames_addr:X} ✓")
                    else:
                        # Try 2: Address is a POINTER to the pool (MOV-style, dereference once)
                        try:
                            gnames_deref = self.reader.read_ptr(gnames_addr)
                            if gnames_deref and gnames_deref < 0x7FFFFFFFFFFF:
                                self._log(f"[VALIDATE] GNames deref: 0x{gnames_addr:X} → 0x{gnames_deref:X}")
                                if self._names.verify_address(gnames_deref, log_fn=self._log):
                                    self._names.set_pool_address(gnames_deref)
                                    found_names = True
                                    self._log(f"[VALIDATE] GNames via direct offset (deref): 0x{gnames_deref:X} ✓")
                                else:
                                    self._log(f"[VALIDATE] GNames deref 0x{gnames_deref:X} also failed verification")
                            else:
                                self._log(f"[VALIDATE] GNames at 0x{gnames_addr:X} points to 0x{gnames_deref:X} (invalid)")
                        except Exception as e:
                            self._log(f"[VALIDATE] GNames deref failed: {e}")
                except Exception as e:
                    self._log(f"[VALIDATE] GNames direct offset strategy failed: {e}")

            # Strategy 1B: Pattern scan for GNames
            if not found_names:
                self._update_progress("validating", f"Scanning {module} for GNames...")
                found_names = self._names.find_pool(module, log_fn=self._log)
                self._log(f"[VALIDATE] Pattern scan for GNames: {'found' if found_names else 'NOT found'}")

            # ---- COMMIT GNames before proceeding to GObjects ----
            # GObjects verification reads object names via the GNames resolver.
            # If GNames isn't committed, all names resolve to "FName_XX" and
            # verify_address() rejects every entry → false negative.
            if not found_names:
                self._log_error(f"GNames not found in {module} (tried direct offsets + {len(self.profile.gnames_patterns_alt)+1} patterns)")
                # Don't give up yet — GObjects might still work with pattern scanning
                # if there's a UE4-style fallback. But log the warning.

            # ---- Phase 2: Resolve GObjects ----

            # Strategy 2A: Direct offsets for GObjects
            if self.profile.gobjects_direct_offset != 0:
                try:
                    exe_base = self.reader.module_base(module)
                    gobjects_addr = exe_base + self.profile.gobjects_direct_offset
                    self._log(f"[VALIDATE] Trying GObjects at 0x{gobjects_addr:X} (base + 0x{self.profile.gobjects_direct_offset:X})")

                    # Try 1: Address IS the array (inline)
                    if self._objects.verify_address(gobjects_addr, log_fn=self._log):
                        self._objects.set_array_address(gobjects_addr)
                        found_objects = True
                        self._log(f"[VALIDATE] GObjects via direct offset (inline): 0x{gobjects_addr:X} ✓")
                    else:
                        # Try 2: Address is a POINTER to the array (dereference once)
                        try:
                            gobjects_deref = self.reader.read_ptr(gobjects_addr)
                            if gobjects_deref and gobjects_deref < 0x7FFFFFFFFFFF:
                                self._log(f"[VALIDATE] GObjects deref: 0x{gobjects_addr:X} → 0x{gobjects_deref:X}")
                                if self._objects.verify_address(gobjects_deref, log_fn=self._log):
                                    self._objects.set_array_address(gobjects_deref)
                                    found_objects = True
                                    self._log(f"[VALIDATE] GObjects via direct offset (deref): 0x{gobjects_deref:X} ✓")
                                else:
                                    self._log(f"[VALIDATE] GObjects deref 0x{gobjects_deref:X} also failed verification")
                            else:
                                self._log(f"[VALIDATE] GObjects at 0x{gobjects_addr:X} points to 0x{gobjects_deref:X} (invalid)")
                        except Exception as e:
                            self._log(f"[VALIDATE] GObjects deref failed: {e}")
                except Exception as e:
                    self._log(f"[VALIDATE] GObjects direct offset strategy failed: {e}")

            # Strategy 2B: Pattern scan for GObjects
            if not found_objects:
                self._update_progress("validating", f"Scanning {module} for GObjects...")
                found_objects = self._objects.find_gobjects(module, log_fn=self._log)
                self._log(f"[VALIDATE] Pattern scan for GObjects: {'found' if found_objects else 'NOT found'}")

            if found_names and found_objects:
                self._update_progress(
                    "validating",
                    f"GNames: 0x{self._names.pool_address:X}, "
                    f"GObjects: 0x{self._objects.array_address:X}",
                )
                return True

            # Log what we couldn't find
            if not found_names:
                self._log_error(f"GNames not found in {module} (tried direct offsets + {len(self.profile.gnames_patterns_alt)+1} patterns)")
            if not found_objects:
                self._log_error(f"GObjects not found in {module} (tried direct offsets + {len(self.profile.gobjects_patterns_alt)+1} patterns)")

            # Stale-offset hint: if BOTH validations failed AND the profile has
            # non-zero direct offsets, the offsets are the most likely culprit
            # — they're game-version-specific and rot on every patch. Tell the
            # user exactly how to fall back to pattern scanning.
            if (not found_names and not found_objects
                    and (self.profile.gnames_direct_offset != 0
                         or self.profile.gobjects_direct_offset != 0)):
                self._log_error(
                    f"Hint: direct offsets in profile '{self.profile.name}' may be "
                    f"stale (game patches invalidate them). To force pattern-scan "
                    f"fallback, set gnames_direct_offset=0 and gobjects_direct_offset=0 "
                    f"on the profile, or regenerate from a current community dump."
                )
            return False

        except Exception as e:
            self._log_error(f"Validation error: {e}")
            import traceback
            self._log_error(traceback.format_exc())
            return False

    # ------------------------------------------------------------------
    # Dump
    # ------------------------------------------------------------------

    def dump(self) -> list[SDKPackage]:
        """
        Walk the entire GObjects array, extract all UClass and UScriptStruct
        definitions, read their properties, and organize into packages.
        """
        if not self._names or not self._objects or not self._props:
            raise RuntimeError("Call validate() first")

        # Step 1: Walk GObjects to find all type definitions
        self._update_progress("dumping", "Walking GObjects array...", 0)
        obj_count = self._objects.get_object_count()
        self._update_progress("dumping", f"Found {obj_count} objects, filtering types...")

        def on_walk_progress(current, total):
            pct = (current / total) * 50  # first 50% is walking
            self._update_progress("dumping", f"Walking objects: {current}/{total}", pct)

        type_entries = self._objects.walk_all(
            progress_callback=on_walk_progress,
            filter_classes=True,
        )

        self.progress.classes_found = len(type_entries)
        self._update_progress(
            "dumping",
            f"Found {len(type_entries)} type definitions",
            50,
        )

        # Step 2: For each Class/ScriptStruct, read properties
        packages_map: dict[str, SDKPackage] = defaultdict(lambda: SDKPackage(name=""))
        processed = 0
        total = len(type_entries)

        for entry in type_entries:
            processed += 1
            if processed % 100 == 0:
                pct = 50 + (processed / total) * 45
                self._update_progress(
                    "dumping",
                    f"Reading properties: {processed}/{total} — {entry.name}",
                    pct,
                )

            pkg_name = entry.package_name or "Unknown"
            if packages_map[pkg_name].name == "":
                packages_map[pkg_name] = SDKPackage(name=pkg_name)

            if entry.class_name in ("Class", "Struct", "ScriptStruct"):
                sdk_class = self._dump_class(entry)
                if sdk_class:
                    packages_map[pkg_name].classes.append(sdk_class)
            elif entry.class_name == "Enum":
                enum_data = self._dump_enum(entry)
                if enum_data:
                    packages_map[pkg_name].enums.append(enum_data)

        self._update_progress("dumping", "Organizing packages...", 95)
        packages = list(packages_map.values())
        packages.sort(key=lambda p: p.name)

        total_fields = sum(len(c.fields) for p in packages for c in p.classes)
        self.progress.fields_found = total_fields

        self._update_progress(
            "dumping",
            f"Done — {len(packages)} packages, "
            f"{self.progress.classes_found} classes, "
            f"{total_fields} fields",
            100,
        )

        return packages

    def _dump_class(self, entry: UObjectEntry) -> Optional[SDKClass]:
        """Read a single UClass/UScriptStruct and its properties."""
        try:
            # Read properties size
            struct_size = self._props.read_struct_size(entry.address)

            # Read super class name
            super_addr = self._props.read_super_struct(entry.address)
            super_name = ""
            if super_addr:
                super_name = self._names.resolve_fname_at(
                    super_addr + self.profile.uobject.name_private
                )

            # Read all properties
            fields = self._props.read_properties(entry.address)

            # Determine class prefix
            prefix = "U" if entry.class_name == "Class" else "F"
            class_name = f"{prefix}{entry.name}"
            super_full = f"{prefix}{super_name}" if super_name else ""

            return SDKClass(
                name=class_name,
                full_name=entry.full_name,
                super_name=super_full,
                size=struct_size,
                fields=fields,
                package=entry.package_name,
            )
        except Exception as e:
            self._log_error(f"Error dumping {entry.name}: {e}")
            return None

    def _dump_enum(self, entry: UObjectEntry) -> Optional[dict]:
        """Read a UEnum and its members."""
        try:
            cfg = self.profile.uenum
            
            # UEnum stores its values as TArray<TPair<FName, int64>>
            array_addr = self.reader.read_ptr(entry.address + cfg.names_array)
            array_count = self.reader.read_int32(entry.address + cfg.names_array + 8)
            
            members = []
            if array_addr and 0 < array_count < 2048:
                for i in range(array_count):
                    # TPair<FName, int64> is 16 bytes
                    fname_addr = array_addr + (i * 16)
                    name = self._names.resolve_fname_at(fname_addr)
                    value = self.reader.read_int64(fname_addr + 8)
                    if name:
                        # Sometimes UE appends "::" to enum names, e.g. "EWeaponType::Pistol"
                        clean_name = name.split("::")[-1]
                        members.append({"name": clean_name, "value": value})

            return {
                "name": f"E{entry.name}",
                "full_name": entry.full_name,
                "members": members,
            }
        except Exception as e:
            self._log_error(f"Error dumping enum {entry.name}: {e}")
            return None

    # ------------------------------------------------------------------
    # Manual offset helpers
    # ------------------------------------------------------------------

    def find_class_by_name(self, class_name: str) -> Optional[SDKClass]:
        """
        Find a specific class by name and dump its properties.
        Useful for targeted offset extraction (e.g., "PlayerController").
        """
        if not self._objects:
            raise RuntimeError("Call validate() first")

        count = self._objects.get_object_count()
        for i in range(count):
            entry = self._objects.read_object_at_index(i)
            if entry is None:
                continue
            if entry.name == class_name:
                entry.class_name = self._objects.resolve_class_name(entry.class_address)
                if entry.class_name in ("Class", "ScriptStruct"):
                    entry.full_name = self._objects.resolve_full_name(entry)
                    entry.package_name = entry.full_name.split(".")[0] if "." in entry.full_name else ""
                    return self._dump_class(entry)
        return None

    def get_gnames_address(self) -> int:
        """Return the resolved GNames address (0 if not found)."""
        return self._names.pool_address if self._names else 0

    def get_gobjects_address(self) -> int:
        """Return the resolved GObjects address (0 if not found)."""
        return self._objects.array_address if self._objects else 0
