"""
BIFROST SDK — UE5 GObjects / FUObjectArray Walker
Iterates the global object array and reads UObject metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.memory import MemoryReader
from core.scanner import PatternScanner
from .structs import UE5Profile, PatternDef
from .names import GNamesResolver


@dataclass
class UObjectEntry:
    """Parsed UObject from the global array."""
    address: int
    internal_index: int
    class_address: int
    outer_address: int
    name: str
    full_name: str = ""
    class_name: str = ""
    package_name: str = ""


class GObjectsWalker:
    """
    Walks UE5's FUObjectArray (chunked) and reads UObject metadata.
    
    The global array (GUObjectArray) is a FChunkedFixedUObjectArray:
        - Array of chunk pointers (each chunk holds N FUObjectItems)
        - Each FUObjectItem contains a UObject* + flags
    """

    def __init__(
        self,
        reader: MemoryReader,
        scanner: PatternScanner,
        names: GNamesResolver,
        profile: UE5Profile,
    ):
        self.reader = reader
        self.scanner = scanner
        self.names = names
        self.profile = profile
        self._array_address: int = 0

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def verify_address(self, addr: int, log_fn=None) -> bool:
        """
        Verify if the given GUObjectArray address is valid.
        Under standard UE5 configurations, the element count must be sensible (100 < N < 5,000,000)
        and resolving the first few object names must succeed or fail cleanly (no memory faults).
        We attempt to read the first 100 entries, and check if we can resolve at least one valid name.

        If *log_fn* is provided, it is called with diagnostic strings.
        """
        if addr == 0:
            return False

        orig_addr = self._array_address
        self._array_address = addr
        try:
            count = self.get_object_count()
            if count <= 100 or count > 5000000:
                if log_fn:
                    log_fn(f"  GObjects 0x{addr:X}: object count {count} out of range (need 100 < N < 5M)")
                return False

            if log_fn:
                log_fn(f"  GObjects 0x{addr:X}: NumElements = {count}")

            # Check if we can read the objects chunk structure and get at least one valid name
            found_valid_name = False
            sample_names = []
            # Check a small range of indices. Not all entries are filled, so we check first 100.
            for i in range(min(count, 100)):
                obj = self.read_object_at_index(i)
                if obj is not None and obj.name and not obj.name.startswith("FName_"):
                    # We found a valid object name that isn't a fallback FName_ string
                    found_valid_name = True
                    if log_fn:
                        log_fn(f"  GObjects 0x{addr:X}: index {i} → '{obj.name}' ✓")
                    break
                elif obj is not None and len(sample_names) < 3:
                    sample_names.append(f"[{i}]={obj.name}")

            if not found_valid_name and log_fn:
                detail = ", ".join(sample_names) if sample_names else "all None"
                log_fn(f"  GObjects 0x{addr:X}: no valid names in first 100 entries ({detail})")

            return found_valid_name
        except Exception as e:
            if log_fn:
                log_fn(f"  GObjects 0x{addr:X}: verification exception: {e}")
            return False
        finally:
            self._array_address = orig_addr

    @staticmethod
    def _unpack_pattern(pat) -> tuple[str, int, int]:
        """Extract (pattern_str, rip_offset, insn_len) from a PatternDef or raw string."""
        if isinstance(pat, PatternDef):
            return pat.pattern, pat.rip_offset, pat.insn_len
        return pat, 3, 7

    def find_gobjects(self, module_name: str, log_fn=None) -> bool:
        """Pattern-scan for GUObjectArray. Returns True if found and verified."""

        def _try_pattern(scanner_fn, pat_or_def, label=""):
            pat_str, rip_off, insn_len = self._unpack_pattern(pat_or_def)
            addr = scanner_fn(pat_str, rip_offset=rip_off, insn_len=insn_len)
            if addr:
                if log_fn:
                    log_fn(f"[GOBJECTS] Pattern hit ({label}): 0x{addr:X}")
                if self.verify_address(addr, log_fn=log_fn):
                    self._array_address = addr
                    return True
                # Try dereferencing (pattern might resolve to pointer-to-array)
                try:
                    deref = self.reader.read_ptr(addr)
                    if deref and deref < 0x7FFFFFFFFFFF:
                        if log_fn:
                            log_fn(f"[GOBJECTS] Deref 0x{addr:X} → 0x{deref:X}")
                        if self.verify_address(deref, log_fn=log_fn):
                            self._array_address = deref
                            return True
                except Exception:
                    pass
            return False

        # Try primary pattern against module
        module_scan = lambda p, **kw: self.scanner.find_address(module_name, p, **kw)
        if _try_pattern(module_scan, self.profile.gobjects_pattern, "primary/module"):
            return True

        for i, pat in enumerate(self.profile.gobjects_patterns_alt):
            if _try_pattern(module_scan, pat, f"alt[{i}]/module"):
                return True

        # FALLBACK: Scan all accessible memory
        global_scan = lambda p, **kw: self.scanner.find_address_global(p, **kw)
        if _try_pattern(global_scan, self.profile.gobjects_pattern, "primary/global"):
            return True

        for i, pat in enumerate(self.profile.gobjects_patterns_alt):
            if _try_pattern(global_scan, pat, f"alt[{i}]/global"):
                return True

        return False

    def set_array_address(self, addr: int):
        self._array_address = addr

    @property
    def array_address(self) -> int:
        return self._array_address

    # ------------------------------------------------------------------
    # Object reading
    # ------------------------------------------------------------------

    def get_object_count(self) -> int:
        """Read NumElements from the object array."""
        if self._array_address == 0:
            return 0
        cfg = self.profile.gobjects
        return self.reader.read_int32(self._array_address + cfg.num_elements_offset)

    def read_object_at_index(self, index: int) -> Optional[UObjectEntry]:
        """Read a single UObject by its index in the global array."""
        if self._array_address == 0:
            return None

        cfg = self.profile.gobjects
        obj_cfg = self.profile.uobject

        # Calculate chunk and offset
        chunk_index = index // cfg.elements_per_chunk
        within_chunk = index % cfg.elements_per_chunk

        # Read chunk pointer
        chunks_base = self.reader.read_ptr(self._array_address + cfg.objects_offset)
        if chunks_base == 0:
            return None

        chunk_ptr = self.reader.read_ptr(chunks_base + chunk_index * 8)
        if chunk_ptr == 0:
            return None

        # Read FUObjectItem
        item_addr = chunk_ptr + within_chunk * cfg.item_size
        obj_ptr = self.reader.read_ptr(item_addr + cfg.item_object_offset)
        if obj_ptr == 0:
            return None

        try:
            # Read core UObject fields
            internal_index = self.reader.read_int32(obj_ptr + obj_cfg.internal_index)
            class_ptr = self.reader.read_ptr(obj_ptr + obj_cfg.class_private)
            outer_ptr = self.reader.read_ptr(obj_ptr + obj_cfg.outer_private)

            # Resolve name
            name = self.names.resolve_fname_at(obj_ptr + obj_cfg.name_private)

            return UObjectEntry(
                address=obj_ptr,
                internal_index=internal_index,
                class_address=class_ptr,
                outer_address=outer_ptr,
                name=name,
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Full name resolution
    # ------------------------------------------------------------------

    def resolve_full_name(self, entry: UObjectEntry) -> str:
        """Build the full path name (e.g., 'Package.ClassName')."""
        parts = [entry.name]
        outer = entry.outer_address
        obj_cfg = self.profile.uobject

        depth = 0
        while outer != 0 and depth < 32:
            try:
                outer_name = self.names.resolve_fname_at(outer + obj_cfg.name_private)
                parts.append(outer_name)
                outer = self.reader.read_ptr(outer + obj_cfg.outer_private)
                depth += 1
            except Exception:
                break

        parts.reverse()
        return ".".join(parts)

    def resolve_class_name(self, class_address: int) -> str:
        """Resolve the name of a UClass at the given address."""
        if class_address == 0:
            return "None"
        obj_cfg = self.profile.uobject
        try:
            return self.names.resolve_fname_at(class_address + obj_cfg.name_private)
        except Exception:
            return "Unknown"

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def walk_all(
        self,
        *,
        progress_callback=None,
        filter_classes: bool = False,
    ) -> list[UObjectEntry]:
        """
        Walk the entire GObjects array and return all valid entries.
        
        If filter_classes is True, only return objects whose class name
        is "Class", "ScriptStruct", or "Enum" (i.e., type definitions).
        """
        count = self.get_object_count()
        if count <= 0:
            return []

        results: list[UObjectEntry] = []
        type_names = {"Class", "ScriptStruct", "Enum", "Struct"}

        for i in range(count):
            if progress_callback and i % 10000 == 0:
                progress_callback(i, count)

            entry = self.read_object_at_index(i)
            if entry is None:
                continue

            # Resolve class name
            entry.class_name = self.resolve_class_name(entry.class_address)

            if filter_classes and entry.class_name not in type_names:
                continue

            # Resolve full path
            entry.full_name = self.resolve_full_name(entry)

            # Extract package from full name
            if "." in entry.full_name:
                entry.package_name = entry.full_name.split(".")[0]

            results.append(entry)

        return results

    def find_object_by_name(self, full_name: str) -> Optional[UObjectEntry]:
        """Search for an object by its full name (slow — walks entire array)."""
        count = self.get_object_count()
        for i in range(count):
            entry = self.read_object_at_index(i)
            if entry is None:
                continue
            entry.full_name = self.resolve_full_name(entry)
            if entry.full_name == full_name:
                entry.class_name = self.resolve_class_name(entry.class_address)
                return entry
        return None
