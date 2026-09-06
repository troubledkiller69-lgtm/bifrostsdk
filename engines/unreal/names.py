"""
BIFROST SDK — UE5 GNames / FNamePool Resolver
Reads the chunked FNamePool and resolves FName indices to strings.
"""

from __future__ import annotations

from typing import Optional

from core.memory import MemoryReader
from core.scanner import PatternScanner
from .structs import UE5Profile, PatternDef


class GNamesResolver:
    """
    Resolves FName ComparisonIndex values to their string representation
    by reading the FNamePool from remote process memory.
    
    UE5 uses a chunked FNamePool:
        - Pool is divided into blocks (up to 8192)
        - Each block is a contiguous allocation
        - Entries within a block are variable-length, aligned to 2 bytes
        - FName.ComparisonIndex encodes (BlockIndex, OffsetInBlock)
    """

    def __init__(self, reader: MemoryReader, scanner: PatternScanner, profile: UE5Profile):
        self.reader = reader
        self.scanner = scanner
        self.profile = profile
        self._pool_address: int = 0
        self._cache: dict[int, str] = {}

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def verify_address(self, addr: int, log_fn=None) -> bool:
        """
        Verify if the given FNamePool address is valid.

        Under standard UE5 configurations, one of the first ~20 ComparisonIndex
        values resolves to 'None' (case-insensitive).  We try a range because
        block 0 may begin with pool metadata or padding, and different UE5
        versions place the 'None' entry at different indices.

        If *log_fn* is provided, it is called with diagnostic strings.
        """
        if addr == 0:
            return False

        # Temporarily set the pool address to test resolution
        orig_addr = self._pool_address
        self._pool_address = addr
        try:
            # Check that the first block pointer is plausible (non-zero, in user space)
            cfg = self.profile.fname_pool
            first_block_ptr_addr = addr + cfg.blocks_offset
            try:
                first_block_ptr = self.reader.read_ptr(first_block_ptr_addr)
            except Exception as e:
                if log_fn:
                    log_fn(f"  GNames 0x{addr:X}: can't read block[0] ptr at 0x{first_block_ptr_addr:X}: {e}")
                return False

            if first_block_ptr == 0:
                if log_fn:
                    log_fn(f"  GNames 0x{addr:X}: block[0] ptr is NULL")
                return False

            if first_block_ptr > 0x7FFFFFFFFFFF:
                if log_fn:
                    log_fn(f"  GNames 0x{addr:X}: block[0] ptr 0x{first_block_ptr:X} out of user-space range")
                return False

            # Try resolving the first 20 indices — look for 'None'
            for idx in range(20):
                try:
                    name = self.resolve(idx)
                    if name.lower() == "none":
                        if log_fn:
                            log_fn(f"  GNames 0x{addr:X}: index {idx} → '{name}' ✓")
                        return True
                except Exception:
                    continue

            # None of the first 20 indices resolved to "None"
            if log_fn:
                # Show what index 0 actually resolved to for diagnostics
                try:
                    sample = self.resolve(0)
                    log_fn(f"  GNames 0x{addr:X}: no 'None' in indices 0-19 (index 0 → '{sample}')")
                except Exception:
                    log_fn(f"  GNames 0x{addr:X}: no 'None' in indices 0-19 (index 0 unreadable)")
            return False

        except Exception as e:
            if log_fn:
                log_fn(f"  GNames 0x{addr:X}: verification exception: {e}")
            return False
        finally:
            self._pool_address = orig_addr

    @staticmethod
    def _unpack_pattern(pat) -> tuple[str, int, int]:
        """Extract (pattern_str, rip_offset, insn_len) from a PatternDef or raw string."""
        if isinstance(pat, PatternDef):
            return pat.pattern, pat.rip_offset, pat.insn_len
        # Raw string — assume default LEA/MOV encoding
        return pat, 3, 7

    def find_pool(self, module_name: str, log_fn=None) -> bool:
        """
        Pattern-scan for the FNamePool global and store its address.
        Returns True if found and verified.
        """
        def _try_pattern(scanner_fn, pat_or_def, label=""):
            pat_str, rip_off, insn_len = self._unpack_pattern(pat_or_def)
            addr = scanner_fn(pat_str, rip_offset=rip_off, insn_len=insn_len)
            if addr:
                if log_fn:
                    log_fn(f"[GNAMES] Pattern hit ({label}): 0x{addr:X}")
                if self.verify_address(addr, log_fn=log_fn):
                    self._pool_address = addr
                    return True
                # Try dereferencing (pattern might resolve to pointer-to-pool)
                try:
                    deref = self.reader.read_ptr(addr)
                    if deref and deref < 0x7FFFFFFFFFFF:
                        if log_fn:
                            log_fn(f"[GNAMES] Deref 0x{addr:X} → 0x{deref:X}")
                        if self.verify_address(deref, log_fn=log_fn):
                            self._pool_address = deref
                            return True
                except Exception:
                    pass
            return False

        # Try primary pattern against module
        module_scan = lambda p, **kw: self.scanner.find_address(module_name, p, **kw)
        if _try_pattern(module_scan, self.profile.gnames_pattern, "primary/module"):
            return True

        # Try alternates against module
        for i, pat in enumerate(self.profile.gnames_patterns_alt):
            if _try_pattern(module_scan, pat, f"alt[{i}]/module"):
                return True

        # FALLBACK: Scan all accessible memory in case module headers are obfuscated
        global_scan = lambda p, **kw: self.scanner.find_address_global(p, **kw)
        if _try_pattern(global_scan, self.profile.gnames_pattern, "primary/global"):
            return True

        for i, pat in enumerate(self.profile.gnames_patterns_alt):
            if _try_pattern(global_scan, pat, f"alt[{i}]/global"):
                return True

        return False

    def set_pool_address(self, addr: int):
        """Manually set the FNamePool address (skip scanning)."""
        self._pool_address = addr
        self._cache.clear()

    @property
    def pool_address(self) -> int:
        return self._pool_address

    # ------------------------------------------------------------------
    # Name resolution
    # ------------------------------------------------------------------

    def resolve(self, comparison_index: int) -> str:
        """Resolves a raw ComparisonIndex into a string from the FNamePool."""
        if comparison_index in self._cache:
            return self._cache[comparison_index]

        if self._pool_address == 0:
            return f"FName_{comparison_index}"

        cfg = self.profile.fname_pool

        # Apply shift if configured
        shifted_index = comparison_index >> cfg.comparison_index_shift

        # Decode block index and offset from the ComparisonIndex
        block_idx = shifted_index >> cfg.block_offset_bits
        block_offset = (shifted_index & ((1 << cfg.block_offset_bits) - 1)) * cfg.stride

        if block_idx >= cfg.max_blocks:
            return f"FName_{comparison_index}"

        try:
            # Read the block pointer
            block_ptr_addr = self._pool_address + cfg.blocks_offset + (block_idx * 8)
            block_ptr = self.reader.read_ptr(block_ptr_addr)
            if block_ptr == 0:
                return f"FName_{comparison_index}"

            # Read the entry header at block_ptr + block_offset
            entry_address = block_ptr + block_offset
            header_addr = entry_address + cfg.header_offset
            header = self.reader.read_uint16(header_addr)
            
            is_wide = (header & cfg.wide_bit_mask) != 0
            length = (header >> cfg.len_shift) & cfg.len_mask
            
            if length == 0 or length > 1024:
                return f"FName_{comparison_index}"

            str_addr = entry_address + cfg.string_offset
            if is_wide:
                raw = self.reader.read_bytes(str_addr, length * 2)
                name = raw.decode("utf-16le", errors="replace")
            else:
                raw = self.reader.read_bytes(str_addr, length)
                name = raw.decode("utf-8", errors="replace")

            self._cache[comparison_index] = name
            return name

        except Exception:
            name = f"FName_{comparison_index}"
            self._cache[comparison_index] = name
            return name

    def resolve_fname_at(self, addr: int) -> str:
        """Read an FName struct at *addr* and resolve it."""
        cfg = self.profile.fname
        comp_idx = self.reader.read_int32(addr + cfg.comparison_index_offset)
        number = self.reader.read_int32(addr + cfg.number_offset)
        base_name = self.resolve(comp_idx)
        if number > 0:
            return f"{base_name}_{number - 1}"
        return base_name

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def dump_all_names(self, max_names: int = 500000) -> dict[int, str]:
        """
        Walk the entire FNamePool and dump all names.
        Returns {index: name_string}.
        """
        if self._pool_address == 0:
            return {}

        cfg = self.profile.fname_pool
        result: dict[int, str] = {}

        # Read current block count
        try:
            current_block = self.reader.read_uint32(
                self._pool_address + cfg.current_block
            )
        except Exception:
            return result

        for block_idx in range(min(current_block + 1, cfg.max_blocks)):
            block_ptr_addr = self._pool_address + cfg.blocks_offset + (block_idx * 8)
            try:
                block_ptr = self.reader.read_ptr(block_ptr_addr)
            except Exception:
                continue
            if block_ptr == 0:
                continue

            # Determine block size to scan
            if block_idx == current_block:
                try:
                    byte_cursor = self.reader.read_uint32(
                        self._pool_address + cfg.current_byte_cursor
                    )
                    block_scan_size = byte_cursor
                except Exception:
                    block_scan_size = cfg.block_size
            else:
                block_scan_size = cfg.block_size

            offset = 0
            while offset < block_scan_size and len(result) < max_names:
                entry_addr = block_ptr + offset
                try:
                    header = self.reader.read_uint16(entry_addr)
                except Exception:
                    break

                is_wide = (header & cfg.wide_bit_mask) != 0
                name_len = (header >> cfg.len_shift) & 0x3FF

                if name_len == 0:
                    break

                str_addr = entry_addr + cfg.string_offset
                try:
                    if is_wide:
                        name = self.reader.read_wstring(str_addr, name_len)
                        entry_size = cfg.string_offset + name_len * 2
                    else:
                        name = self.reader.read_string(str_addr, name_len)
                        entry_size = cfg.string_offset + name_len
                except Exception:
                    break

                # Align to stride
                entry_size = (entry_size + cfg.stride - 1) & ~(cfg.stride - 1)
                if entry_size < cfg.stride:
                    entry_size = cfg.stride

                fname_idx = (block_idx << cfg.block_offset_bits) | (offset // cfg.stride)
                result[fname_idx] = name
                self._cache[fname_idx] = name

                offset += entry_size

        return result
