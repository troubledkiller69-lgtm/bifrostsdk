"""
BIFROST SDK — AOB / Signature Pattern Scanner
Scans remote process memory regions for byte patterns with wildcard support.
Supports stealth mode with reduced chunk sizes and inter-chunk delays.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import random
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .memory import MemoryReader

# Win32 constants
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


@dataclass
class ScanResult:
    """A single pattern match."""
    address: int
    module_name: str = ""
    module_offset: int = 0


@dataclass
class ScanStats:
    """Statistics for the debug panel."""
    regions_scanned: int = 0
    bytes_scanned: int = 0
    patterns_tested: int = 0
    matches_found: int = 0
    scan_time_s: float = 0.0
    chunks_read: int = 0

    def to_dict(self) -> dict:
        return {
            "regions_scanned": self.regions_scanned,
            "bytes_scanned": self.bytes_scanned,
            "bytes_scanned_mb": round(self.bytes_scanned / (1024 * 1024), 2),
            "patterns_tested": self.patterns_tested,
            "matches_found": self.matches_found,
            "scan_time_s": round(self.scan_time_s, 3),
            "chunks_read": self.chunks_read,
        }


class PatternScanner:
    """
    Scan remote process memory for AOB (Array-of-Bytes) patterns.

    Pattern format examples:
        "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8"
        "48 8B 05 ? ? ? ? 48 8B 0C C8"

    '??' or '?' denotes a wildcard byte.
    """

    CHUNK_SIZE = 0x100000  # 1 MiB read granularity (default)

    def __init__(
        self,
        reader: MemoryReader,
        stealth: bool = False,
        chunk_size: int = 0,
        inter_chunk_delay_ms: int = 0,
    ):
        self.reader = reader
        self._stealth = stealth
        self._inter_chunk_delay = inter_chunk_delay_ms / 1000.0 if inter_chunk_delay_ms > 0 else 0
        self.stats = ScanStats()

        if chunk_size > 0:
            self.CHUNK_SIZE = chunk_size
        elif stealth:
            self.CHUNK_SIZE = 0x10000  # 64 KiB in stealth mode

    # ------------------------------------------------------------------
    # Pattern compilation
    # ------------------------------------------------------------------

    @staticmethod
    def _compile_pattern(pattern: str) -> re.Pattern:
        """
        Compile a space-separated hex pattern into a compiled regex object.
        '??' or '?' is treated as any byte (.), concrete bytes are escaped.
        """
        tokens = pattern.strip().split()
        regex_parts = []
        for tok in tokens:
            tok = tok.strip()
            if tok in ("?", "??", "**"):
                regex_parts.append(b".")
            else:
                regex_parts.append(re.escape(bytes([int(tok, 16)])))
        
        return re.compile(b"".join(regex_parts), re.DOTALL)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def _match(self, data: bytes, regex: re.Pattern, start: int = 0) -> int:
        """Return offset of first match within *data*, or -1 using regex."""
        match = regex.search(data, start)
        if match:
            return match.start()
        return -1

    def scan_module(
        self,
        module_name: str,
        pattern: str,
        *,
        return_first: bool = True,
        max_results: int = 50,
    ) -> list[ScanResult]:
        """Scan a specific module for *pattern* by walking its committed pages."""
        base = self.reader.module_base(module_name)
        size = self.reader.module_size(module_name)
        end_addr = base + size
        
        regex = self._compile_pattern(pattern)
        results: list[ScanResult] = []
        self.stats.patterns_tested += 1

        if not getattr(self.reader, 'handle', None):
            # Stealth mode with no handle (driver mode)
            # Cannot use VirtualQueryEx. Parse PE header to find mapped sections!
            sections = self.reader.get_module_sections(module_name)
            if sections:
                for sec in sections:
                    sec_rva = sec["rva"]
                    sec_size = sec["size"]
                    # Skip empty sections or PAGE_NOACCESS (we just check size)
                    if sec_size > 0:
                        self.stats.regions_scanned += 1
                        self._scan_region(
                            base + sec_rva, sec_size,
                            regex, results, module_name, return_first, max_results,
                        )
                        if return_first and results:
                            return results
                        if len(results) >= max_results:
                            return results
                return results
            else:
                # Fallback to entire module if PE parsing fails
                self.stats.regions_scanned += 1
                self._scan_region(
                    base, size,
                    regex, results, module_name, return_first, max_results,
                )
                return results

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        addr = base
        k32 = ctypes.windll.kernel32
        
        while addr < end_addr:
            ret = k32.VirtualQueryEx(
                self.reader.handle,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break
            
            base_addr = mbi.BaseAddress or 0
            
            # Ensure we don't scan past the module boundaries
            region_base = max(addr, base_addr)
            region_end = min(end_addr, base_addr + mbi.RegionSize)
            region_size = region_end - region_base
            
            if (
                region_size > 0
                and mbi.State == MEM_COMMIT
                and mbi.Protect not in (PAGE_NOACCESS, PAGE_GUARD, 0)
            ):
                self.stats.regions_scanned += 1
                self._scan_region(
                    region_base, region_size,
                    regex, results, module_name, return_first, max_results,
                )
                if return_first and results:
                    return results
                if len(results) >= max_results:
                    return results

            # Stealth: add small random delay between VirtualQueryEx calls
            if self._stealth and self._inter_chunk_delay > 0:
                time.sleep(self._inter_chunk_delay * random.uniform(0.5, 1.5))
                    
            addr = base_addr + mbi.RegionSize

        return results

    def scan_all(
        self,
        pattern: str,
        *,
        return_first: bool = True,
        max_results: int = 50,
        executable_only: bool = True,
    ) -> list[ScanResult]:
        """Scan committed memory regions, optionally filtered to executable code."""
        regex = self._compile_pattern(pattern)
        results: list[ScanResult] = []
        self.stats.patterns_tested += 1
        
        if not getattr(self.reader, 'handle', None):
            # Cannot scan entire address space without VirtualQueryEx or VAD walking
            # In stealth driver mode, scan_all is unsupported.
            return results

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        k32 = ctypes.windll.kernel32
        while addr < 0x7FFFFFFFFFFF:
            ret = k32.VirtualQueryEx(
                self.reader.handle,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break
            base_addr = mbi.BaseAddress or 0
            
            is_executable = mbi.Protect in (0x10, 0x20, 0x40, 0x80)
            
            if (
                mbi.State == MEM_COMMIT
                and mbi.Protect not in (PAGE_NOACCESS, PAGE_GUARD, 0)
                and mbi.RegionSize > 0
                and (not executable_only or is_executable)
            ):
                self.stats.regions_scanned += 1
                self._scan_region(
                    base_addr, mbi.RegionSize,
                    regex, results, "", return_first, max_results,
                )
                if return_first and results:
                    return results
                if len(results) >= max_results:
                    return results

            if self._stealth and self._inter_chunk_delay > 0:
                time.sleep(self._inter_chunk_delay * random.uniform(0.3, 1.0))

            addr = base_addr + mbi.RegionSize

        return results

    def _scan_range(
        self,
        base: int,
        size: int,
        pattern: str,
        module_name: str,
        return_first: bool,
        max_results: int,
    ) -> list[ScanResult]:
        regex = self._compile_pattern(pattern)
        results: list[ScanResult] = []
        self._scan_region(base, size, regex, results, module_name, return_first, max_results)
        return results

    def _scan_region(
        self,
        base: int,
        size: int,
        regex: re.Pattern,
        results: list[ScanResult],
        module_name: str,
        return_first: bool,
        max_results: int,
    ):
        """Read a memory region in chunks and scan each."""
        scan_start = time.perf_counter()
        overlap = 128  # Safe overlap size for typical instruction patterns
        offset = 0
        while offset < size:
            chunk_size = min(self.CHUNK_SIZE, size - offset)
            try:
                data = self.reader.read_bytes(base + offset, chunk_size)
                self.stats.bytes_scanned += chunk_size
                self.stats.chunks_read += 1
            except Exception:
                offset += chunk_size
                continue

            pos = 0
            while True:
                hit = self._match(data, regex, pos)
                if hit == -1:
                    break
                abs_addr = base + offset + hit
                results.append(ScanResult(
                    address=abs_addr,
                    module_name=module_name,
                    module_offset=abs_addr - base if module_name else 0,
                ))
                self.stats.matches_found += 1
                if return_first or len(results) >= max_results:
                    self.stats.scan_time_s += time.perf_counter() - scan_start
                    return
                pos = hit + 1

            # Stealth: random delay between chunk reads
            if self._stealth and self._inter_chunk_delay > 0:
                time.sleep(self._inter_chunk_delay * random.uniform(0.5, 2.0))

            # move forward, leaving overlap so patterns split across chunks aren't missed
            advance = chunk_size - overlap
            if advance <= 0:
                break
            offset += advance

        self.stats.scan_time_s += time.perf_counter() - scan_start

    # ------------------------------------------------------------------
    # Convenience: scan + resolve RIP-relative
    # ------------------------------------------------------------------

    def find_address(
        self,
        module_name: str,
        pattern: str,
        rip_offset: int = 3,
        insn_len: int = 7,
    ) -> Optional[int]:
        """
        Scan *module_name* for *pattern*, then resolve the RIP-relative
        address embedded at byte position *rip_offset* of the match.
        Returns the resolved absolute address, or None.
        """
        hits = self.scan_module(module_name, pattern, return_first=True)
        if not hits:
            return None
        return self.reader.resolve_rip_relative(hits[0].address, rip_offset, insn_len)

    def find_address_global(
        self,
        pattern: str,
        rip_offset: int = 3,
        insn_len: int = 7,
        executable_only: bool = True,
    ) -> Optional[int]:
        """
        Scan all committed memory for *pattern*, then resolve RIP-relative.
        Fallback for when module headers are obfuscated.
        """
        hits = self.scan_all(pattern, return_first=True, executable_only=executable_only)
        if not hits:
            return None
        return self.reader.resolve_rip_relative(hits[0].address, rip_offset, insn_len)

    def get_stats(self) -> dict:
        """Return scan statistics for the debug panel."""
        return self.stats.to_dict()
