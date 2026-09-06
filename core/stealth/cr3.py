"""
BIFROST SDK — CR3 Brute Forcer
Defeats EAC CR3 encryption/shuffling by brute-forcing physical memory 
pages for the true Directory Table Base of the target process.
"""

import ctypes
import struct
from typing import Optional

class CR3BruteForcer:
    def __init__(self, driver):
        self.driver = driver
        # Standard x64 Page Size
        self.PAGE_SIZE = 0x1000
        # Scan bound = installed physical RAM, queried live. Falls back to
        # 32GB if the query fails.
        self.MAX_PHYSICAL_MEM = self._query_physical_memory()

    @staticmethod
    def _query_physical_memory() -> int:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        try:
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                if stat.ullTotalPhys > 0:
                    return stat.ullTotalPhys
        except Exception:
            pass
        return 0x800000000  # 32GB fallback

    def brute_force_cr3(self, target_pid: int, target_base_address: int) -> Optional[int]:
        """
        Scans physical memory for PML4 tables to find the true CR3.
        It verifies a CR3 by performing a manual page translation on the 
        target_base_address. If it translates to a physical page starting 
        with the MZ header (0x5A4D), we know we found the correct CR3.
        """
        print(f"[*] Starting Physical CR3 Brute-Force for PID {target_pid}...")

        # We look for candidate PML4 base addresses.
        # A valid PML4 base is page-aligned (ends in 000).
        current_phys = 0x100000  # Skip low memory
        
        while current_phys < self.MAX_PHYSICAL_MEM:
            try:
                # We don't actually read 2MB and parse it all; that's too slow in pure Python.
                # Instead, we are looking for valid PML4 entries for the base address.
                # Since the base address is usually known (e.g., 0x7FF700000000), 
                # we can calculate its PML4 index.
                
                # In a real C++ implementation, this iterates every physical page.
                # For this Python proxy, we simulate the brute-force translation logic.
                
                pml4_index = (target_base_address >> 39) & 0x1FF
                
                # Read a single potential PML4 page
                page_data = self.driver.read_physical(current_phys, self.PAGE_SIZE)
                
                # Check if the entry for our base address is present
                entry_offset = pml4_index * 8
                pml4_entry = struct.unpack("<Q", page_data[entry_offset:entry_offset+8])[0]
                
                # Present bit must be 1
                if (pml4_entry & 1) == 1:
                    pdpt_base = pml4_entry & 0xFFFFFFFFFF000
                    # If this looks like a valid PDPT, we test translation
                    if self._test_translation(current_phys, target_base_address):
                        print(f"[+] SUCCESS: Found True CR3 -> 0x{current_phys:X}")
                        return current_phys

            except Exception:
                pass
                
            current_phys += self.PAGE_SIZE
            
            # Print progress every 1GB
            if current_phys % 0x40000000 == 0:
                print(f"[*] Scanning... {current_phys / (1024**3):.1f} GB")

        print("[-] Failed to brute-force true CR3.")
        return None

    def _test_translation(self, cr3: int, virtual_address: int) -> bool:
        """
        Manually walks the 4-level page table for the given CR3.
        Returns True if the resulting physical address contains an MZ header.
        """
        try:
            pml4_index = (virtual_address >> 39) & 0x1FF
            pdpt_index = (virtual_address >> 30) & 0x1FF
            pd_index   = (virtual_address >> 21) & 0x1FF
            pt_index   = (virtual_address >> 12) & 0x1FF
            page_offset = virtual_address & 0xFFF
            
            # 1. PML4
            pml4e_bytes = self.driver.read_physical(cr3 + (pml4_index * 8), 8)
            pml4e = struct.unpack("<Q", pml4e_bytes)[0]
            if not (pml4e & 1): return False
            
            # 2. PDPT
            pdpt_base = pml4e & 0xFFFFFFFFFF000
            pdpte_bytes = self.driver.read_physical(pdpt_base + (pdpt_index * 8), 8)
            pdpte = struct.unpack("<Q", pdpte_bytes)[0]
            if not (pdpte & 1): return False
            
            # Large page check (1GB)
            if pdpte & 0x80:
                phys_addr = (pdpte & 0xFFFFC0000000) + (virtual_address & 0x3FFFFFFF)
                return self._check_mz(phys_addr)
                
            # 3. PD
            pd_base = pdpte & 0xFFFFFFFFFF000
            pde_bytes = self.driver.read_physical(pd_base + (pd_index * 8), 8)
            pde = struct.unpack("<Q", pde_bytes)[0]
            if not (pde & 1): return False
            
            # Large page check (2MB)
            if pde & 0x80:
                phys_addr = (pde & 0xFFFFFFE00000) + (virtual_address & 0x1FFFFF)
                return self._check_mz(phys_addr)
                
            # 4. PT
            pt_base = pde & 0xFFFFFFFFFF000
            pte_bytes = self.driver.read_physical(pt_base + (pt_index * 8), 8)
            pte = struct.unpack("<Q", pte_bytes)[0]
            if not (pte & 1): return False
            
            phys_addr = (pte & 0xFFFFFFFFFF000) + page_offset
            return self._check_mz(phys_addr)
            
        except Exception:
            return False

    def _check_mz(self, phys_addr: int) -> bool:
        try:
            magic = self.driver.read_physical(phys_addr, 2)
            return magic == b'MZ'
        except Exception:
            return False
