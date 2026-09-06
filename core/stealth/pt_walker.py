"""
BIFROST SDK — Physical Page Table Walker
Performs manual VA -> PA translation in Python to read memory
completely invisibly, bypassing CR3 encryption and MMU hooks.
"""

import struct
from .cr3 import CR3BruteForcer

class PTWalkerReader:
    def __init__(self, pid: int, driver_interface, target_base: int = 0):
        self.pid = pid
        self.driver = driver_interface
        self.active_mode = "pt_walker"
        self.cr3 = 0

        # We need the actual target_base to brute force CR3. For SDK dumpers,
        # games usually load at 0x7FF700000000 or similar. Brute force is
        # attempted when a target_base is provided.
        if target_base > 0:
            bf = CR3BruteForcer(self.driver)
            self.cr3 = bf.brute_force_cr3(pid, target_base)

        if not self.cr3:
            # Fallback to the driver-provided CR3 if brute-force fails or
            # isn't used. Vulnerable to CR3 shuffling but works on games
            # without kernel anti-cheat. Raises on failure — a garbage CR3
            # silently corrupting every read is worse than a visible error.
            self.cr3 = self.driver.get_process_cr3(pid)

    def _translate_va(self, virtual_address: int) -> int:
        """
        Translates a Virtual Address to a Physical Address by manually
        walking the 4-level page tables (PML4 -> PDPT -> PD -> PT).
        """
        if self.cr3 == 0:
            raise RuntimeError("Cannot translate VA: CR3 is 0")

        pml4_index = (virtual_address >> 39) & 0x1FF
        pdpt_index = (virtual_address >> 30) & 0x1FF
        pd_index   = (virtual_address >> 21) & 0x1FF
        pt_index   = (virtual_address >> 12) & 0x1FF
        page_offset = virtual_address & 0xFFF

        # 1. PML4
        pml4e_bytes = self.driver.read_physical(self.cr3 + (pml4_index * 8), 8)
        if len(pml4e_bytes) != 8:
            raise RuntimeError(f"PM4LE read failed at {self.cr3 + pml4_index * 8:#x}")
        pml4e = struct.unpack("<Q", pml4e_bytes)[0]
        if not (pml4e & 1):
            return 0  # Not present

        # 2. PDPT
        pdpt_base = pml4e & 0xFFFFFFFFFF000
        pdpte_bytes = self.driver.read_physical(pdpt_base + (pdpt_index * 8), 8)
        if len(pdpte_bytes) != 8:
            raise RuntimeError(f"PDPTE read failed at {pdpt_base + pdpt_index * 8:#x}")
        pdpte = struct.unpack("<Q", pdpte_bytes)[0]
        if not (pdpte & 1):
            return 0

        # Large page check (1GB)
        if pdpte & 0x80:
            return (pdpte & 0xFFFFC0000000) + (virtual_address & 0x3FFFFFFF)

        # 3. PD
        pd_base = pdpte & 0xFFFFFFFFFF000
        pde_bytes = self.driver.read_physical(pd_base + (pd_index * 8), 8)
        if len(pde_bytes) != 8:
            raise RuntimeError(f"PDE read failed at {pd_base + pd_index * 8:#x}")
        pde = struct.unpack("<Q", pde_bytes)[0]
        if not (pde & 1):
            return 0

        # Large page check (2MB)
        if pde & 0x80:
            return (pde & 0xFFFFFFE00000) + (virtual_address & 0x1FFFFF)

        # 4. PT
        pt_base = pde & 0xFFFFFFFFFF000
        pte_bytes = self.driver.read_physical(pt_base + (pt_index * 8), 8)
        if len(pte_bytes) != 8:
            raise RuntimeError(f"PTE read failed at {pt_base + pt_index * 8:#x}")
        pte = struct.unpack("<Q", pte_bytes)[0]
        if not (pte & 1):
            return 0

        return (pte & 0xFFFFFFFFFF000) + page_offset

    def read_bytes(self, address: int, size: int) -> bytes:
        """
        Reads memory by translating VA to PA and reading physical RAM.

        Splits reads that cross page boundaries: each 4 KiB page is
        translated independently, so reads spanning pages return correct
        data instead of contiguous-physical garbage.
        """
        if size == 0:
            return b""

        out = bytearray()
        remaining = size
        cur = address
        while remaining > 0:
            chunk = min(remaining, 0x1000 - (cur & 0xFFF))
            phys_addr = self._translate_va(cur)
            if phys_addr == 0:
                return b"\x00" * size
            data = self.driver.read_physical(phys_addr, chunk)
            if len(data) != chunk:
                raise RuntimeError(
                    f"Physical read short: wanted {chunk} bytes at {phys_addr:#x}, "
                    f"got {len(data)}"
                )
            out.extend(data)
            cur += chunk
            remaining -= chunk
        return bytes(out)

    def read_uint64(self, address: int) -> int:
        data = self.read_bytes(address, 8)
        return struct.unpack("<Q", data)[0]

    def read_uint32(self, address: int) -> int:
        data = self.read_bytes(address, 4)
        return struct.unpack("<I", data)[0]

    def read_string(self, address: int, length: int = 64) -> str:
        data = self.read_bytes(address, length)
        end = data.find(b'\x00')
        if end != -1:
            data = data[:end]
        return data.decode('utf-8', 'ignore')

    def get_base_address(self) -> int:
        # In a real PT Walker, we'd either already know this from CR3 brute
        # force or we scan the VAD (Virtual Address Descriptor) tree.
        return 0x7FF700000000
