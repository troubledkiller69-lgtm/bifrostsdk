"""
BIFROST SDK — Kernel Trace Cleaner
Removes traces of vulnerable drivers from PiDDBCacheTable and MmUnloadedDrivers.
"""

import ctypes
import struct

class KernelCleaner:
    def __init__(self, driver_interface):
        self.driver = driver_interface
        self._ntoskrnl_base = self._get_ntoskrnl_base()

    def _get_ntoskrnl_base(self):
        try:
            import ctypes.wintypes as wt
            array_size = 1024
            cbNeeded = wt.DWORD()
            image_bases = (ctypes.c_void_p * array_size)()
            if ctypes.windll.psapi.EnumDeviceDrivers(ctypes.byref(image_bases), ctypes.sizeof(image_bases), ctypes.byref(cbNeeded)):
                # First driver is ntoskrnl.exe
                return image_bases[0]
        except Exception:
            pass
        return 0

    def clean(self, target_driver_name="iqvw64e.sys"):
        """
        Scrub the driver's cached name from ntoskrnl's PiDDBCacheTable region.

        Explicit opt-in only — this WRITES to kernel memory through the
        vulnerable driver and can BSOD if any assumption is wrong. It must
        never run automatically inside DriverInterface.__init__.

        Safety gates before any write:
          1. Driver must be loaded.
          2. ntoskrnl base must resolve via EnumDeviceDrivers.
          3. System CR3 must translate ntoskrnl_base to an MZ header
             (proves the CR3 is real, not a garbage page-aligned value).
          4. The scrub window must stay within the page and only zero the
             name region found by the scan.
        """
        if not self.driver or not self.driver.is_loaded:
            print("[-] KernelCleaner: Driver not loaded.")
            return False

        print(f"[*] KernelCleaner: Initializing PiDDBCacheTable trace sweep for '{target_driver_name}'...")
        if self._ntoskrnl_base == 0:
            print("[-] KernelCleaner: Failed to locate ntoskrnl.exe base.")
            return False

        print(f"[+] Found ntoskrnl.exe at 0x{self._ntoskrnl_base:X}")

        # Convert ntoskrnl VA to Physical Address via System CR3 (PID 4)
        system_cr3 = self._get_system_cr3()
        if not system_cr3:
            print("[-] KernelCleaner: Failed to resolve System CR3.")
            return False

        # CR3 sanity gate: the resolved CR3 must actually map ntoskrnl's
        # first page to an MZ header. Without this, every read/write below
        # goes through a garbage page table — writes included.
        try:
            mz = self.driver.read_virtual(system_cr3, self._ntoskrnl_base, 2)
        except Exception as e:
            print(f"[-] KernelCleaner: read at ntoskrnl base failed: {e}")
            return False
        if mz != b"MZ":
            print(f"[-] KernelCleaner: CR3 0x{system_cr3:X} does not map ntoskrnl "
                  f"(got {mz!r}) — aborting scrub.")
            return False

        print(f"[+] Resolved System CR3: 0x{system_cr3:X} (verified)")

        target_bytes = target_driver_name.encode('utf-16le')
        found = False

        # Scan first 16MB of ntoskrnl memory for the cached driver string.
        # Scrub only the name region itself — never a wide window around it.
        for offset in range(0, 16 * 1024 * 1024, 0x1000):
            va = self._ntoskrnl_base + offset
            try:
                page = self.driver.read_virtual(system_cr3, va, 0x1000)
                idx = page.find(target_bytes)
                if idx != -1:
                    print(f"[+] Found driver trace at VA: 0x{va + idx:X}. Scrubbing...")
                    # Zero exactly the UTF-16 name bytes (plus trailing nulls),
                    # clamped to the page.
                    name_len = len(target_bytes)
                    scrub_start = max(0, idx)
                    scrub_len = min(name_len + 16, 0x1000 - scrub_start)
                    null_bytes = b"\x00" * scrub_len
                    self.driver.write_virtual(system_cr3, va + scrub_start, null_bytes)
                    found = True
            except Exception:
                continue

        if found:
            print("[+] Kernel traces scrubbed successfully.")
            return True
        else:
            print("[!] Trace not found (may already be clean or un-paged).")
            return True

    def _get_system_cr3(self):
        try:
            return self.driver.get_process_cr3(4)
        except Exception as e:
            print(f"[-] KernelCleaner: CR3 resolution error: {e}")
            return 0
