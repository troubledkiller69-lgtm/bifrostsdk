"""
BIFROST SDK — Stealth Memory Reader
Drop-in replacement for core.memory.MemoryReader that routes reads
through kernel-level access methods to evade anti-cheat detection.

Access hierarchy for AUTO (tries in order):
  1. Manual page-table walk over physical reads (CR3 brute-force — no handle needed)
  2. Driver-backed physical memory reads (strongest — no handle needed)
  3. Handle hijacking from system processes (usermode, but stealthy)
  4. Direct attach fallback (pymem — only for unprotected games)
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import os
from typing import Optional

from .config import AccessMethod, StealthConfig, STEALTH_MEDIUM
from .driver import DriverInterface
from .handle import HandleHijacker
from .timing import JitteredReader, AdaptiveJitter, TimingStats


k32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED = 0x1000


class StealthReader:
    """
    Stealth memory reader — same API as MemoryReader but routes
    through kernel-level access to bypass anti-cheat.

    Usage:
        reader = StealthReader(process_name="game.exe")
        value = reader.read_uint64(some_addr)
    """

    def __init__(
        self,
        process_name: str | None = None,
        pid: int | None = None,
        config: StealthConfig | None = None,
    ):
        self._config = config or STEALTH_MEDIUM
        self._active_method: Optional[AccessMethod] = None
        self._driver: Optional[DriverInterface] = None
        self._cr3: int = 0
        self._handle: int = 0
        self._pid: int = 0
        self._process_name = process_name
        self._module_cache: dict[str, tuple[int, int]] = {}  # name -> (base, size)
        self._jitter: Optional[JitteredReader] = None

        # Debug stats
        self._debug_stats: dict = {
            "access_method": "none",
            "driver_available": False,
            "hijack_available": False,
            "direct_available": False,
            "gnames_address": 0,
            "gobjects_address": 0,
            "modules_found": 0,
            "errors": [],
        }

        # Resolve PID
        if pid:
            self._pid = pid
        elif process_name:
            self._pid = self._resolve_pid(process_name)
        else:
            raise ValueError("Provide process_name or pid")

        if self._pid == 0:
            raise RuntimeError(f"Process not found: {process_name}")

        # Establish access
        self._connect(self._config.method, self._config.driver_path or None)

        # Setup jitter wrapper
        if self._config.enable_jitter:
            self._jitter = JitteredReader(
                self._raw_read,
                min_delay_us=self._config.jitter_min_us,
                max_delay_us=self._config.jitter_max_us,
                burst_size=self._config.burst_size,
                burst_cooldown_ms=self._config.burst_cooldown_ms,
                enable_idle_mimicry=self._config.enable_idle_mimicry,
            )

    def _resolve_pid(self, name: str) -> int:
        """Find PID by process name using NtQuerySystemInformation to avoid psutil."""
        if self._config.use_ntquery_enumeration:
            return self._resolve_pid_ntquery(name)
        return self._resolve_pid_psutil(name)

    def _resolve_pid_ntquery(self, name: str) -> int:
        """
        Resolve PID via NtQuerySystemInformation(SystemProcessInformation).
        Avoids psutil's CreateToolhelp32Snapshot which is more detectable.
        """
        SYSTEM_PROCESS_INFORMATION = 5
        buf_size = 0x100000  # 1MB initial

        for _ in range(5):  # retry with larger buffer
            buf = (ctypes.c_ubyte * buf_size)()
            return_length = ctypes.c_ulong(0)

            status = ntdll.NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                ctypes.byref(buf),
                buf_size,
                ctypes.byref(return_length),
            )

            if status == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
                buf_size *= 2
                continue

            if status != 0:
                break  # Fall back to psutil

            # Parse SYSTEM_PROCESS_INFORMATION entries
            name_lower = name.lower()
            offset = 0
            raw = bytes(buf[:return_length.value])

            while offset < len(raw) - 64:
                # NextEntryOffset at +0
                next_offset = struct.unpack_from("<I", raw, offset)[0]
                # NumberOfThreads at +4
                # ImageName (UNICODE_STRING) at +56 (0x38)
                #   Length at +56, MaximumLength at +58, Buffer at +64
                img_name_len = struct.unpack_from("<H", raw, offset + 56)[0]
                img_name_buf = struct.unpack_from("<Q", raw, offset + 64)[0]

                # UniqueProcessId at +80 (0x50)
                pid = struct.unpack_from("<Q", raw, offset + 80)[0]

                if img_name_len > 0 and img_name_buf > 0 and pid > 0:
                    try:
                        # The name is inline in the buffer after the struct
                        # For NtQuerySystemInformation, the buffer pointer
                        # may point into our buffer — compute relative offset
                        buf_addr = ctypes.addressof(buf)
                        if buf_addr <= img_name_buf < buf_addr + buf_size:
                            name_offset = img_name_buf - buf_addr
                            proc_name_bytes = raw[name_offset:name_offset + img_name_len]
                            proc_name = proc_name_bytes.decode("utf-16-le", errors="replace")
                            if proc_name.lower() == name_lower:
                                return pid
                    except Exception:
                        pass

                if next_offset == 0:
                    break
                offset += next_offset

            break

        # Fallback to psutil
        return self._resolve_pid_psutil(name)

    @staticmethod
    def _resolve_pid_psutil(name: str) -> int:
        """Fallback PID resolution via psutil."""
        import psutil
        name_lower = name.lower()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"].lower() == name_lower:
                    return proc.info["pid"]
                if proc.info["name"].lower().replace(".exe", "") == name_lower.replace(".exe", ""):
                    return proc.info["pid"]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return 0

    def _connect(self, method: AccessMethod, driver_path: Optional[str]):
        """Establish memory access using the specified (or best available) method.

        AUTO is deliberately usermode-only (handle hijack -> direct attach).
        Kernel access (vulnerable-driver mapping, PT walks, CR3 brute force)
        can BSOD or trip AV and must be requested explicitly via
        AccessMethod.DRIVER or AccessMethod.PT_WALKER. AUTO never loads a
        driver on its own.
        """
        methods_to_try = []

        if method == AccessMethod.AUTO:
            methods_to_try = [AccessMethod.HIJACK, AccessMethod.DIRECT]
        else:
            methods_to_try = [method]

        for m in methods_to_try:
            try:
                if m == AccessMethod.PT_WALKER:
                    self._connect_pt_walker(driver_path)
                    self._active_method = AccessMethod.PT_WALKER
                    self._debug_stats["access_method"] = "PT Walker (Physical CR3)"
                    return
                elif m == AccessMethod.DRIVER:
                    self._connect_driver(driver_path)
                    self._active_method = AccessMethod.DRIVER
                    self._debug_stats["driver_available"] = True
                    self._debug_stats["access_method"] = "Kernel Driver (Physical)"
                    return
                elif m == AccessMethod.HIJACK:
                    self._connect_hijack()
                    self._active_method = AccessMethod.HIJACK
                    self._debug_stats["hijack_available"] = True
                    self._debug_stats["access_method"] = "Handle Hijack"
                    return
                elif m == AccessMethod.DIRECT:
                    self._connect_direct()
                    self._active_method = AccessMethod.DIRECT
                    self._debug_stats["direct_available"] = True
                    self._debug_stats["access_method"] = "Direct Attach"
                    return
            except Exception as e:
                self._debug_stats["errors"].append(f"{m.name} failed: {e}")
                continue

        raise RuntimeError(
            f"All access methods failed for PID {self._pid}. "
            "If this is an anti-cheat-protected game, select the 'driver' "
            "stealth mode explicitly (kernel access is not part of AUTO)."
        )

    def _connect_pt_walker(self, driver_path: Optional[str]):
        """Use Manual Page Table Walker to bypass CR3 Encryption."""
        from .pt_walker import PTWalkerReader
        
        # DriverInterface maps the vulnerable driver inside __init__.
        self._driver = DriverInterface(driver_path=driver_path)
        if not self._driver.is_loaded:
            raise RuntimeError("DriverInterface failed to map a driver")
        
        # We assume base address 0x7FF700000000 for standard Unity/UE5 games.
        # This allows the PTWalker to brute-force the physical CR3.
        self._pt_reader = PTWalkerReader(self._pid, self._driver, 0x7FF700000000)
        
        # If the cr3 is 0, the brute forcer failed or the driver isn't working
        if self._pt_reader.cr3 == 0:
            raise RuntimeError("PTWalker failed to resolve True CR3")

    def _connect_driver(self, driver_path: Optional[str]):
        """Load vulnerable driver and get CR3 for target process."""
        # DriverInterface maps the vulnerable driver inside __init__.
        self._driver = DriverInterface(driver_path=driver_path)
        if not self._driver.is_loaded:
            raise RuntimeError("DriverInterface failed to map a driver")
        self._cr3 = self._driver.get_process_cr3(self._pid)
        if self._cr3 == 0:
            raise RuntimeError("Failed to resolve CR3 for target process")

    def _connect_hijack(self):
        """Duplicate a handle from a system process."""
        hijacker = HandleHijacker()
        self._handle = hijacker.hijack(
            self._pid,
            desired_access=PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        )
        if not self._handle:
            # Try csrss specifically
            self._handle = hijacker.hijack_from_csrss(self._pid)
        if not self._handle:
            raise RuntimeError("Handle hijacking failed")

    def _connect_direct(self):
        """Standard OpenProcess — fallback only."""
        self._handle = k32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            self._pid,
        )
        if not self._handle:
            raise RuntimeError(f"OpenProcess failed for PID {self._pid}")

    # ------------------------------------------------------------------
    # Raw read dispatch
    # ------------------------------------------------------------------

    def _raw_read(self, addr: int, size: int) -> bytes:
        """Route read to active method."""
        if self._active_method == AccessMethod.PT_WALKER:
            return self._pt_reader.read_bytes(addr, size)
        elif self._active_method == AccessMethod.DRIVER:
            return self._driver.read_virtual(self._cr3, addr, size)
        else:
            # Use ReadProcessMemory via handle (hijacked or direct)
            buf = (ctypes.c_byte * size)()
            bytes_read = ctypes.c_size_t(0)
            success = k32.ReadProcessMemory(
                self._handle,
                ctypes.c_void_p(addr),
                ctypes.byref(buf),
                size,
                ctypes.byref(bytes_read),
            )
            if not success:
                raise OSError(f"ReadProcessMemory failed at 0x{addr:X}")
            return bytes(buf)

    # ------------------------------------------------------------------
    # Public read API (mirrors MemoryReader interface)
    # ------------------------------------------------------------------

    def read_bytes(self, addr: int, size: int) -> bytes:
        if self._jitter:
            return self._jitter.read(addr, size)
        return self._raw_read(addr, size)

    def read_bool(self, addr: int) -> bool:
        return struct.unpack("?", self.read_bytes(addr, 1))[0]

    def read_int8(self, addr: int) -> int:
        return struct.unpack("b", self.read_bytes(addr, 1))[0]

    def read_uint8(self, addr: int) -> int:
        return struct.unpack("B", self.read_bytes(addr, 1))[0]

    def read_int16(self, addr: int) -> int:
        return struct.unpack("<h", self.read_bytes(addr, 2))[0]

    def read_uint16(self, addr: int) -> int:
        return struct.unpack("<H", self.read_bytes(addr, 2))[0]

    def read_int32(self, addr: int) -> int:
        return struct.unpack("<i", self.read_bytes(addr, 4))[0]

    def read_uint32(self, addr: int) -> int:
        return struct.unpack("<I", self.read_bytes(addr, 4))[0]

    def read_int64(self, addr: int) -> int:
        return struct.unpack("<q", self.read_bytes(addr, 8))[0]

    def read_uint64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read_bytes(addr, 8))[0]

    def read_float(self, addr: int) -> float:
        return struct.unpack("<f", self.read_bytes(addr, 4))[0]

    def read_double(self, addr: int) -> float:
        return struct.unpack("<d", self.read_bytes(addr, 8))[0]

    def read_ptr(self, addr: int) -> int:
        return self.read_uint64(addr)

    def read_string(self, addr: int, max_len: int = 256, encoding: str = "utf-8") -> str:
        raw = self.read_bytes(addr, max_len)
        null = raw.find(b"\x00")
        if null != -1:
            raw = raw[:null]
        return raw.decode(encoding, errors="replace")

    def read_wstring(self, addr: int, max_len: int = 256) -> str:
        raw = self.read_bytes(addr, max_len * 2)
        result = []
        for i in range(0, len(raw), 2):
            ch = struct.unpack_from("<H", raw, i)[0]
            if ch == 0:
                break
            result.append(chr(ch))
        return "".join(result)

    def read_pointer_chain(self, base: int, offsets: list[int]) -> int:
        addr = base
        for off in offsets:
            addr = self.read_ptr(addr) + off
        return addr

    # ------------------------------------------------------------------
    # Module enumeration (stealth version)
    # ------------------------------------------------------------------

    def module_base(self, module_name: str) -> int:
        """Get module base address (cached)."""
        key = module_name.lower()
        if key not in self._module_cache:
            self._enumerate_modules()
        if key in self._module_cache:
            return self._module_cache[key][0]

        # Fallback 1: psutil memory maps — resolves ANY module by file path,
        # works when anti-cheat strips module enumeration.
        try:
            import psutil
            p = psutil.Process(self._pid)
            maps = p.memory_maps(grouped=False)
            for m in maps:
                if module_name.lower() in (m.path or "").lower():
                    base_addr = int(m.addr.split('-')[0], 16) if '-' in m.addr else int(m.addr, 16)
                    size = self._pe_size_of_image(base_addr)
                    self._module_cache[key] = (base_addr, size)
                    return base_addr
        except Exception as e:
            self._debug_stats["errors"].append(f"psutil module fallback failed: {e}")

        # Fallback 2: PEB ImageBaseAddress — ONLY valid for the main executable.
        # Never use it for other modules: PEB+0x10 always holds the exe base.
        try:
            main_exe = self._resolve_main_exe_name()
            if main_exe and key in (main_exe, main_exe.replace(".exe", "")):
                class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ('ExitStatus', ctypes.c_void_p),
                        ('PebBaseAddress', ctypes.c_void_p),
                        ('AffinityMask', ctypes.c_void_p),
                        ('BasePriority', ctypes.c_void_p),
                        ('UniqueProcessId', ctypes.c_void_p),
                        ('InheritedFromUniqueProcessId', ctypes.c_void_p),
                    ]
                pbi = PROCESS_BASIC_INFORMATION()
                ret_len = ctypes.c_ulong()
                status = ntdll.NtQueryInformationProcess(
                    self._handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
                )
                if status == 0 and pbi.PebBaseAddress:
                    buf = (ctypes.c_ubyte * 8)()
                    bytes_read = ctypes.c_size_t(0)
                    success = k32.ReadProcessMemory(
                        self._handle, pbi.PebBaseAddress + 0x10,
                        ctypes.byref(buf), 8, ctypes.byref(bytes_read),
                    )
                    if success:
                        base_addr = struct.unpack('<Q', bytearray(buf))[0]
                        if base_addr > 0:
                            size = self._pe_size_of_image(base_addr)
                            self._module_cache[key] = (base_addr, size)
                            return base_addr
        except Exception as e:
            self._debug_stats["errors"].append(f"PEB fallback failed: {e}")

        raise RuntimeError(f"Module '{module_name}' not found in PID {self._pid}")

    def _resolve_main_exe_name(self) -> str:
        """Best-effort main executable name for the target process."""
        try:
            import psutil
            return (psutil.Process(self._pid).name() or "").lower()
        except Exception:
            return (self._process_name or "").lower()

    def _pe_size_of_image(self, base: int) -> int:
        """Read SizeOfImage from the in-memory PE optional header."""
        try:
            dos = self.read_bytes(base, 0x40)
            if dos[:2] != b"MZ":
                return 0
            e_lfanew = struct.unpack("<I", dos[0x3C:0x40])[0]
            nt = self.read_bytes(base + e_lfanew, 0x40)
            if nt[:2] != b"PE":
                return 0
            return struct.unpack("<I", nt[0x38:0x3C])[0]
        except Exception:
            return 0

    def module_size(self, module_name: str) -> int:
        key = module_name.lower()
        if key not in self._module_cache:
            self._enumerate_modules()
        if key not in self._module_cache:
            raise RuntimeError(f"Module '{module_name}' not found")
        return self._module_cache[key][1]

    def list_modules(self) -> list[dict]:
        if not self._module_cache:
            self._enumerate_modules()
        return [
            {"name": name, "base": base, "size": size}
            for name, (base, size) in self._module_cache.items()
        ]

    def get_module_sections(self, module_name: str) -> list[dict]:
        """Read PE section headers from the module loaded in memory."""
        base = self.module_base(module_name)
        try:
            import pefile
            header_data = self.read_bytes(base, 0x1000)
            pe = pefile.PE(data=header_data, fast_load=True)
            sections = []
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                sections.append({
                    "name": sec_name,
                    "rva": section.VirtualAddress,
                    "size": section.Misc_VirtualSize,
                })
            return sections
        except Exception:
            return []

    def _enumerate_modules(self):
        """
        Enumerate modules via PEB walk or handle-based fallback.
        When using driver mode, we walk the PEB from physical memory
        to avoid any usermode API calls.
        """
        if self._active_method == AccessMethod.DRIVER:
            self._enumerate_modules_via_peb()
        else:
            self._enumerate_modules_via_handle()

        self._debug_stats["modules_found"] = len(self._module_cache)

    def _enumerate_modules_via_handle(self):
        """Standard module enumeration using the process handle."""
        import pymem.process
        try:
            for mod in pymem.process.enum_process_module(self._handle):
                self._module_cache[mod.name.lower()] = (mod.lpBaseOfDll, mod.SizeOfImage)
        except Exception:
            pass

    def _enumerate_modules_via_peb(self):
        """
        Walk PEB->Ldr->InMemoryOrderModuleList via physical memory.
        No handle or API calls needed — pure memory reads.
        """
        # EPROCESS->Peb offset varies by Windows build. Try in order:
        #   0x550  Win11 22H2+
        #   0x510  Win10 20H1-22H2
        #   0x3E8  Win10 1703-1909 (older layouts)
        PEB_OFFSETS = (0x550, 0x510, 0x3E8)

        eprocess = self._driver._find_eprocess(self._pid)
        if not eprocess:
            return

        peb_addr = 0
        used_offset = 0
        for off in PEB_OFFSETS:
            try:
                raw = self._driver.read_physical(eprocess + off, 8)
                if len(raw) == 8:
                    candidate = struct.unpack("<Q", raw)[0]
                    # PEB is always 4KB-aligned in user space
                    if candidate and candidate % 0x1000 == 0 and candidate < 0x800000000000:
                        peb_addr = candidate
                        used_offset = off
                        break
            except Exception:
                continue
        if peb_addr == 0:
            return
        self._debug_stats["peb_offset"] = f"0x{used_offset:X}"

        # PEB->Ldr offset: 0x18
        ldr_addr = self.read_uint64(peb_addr + 0x18)
        if ldr_addr == 0:
            return

        # PEB_LDR_DATA->InMemoryOrderModuleList.Flink offset: 0x20
        list_head = ldr_addr + 0x20
        flink = self.read_uint64(list_head)

        visited = set()
        while flink != 0 and flink != list_head and flink not in visited:
            visited.add(flink)
            if len(visited) > 1024:
                break

            entry_base = flink - 0x10

            dll_base = self.read_uint64(entry_base + 0x30)
            size_of_image = self.read_uint32(entry_base + 0x40)

            name_len = self.read_uint16(entry_base + 0x58)
            name_buf_ptr = self.read_uint64(entry_base + 0x60)

            if name_len > 0 and name_buf_ptr > 0 and dll_base > 0:
                try:
                    name = self.read_wstring(name_buf_ptr, name_len // 2)
                    if name:
                        self._module_cache[name.lower()] = (dll_base, size_of_image)
                except Exception:
                    pass

            flink = self.read_uint64(flink)

    # ------------------------------------------------------------------
    # RIP-relative resolution (same as MemoryReader)
    # ------------------------------------------------------------------

    @staticmethod
    def resolve_relative(instruction_addr: int, offset_position: int, instruction_size: int, offset_bytes: bytes) -> int:
        rel = struct.unpack("<i", offset_bytes)[0]
        return instruction_addr + instruction_size + rel

    def resolve_rip_relative(self, pattern_addr: int, rip_offset_pos: int = 3, insn_len: int = 7) -> int:
        raw = self.read_bytes(pattern_addr + rip_offset_pos, 4)
        rel = struct.unpack("<i", raw)[0]
        return pattern_addr + insn_len + rel

    # ------------------------------------------------------------------
    # Debug & diagnostics
    # ------------------------------------------------------------------

    def get_debug_stats(self) -> dict:
        """Return comprehensive debug info for the debug panel."""
        stats = dict(self._debug_stats)
        stats["pid"] = self._pid
        stats["process_name"] = self._process_name or ""

        if self._jitter:
            stats["timing"] = self._jitter.get_stats()
        else:
            stats["timing"] = {"jitter": "disabled"}

        stats["module_list"] = [
            {"name": name, "base": f"0x{base:X}", "size": f"0x{size:X}"}
            for name, (base, size) in self._module_cache.items()
        ]

        return stats

    # ------------------------------------------------------------------
    # Status & cleanup
    # ------------------------------------------------------------------

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def access_method(self) -> AccessMethod:
        return self._active_method

    @property
    def method_name(self) -> str:
        names = {
            AccessMethod.PT_WALKER: "PT Walker (Physical CR3)",
            AccessMethod.DRIVER: "Kernel Driver (Physical)",
            AccessMethod.HIJACK: "Handle Hijack",
            AccessMethod.DIRECT: "Direct Attach",
        }
        return names.get(self._active_method, "Unknown")

    def close(self):
        if self._driver and self._driver.is_loaded:
            self._driver.unload()
        if self._handle and self._active_method != AccessMethod.DRIVER:
            k32.CloseHandle(self._handle)
            self._handle = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
