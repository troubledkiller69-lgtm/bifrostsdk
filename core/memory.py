"""
BIFROST SDK — Process Memory Reader
Wraps pymem into a clean, engine-agnostic API for reading remote process memory.
Handles module enumeration, base resolution, and typed reads.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
from typing import Optional, Protocol, runtime_checkable

import pefile
import pymem
import pymem.process


@runtime_checkable
class ReaderProtocol(Protocol):
    """
    Structural typing protocol for all memory readers.
    Both MemoryReader and StealthReader satisfy this interface.
    Used as a type annotation for engine dumpers that accept either reader type.
    """

    def read_bytes(self, addr: int, size: int) -> bytes: ...
    def read_ptr(self, addr: int) -> int: ...
    def read_int32(self, addr: int) -> int: ...
    def read_uint16(self, addr: int) -> int: ...
    def read_uint64(self, addr: int) -> int: ...
    def read_string(self, addr: int, max_len: int = 256, encoding: str = "utf-8") -> str: ...
    def module_base(self, module_name: str) -> int: ...
    def module_size(self, module_name: str) -> int: ...
    def list_modules(self) -> list[dict]: ...
    def get_module_sections(self, module_name: str) -> list[dict]: ...
    def resolve_rip_relative(self, pattern_addr: int, rip_offset_pos: int = 3, insn_len: int = 7) -> int: ...
    def close(self) -> None: ...


class MemoryReader:
    """Attach to a running process and perform typed memory reads."""

    def __init__(self, process_name: str | None = None, pid: int | None = None):
        if process_name:
            self._pm = pymem.Pymem(process_name)
        elif pid:
            self._pm = pymem.Pymem()
            self._pm.open_process_from_id(pid)
        else:
            raise ValueError("Provide either process_name or pid")

        self.pid: int = self._pm.process_id
        self.handle = self._pm.process_handle
        self._module_cache: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Module helpers
    # ------------------------------------------------------------------

    def module_base(self, module_name: str) -> int:
        """Return the base address of *module_name* (cached)."""
        key = module_name.lower()
        if key in self._module_cache:
            return self._module_cache[key]

        # Strategy 1 (main executable only): PEB ImageBaseAddress.
        # PEB+0x10 ALWAYS holds the main exe base — using it for other
        # modules poisons the cache with the wrong address. Only take this
        # path when the requested name matches the process executable.
        exe_name = self._pm.process_base["name"].lower() if self._pm.process_base else ""
        if exe_name and key in (exe_name, exe_name.replace(".exe", "")):
            try:
                ntdll = ctypes.windll.ntdll
                k32 = ctypes.windll.kernel32

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
                    self.handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
                )
                if status == 0 and pbi.PebBaseAddress:
                    buf = (ctypes.c_ubyte * 8)()
                    bytes_read = ctypes.c_size_t()
                    success = k32.ReadProcessMemory(
                        self.handle, pbi.PebBaseAddress + 0x10,
                        ctypes.byref(buf), 8, ctypes.byref(bytes_read),
                    )
                    if success:
                        base_addr = struct.unpack('<Q', bytearray(buf))[0]
                        if base_addr > 0:
                            self._module_cache[key] = base_addr
                            return base_addr
            except Exception as e:
                print(f"[MemoryReader] PEB fallback failed: {e}")

        # Strategy 2: Win32 API (EnumProcessModules) — the correct path for
        # every non-executable module and the fallback for the exe itself.
        try:
            mod = pymem.process.module_from_name(self.handle, module_name)
            if mod is not None:
                self._module_cache[key] = mod.lpBaseOfDll
                return mod.lpBaseOfDll
        except Exception as e:
            print(f"[MemoryReader] EnumProcessModules failed: {e}")

        raise RuntimeError(f"Module '{module_name}' not found")

    def module_size(self, module_name: str) -> int:
        mod = None
        try:
            mod = pymem.process.module_from_name(self.handle, module_name)
        except Exception:
            pass
            
        if mod is not None:
            return mod.SizeOfImage
            
        # Fallback to list_modules which uses Toolhelp32Snapshot
        for m in self.list_modules():
            if m["name"].lower() == module_name.lower():
                return m["size"]
                
        raise RuntimeError(f"Module '{module_name}' not found")

    def list_modules(self) -> list[dict]:
        """Return all loaded modules as [{name, base, size}]."""
        out = []
        try:
            for mod in pymem.process.enum_process_module(self.handle):
                out.append({
                    "name": mod.name,
                    "base": mod.lpBaseOfDll,
                    "size": mod.SizeOfImage,
                })
        except Exception:
            pass

        # Fallback to Toolhelp32Snapshot if EnumProcessModules failed or returned nothing
        # (often happens when anti-cheat strips PROCESS_QUERY_INFORMATION but leaves basic access)
        if not out:
            try:
                for mod in self._pm.list_modules():
                    out.append({
                        "name": mod.name,
                        "base": mod.lpBaseOfDll,
                        "size": mod.SizeOfImage,
                    })
            except Exception:
                pass

        return out

    def get_module_sections(self, module_name: str) -> list[dict]:
        """
        Read the PE header from memory and return a list of mapped sections.
        This is crucial for stealth pattern scanning to avoid unmapped memory BSODs.
        Returns: [{"name": ".text", "rva": 0x1000, "size": 0x5000}, ...]
        """
        base = self.module_base(module_name)
        # Read the first 0x1000 bytes (DOS header, NT headers, Section headers)
        try:
            header_data = self.read_bytes(base, 0x1000)
            pe = pefile.PE(data=header_data, fast_load=True)
            sections = []
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                sections.append({
                    "name": sec_name,
                    "rva": section.VirtualAddress,
                    "size": section.Misc_VirtualSize
                })
            return sections
        except Exception as e:
            print(f"[!] PE Parsing failed for {module_name}: {e}")
            return []

    # ------------------------------------------------------------------
    # Primitive reads
    # ------------------------------------------------------------------

    def read_bytes(self, addr: int, size: int) -> bytes:
        return self._pm.read_bytes(addr, size)

    def read_bool(self, addr: int) -> bool:
        return self._pm.read_bool(addr)

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
        """Read a 64-bit pointer."""
        return self.read_uint64(addr)

    def read_string(self, addr: int, max_len: int = 256, encoding: str = "utf-8") -> str:
        """Read a null-terminated string."""
        raw = self.read_bytes(addr, max_len)
        null = raw.find(b"\x00")
        if null != -1:
            raw = raw[:null]
        return raw.decode(encoding, errors="replace")

    def read_wstring(self, addr: int, max_len: int = 256) -> str:
        """Read a null-terminated wide string (UTF-16LE)."""
        raw = self.read_bytes(addr, max_len * 2)
        result = []
        for i in range(0, len(raw), 2):
            ch = struct.unpack_from("<H", raw, i)[0]
            if ch == 0:
                break
            result.append(chr(ch))
        return "".join(result)

    # ------------------------------------------------------------------
    # Pointer chain / multi-level dereference
    # ------------------------------------------------------------------

    def read_pointer_chain(self, base: int, offsets: list[int]) -> int:
        """Follow a chain of pointers: base -> [off0] -> [off1] -> ..."""
        addr = base
        for off in offsets:
            addr = self.read_ptr(addr) + off
        return addr

    # ------------------------------------------------------------------
    # Relative address resolution (for pattern scan results)
    # ------------------------------------------------------------------

    @staticmethod
    def resolve_relative(instruction_addr: int, offset_position: int, instruction_size: int, offset_bytes: bytes) -> int:
        """
        Resolve a RIP-relative address from a pattern hit.
        
        instruction_addr  : address where the matched pattern begins
        offset_position   : byte index within the pattern where the 4-byte offset lives
        instruction_size  : total length of the instruction
        offset_bytes      : the 4 raw bytes of the relative offset
        """
        rel = struct.unpack("<i", offset_bytes)[0]
        return instruction_addr + instruction_size + rel

    def resolve_rip_relative(self, pattern_addr: int, rip_offset_pos: int = 3, insn_len: int = 7) -> int:
        """
        Common helper: read a RIP-relative LEA/MOV at *pattern_addr* and resolve it.
        Default assumes `48 8B 05 xx xx xx xx` (MOV RAX, [rip+xx]) style.
        """
        raw = self.read_bytes(pattern_addr + rip_offset_pos, 4)
        rel = struct.unpack("<i", raw)[0]
        return pattern_addr + insn_len + rel

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self):
        try:
            self._pm.close_process()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
