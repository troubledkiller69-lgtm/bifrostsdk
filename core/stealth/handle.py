"""
BIFROST SDK — Handle Hijacking
Instead of calling OpenProcess (which ACs monitor), we duplicate
an existing handle from a system process that already has access.

Targets: csrss.exe, lsass.exe, or any system service that holds
PROCESS_VM_READ handles to game processes.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
from dataclasses import dataclass
from typing import Optional

k32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll


# NtQuerySystemInformation constants
SYSTEM_HANDLE_INFORMATION = 16
SYSTEM_HANDLE_INFORMATION_EX = 64

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_SUCCESS = 0

PROCESS_DUP_HANDLE = 0x0040
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
DUPLICATE_SAME_ACCESS = 0x0002


@dataclass
class SystemHandle:
    """Represents a kernel handle entry."""
    pid: int
    handle_value: int
    object_type: int
    access_mask: int
    object_address: int


class HandleHijacker:
    """
    Acquire a process handle by duplicating one from a system process,
    bypassing ObRegisterCallbacks handle stripping.

    Strategy:
      1. Enumerate all system handles via NtQuerySystemInformation
      2. Find handles to our target PID held by privileged processes
      3. Duplicate the handle into our process with the access we need
    """

    # Processes that commonly hold handles to game processes
    DONOR_PROCESSES = ["csrss.exe", "lsass.exe", "services.exe", "svchost.exe"]

    # Object type index for Process objects (varies by Windows build)
    # Win10/11: typically 7
    PROCESS_OBJECT_TYPE = 7

    def __init__(self):
        self._handles: list[SystemHandle] = []

    def enumerate_handles(self) -> list[SystemHandle]:
        """
        Call NtQuerySystemInformation(SystemHandleInformationEx) to get
        all open handles in the system.
        """
        buf_size = 0x400000  # Start with 4MB

        while buf_size < 0x4000000:  # Cap at 64MB
            buf = (ctypes.c_ubyte * buf_size)()
            return_length = ctypes.c_ulong(0)

            status = ntdll.NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_EX,
                ctypes.byref(buf),
                buf_size,
                ctypes.byref(return_length),
            )

            if (status & 0xFFFFFFFF) == STATUS_INFO_LENGTH_MISMATCH:
                buf_size *= 2
                continue

            if status != STATUS_SUCCESS:
                raise OSError(f"NtQuerySystemInformation failed: 0x{status:08X}")

            break
        else:
            raise MemoryError("Handle enumeration buffer exceeded limit")

        # Parse SYSTEM_HANDLE_INFORMATION_EX structure
        # First 8 bytes: NumberOfHandles (ULONG_PTR)
        num_handles = struct.unpack_from("<Q", bytes(buf), 0)[0]

        handles = []
        # Each entry: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        # Layout: Object(8) + UniqueProcessId(8) + HandleValue(8) + GrantedAccess(4) +
        #          CreatorBackTraceIndex(2) + ObjectTypeIndex(2) + HandleAttributes(4) + Reserved(4)
        ENTRY_SIZE = 40
        HEADER_SIZE = 16  # NumberOfHandles(8) + Reserved(8)

        for i in range(min(num_handles, 500000)):  # safety cap
            offset = HEADER_SIZE + i * ENTRY_SIZE
            if offset + ENTRY_SIZE > buf_size:
                break

            entry = bytes(buf[offset:offset + ENTRY_SIZE])
            obj_addr = struct.unpack_from("<Q", entry, 0)[0]
            pid = struct.unpack_from("<Q", entry, 8)[0]
            handle_val = struct.unpack_from("<Q", entry, 16)[0]
            access = struct.unpack_from("<I", entry, 24)[0]
            obj_type = struct.unpack_from("<H", entry, 30)[0]

            handles.append(SystemHandle(
                pid=pid,
                handle_value=handle_val,
                object_type=obj_type,
                access_mask=access,
                object_address=obj_addr,
            ))

        self._handles = handles
        return handles

    def find_handle_to_process(
        self,
        target_pid: int,
        required_access: int = PROCESS_VM_READ,
    ) -> list[SystemHandle]:
        """
        Find handles that reference our target process with at least
        *required_access* permissions.
        """
        if not self._handles:
            self.enumerate_handles()

        # First, get the object address of our target process
        # We need to know what object address corresponds to target_pid
        # Strategy: open target briefly to get object address, then close
        target_object = self._get_process_object_address(target_pid)
        if not target_object:
            return []

        matches = []
        for h in self._handles:
            if h.object_type != self.PROCESS_OBJECT_TYPE:
                continue
            if h.object_address != target_object:
                continue
            if (h.access_mask & required_access) != required_access:
                continue
            if h.pid == target_pid:
                continue  # skip self-handles
            matches.append(h)

        return matches

    def _get_process_object_address(self, pid: int) -> int:
        """
        Briefly open the process to determine its kernel object address.
        We compare this against the handle table to find donors.
        """
        # Open with minimum access just to identify
        handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return 0

        try:
            # Query the object address for our handle
            # NtQueryObject or compare against our own handle in the table
            if not self._handles:
                self.enumerate_handles()

            our_pid = k32.GetCurrentProcessId()
            for h in self._handles:
                if h.pid == our_pid and h.handle_value == handle:
                    return h.object_address
        finally:
            k32.CloseHandle(handle)

        return 0

    def hijack(
        self,
        target_pid: int,
        desired_access: int = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
    ) -> int:
        """
        Hijack a handle to *target_pid* from a donor system process.
        Returns a duplicated handle in our process, or 0 on failure.
        """
        candidates = self.find_handle_to_process(target_pid, desired_access)

        if not candidates:
            # Fallback: look for ANY handle to the target, even with lesser access
            candidates = self.find_handle_to_process(target_pid, 0x0001)

        for candidate in candidates:
            # Open the donor process
            donor_handle = k32.OpenProcess(
                PROCESS_DUP_HANDLE, False, candidate.pid
            )
            if not donor_handle:
                continue

            # Duplicate the handle from donor into our process
            duplicated = wt.HANDLE(0)
            success = k32.DuplicateHandle(
                donor_handle,
                candidate.handle_value,
                k32.GetCurrentProcess(),
                ctypes.byref(duplicated),
                desired_access,
                False,
                0,  # Don't use DUPLICATE_SAME_ACCESS — request specific rights
            )

            k32.CloseHandle(donor_handle)

            if success and duplicated.value:
                return duplicated.value

        return 0

    def hijack_from_csrss(self, target_pid: int) -> int:
        """
        Specifically target csrss.exe as the donor — it holds handles
        to all user processes and typically isn't monitored by game ACs.
        """
        import psutil

        csrss_pids = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"].lower() == "csrss.exe":
                    csrss_pids.append(proc.info["pid"])
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        if not self._handles:
            self.enumerate_handles()

        for csrss_pid in csrss_pids:
            # Find handles held by this csrss instance
            for h in self._handles:
                if h.pid != csrss_pid:
                    continue
                if h.object_type != self.PROCESS_OBJECT_TYPE:
                    continue

                # Try to duplicate
                donor = k32.OpenProcess(PROCESS_DUP_HANDLE, False, csrss_pid)
                if not donor:
                    continue

                duplicated = wt.HANDLE(0)
                success = k32.DuplicateHandle(
                    donor,
                    h.handle_value,
                    k32.GetCurrentProcess(),
                    ctypes.byref(duplicated),
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    False, 0,
                )
                k32.CloseHandle(donor)

                if success and duplicated.value:
                    # Verify this handle is to our target
                    check_pid = ctypes.c_ulong(0)
                    k32.GetProcessId(duplicated.value)
                    if k32.GetProcessId(duplicated.value) == target_pid:
                        return duplicated.value
                    else:
                        k32.CloseHandle(duplicated.value)

        return 0
