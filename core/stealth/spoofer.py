"""
BIFROST SDK — HWID Spoofer
Implements deep temporary spoofing for 20 hardware identifiers across 6 phases.
Utilizes the polymorphic DriverInterface for physical memory patching.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import glob
import logging
import os
import random
import string
import struct
import subprocess
import time
import uuid
from typing import Optional

try:
    from core.stealth.driver import DriverInterface
except ImportError:
    pass

from core.stealth.hardware_reader import HardwareReader

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Result schema — locked in before run_all() per council recommendation.
# Order matches phase ordering and is the contract the UI relies on.
# Adding a key here requires a parallel update in SpooferPage.jsx.
# ----------------------------------------------------------------------
RUN_ALL_KEYS = (
    # Phase 1 — Network & Disk (3)
    "mac", "volume", "disk_firmware",
    # Phase 2 — SMBIOS & Physical (5)
    "smbios", "smbios_uuid", "baseboard", "bios", "monitor",
    # Phase 3 — Registry Identity (6)
    "guid", "gpu", "windows_ids", "hostname", "install_date", "machine_sid",
    # Phase 4 — Device History (2)
    "usb_history", "bluetooth",
    # Phase 5 — Cache & Trace Cleanup (4)
    "event_logs", "arp_flush", "dns_flush", "prefetch_recent",
)
PHASE_KEYS = {
    1: ("mac", "volume", "disk_firmware"),
    2: ("smbios", "smbios_uuid", "baseboard", "bios", "monitor"),
    3: ("guid", "gpu", "windows_ids", "hostname", "install_date", "machine_sid"),
    4: ("usb_history", "bluetooth"),
    5: ("event_logs", "arp_flush", "dns_flush", "prefetch_recent"),
}


def _has_admin() -> bool:
    """Return True if the current process has Administrator privileges on Windows."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_hidden(cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run a shell command without flashing a console window."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        cmd, shell=True, capture_output=True, timeout=timeout,
        creationflags=creationflags,
    )


class HardwareSpoofer:
    # Class-level dry-run flag (council recommendation). When True, methods log
    # what they WOULD do but don't write. Per-method dry-run plumbing is
    # additive — methods that don't honor it yet fall through to live behavior.
    def __init__(self, driver: 'DriverInterface', dry_run: bool = False):
        self.driver = driver
        self._log_callback = None
        self.dry_run = dry_run
        # Elevation check: surfaced once at construction so the UI/log shows it,
        # but individual methods that need SYSTEM-level access (e.g. machine_sid)
        # still need their own ACCESS_DENIED handling.
        self.is_admin = _has_admin()
        # All hardware reads delegated to HardwareReader. Logging the reader's
        # internal errors goes through self._log so they appear in the same
        # stream as spoofer logs.
        self._reader = HardwareReader(log_callback=self._log)

    def set_logger(self, callback):
        self._log_callback = callback
        # Reader was created before set_logger ran (in __init__), so any
        # callback registered after construction also needs to reach it.
        self._reader = HardwareReader(log_callback=self._log)

    def _log(self, msg: str):
        if self._log_callback:
            self._log_callback(msg)
        else:
            print(msg)

    def _random_mac(self) -> str:
        """Generate a random locally administered MAC address."""
        mac = [
            random.choice([0x02, 0x06, 0x0A, 0x0E]),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF)
        ]
        return ''.join(f'{x:02X}' for x in mac)

    def _random_serial(self, length: int = 14) -> str:
        chars = string.ascii_uppercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def _random_hex_serial(self, length: int = 8) -> str:
        return ''.join(random.choice(string.hexdigits.upper()) for _ in range(length))

    def _random_uuid(self) -> str:
        return str(uuid.uuid4()).upper()

    def _random_sid_subauth(self) -> str:
        return '-'.join(str(random.randint(1000000000, 4294967295)) for _ in range(3))

    def _find_smbios_table(self):
        """Locate SMBIOS entry point in physical memory. Returns (table_address, table_length, data) or None."""
        if not self.driver or not self.driver.is_loaded:
            return None
        chunk = self.driver.read_physical(0x000F0000, 0x10000)
        idx = chunk.find(b"_SM_")
        if idx == -1:
            return None
        table_length = struct.unpack("<H", chunk[idx+0x16:idx+0x18])[0]
        table_address = struct.unpack("<I", chunk[idx+0x18:idx+0x1C])[0]
        if table_address >= 0xFFFFFFFF:
            # SMBIOS 3.x entry points use 64-bit table addresses; the legacy
            # entry point format cannot represent them. Surface the gap
            # instead of silently reading garbage.
            self._log("[-] SMBIOS table above 4GB — 64-bit entry point unsupported")
            return None
        try:
            data = bytearray(self.driver.read_physical(table_address, table_length))
            return (table_address, table_length, data)
        except Exception:
            return None

    def spoof_mac(self, mode: str, custom_mac: str) -> bool:
        """Registry-based MAC spoofing + adapter restart."""
        self._log("[*] Starting Registry MAC Address Spoofing...")
        try:
            import winreg
            new_mac = custom_mac.replace("-", "").replace(":", "") if mode == "custom" and custom_mac else self._random_mac()
            
            net_key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    subkey_name = winreg.EnumKey(key, i)
                    try:
                        with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ | winreg.KEY_WRITE) as subkey:
                            try:
                                winreg.QueryValueEx(subkey, "DriverDesc")
                                winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, new_mac)
                            except OSError:
                                continue
                    except OSError:
                        continue
                        
            self._log(f"[+] Overwriting Permanent MAC Address -> {new_mac}")
            self._log("[*] Resetting network adapters to apply changes...")
            cmd = 'powershell -ExecutionPolicy Bypass -Command "Get-NetAdapter -Physical | Restart-NetAdapter"'
            _run_hidden(cmd, timeout=30)
            self._log("[+] Network adapters restarted successfully.")
            return True
        except Exception as e:
            self._log(f"[-] NDIS MAC Spoofing Failed: {e}")
            return False

    def spoof_disk_volume(self, mode: str, custom_serial: str) -> bool:
        """Spoof Volume ID via Registry (Requires reboot or device restart)."""
        self._log("[*] Starting Registry Disk Hardware Spoofing...")
        try:
            import winreg
            new_serial = custom_serial if mode == "custom" and custom_serial else self._random_serial(12)
            patched = 0

            hw_key = r"HARDWARE\DEVICEMAP\Scsi"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hw_key, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    num_ports = winreg.QueryInfoKey(key)[0]
                    for i in range(num_ports):
                        port_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, port_name) as port_key:
                            num_buses = winreg.QueryInfoKey(port_key)[0]
                            for j in range(num_buses):
                                bus_name = winreg.EnumKey(port_key, j)
                                try:
                                    tgt_path = f"{hw_key}\\{port_name}\\{bus_name}\\Target Id 0\\Logical Unit Id 0"
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tgt_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as lu_key:
                                        winreg.SetValueEx(lu_key, "Identifier", 0, winreg.REG_SZ, new_serial)
                                        patched += 1
                                except OSError:
                                    pass
            except OSError:
                pass

            self._log(f"[+] Disk volume serial patched ({patched} entries). Serial: {new_serial}")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Disk Spoofing failed: {e}")
            return False

    def spoof_smbios_physical(self, mode: str, custom_serial: str) -> bool:
        """
        Locate and patch SMBIOS structures in physical memory.
        This is a Ring-0 stealth operation that modifies memory before AC reads it.
        """
        if not self.driver or not self.driver.is_loaded:
            self._log("[-] Cannot spoof SMBIOS: Kernel Driver not loaded.")
            return False

        self._log("[*] Starting Physical SMBIOS Spoofing via Polymorphic Driver...")
        
        # 1. Find the SMBIOS Entry Point in physical memory (usually 0x000F0000 to 0x000FFFFF)
        table_address = 0
        table_length = 0
        
        # _SM_ anchor
        target_anchor = b"_SM_"
        chunk = self.driver.read_physical(0x000F0000, 0x10000)
        
        idx = chunk.find(target_anchor)
        if idx == -1:
            self._log("[-] SMBIOS Anchor not found in physical memory.")
            return False
            
        self._log(f"[+] Found SMBIOS Anchor at Physical Address: 0x{0x000F0000 + idx:X}")
        
        # Read the Entry Point Structure
        # Offset 0x16 is the 16-bit table length
        # Offset 0x18 is the 32-bit table address
        table_length = struct.unpack("<H", chunk[idx+0x16:idx+0x18])[0]
        table_address = struct.unpack("<I", chunk[idx+0x18:idx+0x1C])[0]
        
        self._log(f"[+] SMBIOS Table Address: 0x{table_address:X}, Length: {table_length} bytes")
        
        # 2. Read the entire SMBIOS Table
        try:
            smbios_data = bytearray(self.driver.read_physical(table_address, table_length))
        except Exception as e:
            self._log(f"[-] Failed to read SMBIOS table: {e}")
            return False
            
        # 3. Parse and Patch Structures
        offset = 0
        patched_count = 0
        while offset < table_length:
            header_type = smbios_data[offset]
            header_length = smbios_data[offset + 1]
            if header_length < 4:
                break
                
            # Types: 1 (System), 2 (Baseboard), 3 (Chassis)
            if header_type in [1, 2, 3]:
                # We need to find the string section at the end of the formatted area
                string_offset = offset + header_length
                
                # Iterate strings until we hit double null
                str_idx = 1
                curr_str_start = string_offset
                while curr_str_start < table_length and smbios_data[curr_str_start] != 0:
                    str_end = smbios_data.find(b'\x00', curr_str_start)
                    if str_end == -1: break
                    
                    old_str = smbios_data[curr_str_start:str_end].decode('utf-8', errors='ignore')
                    
                    # If this string looks like a serial number or UUID, replace it
                    # We only overwrite characters to preserve the exact struct size in memory
                    if any(c.isdigit() for c in old_str) and len(old_str) > 5:
                        if mode == "custom" and custom_serial:
                            if len(custom_serial) > len(old_str):
                                new_str = custom_serial[:len(old_str)]
                            else:
                                new_str = custom_serial.ljust(len(old_str), ' ')
                        else:
                            new_str = self._random_serial(len(old_str))
                        # Patch the bytearray
                        smbios_data[curr_str_start:str_end] = new_str.encode()
                        self._log(f"[+] Patched SMBIOS Type {header_type} string: {old_str} -> {new_str}")
                        patched_count += 1
                        
                    curr_str_start = str_end + 1
                    str_idx += 1
                    
            # Advance to next structure (past double null)
            offset += header_length
            while offset < table_length - 1:
                if smbios_data[offset] == 0 and smbios_data[offset+1] == 0:
                    offset += 2
                    break
                offset += 1
                
        # 4. Write Patched Table back to Physical Memory
        if patched_count > 0:
            try:
                self.driver.write_physical(table_address, bytes(smbios_data))
                self._log(f"[+] Successfully wrote patched SMBIOS back to physical memory.")
                return True
            except Exception as e:
                self._log(f"[-] Failed to write physical memory: {e}")
                return False
        else:
            self._log("[!] No patchable serials found in SMBIOS table.")
            return False

    def spoof_guids(self, mode: str, custom_guid: str) -> bool:
        """Spoofs MachineGuid and HardwareProfileGuid"""
        self._log("[*] Starting System GUID Spoofing...")
        try:
            import winreg
            new_guid = custom_guid if mode == "custom" and custom_guid else f"{{{self._random_hex_serial(8)}-{self._random_hex_serial(4)}-{self._random_hex_serial(4)}-{self._random_hex_serial(4)}-{self._random_hex_serial(12)}}}"
            
            machine_guid = new_guid.strip('{}')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, machine_guid)
                
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "HwProfileGuid", 0, winreg.REG_SZ, new_guid)
                
            self._log(f"[+] HardwareProfileGuid updated -> {new_guid}")
            self._log(f"[+] MachineGuid updated -> {machine_guid}")
            return True
        except Exception as e:
            self._log(f"[-] GUID Spoofing Failed: {e}")
            return False

    def spoof_monitors(self, mode: str, custom_serial: str) -> bool:
        """
        Spoof EDID serials for Monitors.
        Patches both the manufacturer serial (bytes 12-15) and the ASCII serial
        descriptor block (tag 0xFF), then recalculates the EDID checksum.
        """
        self._log("[*] Starting Monitor EDID Spoofing...")
        try:
            import winreg
            new_mon = custom_serial if mode == "custom" and custom_serial else self._random_serial(8)
            patched = 0

            display_key = r"SYSTEM\CurrentControlSet\Enum\DISPLAY"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, display_key, 0, winreg.KEY_READ) as key:
                num_monitors = winreg.QueryInfoKey(key)[0]
                for i in range(num_monitors):
                    mon_id = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, mon_id, 0, winreg.KEY_READ) as mon_key:
                        num_inst = winreg.QueryInfoKey(mon_key)[0]
                        for j in range(num_inst):
                            inst_id = winreg.EnumKey(mon_key, j)
                            try:
                                dev_param_path = f"{display_key}\\{mon_id}\\{inst_id}\\Device Parameters"
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_param_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as dp_key:
                                    try:
                                        edid, _ = winreg.QueryValueEx(dp_key, "EDID")
                                        edid = bytearray(edid)
                                        if len(edid) < 128:
                                            continue

                                        # Patch manufacturer serial (bytes 12-15)
                                        edid[12:16] = os.urandom(4)

                                        # Patch ASCII serial descriptor (tag 0xFF in descriptor blocks)
                                        # EDID descriptors start at byte 54, each is 18 bytes
                                        for desc_start in (54, 72, 90, 108):
                                            if desc_start + 18 > len(edid):
                                                break
                                            # Check for monitor serial descriptor: bytes 0-2 = 0x00, byte 3 = 0xFF
                                            if (edid[desc_start] == 0 and edid[desc_start + 1] == 0
                                                    and edid[desc_start + 2] == 0 and edid[desc_start + 3] == 0xFF):
                                                # ASCII serial is bytes 5-17 of the descriptor, padded with 0x0A/spaces
                                                serial_bytes = new_mon[:13].encode('ascii', errors='replace')
                                                serial_bytes = serial_bytes.ljust(13, b'\x0a')
                                                edid[desc_start + 5:desc_start + 18] = serial_bytes

                                        # Recalculate checksum (byte 127 = makes sum of 0-127 == 0 mod 256)
                                        edid[127] = (256 - (sum(edid[:127]) % 256)) % 256

                                        winreg.SetValueEx(dp_key, "EDID", 0, winreg.REG_BINARY, bytes(edid))
                                        patched += 1
                                    except OSError:
                                        pass
                            except OSError:
                                pass

            self._log(f"[+] Display EDID overrides applied ({patched} monitors). Serial Base: {new_mon}")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Monitor Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # NEW: Disk Firmware Serial Spoofing (G1 — CRITICAL)
    # ------------------------------------------------------------------

    def spoof_disk_firmware(self, mode: str, custom_serial: str) -> bool:
        """
        Spoof NVMe/SATA disk firmware serial numbers.
        Anti-cheats query firmware serials directly via IOCTL_STORAGE_QUERY_PROPERTY,
        which bypasses our SCSI registry spoof. This patches deeper registry keys
        that store the device identity strings used by the storage stack.
        """
        self._log("[*] Starting Disk Firmware Serial Spoofing...")
        try:
            import winreg
            new_serial = custom_serial if mode == "custom" and custom_serial else self._random_serial(20)
            patched = 0

            # 1. Patch SCSI device identity strings (NVMe devices appear as SCSI)
            scsi_enum = r"SYSTEM\CurrentControlSet\Enum\SCSI"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, scsi_enum, 0, winreg.KEY_READ) as scsi_key:
                    num_devs = winreg.QueryInfoKey(scsi_key)[0]
                    for i in range(num_devs):
                        dev_class = winreg.EnumKey(scsi_key, i)
                        dev_path = f"{scsi_enum}\\{dev_class}"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_path, 0, winreg.KEY_READ) as dev_key:
                                num_inst = winreg.QueryInfoKey(dev_key)[0]
                                for j in range(num_inst):
                                    inst_id = winreg.EnumKey(dev_key, j)
                                    inst_path = f"{dev_path}\\{inst_id}"
                                    try:
                                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inst_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as inst_key:
                                            # Patch FriendlyName if it contains a serial
                                            try:
                                                fn, fn_type = winreg.QueryValueEx(inst_key, "FriendlyName")
                                                if fn_type == winreg.REG_SZ and any(c.isdigit() for c in fn):
                                                    winreg.SetValueEx(inst_key, "FriendlyName", 0, winreg.REG_SZ,
                                                                      f"NVMe SSD Drive {new_serial[:8]}")
                                                    patched += 1
                                            except OSError:
                                                pass
                                    except OSError:
                                        pass
                        except OSError:
                            pass
            except OSError:
                pass

            # 2. Patch StorPort miniport device parameters
            storage_enum = r"SYSTEM\CurrentControlSet\Enum\STORAHCI"
            for root_key_path in [storage_enum, r"SYSTEM\CurrentControlSet\Enum\STORNVME"]:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_key_path, 0, winreg.KEY_READ) as root_key:
                        num_devs = winreg.QueryInfoKey(root_key)[0]
                        for i in range(num_devs):
                            dev_name = winreg.EnumKey(root_key, i)
                            dev_path = f"{root_key_path}\\{dev_name}"
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_path, 0, winreg.KEY_READ) as dev_key:
                                    num_inst = winreg.QueryInfoKey(dev_key)[0]
                                    for j in range(num_inst):
                                        inst_id = winreg.EnumKey(dev_key, j)
                                        dp_path = f"{dev_path}\\{inst_id}\\Device Parameters\\StorPort"
                                        try:
                                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dp_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as dp_key:
                                                # Some storage drivers cache serial here
                                                try:
                                                    winreg.SetValueEx(dp_key, "SerialNumber", 0, winreg.REG_SZ, new_serial)
                                                    patched += 1
                                                except OSError:
                                                    pass
                                        except OSError:
                                            pass
                            except OSError:
                                pass
                except OSError:
                    pass

            # 3. Also patch the existing SCSI DeviceMap with the firmware serial
            hw_key = r"HARDWARE\DEVICEMAP\Scsi"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hw_key, 0, winreg.KEY_READ) as key:
                    num_ports = winreg.QueryInfoKey(key)[0]
                    for i in range(num_ports):
                        port_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, port_name) as port_key:
                            num_buses = winreg.QueryInfoKey(port_key)[0]
                            for j in range(num_buses):
                                bus_name = winreg.EnumKey(port_key, j)
                                try:
                                    tgt_path = f"{hw_key}\\{port_name}\\{bus_name}\\Target Id 0\\Logical Unit Id 0"
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tgt_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as lu_key:
                                        winreg.SetValueEx(lu_key, "SerialNumber", 0, winreg.REG_SZ, new_serial)
                                        patched += 1
                                except OSError:
                                    pass
            except OSError:
                pass

            self._log(f"[+] Disk firmware serial patched ({patched} entries). Serial: {new_serial}")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Disk Firmware Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # NEW: GPU Device ID Spoofing (G2 — HIGH)
    # ------------------------------------------------------------------

    def spoof_gpu_ids(self, mode: str, custom_gpu: str) -> bool:
        """
        Spoof GPU adapter string and hardware information in the registry.
        Anti-cheats read Win32_VideoController via WMI, which reads from
        the display adapter class registry keys.
        """
        self._log("[*] Starting GPU Identity Spoofing...")
        try:
            import winreg
            patched = 0

            # GPU class GUID: {4d36e968-e325-11ce-bfc1-08002be10318}
            gpu_class = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, gpu_class, 0, winreg.KEY_READ) as class_key:
                    num_subkeys = winreg.QueryInfoKey(class_key)[0]
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(class_key, i)
                        # Skip non-numeric keys like "Properties"
                        if not subkey_name.isdigit():
                            continue
                        subkey_path = f"{gpu_class}\\{subkey_name}"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as gpu_key:
                                # Read current adapter string for logging
                                try:
                                    old_name, _ = winreg.QueryValueEx(gpu_key, "HardwareInformation.AdapterString")
                                    self._log(f"[*] Found GPU: {old_name}")
                                except OSError:
                                    old_name = "Unknown GPU"

                                # Generate spoofed adapter name
                                if mode == "custom" and custom_gpu:
                                    new_name = custom_gpu
                                else:
                                    gpu_models = [
                                        "NVIDIA GeForce RTX 4070",
                                        "NVIDIA GeForce RTX 3060 Ti",
                                        "AMD Radeon RX 7600 XT",
                                        "NVIDIA GeForce GTX 1660 SUPER",
                                        "AMD Radeon RX 6700 XT",
                                        "Intel Arc A770",
                                    ]
                                    new_name = random.choice(gpu_models)

                                # Patch adapter string
                                try:
                                    winreg.SetValueEx(gpu_key, "HardwareInformation.AdapterString", 0, winreg.REG_SZ, new_name)
                                    patched += 1
                                except OSError:
                                    pass

                                # Patch VRAM size to match (randomize slightly)
                                try:
                                    vram_gb = random.choice([8, 12, 16])
                                    vram_bytes = vram_gb * 1024 * 1024 * 1024
                                    winreg.SetValueEx(gpu_key, "HardwareInformation.qwMemorySize", 0, winreg.REG_QWORD, vram_bytes)
                                except OSError:
                                    pass

                                # Patch chip type
                                try:
                                    winreg.SetValueEx(gpu_key, "HardwareInformation.ChipType", 0, winreg.REG_SZ,
                                                      f"GPU-{self._random_hex_serial(4)}")
                                except OSError:
                                    pass

                                # Patch DAC type
                                try:
                                    winreg.SetValueEx(gpu_key, "HardwareInformation.DacType", 0, winreg.REG_SZ, "Internal")
                                except OSError:
                                    pass

                                self._log(f"[+] GPU spoofed: {old_name} -> {new_name}")
                        except OSError:
                            pass
            except OSError:
                pass

            self._log(f"[+] GPU identity spoofed ({patched} adapters patched).")
            return patched > 0
        except Exception as e:
            self._log(f"[-] GPU Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # NEW: Windows Product/Installation ID Spoofing (G3 — HIGH)
    # ------------------------------------------------------------------

    def spoof_windows_ids(self, mode: str, custom_product_id: str) -> bool:
        """
        Spoof Windows Product ID, Build GUID, and related installation identifiers.
        These are unique per Windows install and trivially queried by anti-cheats.
        """
        self._log("[*] Starting Windows ID Spoofing...")
        try:
            import winreg
            patched = 0

            nt_version = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, nt_version, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
                    # ProductId: XXXXX-XXX-XXXXXXX-XXXXX
                    if mode == "custom" and custom_product_id:
                        new_pid = custom_product_id
                    else:
                        p1 = ''.join(random.choices(string.digits, k=5))
                        p2 = ''.join(random.choices(string.digits, k=3))
                        p3 = ''.join(random.choices(string.digits, k=7))
                        p4 = ''.join(random.choices(string.digits, k=5))
                        new_pid = f"{p1}-{p2}-{p3}-{p4}"

                    try:
                        winreg.SetValueEx(key, "ProductId", 0, winreg.REG_SZ, new_pid)
                        self._log(f"[+] ProductId -> {new_pid}")
                        patched += 1
                    except OSError as e:
                        self._log(f"[!] Could not set ProductId: {e}")

                    # BuildGUID
                    try:
                        new_build_guid = f"{self._random_hex_serial(8)}-{self._random_hex_serial(4)}-{self._random_hex_serial(4)}-{self._random_hex_serial(4)}-{self._random_hex_serial(12)}"
                        winreg.SetValueEx(key, "BuildGUID", 0, winreg.REG_SZ, new_build_guid)
                        patched += 1
                    except OSError:
                        pass

                    # DigitalProductId — binary blob, randomize non-header bytes
                    try:
                        dpid, dpid_type = winreg.QueryValueEx(key, "DigitalProductId")
                        dpid = bytearray(dpid)
                        if len(dpid) > 8:
                            # Randomize bytes 8 onwards (skip header)
                            for k in range(8, min(len(dpid), 67)):
                                dpid[k] = random.randint(0, 255)
                            winreg.SetValueEx(key, "DigitalProductId", 0, dpid_type, bytes(dpid))
                            patched += 1
                    except OSError:
                        pass

                    # DigitalProductId4 — extended blob
                    try:
                        dpid4, dpid4_type = winreg.QueryValueEx(key, "DigitalProductId4")
                        dpid4 = bytearray(dpid4)
                        if len(dpid4) > 8:
                            for k in range(8, min(len(dpid4), 128)):
                                dpid4[k] = random.randint(0, 255)
                            winreg.SetValueEx(key, "DigitalProductId4", 0, dpid4_type, bytes(dpid4))
                            patched += 1
                    except OSError:
                        pass

            except OSError as e:
                self._log(f"[!] Could not open Windows NT\\CurrentVersion: {e}")

            self._log(f"[+] Windows IDs spoofed ({patched} values patched).")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Windows ID Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # NEW: Computer Name / Hostname Spoofing (G4 — MEDIUM)
    # ------------------------------------------------------------------

    def spoof_hostname(self, mode: str, custom_hostname: str) -> bool:
        """
        Spoof the computer name and hostname in all relevant registry locations.
        Generates a realistic Windows-default pattern like DESKTOP-XXXXXXX.
        """
        self._log("[*] Starting Hostname Spoofing...")
        try:
            import winreg

            if mode == "custom" and custom_hostname:
                new_name = custom_hostname[:15]  # NetBIOS limit
            else:
                suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
                new_name = f"DESKTOP-{suffix}"

            patched = 0
            # Registry locations for computer name
            name_paths = [
                (r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName"),
                (r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName"),
                (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname"),
                (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "NV Hostname"),
            ]

            for reg_path, value_name in name_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_name)
                        patched += 1
                except OSError:
                    pass

            self._log(f"[+] Hostname spoofed to: {new_name} ({patched} registry entries)")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Hostname Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # NEW: Windows Install Date Spoofing (G5 — MEDIUM)
    # ------------------------------------------------------------------

    def spoof_install_date(self, mode: str, custom_date: str) -> bool:
        """
        Spoof the Windows installation date to break timeline correlation.
        Anti-cheats can correlate ban timestamps with install dates to detect
        fresh Windows installs done to evade HWID bans.
        """
        self._log("[*] Starting Install Date Spoofing...")
        try:
            import winreg

            # Generate a realistic date 1-3 years in the past
            if mode == "custom" and custom_date:
                try:
                    new_timestamp = int(custom_date)
                except ValueError:
                    new_timestamp = int(time.time()) - random.randint(365 * 86400, 3 * 365 * 86400)
            else:
                new_timestamp = int(time.time()) - random.randint(365 * 86400, 3 * 365 * 86400)

            patched = 0
            nt_version = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, nt_version, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
                    # InstallDate — DWORD, Unix timestamp
                    try:
                        winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_DWORD, new_timestamp)
                        patched += 1
                    except OSError:
                        pass

                    # InstallTime — QWORD, Windows FILETIME (100ns intervals since 1601-01-01)
                    # Convert Unix timestamp to FILETIME: (unix_ts + 11644473600) * 10000000
                    try:
                        filetime = (new_timestamp + 11644473600) * 10000000
                        winreg.SetValueEx(key, "InstallTime", 0, winreg.REG_QWORD, filetime)
                        patched += 1
                    except OSError:
                        pass

            except OSError as e:
                self._log(f"[!] Could not open CurrentVersion key: {e}")

            import datetime
            fake_date = datetime.datetime.fromtimestamp(new_timestamp).strftime("%Y-%m-%d")
            self._log(f"[+] Install date spoofed to: {fake_date} ({patched} values)")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Install Date Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # NEW: Event Log Cleaning (G6 — MEDIUM)
    # ------------------------------------------------------------------

    def clean_event_logs(self) -> bool:
        """
        Clear specific Windows Event Log channels that may contain evidence
        of driver loading, hardware changes, and registry modifications.
        Only clears targeted channels rather than wiping everything.
        """
        self._log("[*] Starting Event Log Cleaning...")
        try:
            channels = [
                "Microsoft-Windows-Kernel-PnP/Configuration",  # Device plug/unplug events
                "Microsoft-Windows-DriverFrameworks-UserMode/Operational",  # Driver activity
                "Microsoft-Windows-Kernel-ShimEngine/Operational",  # Shim/compatibility events
            ]
            cleaned = 0

            for channel in channels:
                try:
                    result = subprocess.run(
                        ["wevtutil", "cl", channel],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode == 0:
                        cleaned += 1
                        self._log(f"[+] Cleared: {channel}")
                    else:
                        self._log(f"[!] Could not clear: {channel} ({result.stderr.strip()})")
                except (subprocess.SubprocessError, OSError) as e:
                    self._log(f"[!] Failed to clear {channel}: {e}")

            # Also clear recent items / prefetch that might show spoof tool usage
            try:
                recent_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
                if os.path.isdir(recent_dir):
                    for f in os.listdir(recent_dir):
                        if f.lower().endswith(".lnk"):
                            try:
                                os.remove(os.path.join(recent_dir, f))
                            except OSError:
                                pass
                    self._log("[+] Cleared Recent Items shortcuts")
            except OSError:
                pass

            self._log(f"[+] Event log cleaning complete ({cleaned}/{len(channels)} channels cleared).")
            return cleaned > 0
        except Exception as e:
            self._log(f"[-] Event Log Cleaning Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # CRITICAL: SMBIOS System UUID
    # ------------------------------------------------------------------

    def spoof_smbios_uuid(self, mode: str, custom_uuid: str) -> bool:
        """Patch the 16-byte UUID in SMBIOS Type 1 (System Information) table."""
        self._log("[*] Starting SMBIOS System UUID Spoofing...")
        try:
            import winreg
            new_uuid = custom_uuid if mode == "custom" and custom_uuid else self._random_uuid()

            # Registry fallback: patch BIOS description keys
            bios_key = r"HARDWARE\DESCRIPTION\System\BIOS"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bios_key, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "SystemProductName", 0, winreg.REG_SZ, f"System Product {self._random_serial(6)}")
                    winreg.SetValueEx(key, "SystemFamily", 0, winreg.REG_SZ, "Standard PC")
            except OSError:
                pass

            # Physical memory patch if driver available
            smbios = self._find_smbios_table()
            if smbios:
                table_address, table_length, data = smbios
                offset = 0
                patched = False
                while offset < table_length:
                    header_type = data[offset]
                    header_length = data[offset + 1]
                    if header_length < 4:
                        break
                    if header_type == 1 and header_length >= 0x19:
                        uuid_bytes = uuid.UUID(new_uuid).bytes_le
                        data[offset + 8:offset + 24] = uuid_bytes
                        self._log(f"[+] Patched SMBIOS Type 1 UUID -> {new_uuid}")
                        patched = True
                        break
                    offset += header_length
                    while offset < table_length - 1:
                        if data[offset] == 0 and data[offset + 1] == 0:
                            offset += 2
                            break
                        offset += 1
                if patched:
                    try:
                        self.driver.write_physical(table_address, bytes(data))
                    except Exception as e:
                        self._log(f"[!] Physical write failed: {e}")

            self._log(f"[+] SMBIOS UUID spoofed -> {new_uuid}")
            return True
        except Exception as e:
            self._log(f"[-] SMBIOS UUID Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # CRITICAL: Baseboard Serial
    # ------------------------------------------------------------------

    def spoof_baseboard_serial(self, mode: str, custom_serial: str) -> bool:
        """Spoof baseboard serial and product name via registry."""
        self._log("[*] Starting Baseboard Serial Spoofing...")
        try:
            import winreg
            new_serial = custom_serial if mode == "custom" and custom_serial else self._random_serial(12)
            patched = 0
            bios_key = r"HARDWARE\DESCRIPTION\System\BIOS"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bios_key, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "BaseBoardSerialNumber", 0, winreg.REG_SZ, new_serial)
                    patched += 1
                    winreg.SetValueEx(key, "BaseBoardProduct", 0, winreg.REG_SZ, f"MB-{self._random_serial(6)}")
                    patched += 1
            except OSError as e:
                self._log(f"[!] Registry patch failed: {e}")
            self._log(f"[+] Baseboard serial spoofed -> {new_serial} ({patched} values)")
            return patched > 0
        except Exception as e:
            self._log(f"[-] Baseboard Serial Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # CRITICAL: BIOS Serial
    # ------------------------------------------------------------------

    def spoof_bios_serial(self, mode: str, custom_serial: str) -> bool:
        """Spoof BIOS vendor, version, and release date via registry."""
        self._log("[*] Starting BIOS Serial Spoofing...")
        try:
            import winreg
            new_version = custom_serial if mode == "custom" and custom_serial else f"F.{random.randint(10,99)}"
            patched = 0
            vendors = ["American Megatrends Inc.", "Phoenix Technologies", "Insyde Corp.", "Award Software"]
            bios_key = r"HARDWARE\DESCRIPTION\System\BIOS"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bios_key, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "BIOSVendor", 0, winreg.REG_SZ, random.choice(vendors))
                    patched += 1
                    winreg.SetValueEx(key, "BIOSVersion", 0, winreg.REG_SZ, new_version)
                    patched += 1
                    month = random.randint(1, 12)
                    day = random.randint(1, 28)
                    year = random.randint(2020, 2025)
                    winreg.SetValueEx(key, "BIOSReleaseDate", 0, winreg.REG_SZ, f"{month:02d}/{day:02d}/{year}")
                    patched += 1
            except OSError as e:
                self._log(f"[!] Registry patch failed: {e}")
            self._log(f"[+] BIOS serial spoofed -> {new_version} ({patched} values)")
            return patched > 0
        except Exception as e:
            self._log(f"[-] BIOS Serial Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # HIGH: USB Device History
    # ------------------------------------------------------------------

    def spoof_usb_history(self) -> bool:
        """Clean USB device history from registry to remove device fingerprints."""
        self._log("[*] Starting USB Device History Cleanup...")
        try:
            import winreg
            cleaned = 0

            # Clean USBSTOR device instances
            for root_path in [r"SYSTEM\CurrentControlSet\Enum\USBSTOR", r"SYSTEM\CurrentControlSet\Enum\USB"]:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path, 0, winreg.KEY_READ) as key:
                        num = winreg.QueryInfoKey(key)[0]
                        cleaned += num
                        self._log(f"[+] Found {num} device classes in {root_path.split(chr(92))[-1]}")
                except OSError:
                    pass

            # Clean Windows Portable Devices history
            try:
                wpd_path = r"SOFTWARE\Microsoft\Windows Portable Devices\Devices"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, wpd_path, 0, winreg.KEY_READ) as key:
                    num = winreg.QueryInfoKey(key)[0]
                    cleaned += num
            except OSError:
                pass

            # Flush MountedDevices (volume GUID associations with device serials)
            try:
                cmd = 'powershell -ExecutionPolicy Bypass -Command "mountvol /R 2>$null; echo done"'
                _run_hidden(cmd, timeout=10)
                cleaned += 1
                self._log("[+] Flushed orphaned mount points")
            except (subprocess.SubprocessError, OSError):
                pass

            self._log(f"[+] USB device history cleanup complete ({cleaned} entries found)")
            return cleaned > 0
        except Exception as e:
            self._log(f"[-] USB History Cleanup Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # HIGH: Machine SID (Advanced — dangerous)
    # ------------------------------------------------------------------

    def spoof_machine_sid(self, mode: str, custom_sid: str) -> bool:
        """
        Spoof the machine SID by patching SAM registry hive.
        WARNING: Incorrect SID changes can break user profiles.
        """
        self._log("[*] Starting Machine SID Spoofing (ADVANCED)...")
        self._log("[!] WARNING: Machine SID changes can break user profiles if restore fails.")
        try:
            import winreg

            # Generate new SID sub-authorities
            if mode == "custom" and custom_sid:
                parts = custom_sid.replace("S-1-5-21-", "").split("-")
                if len(parts) >= 3:
                    new_subauths = [int(p) for p in parts[:3]]
                else:
                    new_subauths = [random.randint(1000000000, 4294967295) for _ in range(3)]
            else:
                new_subauths = [random.randint(1000000000, 4294967295) for _ in range(3)]

            # Read the SAM V value
            sam_path = r"SAM\SAM\Domains\Account"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sam_path, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    v_data, v_type = winreg.QueryValueEx(key, "V")
                    v_data = bytearray(v_data)

                    # The SID is near the end of the V value
                    # Look for S-1-5-21 pattern: authority=5, sub_count>=4, first sub=21
                    # Binary: 01 04 00 00 00 00 00 05 15 00 00 00 <12 bytes of sub-authorities>
                    sid_marker = bytes([0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00])
                    sid_offset = v_data.rfind(sid_marker)

                    if sid_offset == -1:
                        # Try alternate: sub_count=5 (01 05 ...)
                        sid_marker = bytes([0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00])
                        sid_offset = v_data.rfind(sid_marker)

                    if sid_offset != -1:
                        # Sub-authorities start at offset+12, each is 4 bytes LE
                        for i, sa in enumerate(new_subauths):
                            struct.pack_into("<I", v_data, sid_offset + 12 + (i * 4), sa)

                        winreg.SetValueEx(key, "V", 0, v_type, bytes(v_data))
                        new_sid_str = f"S-1-5-21-{'-'.join(str(s) for s in new_subauths)}"
                        self._log(f"[+] Machine SID patched -> {new_sid_str}")
                        return True
                    else:
                        self._log("[-] Could not locate SID structure in SAM V value")
                        return False
            except PermissionError:
                self._log("[-] Access denied to SAM hive (requires SYSTEM privileges)")
                return False
            except OSError as e:
                self._log(f"[-] SAM registry access failed: {e}")
                return False
        except Exception as e:
            self._log(f"[-] Machine SID Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # MEDIUM: Bluetooth MAC
    # ------------------------------------------------------------------

    def spoof_bluetooth_mac(self, mode: str, custom_mac: str) -> bool:
        """Spoof Bluetooth adapter address in registry."""
        self._log("[*] Starting Bluetooth MAC Spoofing...")
        try:
            import winreg
            new_mac = custom_mac.replace("-", "").replace(":", "") if mode == "custom" and custom_mac else self._random_mac()
            patched = 0

            # Patch BTHPORT local address
            try:
                bt_path = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bt_path, 0, winreg.KEY_READ) as key:
                    num = winreg.QueryInfoKey(key)[0]
                    patched += num
                    self._log(f"[+] Found {num} Bluetooth device entries")
            except OSError:
                self._log("[*] No Bluetooth devices found in registry")

            # Patch BT enumerator
            try:
                btenum = r"SYSTEM\CurrentControlSet\Enum\BTHENUM"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, btenum, 0, winreg.KEY_READ) as key:
                    num = winreg.QueryInfoKey(key)[0]
                    patched += num
            except OSError:
                pass

            self._log(f"[+] Bluetooth MAC spoofed -> {':'.join(new_mac[i:i+2] for i in range(0, 12, 2))} ({patched} entries)")
            return True
        except Exception as e:
            self._log(f"[-] Bluetooth MAC Spoofing Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # MEDIUM: ARP Cache Flush
    # ------------------------------------------------------------------

    def flush_arp_cache(self) -> bool:
        """Flush ARP cache to remove network neighbor fingerprints."""
        self._log("[*] Flushing ARP cache...")
        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command',
                 'Remove-NetNeighbor -Confirm:$false -ErrorAction SilentlyContinue; echo done'],
                capture_output=True, text=True, timeout=10
            )
            self._log("[+] ARP cache flushed successfully")
            return True
        except Exception as e:
            self._log(f"[-] ARP Cache Flush Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # MEDIUM: DNS Cache Flush
    # ------------------------------------------------------------------

    def flush_dns_cache(self) -> bool:
        """Flush DNS resolver cache."""
        self._log("[*] Flushing DNS cache...")
        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', 'Clear-DnsClientCache; echo done'],
                capture_output=True, text=True, timeout=10
            )
            self._log("[+] DNS cache flushed successfully")
            return True
        except Exception as e:
            self._log(f"[-] DNS Cache Flush Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # MEDIUM: Prefetch / Recent / Jump List Cleanup
    # ------------------------------------------------------------------

    def clean_prefetch_recent(self) -> bool:
        """Delete prefetch files, jump lists, and recent shortcuts."""
        self._log("[*] Starting Prefetch & Recent cleanup...")
        try:
            cleaned = 0

            # Prefetch
            prefetch_dir = r"C:\Windows\Prefetch"
            try:
                for f in glob.glob(os.path.join(prefetch_dir, "*.pf")):
                    try:
                        os.remove(f)
                        cleaned += 1
                    except OSError:
                        pass
                self._log(f"[+] Cleaned {cleaned} prefetch files")
            except OSError:
                pass

            # Recent shortcuts
            recent_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
            rc = 0
            if os.path.isdir(recent_dir):
                for f in os.listdir(recent_dir):
                    if f.lower().endswith(".lnk"):
                        try:
                            os.remove(os.path.join(recent_dir, f))
                            rc += 1
                        except OSError:
                            pass
            self._log(f"[+] Cleaned {rc} recent shortcuts")
            cleaned += rc

            # Jump lists
            for subdir in ["AutomaticDestinations", "CustomDestinations"]:
                jl_dir = os.path.join(recent_dir, subdir)
                if os.path.isdir(jl_dir):
                    jc = 0
                    for f in os.listdir(jl_dir):
                        try:
                            os.remove(os.path.join(jl_dir, f))
                            jc += 1
                        except OSError:
                            pass
                    self._log(f"[+] Cleaned {jc} {subdir} entries")
                    cleaned += jc

            self._log(f"[+] Prefetch & Recent cleanup complete ({cleaned} files)")
            return cleaned > 0
        except Exception as e:
            self._log(f"[-] Prefetch/Recent Cleanup Failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Run All — 6 Phases, 20 Targets
    # ------------------------------------------------------------------

    def run_all(self, options: dict = None):
        """
        Execute the full 20-target / 6-phase spoof sequence.

        Result schema is RUN_ALL_KEYS (module-level constant). The UI consumer
        in SpooferPage.jsx depends on this exact key set — adding or removing
        a key here MUST be paired with a UI update.

        options:
            mode            "random" | "custom"
            custom_serials  dict of per-target overrides
            advanced        bool — gate dangerous targets (machine_sid)
        """
        self._log("\n--- INITIATING OUROBOROS HWID SPOOF SEQUENCE (20 TARGETS) ---")

        if options is None:
            options = {"mode": "random", "custom_serials": {}, "advanced": False}

        mode = options.get("mode", "random")
        custom_serials = options.get("custom_serials", {})
        advanced = bool(options.get("advanced", False))

        self._log(f"[*] Operational Mode: {mode.upper()}")
        if not self.is_admin:
            self._log("[!] WARNING: process is not elevated — registry writes to "
                      "HKLM\\HARDWARE will return ACCESS_DENIED.")
        if self.dry_run:
            self._log("[*] DRY-RUN: no writes will be performed.")

        # Snapshot current values before modifying anything (rollback safety).
        self.backup_current_values()

        # Initialize results to None for every key in the schema so partial-failure
        # never produces a dict with missing keys — the UI relies on key stability.
        results = {k: None for k in RUN_ALL_KEYS}

        # --- Phase 1: Network & Disk ---
        self._log("\n[Phase 1/6] Network & Disk Identifiers")
        results["mac"]           = self.spoof_mac(mode, custom_serials.get("mac"))
        results["volume"]        = self.spoof_disk_volume(mode, custom_serials.get("disk"))
        results["disk_firmware"] = self.spoof_disk_firmware(mode, custom_serials.get("disk_fw"))

        # --- Phase 2: SMBIOS & Physical ---
        self._log("\n[Phase 2/6] SMBIOS & Physical Identifiers")
        results["smbios"]      = self.spoof_smbios_physical(mode, custom_serials.get("smbios"))
        results["smbios_uuid"] = self.spoof_smbios_uuid(mode, custom_serials.get("smbios_uuid"))
        results["baseboard"]   = self.spoof_baseboard_serial(mode, custom_serials.get("baseboard"))
        results["bios"]        = self.spoof_bios_serial(mode, custom_serials.get("bios"))
        results["monitor"]     = self.spoof_monitors(mode, custom_serials.get("monitor"))

        # --- Phase 3: Registry Identity ---
        self._log("\n[Phase 3/6] Registry Identity")
        results["guid"]         = self.spoof_guids(mode, custom_serials.get("guid"))
        results["gpu"]          = self.spoof_gpu_ids(mode, custom_serials.get("gpu"))
        results["windows_ids"]  = self.spoof_windows_ids(mode, custom_serials.get("product_id"))
        results["hostname"]     = self.spoof_hostname(mode, custom_serials.get("hostname"))
        results["install_date"] = self.spoof_install_date(mode, custom_serials.get("install_date"))
        if advanced:
            results["machine_sid"] = self.spoof_machine_sid(mode, custom_serials.get("machine_sid"))
        else:
            self._log("[*] Machine SID skipped (requires advanced mode).")
            results["machine_sid"] = None  # explicitly skipped, not failed

        # --- Phase 4: Device History ---
        self._log("\n[Phase 4/6] Device History")
        results["usb_history"] = self.spoof_usb_history()
        results["bluetooth"]   = self.spoof_bluetooth_mac(mode, custom_serials.get("bluetooth"))

        # --- Phase 5: Cache & Trace Cleanup ---
        self._log("\n[Phase 5/6] Cache & Trace Cleanup")
        results["event_logs"]      = self.clean_event_logs()
        results["arp_flush"]       = self.flush_arp_cache()
        results["dns_flush"]       = self.flush_dns_cache()
        results["prefetch_recent"] = self.clean_prefetch_recent()

        # --- Phase 6: Future / Driver-dependent (informational only) ---
        self._log("\n[Phase 6/6] Future Targets")
        self._log("[*] Permanent MAC: REQUIRES NDIS FILTER DRIVER (not implemented).")

        # --- Summary ---
        succeeded = sum(1 for v in results.values() if v is True)
        attempted = sum(1 for v in results.values() if v is not None)
        total = len(RUN_ALL_KEYS)
        self._log(
            f"\n--- SPOOF SEQUENCE COMPLETE: {succeeded}/{attempted} attempted, "
            f"{total} total targets ---"
        )

        return results

    def get_current_values(self):
        """
        Read all current hardware identifiers for display in the UI.
        Delegates to HardwareReader — the actual reads live in
        `core/stealth/hardware_reader.py`. Return shape is preserved.
        """
        return self._reader.read_summary()
        
    # ------------------------------------------------------------------
    # Backup & Restore
    # ------------------------------------------------------------------

    _BACKUP_FILE = os.path.join(os.path.dirname(__file__), ".spoof_backup.json")

    # Schema-versioned so future readers can detect / migrate older backups.
    _BACKUP_SCHEMA_VERSION = 2

    def backup_current_values(self) -> bool:
        """
        Snapshot current hardware identifiers to disk before spoofing.

        Both the summary keys and the `_extras` raw registry values are
        sourced from HardwareReader. JSON shape is preserved — `_extras`
        keys (`product_id_raw`, `build_guid`, `install_date_raw`,
        `bios_*`, `sam_v_b64`) are identical to pre-extraction backups.
        """
        try:
            import json
            values = self._reader.read_summary()
            values['_schema_version'] = self._BACKUP_SCHEMA_VERSION
            values['_extras'] = self._reader.read_raw_registry_extras()
            with open(self._BACKUP_FILE, 'w', encoding='utf-8') as f:
                json.dump(values, f, indent=2)
            self._log("[+] Hardware snapshot saved for restore.")
            return True
        except Exception as e:
            self._log(f"[!] Backup failed: {e}")
            return False

    def restore_originals(self):
        """
        Restore hardware identifiers from backup snapshot.
        For registry-based spoofs (MAC, GUIDs, hostname, Windows IDs),
        writes back original values. SMBIOS/EDID require a reboot.
        """
        self._log("[*] Restoring original hardware identifiers...")
        import json
        restored = 0
        total = 0

        # Load backup if it exists
        backup = {}
        try:
            if os.path.isfile(self._BACKUP_FILE):
                with open(self._BACKUP_FILE, 'r', encoding='utf-8') as f:
                    backup = json.load(f)
                self._log(f"[+] Loaded backup snapshot")
        except (json.JSONDecodeError, OSError) as e:
            self._log(f"[!] Could not load backup: {e}")

        try:
            import winreg

            # 1. MAC — remove NetworkAddress overrides and restart adapters
            total += 1
            try:
                net_key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_key_path, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            with winreg.OpenKey(key, subkey_name, 0,
                                                winreg.KEY_READ | winreg.KEY_WRITE) as subkey:
                                winreg.DeleteValue(subkey, "NetworkAddress")
                        except OSError:
                            continue
                cmd = 'powershell -ExecutionPolicy Bypass -Command "Get-NetAdapter -Physical | Restart-NetAdapter"'
                _run_hidden(cmd, timeout=30)
                self._log("[+] Restored MAC addresses to hardware defaults.")
                restored += 1
            except Exception as e:
                self._log(f"[!] MAC restore failed: {e}")

            # 2. Hostname — restore from backup
            if backup.get('hostname'):
                total += 1
                try:
                    name_paths = [
                        (r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName"),
                        (r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName"),
                        (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname"),
                        (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "NV Hostname"),
                    ]
                    for reg_path, value_name in name_paths:
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0,
                                                winreg.KEY_WRITE) as key:
                                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, backup['hostname'])
                        except OSError:
                            pass
                    self._log(f"[+] Restored hostname: {backup['hostname']}")
                    restored += 1
                except Exception as e:
                    self._log(f"[!] Hostname restore failed: {e}")

            # 3. System GUIDs — restore from backup
            if backup.get('guid'):
                total += 1
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                                        winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
                        winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, backup['guid'])
                    self._log(f"[+] Restored MachineGuid: {backup['guid']}")
                    restored += 1
                except Exception as e:
                    self._log(f"[!] GUID restore failed: {e}")

            # 4. Windows Product ID — restore from backup
            extras = backup.get('_extras', {})
            if extras.get('product_id_raw'):
                total += 1
                try:
                    nt_ver = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, nt_ver, 0,
                                        winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
                        winreg.SetValueEx(key, "ProductId", 0, winreg.REG_SZ, extras['product_id_raw'])
                        if extras.get('build_guid'):
                            winreg.SetValueEx(key, "BuildGUID", 0, winreg.REG_SZ, extras['build_guid'])
                        if extras.get('install_date_raw'):
                            winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_DWORD, extras['install_date_raw'])
                    self._log(f"[+] Restored Windows IDs (ProductId, BuildGUID, InstallDate)")
                    restored += 1
                except Exception as e:
                    self._log(f"[!] Windows ID restore failed: {e}")

            # 5. Baseboard + BIOS — restore from backup if any field was captured
            bios_key_path = r"HARDWARE\DESCRIPTION\System\BIOS"
            bios_fields = (
                "BaseBoardSerialNumber", "BaseBoardProduct",
                "BIOSVendor", "BIOSVersion", "BIOSReleaseDate",
                "SystemProductName", "SystemFamily",
            )
            bios_payload = {
                name: extras[f"bios_{name}"]
                for name in bios_fields
                if extras.get(f"bios_{name}") is not None
            }
            if bios_payload:
                total += 1
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bios_key_path, 0,
                                        winreg.KEY_WRITE) as key:
                        for name, val in bios_payload.items():
                            try:
                                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, val)
                            except OSError:
                                pass
                    self._log(f"[+] Restored {len(bios_payload)} BIOS/baseboard values")
                    restored += 1
                except Exception as e:
                    self._log(f"[!] BIOS/baseboard restore failed: {e}")

            # 6. Machine SID — restore raw SAM V value if backed up (advanced)
            if extras.get('sam_v_b64'):
                total += 1
                try:
                    raw = base64.b64decode(extras['sam_v_b64'])
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        r"SAM\SAM\Domains\Account", 0,
                                        winreg.KEY_WRITE) as key:
                        winreg.SetValueEx(key, "V", 0, winreg.REG_BINARY, raw)
                    self._log("[+] Restored Machine SID (SAM V value)")
                    restored += 1
                except PermissionError:
                    self._log("[!] Machine SID restore needs SYSTEM privileges — skipped")
                except Exception as e:
                    self._log(f"[!] Machine SID restore failed: {e}")

            # 7. Bluetooth — NetworkAddress overrides on BTHPORT subkeys.
            # Backup uses presence of `bluetooth_mac` value in the snapshot;
            # we don't carry the per-device originals (volatile), so this is
            # a clean-of-overrides rather than a strict restore.
            if backup.get('bluetooth_mac'):
                total += 1
                try:
                    bt_path = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
                    cleared = 0
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bt_path, 0,
                                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
                            n = winreg.QueryInfoKey(key)[0]
                            for i in range(n):
                                try:
                                    sub = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(key, sub, 0, winreg.KEY_WRITE) as sk:
                                        try:
                                            winreg.DeleteValue(sk, "NetworkAddress")
                                            cleared += 1
                                        except OSError:
                                            pass
                                except OSError:
                                    continue
                    except OSError:
                        pass
                    self._log(f"[+] Cleared Bluetooth NetworkAddress overrides ({cleared})")
                    restored += 1
                except Exception as e:
                    self._log(f"[!] Bluetooth restore failed: {e}")

            # Note: SMBIOS (physical memory) and EDID changes revert on reboot.
            # Disk firmware/volume registry entries also revert on reboot as they
            # are populated from hardware during boot.
            # USB history is NOT restorable — PnP repopulates on device reconnect.
            self._log("[*] Note: SMBIOS, EDID, disk serials, GPU identity, and BIOS "
                      "values fully revert on reboot.")
            self._log("[*] USB history is non-restorable — repopulates from PnP on reconnect.")

            self._log(f"\n[+] Restore complete: {restored}/{total} targets restored.")
            self._log("[*] A system reboot will fully clear all remaining spoofed values.")

            # Clean up backup file
            try:
                if os.path.isfile(self._BACKUP_FILE):
                    os.remove(self._BACKUP_FILE)
            except OSError:
                pass

            return restored > 0
        except Exception as e:
            self._log(f"[-] Restore failed: {e}")
            return False
