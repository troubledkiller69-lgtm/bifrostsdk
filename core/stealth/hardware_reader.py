"""
BIFROST SDK — HardwareReader

Free-standing reader for all hardware identifiers the spoofer touches.

Extracted from `HardwareSpoofer.get_current_values()` and the inline `_extras`
collection in `HardwareSpoofer.backup_current_values()`. Behavior is
byte-identical to the source: same dict keys, same fallback strings, same
PowerShell / `whoami` / `winreg` calls in the same order.

The reader has no dependency on `HardwareSpoofer` or `DriverInterface`. It
optionally accepts a `log_callback(msg: str)` for symmetry with the spoofer's
logging hook.

Two public methods:
  - `read_summary()` — the 15-key dict UI consumers expect.
  - `read_raw_registry_extras()` — the raw registry values used by backup +
    restore. Includes `bios_*`, raw `product_id` / `build_guid` /
    `install_date`, and `sam_v_b64` (when SYSTEM-level access is available).

Adding a new identifier requires a parallel update in `SUMMARY_KEYS` and a
private `_read_*` method.
"""

from __future__ import annotations

import base64
import datetime
import subprocess
import sys
from typing import Callable, Dict, Optional, Tuple

# Stable contract of the 15 keys read_summary() returns. UI consumers
# (gui/src/components/SpooferPage.jsx) read these — adding a key here
# requires a parallel UI update.
SUMMARY_KEYS: Tuple[str, ...] = (
    "mac", "guid", "disk", "disk_firmware", "gpu",
    "product_id", "hostname", "install_date",
    "smbios_uuid", "baseboard_serial", "bios_vendor", "bios_version",
    "bluetooth_mac", "machine_sid", "usb_device_count",
)

# Subset of summary keys returned with "N/A (Windows only)" on non-Windows
# platforms. Matches the previous get_current_values() behavior.
_NON_WINDOWS_KEYS: Tuple[str, ...] = (
    "mac", "guid", "disk", "disk_firmware", "gpu",
    "product_id", "hostname", "install_date",
)

# Registry path that holds nearly all BIOS / baseboard fields.
_BIOS_KEY = r"HARDWARE\DESCRIPTION\System\BIOS"

# PowerShell command timeout — matches the previous spoofer.py value.
_PS_TIMEOUT = 10

# CREATE_NO_WINDOW so background subprocess calls don't flash a console.
# Matches the pattern in gui_bridge._curl_send / _powershell_send.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run_ps(cmd: str) -> str:
    """Run a PowerShell one-liner and return stripped stdout (or '')."""
    out = subprocess.check_output(
        cmd, shell=True, text=True, timeout=_PS_TIMEOUT,
        creationflags=_NO_WINDOW,
    ).strip()
    return out


class HardwareReader:
    """
    Reads all 15 hardware identifiers + the raw registry values used by
    backup / restore. Side-effect free aside from PowerShell / winreg
    queries.
    """

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self._log: Callable[[str], None] = log_callback or (lambda _: None)

    # ------------------------------------------------------------------
    # Summary readers — one per identifier. Each MUST return a string and
    # MUST NOT raise. Fallback strings match the previous behavior.
    # ------------------------------------------------------------------

    def _read_mac(self) -> str:
        try:
            return _run_ps(
                'powershell -ExecutionPolicy Bypass -Command '
                '"(Get-NetAdapter -Physical).MacAddress | Select-Object -First 1"'
            )
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_guid(self) -> str:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                return val
        except OSError:
            return "Unknown"

    def _read_disk_volume(self) -> str:
        try:
            return _run_ps(
                'powershell -ExecutionPolicy Bypass -Command '
                '"(Get-Volume -DriveLetter C).UniqueId"'
            )
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_disk_firmware(self) -> str:
        try:
            out = _run_ps(
                'powershell -ExecutionPolicy Bypass -Command '
                '"(Get-PhysicalDisk | Select-Object -First 1).SerialNumber"'
            )
            return out if out else "Unknown"
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_gpu(self) -> str:
        try:
            out = _run_ps(
                'powershell -ExecutionPolicy Bypass -Command '
                '"(Get-CimInstance Win32_VideoController | Select-Object -First 1).Name"'
            )
            return out if out else "Unknown"
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_product_id(self) -> str:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "ProductId")
                return val
        except OSError:
            return "Unknown"

    def _read_hostname(self) -> str:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
                0, winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "ComputerName")
                return val
        except OSError:
            return "Unknown"

    def _read_install_date(self) -> str:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "InstallDate")
                install_dt = datetime.datetime.fromtimestamp(val)
                return install_dt.strftime("%Y-%m-%d")
        except (OSError, ValueError, OverflowError):
            return "Unknown"

    def _read_smbios_uuid(self) -> str:
        try:
            out = _run_ps(
                'powershell -ExecutionPolicy Bypass -Command '
                '"(Get-CimInstance Win32_ComputerSystemProduct).UUID"'
            )
            return out or "Unknown"
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_baseboard_serial(self) -> str:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, _BIOS_KEY, 0, winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "BaseBoardSerialNumber")
                return val
        except OSError:
            return "Unknown"

    def _read_bios_vendor_and_version(self) -> Tuple[str, str]:
        """Returns (vendor, version) tuple. version can be REG_MULTI_SZ."""
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, _BIOS_KEY, 0, winreg.KEY_READ,
            ) as key:
                vendor, _ = winreg.QueryValueEx(key, "BIOSVendor")
                version, _ = winreg.QueryValueEx(key, "BIOSVersion")
                version_str = (
                    version if isinstance(version, str)
                    else " ".join(v for v in version if v)
                )
                return vendor, version_str
        except OSError:
            return "Unknown", "Unknown"

    def _read_bluetooth_mac(self) -> str:
        try:
            out = _run_ps(
                'powershell -ExecutionPolicy Bypass -Command '
                '"(Get-PnpDevice -Class Bluetooth | Where-Object Status -eq OK | '
                'Select-Object -First 1).InstanceId"'
            )
            return out if out else "Not present"
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_machine_sid(self) -> str:
        """whoami /user — works without SAM access."""
        try:
            out = subprocess.check_output(
                'whoami /user /fo csv /nh',
                shell=True, text=True, timeout=_PS_TIMEOUT,
                creationflags=_NO_WINDOW,
            ).strip()
            # CSV: "user","S-1-5-21-..."
            parts = out.replace('"', '').split(',')
            if len(parts) >= 2 and parts[-1].startswith("S-1-5-"):
                sid_parts = parts[-1].split('-')
                # Strip the trailing RID to expose the machine SID portion
                return '-'.join(sid_parts[:-1]) if len(sid_parts) > 4 else parts[-1]
            return "Unknown"
        except (subprocess.SubprocessError, OSError):
            return "Unknown"

    def _read_usb_device_count(self) -> str:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
                0, winreg.KEY_READ,
            ) as key:
                return str(winreg.QueryInfoKey(key)[0])
        except OSError:
            return "0"

    # ------------------------------------------------------------------
    # Public orchestrators
    # ------------------------------------------------------------------

    def read_summary(self) -> Dict[str, str]:
        """
        Return the 15-key hardware identifier dict the UI consumes.

        Order is preserved to match the previous get_current_values() output
        (so a backup-baseline diff stays clean). Every key in SUMMARY_KEYS
        will be present even if individual reads fail (fallback strings).

        Non-Windows platforms get "N/A (Windows only)" for the 8 keys that
        existed before the Phase 2/3/4 additions, matching prior behavior.
        """
        if sys.platform != "win32":
            return {k: "N/A (Windows only)" for k in _NON_WINDOWS_KEYS}

        values: Dict[str, str] = {}
        values['mac']           = self._read_mac()
        values['guid']          = self._read_guid()
        values['disk']          = self._read_disk_volume()
        values['disk_firmware'] = self._read_disk_firmware()
        values['gpu']           = self._read_gpu()
        values['product_id']    = self._read_product_id()
        values['hostname']      = self._read_hostname()
        values['install_date']  = self._read_install_date()
        values['smbios_uuid']   = self._read_smbios_uuid()
        values['baseboard_serial'] = self._read_baseboard_serial()
        vendor, version = self._read_bios_vendor_and_version()
        values['bios_vendor']   = vendor
        values['bios_version']  = version
        values['bluetooth_mac'] = self._read_bluetooth_mac()
        values['machine_sid']   = self._read_machine_sid()
        values['usb_device_count'] = self._read_usb_device_count()
        return values

    def read_raw_registry_extras(self) -> Dict[str, object]:
        """
        Return the raw registry values that backup_current_values() embeds
        under `_extras`. Keys are sparse — only present when the read
        succeeded. Used by restore_originals().

        Key contract (must not change without bumping _BACKUP_SCHEMA_VERSION
        on the spoofer side):
          - product_id_raw, build_guid, install_date_raw
          - bios_BaseBoardSerialNumber, bios_BaseBoardProduct,
            bios_BIOSVendor, bios_BIOSVersion, bios_BIOSReleaseDate,
            bios_SystemProductName, bios_SystemFamily
          - sam_v_b64 (only when SYSTEM-level access is available)
        """
        extras: Dict[str, object] = {}

        if sys.platform != "win32":
            return extras

        import winreg

        # ProductId / BuildGUID / InstallDate raw
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                extras['product_id_raw'], _ = winreg.QueryValueEx(key, "ProductId")
                try:
                    extras['build_guid'], _ = winreg.QueryValueEx(key, "BuildGUID")
                except OSError:
                    pass
                try:
                    extras['install_date_raw'], _ = winreg.QueryValueEx(key, "InstallDate")
                except OSError:
                    pass
        except OSError:
            pass

        # Baseboard + BIOS raw values (HARDWARE\DESCRIPTION\System\BIOS)
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, _BIOS_KEY, 0, winreg.KEY_READ,
            ) as key:
                for name in (
                    "BaseBoardSerialNumber", "BaseBoardProduct",
                    "BIOSVendor", "BIOSVersion", "BIOSReleaseDate",
                    "SystemProductName", "SystemFamily",
                ):
                    try:
                        val, _ = winreg.QueryValueEx(key, name)
                        extras[f"bios_{name}"] = val
                    except OSError:
                        pass
        except OSError:
            pass

        # Machine SID — store raw SAM V value as base64. Requires SYSTEM
        # privileges; absent extras['sam_v_b64'] is the normal case.
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SAM\SAM\Domains\Account",
                0, winreg.KEY_READ,
            ) as key:
                v_data, _ = winreg.QueryValueEx(key, "V")
                extras['sam_v_b64'] = base64.b64encode(v_data).decode('ascii')
        except (OSError, PermissionError):
            pass

        return extras
