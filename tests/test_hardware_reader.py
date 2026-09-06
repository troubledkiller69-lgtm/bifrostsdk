"""
Unit tests for HardwareReader.

Mocks `winreg`, `subprocess.check_output`, and the `_run_ps` helper to verify:

  - Each `_read_*` method returns the expected value on happy path
  - Each `_read_*` method returns the documented fallback string on failure
  - `read_summary()` returns exactly the 15 SUMMARY_KEYS keys regardless
    of individual read success/failure
  - `read_raw_registry_extras()` returns only the keys whose reads succeeded
    (sparse contract — used by backup_current_values)
  - Non-Windows platforms get the 8-key "N/A (Windows only)" dict
  - Optional log_callback is invoked or noop'd correctly

These tests prove the contract is preserved after extraction from
HardwareSpoofer. No real registry or subprocess access.
"""

from __future__ import annotations

import datetime
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from core.stealth.hardware_reader import (
    HardwareReader, SUMMARY_KEYS, _run_ps,
)


# Manifest of the contract — adding a key here forces a deliberate decision.
EXPECTED_SUMMARY_KEYS = frozenset({
    "mac", "guid", "disk", "disk_firmware", "gpu",
    "product_id", "hostname", "install_date",
    "smbios_uuid", "baseboard_serial", "bios_vendor", "bios_version",
    "bluetooth_mac", "machine_sid", "usb_device_count",
})
EXPECTED_NON_WINDOWS_KEYS = frozenset({
    "mac", "guid", "disk", "disk_firmware", "gpu",
    "product_id", "hostname", "install_date",
})


def test_summary_keys_contract_unchanged():
    """If this test fails, the UI consumer in SpooferPage.jsx may break."""
    assert frozenset(SUMMARY_KEYS) == EXPECTED_SUMMARY_KEYS
    assert len(SUMMARY_KEYS) == 15


# ----------------------------------------------------------------------
# Per-method happy-path + fallback
# ----------------------------------------------------------------------

class TestMacReader:
    def test_happy_path(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value="AA-BB-CC-DD-EE-FF"):
            assert r._read_mac() == "AA-BB-CC-DD-EE-FF"

    def test_subprocess_error_falls_back(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps",
                   side_effect=subprocess.SubprocessError("boom")):
            assert r._read_mac() == "Unknown"

    def test_os_error_falls_back(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", side_effect=OSError("denied")):
            assert r._read_mac() == "Unknown"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestGuidReader:
    def test_happy_path(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx",
                          return_value=("AB-CD-EF-12-34-56", 1)):
            assert r._read_guid() == "AB-CD-EF-12-34-56"

    def test_os_error_falls_back(self):
        r = HardwareReader()
        import winreg
        with patch.object(winreg, "OpenKey", side_effect=OSError("not found")):
            assert r._read_guid() == "Unknown"


class TestDiskVolumeReader:
    def test_happy_path(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value="{ABC123}"):
            assert r._read_disk_volume() == "{ABC123}"

    def test_failure_falls_back(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", side_effect=OSError):
            assert r._read_disk_volume() == "Unknown"


class TestDiskFirmwareReader:
    def test_happy_path(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value="SN12345"):
            assert r._read_disk_firmware() == "SN12345"

    def test_empty_string_becomes_unknown(self):
        """Empty output must NOT be returned — falls back to Unknown."""
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value=""):
            assert r._read_disk_firmware() == "Unknown"

    def test_failure_falls_back(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps",
                   side_effect=subprocess.SubprocessError):
            assert r._read_disk_firmware() == "Unknown"


class TestGpuReader:
    def test_happy_path(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value="NVIDIA RTX 4090"):
            assert r._read_gpu() == "NVIDIA RTX 4090"

    def test_empty_becomes_unknown(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value=""):
            assert r._read_gpu() == "Unknown"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestProductIdReader:
    def test_happy_path(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx",
                          return_value=("00330-12345-67890-AA111", 1)):
            assert r._read_product_id() == "00330-12345-67890-AA111"

    def test_os_error_falls_back(self):
        r = HardwareReader()
        import winreg
        with patch.object(winreg, "OpenKey", side_effect=OSError):
            assert r._read_product_id() == "Unknown"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestHostnameReader:
    def test_happy_path(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx",
                          return_value=("DESKTOP-ABCDEF", 1)):
            assert r._read_hostname() == "DESKTOP-ABCDEF"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestInstallDateReader:
    def test_happy_path(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        # 1700000000 ≈ 2023-11-14
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx", return_value=(1700000000, 1)):
            result = r._read_install_date()
            # Tolerate the runner's local TZ — just confirm shape
            assert len(result) == 10 and result.count("-") == 2

    def test_overflow_falls_back(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx", return_value=(99999999999, 1)):
            assert r._read_install_date() == "Unknown"


class TestSmbiosUuidReader:
    def test_happy_path(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps",
                   return_value="11111111-2222-3333-4444-555555555555"):
            assert r._read_smbios_uuid() == "11111111-2222-3333-4444-555555555555"

    def test_empty_becomes_unknown(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value=""):
            assert r._read_smbios_uuid() == "Unknown"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestBaseboardSerialReader:
    def test_happy_path(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx", return_value=("BBSN12345", 1)):
            assert r._read_baseboard_serial() == "BBSN12345"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestBiosVendorAndVersion:
    def test_happy_path_string_version(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx",
                          side_effect=[("AMI", 1), ("F.42", 1)]):
            vendor, version = r._read_bios_vendor_and_version()
            assert vendor == "AMI"
            assert version == "F.42"

    def test_multi_sz_version_joins(self):
        """BIOSVersion can be REG_MULTI_SZ — joined with spaces, empties skipped."""
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryValueEx",
                          side_effect=[("Phoenix", 1), (["v1.2", "", "rev3"], 7)]):
            vendor, version = r._read_bios_vendor_and_version()
            assert vendor == "Phoenix"
            assert version == "v1.2 rev3"

    def test_failure_returns_unknown_tuple(self):
        r = HardwareReader()
        import winreg
        with patch.object(winreg, "OpenKey", side_effect=OSError):
            vendor, version = r._read_bios_vendor_and_version()
            assert vendor == "Unknown"
            assert version == "Unknown"


class TestBluetoothMacReader:
    def test_happy_path(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps",
                   return_value="BTHENUM\\DEV_AABBCCDDEEFF"):
            assert r._read_bluetooth_mac() == "BTHENUM\\DEV_AABBCCDDEEFF"

    def test_no_adapter_says_not_present(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps", return_value=""):
            assert r._read_bluetooth_mac() == "Not present"

    def test_failure_says_unknown(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader._run_ps",
                   side_effect=subprocess.SubprocessError):
            assert r._read_bluetooth_mac() == "Unknown"


class TestMachineSidReader:
    def test_happy_path_strips_rid(self):
        r = HardwareReader()
        csv = '"DESKTOP-AB\\user","S-1-5-21-1111111111-2222222222-3333333333-1001"'
        with patch("subprocess.check_output", return_value=csv):
            sid = r._read_machine_sid()
            # RID 1001 stripped; machine SID remains
            assert sid == "S-1-5-21-1111111111-2222222222-3333333333"

    def test_short_sid_passes_through(self):
        """A SID with ≤4 parts after the prefix isn't stripped."""
        r = HardwareReader()
        csv = '"u","S-1-5-21"'
        with patch("subprocess.check_output", return_value=csv):
            sid = r._read_machine_sid()
            assert sid == "S-1-5-21"

    def test_failure_returns_unknown(self):
        r = HardwareReader()
        with patch("subprocess.check_output", side_effect=OSError):
            assert r._read_machine_sid() == "Unknown"

    def test_unexpected_csv_returns_unknown(self):
        r = HardwareReader()
        with patch("subprocess.check_output", return_value="garbage"):
            assert r._read_machine_sid() == "Unknown"


@pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
class TestUsbDeviceCountReader:
    def test_happy_path(self):
        r = HardwareReader()
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = MagicMock(return_value=mock_key)
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, "OpenKey", return_value=mock_key), \
             patch.object(winreg, "QueryInfoKey", return_value=(7, 0, 12345)):
            assert r._read_usb_device_count() == "7"

    def test_failure_returns_zero_string(self):
        """Note: fallback is '0' not 'Unknown' — preserved from old code."""
        r = HardwareReader()
        import winreg
        with patch.object(winreg, "OpenKey", side_effect=OSError):
            assert r._read_usb_device_count() == "0"


# ----------------------------------------------------------------------
# Orchestrator: read_summary
# ----------------------------------------------------------------------

class TestReadSummary:
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only path")
    def test_returns_all_15_keys_on_windows(self):
        """Even if every reader fails, all 15 keys must be present."""
        r = HardwareReader()
        # Patch every reader to deterministically return failure-fallback
        with patch.object(r, "_read_mac", return_value="Unknown"), \
             patch.object(r, "_read_guid", return_value="Unknown"), \
             patch.object(r, "_read_disk_volume", return_value="Unknown"), \
             patch.object(r, "_read_disk_firmware", return_value="Unknown"), \
             patch.object(r, "_read_gpu", return_value="Unknown"), \
             patch.object(r, "_read_product_id", return_value="Unknown"), \
             patch.object(r, "_read_hostname", return_value="Unknown"), \
             patch.object(r, "_read_install_date", return_value="Unknown"), \
             patch.object(r, "_read_smbios_uuid", return_value="Unknown"), \
             patch.object(r, "_read_baseboard_serial", return_value="Unknown"), \
             patch.object(r, "_read_bios_vendor_and_version",
                          return_value=("Unknown", "Unknown")), \
             patch.object(r, "_read_bluetooth_mac", return_value="Unknown"), \
             patch.object(r, "_read_machine_sid", return_value="Unknown"), \
             patch.object(r, "_read_usb_device_count", return_value="0"):
            summary = r.read_summary()
        assert frozenset(summary.keys()) == EXPECTED_SUMMARY_KEYS

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only path")
    def test_returns_real_values_when_readers_succeed(self):
        r = HardwareReader()
        with patch.object(r, "_read_mac", return_value="AA-BB-CC-DD-EE-FF"), \
             patch.object(r, "_read_guid", return_value="my-guid"), \
             patch.object(r, "_read_disk_volume", return_value="my-disk"), \
             patch.object(r, "_read_disk_firmware", return_value="my-fw"), \
             patch.object(r, "_read_gpu", return_value="my-gpu"), \
             patch.object(r, "_read_product_id", return_value="my-pid"), \
             patch.object(r, "_read_hostname", return_value="my-host"), \
             patch.object(r, "_read_install_date", return_value="2024-01-01"), \
             patch.object(r, "_read_smbios_uuid", return_value="my-uuid"), \
             patch.object(r, "_read_baseboard_serial", return_value="my-bb"), \
             patch.object(r, "_read_bios_vendor_and_version",
                          return_value=("AMI", "F.42")), \
             patch.object(r, "_read_bluetooth_mac", return_value="my-bt"), \
             patch.object(r, "_read_machine_sid", return_value="my-sid"), \
             patch.object(r, "_read_usb_device_count", return_value="3"):
            summary = r.read_summary()
        assert summary["mac"] == "AA-BB-CC-DD-EE-FF"
        assert summary["bios_vendor"] == "AMI"
        assert summary["bios_version"] == "F.42"
        assert summary["install_date"] == "2024-01-01"

    def test_non_windows_returns_eight_keys(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader.sys") as mock_sys:
            mock_sys.platform = "linux"
            summary = r.read_summary()
        assert frozenset(summary.keys()) == EXPECTED_NON_WINDOWS_KEYS
        assert all(v == "N/A (Windows only)" for v in summary.values())


# ----------------------------------------------------------------------
# Orchestrator: read_raw_registry_extras
# ----------------------------------------------------------------------

class TestReadRawRegistryExtras:
    def test_non_windows_returns_empty_dict(self):
        r = HardwareReader()
        with patch("core.stealth.hardware_reader.sys") as mock_sys:
            mock_sys.platform = "linux"
            extras = r.read_raw_registry_extras()
        assert extras == {}

    @pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
    def test_sparse_contract_when_all_reads_fail(self):
        """If every key read fails, return an empty dict — not key:'Unknown'."""
        r = HardwareReader()
        import winreg
        with patch.object(winreg, "OpenKey", side_effect=OSError):
            extras = r.read_raw_registry_extras()
        assert extras == {}

    @pytest.mark.skipif(sys.platform != "win32", reason="winreg only on Windows")
    def test_real_extras_shape_is_valid_subset(self):
        """
        On a real Windows machine, the live reader should produce a dict
        whose keys are all from the expected set. This catches accidental
        key renames.
        """
        r = HardwareReader()
        extras = r.read_raw_registry_extras()
        allowed = {
            "product_id_raw", "build_guid", "install_date_raw",
            "bios_BaseBoardSerialNumber", "bios_BaseBoardProduct",
            "bios_BIOSVendor", "bios_BIOSVersion", "bios_BIOSReleaseDate",
            "bios_SystemProductName", "bios_SystemFamily",
            "sam_v_b64",
        }
        unexpected = set(extras.keys()) - allowed
        assert not unexpected, f"Unexpected extras keys: {unexpected}"


# ----------------------------------------------------------------------
# Logger optionality
# ----------------------------------------------------------------------

class TestLoggerOptionality:
    def test_default_logger_is_noop(self):
        r = HardwareReader()
        r._log("anything")  # must not raise

    def test_custom_logger_is_stored(self):
        captured = []
        r = HardwareReader(log_callback=captured.append)
        r._log("hello")
        assert captured == ["hello"]
