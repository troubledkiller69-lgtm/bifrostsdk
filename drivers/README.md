# BIFROST SDK — Driver Binaries

Place vulnerable signed driver binaries here. The mapper (`mapper.py`) will auto-detect and load the first available.

## Supported Drivers (Tier 1 — Full Strategy Support)

| Driver | Filename | Vendor | Device Path | Access Method | CVEs |
|--------|----------|--------|-------------|---------------|------|
| Intel NAL | `iqvw64e.sys` | Intel | `\\.\Nal` | Bulk physical R/W | — |
| Dell DBUtil | `dbutil_2_3.sys` | Dell | `\\.\DBUtil_2_3` | Physical R/W | CVE-2021-21551 |
| MSI RTCore | `RTCore64.sys` | MSI | `\\.\RTCore64` | DWORD physical R/W | CVE-2019-16098 |
| Dell WDT | `WDTKernel.sys` | Dell (WHQL) | `\\.\__WDT__` | DWORD via MmMapIoSpace | — |
| Corsair iCUE | `CorsairLLAccess64.sys` | Corsair (WHQL) | `\\.\CorsairLLAccess` | MMIO + PhysMem MAP | — |
| Gigabyte GIO | `gdrv.sys` | Gigabyte | `\\.\GIO` | Ring0 memcpy (bulk) | CVE-2018-19320/21/22/23 |

## Candidate Drivers (Tier 2 — Profile Only, No Strategy Yet)

| Driver | Filename | Vendor | Notes |
|--------|----------|--------|-------|
| TRIXX | `TRIXX.sys` | TechPowerUp | MMIO via PCI BAR remapping, port I/O |
| ASUS AsIO | `AsIO64.sys` | ASUS | MmMapIoSpace, multiple variants |
| MSI NTIOLib | `NTIOLib.sys` | MSI | MmMapIoSpace, 50+ hash variants |

## Acquisition

These are legitimately signed Microsoft-certified drivers with known unpatched vulnerabilities. Available from:
- Original software packages (Intel PROSet, Dell utilities, MSI Afterburner, Corsair iCUE, Gigabyte APP Center)
- [LOLDrivers project](https://www.loldrivers.io/) catalogs and GitHub releases
- [physmem_drivers](https://github.com/namazso/physmem_drivers) collection
- Archived driver repositories

## Usage

```python
from drivers.mapper import DriverMapper

mapper = DriverMapper()
print(mapper.list_available())  # ['intel', 'dell', 'msi', 'dell_wdt', 'corsair', 'gigabyte']
mapper.load("corsair")          # Load specific driver
# Or auto-detect first available:
mapper.load()
mapper.unload()
```

Driver-based access is an explicit opt-in from the GUI or the `dump` API (`stealth: driver` / `stealth: cr3`). There is no auto-fallback into kernel code — `auto` means direct attach.

## Security Notes

- Always run as Administrator (required for SCM access and SeLoadDriverPrivilege)
- The mapper randomizes the staged filename and service name
- Driver is copied to system temp with a generic name (wdf*.sys)
- Service is deleted on cleanup — no persistent traces
- VBS/HVCI will block unsigned or revoked drivers on some systems
- WHQL-signed drivers (Dell WDT, Corsair) are less likely to be blocked by VBS
