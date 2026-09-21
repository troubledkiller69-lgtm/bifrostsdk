# BYO Drivers — Bring Your Own Vulnerable Driver

Drop your own `.sys` here and add a JSON sidecar. The mapper auto-discovers it on next `driver:list` or dump with `stealth: driver`.

## Quick start

1. Copy `myvuln.sys` into `drivers/byo/` (or `drivers/` — both scanned).
2. Create `myvuln.json` next to it:

```json
{
  "key": "myvuln",
  "filename": "myvuln.sys",
  "service_name": "MyVulnDrv",
  "device_path": "\\\\.\\MyDevice",
  "strategy": "intel",
  "ioctl_read": "0x222003",
  "ioctl_write": "0x222007",
  "known_hashes": ["<sha256 of your .sys>"],
  "description": "My BYO driver — Intel-style bulk phys R/W"
}
```

Fields:
- `key` — unique id (lowercase, used as `stealth: driver` selector `myvuln`)
- `filename` — must match the .sys filename in this folder
- `service_name` — SCM service name (random suffix added at load so you can reuse)
- `device_path` — `\\.\YourDevice` as the driver exposes
- `strategy` — which phys R/W template to use:
  - `intel` — bulk `QIQ` (iqvw64e style, 0x80862007/0x80862008)
  - `msi` — DWORD loop (RTCore64 style)
  - `siv` — scatter read + mapped write (SIVX64 raw cmds 0x10/0x14)
  - `throttlestop` — QWORD loop (0x80006498/0x8000649C, CVE-2025-7771)
  - `lenovo` — struct phys R/W (0x9C406104/0x9C40A108, CVE-2025-8061)
  - `wdt` — Dell WDT DWORD via MmMapIoSpace
  - `corsair` — Corsair MMIO
  - `gigabyte` — GIO ring0 memcpy
  - `generic_bulk` — Intel bulk but with *your* ioctl codes
  - `generic_dword` — MSI dword loop but with *your* ioctl codes
- `ioctl_read` / `ioctl_write` — hex or decimal (required for generic, otherwise defaults to strategy's codes)
- `known_hashes` — optional. Empty = skip hash check; with entries = fail-closed unless `force:true` in the dump call.
- `description` — shown in the UI.

3. From the app: `Diagnostics → Driver Bay` lists it, hash check, and a **Test** button does a 0x100-byte probe read at `KUSER_SHARED_DATA` via that driver. Or from Python:

```python
from drivers.mapper import DriverMapper
m = DriverMapper()
print(m.list_available())  # includes 'myvuln' if .sys + .json present
m.load("myvuln")           # maps your driver
```

4. Use it for dumps: in the Dump page pick `stealth: driver` and select `myvuln` when prompted (or via API `dump {stealth:"driver", driver:"myvuln"}`), or set `Default Stealth Mode → Driver (myvuln)` in Settings.

## Examples

`drivers/byo/example_generic_bulk.json` ships as a template — copy and fill.

## Notes

- Drivers must be legitimately signed (or test-signed with Test Mode on). BIFROST never bypasses signature checks — it just maps a driver you already have permission to load via `SeLoadDriverPrivilege` (Admin).
- BYO drivers are staged to `%TEMP%\wdf*.sys` with a randomized service name/suffix on every load and deleted on unload — same hygiene as built-ins.
- `force:true` skips hash mismatch abort for dev — don't ship with it.
- Keep the .sys next to the .json; the mapper resolves both under `gui/extra/drivers` when frozen.
