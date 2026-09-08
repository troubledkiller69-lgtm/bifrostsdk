# bifrostsdk — project notes

Memory/SDK framework (Python core + engines, Electron/React GUI, JSON IPC protocol v1.3). Decompiler stack: one-shot rizin + rz-ghidra, iced-x86 fallback. Workspace rules in `~/.gemini/antigravity/scratch/AGENTS.md` and the global config apply.

## Canonical interpreter — non-negotiable

- Build, test, smoke, and PyInstaller runs use ONE python: `C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe`.
- The `python` on PATH and the `pyinstaller` on PATH belong to OTHER installs (hermes 3.11 venv, Python 3.9 Scripts) whose site-packages lack deps like `iced_x86`. A frozen backend built under them silently drops iced and packaged disasm dies with `DISASM_FAILED` at runtime — collect_submodules() returning [] raises no error.
- Never invoke bare `pyinstaller`; `build.ps1` already uses `& $CanonicalPy -m PyInstaller`. Keep it that way.

## Build & run

- Packaged one-click: `gui\dist-electron\win-unpacked\BIFROST SDK.exe` (backend frozen inside; nothing to install).
- Full rebuild (backend + electron + NSIS + smoke): `powershell -ExecutionPolicy Bypass -File build.ps1` (~10-15 min; electron-builder is the slow part).
- Dev mode: double-click `BIFROST.bat` (sets PATH to canonical python, boots vite + Electron).
- Rizin toolchain is provisioned in-tree at `gui/extra/rizin` — never rely on a system rizin.

## Verification paths

- Python: `python -m pytest tests -q` (242 tests; live tests exercise a real PE through the bridge).
- Frozen backend surface: `python scripts/smoke_bridge.py --packaged`.
- After touching GUI JSX: `npx.cmd vite build` in `gui/` (the JSX grammar gate — matched-pair edits can break nesting).
- Protocol additions must land in `contracts/bifrost_protocol.json` (single source of truth), then `contracts/validate.py` fallback list.

## CS2 / direct-attach notes
- cs2.exe maps to the 'source' engine -> SourceDumper Source-2 path (SchemaSystem in schemasystem.dll). Verified dumping live: 3340 classes / 16630 fields.
- VAC'd targets (CS2): stealth driver/hijack attach fails and falls back to direct MemoryReader — that path must stay exercised; it once hid the module_base MODULEINFO crash for months.
- pymem structs are ctypes: use .name/.lpBaseOfDll, never subscript.

## Stealth transports (v2, c130661)
- No AUTO/PT_WALKER modes, no StealthLevel presets, no cleaner module. AccessMethod = DIRECT/HIJACK/DRIVER/CR3 only; `auto` == direct attach. GUI cycle: auto/direct/hijack/driver/cr3; legacy 'extreme' session value migrates to 'cr3'.
- Kernel transports (driver/cr3) map a vulnerable driver — explicit opt-in only, never an implicit fallback. `gui_bridge.run_dump` whitelists transports and falls back to direct with a log line when a kernel mode fails.
- Every StealthReader connect self-tests: probe read of KUSER_SHARED_DATA (0x7FFE0000), ordered `attach_steps`, failure chain on exception. `STEALTH_OFF = StealthConfig()` equality is the engines/base stealth-on contract; StealthConfig attribute names (scan_chunk_size, scan_inter_chunk_delay_ms, jitter knobs) must not drift.
- Driver Hunter is gone (page, core/hunter, hunt channels/commands in protocol v1.3, TestMaxDriversCap). Do not resurrect via LOLDrivers fetch; candidate drivers are enumerated in drivers/README.md instead.
