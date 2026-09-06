# BIFROST SDK

Universal game engine SDK dumper for Windows — plus a decompiler, so it doubles as a reverse-engineering workstation. Attach to a running game, walk its engine structures, and generate ready-to-compile C++ SDK headers, `offsets.json`, or decompiled C straight from the same target.

Supports Unreal Engine 5 (per-game profiles), Unity Mono and IL2CPP, Source 1 and 2, and Blizzard engines. Stealth access modes cover kernel anti-cheat: vulnerable-driver physical reads, page-table walks, handle hijacking, direct pymem.

## Requirements

- Windows 10/11 x64
- Python 3.10+ (dev only; the shipped app bundles its backend via PyInstaller)
- Node.js 18+
- Administrator rights (opening protected game processes)
- rz-ghidra decompiler: optional. Run `tools/provision_rizin.ps1` once (builds against bundled rizin). Without it the Analyzer falls back to iced-x86 disassembly-only.

## Dev setup

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest, for the test suite

cd gui
npm install
npm run dev                           # Vite on :5173 + Electron window
```

## Tests

```bash
python -m pytest tests/ -v            # 199 tests; engine dumpers run against mock readers
python scripts/smoke_bridge.py        # exercises the stdio JSON IPC protocol end to end
```

## Build

One script does the whole chain — PyInstaller backend, `gui/extra` staging, Electron installer, packaged smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Flags: `-SkipBackend` (reuse an existing `dist\api_server.exe`), `-SkipSmoke`.

Outputs:

- `dist/api_server.exe` — the Python backend, frozen
- `gui/dist-electron/win-unpacked/BIFROST SDK.exe` — unpacked app
- `gui/dist-electron/BIFROST-SDK-4.0.0-Setup.exe` — NSIS installer

The installer requires admin (`requestedExecutionLevel: requireAdministrator`).

## Architecture

Four layers, top to bottom:

1. **React UI** (`gui/src/`) — page components, state centralized in `App.jsx`, session persisted to `localStorage` under a `bifrost_` prefix.
2. **Electron shell** (`gui/electron/`) — frameless `BrowserWindow`, spawns the backend as a child process, bridges IPC. `preload.js` exposes `window.bifrost` with context isolation on.
3. **IPC dispatch** (`api_server.py`, `gui_bridge.py`) — stdin/stdout line-delimited JSON. Every command is validated against the contract allow-list in `contracts/bifrost_protocol.json` before dispatch. Streaming operations carry a `stream` tag so events route only to their own channels.
4. **Core + engines** — process-agnostic primitives in `core/` and engine dumpers in `engines/` behind a registry.

```text
bifrostsdk/
  api_server.py         # JSON IPC dispatcher (stdin/stdout)
  api_server.spec       # PyInstaller spec for dist/api_server.exe
  build.ps1             # one-shot build: backend -> extra/ -> installer -> smoke
  gui_bridge.py         # command router, business logic, KNOWN_GAME_EXES
  core/                 # memory readers, AOB scanner, signature gen
  core/decomp/          # analyzer: rizin-ghidra engine, iced-x86 fallback, module dumper
  core/stealth/         # driver/hijack/PT-walker readers, spoofer, cleaner, timing
  core/hunter/          # vulnerable driver hunter
  core/generator/       # SDKPackage -> C++ headers (schema-validated)
  engines/              # unreal/, unity/, source/, blizzard/ dumpers + registry
  contracts/            # bifrost_protocol.json + sdk_output_schema.json + validator
  drivers/              # vulnerable drivers + mapper + fetcher (hash-verified)
  tools/                # provision_rizin.ps1 (rizin + rz-ghidra bundling)
  gui/                  # Electron + React frontend
  scripts/              # smoke_bridge.py
  tests/                # pytest suite (199 tests)
  output/               # dump + decompile artifacts (gitignored)
```

## Engine coverage

| Engine | Key | Notes |
|---|---|---|
| Unreal Engine 5 | `unreal5` / `unreal5_marvel` | GWorld/GNames/GObjects traversal, compact FNamePool, game-specific profiles |
| Unity Mono | `unity_mono` | Assembly + MonoClass walking |
| Unity IL2CPP | `unity_il2cpp` | GameAssembly metadata parsing |
| Source 1 | `source` | ClientClass/RecvTable/RecvProp walk (netvars), x86 + x64 |
| Source 2 | `source` | CSchemaSystem via CUtlTSHash (CS2) |
| Blizzard | `blizzard` | ECS entity/component walking, RTTI class enumeration |

`KNOWN_GAME_EXES` in `gui_bridge.py` maps known executables to engines; unknown processes fall back to module-based auto-detection in `core/process.py`.

Adding an engine: subclass `BaseDumper` in `engines/<engine>/dumper.py`, register it in `engines/registry.py`, add any known exes to `KNOWN_GAME_EXES`. No other files need changes.

## Analyzer / decompiler

The Analyzer is the RE half of the SDK. It opens a file (or dumps a module from a live process, hijack -> direct only — never implicitly a driver) and hands it to rizin:

- `analyze` — load + auto-analysis (`aaa`), returns the function list ranked by size
- `decompile_fn` — `pdgj` for one address; session stays open, bodies cached
- `analyze_export` — batch-decompiles the top functions to `.c` files under `<source>/decomp/`

Sessions idle-close after 5 minutes. Rizin binaries live in `gui/extra/rizin/` (see provisioning above); when absent, `analyze` degrades to iced-x86 linear disassembly and says so. No rizin process is spawned by the probe — the GUI can always tell you what engine you'll get before you click.

## Stealth access modes

`dump` accepts `stealth` as `auto | driver | hijack | direct`:

- `auto` tries PT walker -> vulnerable driver -> handle hijack -> direct, degrading gracefully.
- `driver` maps a signed-but-vulnerable driver (Intel iQVW64E, MSI RTCore64, Dell DBUtil/WDT, Corsair, Gigabyte) and reads physical memory.
- `hijack` duplicates a `PROCESS_VM_READ` handle from a system process.
- `direct` is plain pymem — fine for VAC-only games, not for EAC/BE/Vanguard.

The bundled `.sys` files are hash-verified against known-good SHA256 values before they're mapped. Loading refuses on mismatch unless you pass `force=True`.

## The bridge protocol

`contracts/bifrost_protocol.json` is the single source of truth for the Electron <-> Python surface — commands, streaming commands, event shapes, error shape. Version 1.3. It's enforced:

- `api_server.py` rejects unknown commands before dispatch, echoes the request `id` as `_id`, tags every streaming event with the originating operation.
- `main.js` routes events per operation channel and keeps an allow-list.
- `contracts/validate.py` holds the loader + validation logic, consumed by the smoke test and by tests.

Changing a command or event means updating the protocol file first. The tests (`tests/test_validate.py`) fail on drift between the Python allow-list and the JSON.

## Discord notifications

`dump` accepts a webhook URL. The sender validates the URL shape (snowflake ID, token charset), redacts the token in logs, uses the Discord-recommended bot User-Agent, and falls back through three HTTP fingerprints (urllib -> curl -> PowerShell) when Cloudflare 403s the default one.

## Known limits

- `cancel` is cooperative: operations abort at checkpoints (scanner chunks, between dump stages), not mid-read.
- Streaming commands have no timeout; request/response commands use a 15s window — big `decompile_fn` calls can exceed it, retry or use the export pass.
- The dump result carries `{headers, json, classes, fields, elapsed}` — page code that wants the full class data loads the JSON from `output/`.
- Anti-cheat access is a moving target. Offsets and patterns in `engines/*/structs.py` are per-patch and need refreshing against a fresh dump (see the "Pattern miss" warnings in dump logs).
- Decompiled module images are raw memory snapshots, not rebuilt PEs — section layout reflects the loader, and rizin's analysis is best-effort on `bin.cache`-mapped dumps.
- The rz-ghidra plugin must be built once per rizin pairing (`tools/provision_rizin.ps1`); rizinorg publishes no prebuilt Windows plugin.

## Security notes

See `SECURITY.md` for the threat model. Short version: the backend is an admin-elevated process with kernel access primitives; the renderer only reaches it through the validated stdio contract, and bundled drivers are hash-checked fail-closed.
