# BIFROST SDK — Changelog

## 4.0.0 — Rebrand + Full Rework (2026-09)

Complete re-evaluation of the codebase. Brand consolidated to BIFROST SDK everywhere (the Ouroboros naming is gone from code, packaging, and persisted state).

### Analyzer / decompiler (new)

- IDA-style decompiler surface behind the same four-layer bridge: rizin + rz-ghidra (`pdg`/`pdgj`) when provisioned, iced-x86 linear disassembly otherwise. No rizin process is ever spawned implicitly; `analyze_probe` reports engine state up front.
- Protocol v1.3 adds `analyze` (streaming), `analyze_export` (streaming), `analyze_probe` and `decompile_fn` (request/response). One rizin session per backend process stays open after analysis for cheap per-function decompile; sessions idle-close after 5 minutes.
- Module analysis sources dump the target module raw to `output/analyzer/<module>/` with hijack -> direct attach only — the no-implicit-driver rule from the BSOD work extends here.
- `tools/provision_rizin.ps1` fetches the official rizin static win64 build and compiles rz-ghidra v0.9.0 against it (rizinorg publishes no prebuilt Windows plugin — verified across the full release history).
- Export pass batch-decompiles the largest functions to `.c` files under `<source>/decomp/`.
- iced-x86 fallback and module dumper covered by new tests (31 added; rizin path tested through a fake-runner seam, no binary required).

### Protocol (v1.3)

- v1.3 adds the analyzer command surface (see above). The pre-existing v1.2 changes below remain as shipped:
- `cancel` command added. `stop-dump` now actually reaches the backend; operations abort at checkpoints via a shared `CANCEL_EVENT` (pattern scanner chunks, between dump stages).
- Validation-reject responses echo `_id` — previously they dropped the correlation id and every rejected command left the renderer hanging for the full 15s timeout.
- `ping` reports the live build stamp and `protocol_version`; version drift (2.0.0 vs 3.0.0) fixed.
- Protocol document rewritten to match reality: `read_memory`/`ac_detect` are documented as implemented, `dump.stealth` is a string enum, error shape documented where it's actually emitted.
- Dead allow-list entries removed from `main.js` (`detect_engine`, `get_debug_info`, `load_config`, `save_config`, `list_configs`).
- Streaming events are tagged with the originating operation and routed per-channel in `main.js`. Cross-contamination between dump/spoof/gen/hunt events is gone — a spoof completion no longer auto-navigates the dump UI to Results.

### Backend fixes

- `StealthReader` called `DriverInterface.load()`, which doesn't exist — the PT walker and driver access modes failed with a swallowed `AttributeError` on every run and silently degraded to hijack/direct. Fixed; the mapper's loaded state is verified before declaring success.
- `module_base` PEB fallback returned the main exe base for *any* requested module and cached it — `client.dll` could resolve to the game exe. PEB path is now exe-only; psutil maps handle other modules; sizes come from PE headers instead of being cached as 0.
- PT walker returned a hardcoded placeholder CR3 (`0x1AA00000`) on failure and assumed contiguous physical pages — garbage reads. Placeholder removed (failure now raises), page-crossing reads split per page, short physical reads raise.
- `DriverInterface.read_virtual` zero-filled on unmapped pages — data corruption masquerading as data. Now raises.
- EPROCESS offsets were hardcoded per one Windows build (`Peb=0x550`, `DTB=0x28`). Both now try per-build offset candidates and surface what they found.
- PID validation rejected anything above 65535. Windows PIDs are 32-bit; fixed.
- Driver hash verification was prefix-match and fail-open (warn, then load anyway). Now full SHA256 compare, fail-closed, `force=True` is the only bypass.
- `drivers/mapper.py` auto-fetch was dead — `import fetcher` fails under the app's import layout and the exception was swallowed. Fixed to a package-relative import with surfaced errors.
- Webhook PowerShell fallback interpolated the raw URL into a script string — command injection via crafted webhook token. Token charset is now validated, and the URL is quote-escaped before interpolation. Third tier kept as fallback fingerprint.
- Blizzard `_resolve_globals` applied a fixed `(3,7)` rip-relative resolution to patterns that don't have a disp32 at byte 3. Resolvers are now per-pattern, and the `component_registry` pattern was replaced with a real global-load shape.
- Unity Mono `_dump_fallback` returned an empty package — a "successful" dump with zero classes. Now raises so the failure surfaces.
- `list_processes` never populated the `window` field — process enumeration now collects visible window titles in one `EnumWindows` pass.
- `run_read_memory` implemented (stealth attach with direct fallback, byte-array response for the Memory Viewer).
- `run_ac_detect` implemented (process/service/driver scan for EAC, BattlEye, Vanguard, RICOCHET, GameGuard).
- Console flashing: subprocess calls in the spoofer use `CREATE_NO_WINDOW`.
- SMBIOS tables above 4GB (64-bit entry points) are surfaced instead of silently read as garbage.
- `KNOWN_GAME_EXES` expanded: TF2 x64, CS:S, DoD:S, HL2:DM, Palworld, Delta Force, Squad, Tekken 8, Hogwarts Legacy, PUBG, Ready or Not, Valheim, Lethal Company; Rust/Phasmophobia/Among Us corrected to `unity_il2cpp`.

### Frontend fixes

- SpooferPage, BoilerplatePage, DriverHunterPage read the result envelope (`{type:'result', data}`) correctly — spoof results were stuck PENDING, boilerplate always rendered failure, hunter results never rendered.
- MemoryViewerPage surfaces read errors instead of drawing a fake zero grid; ACMonitorPage no longer fabricates "No anti-cheat detected" when the backend scan fails.
- BridgeStatus maps resolved `{error}` from ping to offline; protocol version pill now renders.
- `preload.js` exposes the missing `on*Error`/`on*Progress` methods for spoof/gen/hunt.
- localStorage keys migrated `ouroboros_*` -> `bifrost_*`.

### Cleanup

Deleted: `core/generator.py` (flat module shadowed by the `core/generator/` package), `core/discord.py`, `core/pointer_scanner.py`, `core/stealth/scanner.py` (all zero importers), `main.py` + `ui/` (legacy Textual TUI with an out-of-sync engine chain), the `second-brain/` Node project bundled inside the repo, scratch files (`delete`, `query`, `stop`, `test_github.py`, `test_hijack.py`), stale PyInstaller artifacts (`api_server_new3/new4.exe`, specs, `build_out/`, `dist/`), the old Ouroboros installer, and the Ouroboros-branded asset generator.

### Build

- `api_server.spec` replaces the new3/new4 specs — collects all engine/core submodules explicitly so dynamic imports survive freezing (the old builds shipped engines that couldn't load), embeds the protocol JSONs, excludes irrelevant stdlib-heavy packages.
- `build.ps1` — one-shot build: PyInstaller -> `gui/extra` staging (exe + drivers + config) -> Electron NSIS -> packaged smoke test gate.
- `scripts/smoke_bridge.py` tracks the new artifact name (`api_server.exe`) and protocol v1.2.

## 3.0.0 (Ouroboros era) — historical

Prior history: CS2 dump fixes (8 total), council remediation clusters (protocol v1.1, listener hygiene), and the schema-system traversal work. See `COUNCIL-REVIEW.md` and `plan.md` for the full narrative of that period, including the documentation-debt correction that is no longer relevant to the current implementation.

## Build Commands

```powershell
# One-shot
powershell -ExecutionPolicy Bypass -File build.ps1

# Backend only
pyinstaller api_server.spec --noconfirm --clean
copy dist\api_server.exe gui\extra\api_server.exe

# Frontend only
cd gui
npm run build
```

Outputs: `gui\dist-electron\win-unpacked\BIFROST SDK.exe`, installer `gui\dist-electron\BIFROST-SDK-4.0.0-Setup.exe`.

> The backend artifact must be named `api_server.exe` to match `gui/electron/main.js`.
> A wrong name fails silently on startup — the packaged smoke test exists to catch it.

## How to Test

1. `python -m pytest tests/ -q` — 199 tests, all engines exercised against mocks
2. `python scripts/smoke_bridge.py` — protocol envelope, allow-list rejection, streaming acceptance
3. `powershell -File build.ps1` — full build with packaged smoke gate
4. Launch `BIFROST SDK.exe` as Administrator, dump a target, check logs for the per-operation routing and the results page
