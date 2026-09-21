# BIFROST SDK — Full Scope Spec

We turn a live game process into compilable C++ headers, `offsets.json`, and decompiled C. That's the whole pitch. Point it at a game, pick an engine, dump the class/field layout, diff it across patches, decompile the binary, and (if you bring a driver) read memory the anti-cheat can't see.

Stack: Python backend (canonical 3.14) over stdio JSON IPC, Electron + React + Vite GUI, zero HTTP anywhere. Offline-first. Rizin ships in-tree, IDA is optional BYO-license.

## Dump engines

Seven real engines, all extending `engines/base.py:BaseDumper`. One contract: `validate()` then `dump()` returns `SDKPackage` list, progress streams as `DumpProgress{stage,detail,percent,classes_found,fields_found,errors}`.

**Unreal (`unreal`, `unreal5_marvel`)** — UE4.25+/UE5: Fortnite, Valorant, Palworld, Marvel Rivals. GNames + GObjects pattern scan, FNamePool chunk walk (`ComparisonIndex → string`), FUObjectArray chunk iteration, FProperty chain → typed `SDKField` via `PROPERTY_TYPE_MAP`. Per-game presets: `UE5_DEFAULT`, `UE5_MARVEL_RIVALS` (auto-switches when the exe name contains "marvel"). 4-tier module detection: exact → case-insensitive → substring-largest → blind trust. Profile knobs in `engines/unreal/structs.py` (`FNamePoolConfig`, `GObjectsConfig`, `UObjectConfig`, …).

**Unity Mono (`unity_mono`)** — Mono Unity games (Tarkov). Direct struct reads of `MonoClass`/`MonoClassField` (no remote threads). Validates against `mono.dll` variants.

**Unity IL2CPP (`unity_il2cpp`)** — IL2CPP Unity (Rust, Phasmo, Valheim). Finds `GameAssembly.dll` + `global-metadata.dat` on disk or in memory, parses TypeDef/FieldDef/string tables, reads live `Il2CppClass`/`FieldInfo` for runtime offsets. If the GUI can't tell Mono from IL2CPP, `_resolve_unity_ambiguity()` checks for `GameAssembly.dll` vs `mono.dll` and switches automatically.

**Source (`source`)** — Source 1 (CS:GO, TF2: `client.dll` ClientClass → RecvTable → RecvProp walk) and Source 2 (CS2, Dota2: `schemasystem.dll` SchemaSystem → TypeScopes → ClassBindings → FieldData) under one key. `validate()` sniffs the module list to pick the path. Live-verified on CS2: 3340 classes / 16630 fields.

**Source EAC (`source_eac`)** — Apex Legends `r5apex.exe` (modified Source r5). Pattern set for entity list, local player, view render, level name, highlight settings, name list, globals, plus `ApexPlayer`/`ApexWeapon`/`ApexGlow` offset dataclasses.

**Blizzard (`blizzard`)** — Overwatch 2 `Overwatch.exe`. Custom ECS, no reflection to lean on: pattern-scan EntityManager/ComponentRegistry/HeroDatabase, RTTI + vtable walk, hero hash table.

**Custom (`custom`)** — generic AOB fallback for anything else.

Not an engine: `engines/template/` is scaffolding for adding one (`YourDumper` + `YourEngineConfig` + a checklist). Never registered, never GUI-selectable.

Engine detection for the process picker lives in `core/process.py:ProcessEnumerator` — psutil list fingerprinted by `ENGINE_SIGNATURES` (indicator modules, DLL names, process names, heuristic strings).

## Stealth / transports

Four access methods. No auto-ladder, no presets. You pick, it self-tests, failures say why.

- `direct` — plain `MemoryReader` (pymem). PEB ImageBase fast-path for the main exe, typed reads, module cache. `auto` in the GUI just means direct.
- `hijack` — `HandleHijacker`: enumerates system handles via `NtQuerySystemInformation`, duplicates a usable handle out of csrss/lsass. Dodges OpenProcess monitoring and callback-based handle stripping.
- `driver` — `DriverInterface` over a mapped vulnerable driver: physical read/write, `get_process_cr3`, VA→PA via manual PTE walk. Explicit opt-in only, never a silent fallback.
- `cr3` — `CR3BruteForcer` scans physical RAM (live-sized via `GlobalMemoryStatusEx`, 32GB fallback) for the target PML4, verified by the MZ header at the target base. Survives EAC's CR3 shuffling. `PTWalkerReader` does the 4-level walk once CR3 is known.

Every `StealthReader` connect self-tests with a probe read of `KUSER_SHARED_DATA` (`0x7FFE0000`) and records ordered `attach_steps` — the Dump page renders these as the per-step dot strip, and the bridge emits them as the `access` event (`requested` vs `actual` transport, fallback note, ms). If a kernel transport fails, it falls back to direct *with a log line*, never silently. `STEALTH_OFF = StealthConfig()` equality is the engines/base stealth-off contract — attribute names must not drift.

Jitter lives in `core/stealth/timing.py` (`JitteredReader`, `AdaptiveJitter`, `TimingStats`) — microsecond delays, burst/cooldown, idle mimicry. Scan chunk size and inter-chunk delay are config knobs.

## Analyzer (binary workbench)

Three decompiler backends, tried in order. `auto` means rizin → IDA → iced.

**Rizin + rz-ghidra (default, ships in-tree at `gui/extra/rizin`)**. One-shot spawns — Windows can't drive rizin over an interactive pipe, so every op is its own process (cold cost ~2-4s, all `CREATE_NO_WINDOW` silent). `aaa` analysis, `aflj` functions, `pdgj` decompile, `axtj` xrefs, `pdfj` calls, `iij` imports. Parsers (`parse_aflj/pdgj/pdfj_calls/iij/axtj`) are pure and unit-tested without rizin. Provisioned by `tools/provision_rizin.ps1` (shared64 rizin 0.9.0 + rz-ghidra built from source — static builds embed a duplicate librz and deadlock, so shared is mandatory). Never relies on a system rizin.

**IDA (optional, your license)**. `find_ida_exe()` checks install paths then fuzzy-scans `Downloads\IDA_Test`. Batch mode: `idat.exe -A -S<script>` with a 25-minute cancellable timeout, 60s heartbeat logs, cooperative cancel via `CANCEL_EVENT`, and `.idb` droppings cleaned out of your target dir afterward. The embedded script decompiles the top functions via hexrays (cap 300, 100KB per body) so `decompile_fn`, callgraph, and export all serve from cache without re-running IDA. `%TEMP%/bifrost_ida_cache/` keeps the `.idb` set keyed by file hash + size + IDA build — re-analyzing an unchanged binary goes incremental, patching it invalidates automatically. Probe never executes the binary (version is parsed from the install path — `idat.exe -h` hangs on stdin and used to flash a console on every Analyzer open).

**iced-x86 (always available)**. Stateless linear disassembly, 64KB window cap. The floor everything degrades to.

Session model: single `CURRENT{session,source,engine,cache,symbols,functions,lock}` in `core/decomp/analyzer.py`. Bodies cached per address. Idle sessions close after 5 minutes. Module sources (`pid + module`) get dumped raw to `output/analyzer/<module>/` first (16KB chunks, guard pages zero-filled with a missing-chunk count), hijack → direct only, then analyzed as files.

Ops: `analyze` (streaming, cancellable), `decompile_fn` (one function), `analyze_export` (`split` = one `.c` per function, `single` = `bundle.c`, both with `index.json`, limit 1–2000), `analyzer_hexdump` / `analyzer_disasm_at` (stateless, no rizin needed), `analyzer_xrefs`, `analyzer_callgraph` (calls + called-by with resolved names), `analyzer_search` (imports + strings + xrefs, 25-target cap), `analyzer_symbols` (full name→addr map), `analyzer_strings` (whole-image ASCII/UTF-16LE scan).

## Driver Bay + BYO drivers

Six tier-1 known drivers in `drivers/drivers_list.json`: Intel `iqvw64e.sys` (bulk physical), Dell `dbutil_2_3.sys` (CVE-2021-21551), MSI `RTCore64.sys` (CVE-2019-16098, dword loop), Dell `WDTKernel.sys` (WHQL), Corsair `CorsairLLAccess64.sys` (WHQL, MMIO), Gigabyte `gdrv.sys` (4× CVE-2018-19320–23). Three tier-2 candidates with null IOCTLs. Binaries live next to the mapper (`iqvw64e.sys`, `RTCore64.sys` in-tree); `.sys` never touches git.

`DriverMapper` stages to `%TEMP%\wdf*.sys` with a randomized service name, enables `SeLoadDriverPrivilege`, verifies SHA256 fail-closed (unless `force`), maps via `NtLoadDriver`, cleans up on unload. Seven `IoctlStrategy` classes: `IntelStrategy` (`0x80862007/08`), `MsiStrategy`, `WdtStrategy`, `CorsairStrategy`, `GigabyteStrategy`, plus `GenericBulkStrategy` and `GenericDwordStrategy` for anything else.

**BYO**: drop a `.sys` + a sidecar `.json` in `drivers/byo/` — `key`, `filename`, `service_name`, `device_path`, `strategy` (a known name or `generic_bulk`/`generic_dword` with custom `ioctl_read`/`ioctl_write`), `known_hashes` (empty = skip check), `description`. The mapper merges repo `drivers/byo/`, frozen `exe/drivers/byo/`, and single-file `drivers.json` lists. `example_generic_bulk.json` is the template.

`driver_list` reports per profile: present on disk, hash ok/mismatch + actual hash, BYO flag, and `loaded` via SCM `QueryServiceStatus` (true = running right now). `driver_test` maps, opens the device, fires a 0-byte ioctl probe, unloads. Needs Admin + `SeLoadDriverPrivilege`. The Driver Bay page renders all of it as cards with Test Load / Force / Use / copy-device-path actions.

## The GUI (13 pages, one frameless window)

Frameless Electron (1200×800, custom 36px titlebar), React 18, offline vendored fonts (Rajdhani + JetBrains Mono). Black `#030303` + FM lime `#7EFF3F`, matte bevels. All backend traffic goes through `window.bifrost` (preload allow-list) as stdio JSON — no HTTP. Global state in `App.jsx`: page router (no react-router), stealth, driver key, engine/process selection, dump progress + logs, persisted queue, watch timer, toasts, confirms, per-page error boundaries.

- **Dashboard** — garage header, 4-button quick launch, recent activity from last dump, shortcut hints.
- **Engines** — 7 static cards grouped by family with module/profile/strategy chips, search filter.
- **Processes** — `list_processes` table (PID/name/window/engine), search, skeleton rows, offline banner; picking one auto-sets the engine and jumps to Dump.
- **Dump** — the main event. Armed-target header, coolant-tube progress, kernel driver strip (present-only driver picker) when `driver`/`cr3`, access panel (requested vs actual transport + step dots), auto-scrolling log console, `forceDiscovery`/`regenerate` options, queue controls, watch controls, Start/Stop/Redump. Stall watchdog warns after 45s of silence and points at Diagnostics.
- **Results** — class tree + field table, search, export as JSON/CSV/C++ header (`offsets::{Class}::FIELD`, runtime offsets marked), copy + save-dialog, load-from-disk recovery via `_meta`.
- **Diff** — two modes. Manual: load two `offsets.json` files, client-side compare by `Class::Field` with filter tabs. History: pick a game, pick before/after snapshots, server-side diff with drift panel.
- **Memory** — hex editor. PID + address → 512B grid (clickable bytes, ASCII, changed-byte highlight, zero-dim), interpreter panel (int8→double, ptr64, float, ascii) from selection, auto-refresh with rate, hex write (`write_memory`, direct-only), pointer-chain history, bookmarks in localStorage, and a Signature section (`make_signature`: 1–16 addresses → scored AOB candidates with verify toggle, copy per pattern).
- **AC Monitor** — `ac_detect` for EAC/BattlEye/Vanguard/RICOCHET/nProtect (processes + services + drivers), ACTIVE/Not Found cards, and a recommendation engine: clean → DIRECT, light → HIJACK, EAC/BE → DRIVER, Vanguard/Ricochet → CR3.
- **Analyzer** — the workbench. File or live-module source, engine picker, streaming analyze with log console, filterable function list, click-to-decompile C view with tokenizer (function names and `0x` addresses are jump links), tabs for strings / call-site search / export (limit + split/single), embedded AddressExplorer.
- **AddressExplorer** (inside Analyzer) — one address → parallel hexdump + disasm + xrefs, plus lazy callgraph tab. Jump targets arrive from strings and code links.
- **Diagnostics** — `debug_snapshot`: current op (idle seconds, stall flag), last op outcome, ring buffer, thread dump viewer, output file listing, copy-snapshot, Go-to-Dump. Auto-refresh toggle.
- **Driver Bay** — described above.
- **Config** — AOB pattern JSON editor (`GWorld`/`GNames`/`GObjects` defaults + Unity) with live validation, in localStorage.
- **Settings** — theme (midnight/paper/terminal/garage), compact tables, font scale, output dir, auto-navigate, auto-export format, default stealth/engine/analyzer, Discord webhook URL + test button, log level, about (build stamp, features), reset-all.

Plus: `Ctrl+K` command palette (13 pages + actions, fuzzy scored), `Ctrl+1..13` page jumps, `Ctrl+Enter` start dump, `Ctrl+Esc` stop, `beforeunload` guard during ops, stale-backend banner, bridge health pill (15s ping, error counter that never mistakes op failures for bridge death).

## Dump queue, watch mode, history

**Queue** — arm multiple targets, they drain in order. Persisted in localStorage, survives reloads, errors skip to next, Cancel clears. The watch timer pauses while the queue runs.

**Watch** — re-dump the armed target every 5/15/30/60 min. Timer lives in App (survives navigation), pauses for queues and running dumps. Each completion compares class/field counts against the previous run; drift logs `[WATCH]` and toasts. Every cycle archives to history.

**History** — every successful dump auto-archives `offsets.json` to `output/<game>/.history/<UTC>.json` (newest 20, sidecar with engine/class/field counts, never breaks the dump if archiving fails). `dump_history` lists per game, `dump_diff` diffs any two snapshots with the same logic as `scripts/compare_dumps.py` (`drift` = fields changed or classes removed; pure additions are fine).

## Code generation

`run_generate` turns a dump into a VS C++ scaffold: `.sln`, `.vcxproj`, `main.cpp`, `memory.h`, `driver.h`, `offsets.h`, IDA script. Streaming with progress.

## Protocol + IPC

`contracts/bifrost_protocol.json` (v1.3) is the single source of truth both sides validate against. stdio newline-delimited JSON. Request-response (`ping`, `list_processes`, `bridge_info`, `read_memory`, `write_memory`, `ac_detect`, `analyze_probe`, `decompile_fn`, `analyzer_*`, `debug_snapshot`, `dump_history`, `dump_diff`, `driver_list`, `driver_test`, `test_webhook`, `cancel`) with `id` → `_id` correlation and a 15s timeout (longer per-op in Electron: decompile 120s, callgraph 180s, search 300s). Streaming (`dump`, `generate`, `analyze`, `analyze_export`) with `log`/`progress`/`result`/`access`/`error` events, cooperative cancel, one stream at a time (`BUSY` otherwise). `contracts/validate.py` gates the backend at boot and derives the allow-list from the JSON.

`api_server.py` is the frozen stdio dispatcher (stdout is protocol-only, prints go to stderr, build stamp from hash + mtime). `gui/electron/main.js` spawns it (`windowsHide`, no console), enforces its own `ALLOWED_COMMANDS`, routes streams to channels, recovers crashes by failing pending calls with `BACKEND_CRASHED`. `gui/src/types/protocol.d.ts` is generated from the protocol JSON.

## MCP server

`mcp_server.py` — zero-dependency stdio JSON-RPC (`2024-11-05`), 19 tools wrapping the same `gui_bridge.run_*` handlers agents would otherwise click through: `list_processes`, `dump`, `dump_history`, `dump_diff`, `make_signature`, `analyze_probe`, `analyze`, `decompile_fn`, `analyze_export`, `hexdump`, `disasm`, `xrefs`, `callgraph`, `search_callsites`, `symbols`, `strings`, `read_memory`, `driver_list`, `driver_test`. Streaming ops block to completion and return the result plus a log tail. 100KB output cap. Registered in `opencode.json` as the `bifrost` local server. Deliberately no `write_memory` — reads are safe to delegate, writes stay human-gated.

## Outputs, schema, CLIs

Dumps land in `output/<game>/`: `offsets.json` (schema-validated: `_meta{generator,engine,timestamp,total_classes,total_fields}` + `offsets{class→{size,super,fields{name→{offset,size,type}}}}`, hex as `0x…`) plus generated headers. Three CLIs keep them honest: `verify_output.py` (schema + `_meta` cross-check + header sanity, `--strict`), `compare_dumps.py` (drift with exit codes 0/1/2), `smoke_bridge.py` (`--packaged` runs the frozen exe through ping/processes/rejection/streaming/probe checks). `gen_protocol_types.py` regenerates the TS types.

## Build, dev, provisioning

One interpreter for everything: `C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe` (the PATH pythons lack `iced_x86` and would silently break frozen disasm — never use them). `build.ps1` does the full chain: kill locking processes → PyInstaller `api_server.exe` → stage `gui/extra/` (exe + drivers + config + optional IDA mirror) → `vite build` → hash-gated `electron-builder` (win dir + NSIS, `requireAdministrator`) → strict output gate → packaged smoke. ~10-15 min, prints backend/app/installer paths. `BIFROST.bat` is the dev launcher (canonical python on PATH + `npm run dev`). `tools/provision_rizin.ps1` fetches and builds the rizin toolchain (~10 min), `tools/provision_ida.ps1` mirrors your IDA install, `tools/verify_extra.ps1` checks the bundle (`-Strict` fails without rizin).

Tests: `pytest tests -q`, ~250 tests. Mock/unit for every engine pipeline, scanner, signatures, stealth config, hardware reader, dump history, schema, protocol, MCP framing, webhook, analyzer parsers, explorer ops, path-traversal security; live tests drive a real PE through the bridge.

## Limits (stated, not apologized for)

Cancel is cooperative — checkpoints abort, they don't preempt. Offsets die every game patch; that's what history + diff + watch are for. Module images are raw snapshots, not rebased PEs. rz-ghidra is pinned per rizin version. Kernel transports need Admin and an explicit choice. The backend runs elevated because it has to — stdio allow-list is the trust boundary (`SECURITY.md` has the threat model).
