# BIFROST SDK

A reverse-engineering workstation that turns a running game into ready-to-compile C++ headers, `offsets.json`, or decompiled C. Attach to a process, walk its engine structures, and walk out with SDK code.

Covers Unreal Engine 5 (per-game profiles), Unity Mono and IL2CPP, Source 1 and 2, and Blizzard engines. When the game is behind a kernel anti-cheat, stealth access modes (vulnerable-driver reads, page-table walks, handle hijacking) get you in. A rizin + rz-ghidra backend does the IDA-style decompiling; without it, the Analyzer degrades to iced-x86 disassembly and tells you so.

## What it does

- **Dump** — pick a process, let the right engine walk its structures. Output is schema-validated: C++ headers, JSON, class/field lists.
- **Analyze** — decompile any function in a dumped module to readable C, or export the whole binary's top functions to `.c` files in one batch pass.
- **Spoof** — hardware ID spoofing through the same access pipeline.
- **Hunt** — find hash-verified vulnerable signed drivers on the machine.
- **Boilerplate** — generate a C++ project scaffold from a dump's data.

The GUI is a frameless Electron app (React + Vite). The backend is a Python process that speaks line-delimited JSON over stdio — no HTTP, no ports.

## Requirements

- Windows 10/11 x64. Admin rights (opening protected processes; the installer asks).
- Dev only: Python 3.10+, Node 18+. The shipped app freezes the backend with PyInstaller.
- Decompiler (optional): run `tools/provision_rizin.ps1` once. It fetches rizin and compiles the rz-ghidra plugin against it — rizinorg ships no prebuilt Windows plugin, so this is a one-time ~10 minute build on each machine.

## Dev setup

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest only

cd gui
npm install
npm run dev                            # Vite on :5173, Electron window opens
```

## Tests

```bash
python -m pytest tests/ -q             # 208 tests, no game required
python scripts/smoke_bridge.py         # exercises the stdio IPC protocol end to end
```

Engine dumpers run against mock readers; the rizin path is covered through a fake-runner seam plus live backend tests that hit a real `api_server.py`.

## Build

One script does the whole chain — PyInstaller backend, `gui/extra` staging, Electron installer, packaged smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Flags: `-SkipBackend` (reuse an existing `dist\api_server.exe`), `-SkipSmoke`.

Outputs:

- `dist/api_server.exe` — frozen backend
- `gui/dist-electron/win-unpacked/BIFROST SDK.exe` — unpacked app
- `gui/dist-electron/BIFROST-SDK-4.0.0-Setup.exe` — NSIS installer (admin-elevated)

## Repo map

```text
api_server.py         stdio JSON dispatcher
gui_bridge.py         command router + business logic (KNOWN_GAME_EXES)
core/                 memory readers, AOB scanner, signature gen
core/decomp/          analyzer: rizin-ghidra engine, iced fallback, module dumper
core/stealth/         driver / hijack / PT-walker readers, spoofer
core/generator/       dump data -> C++ headers
engines/              unreal/, unity/, source/, blizzard/ dumpers behind a registry
contracts/            protocol JSON + schema + validator (single source of truth)
drivers/              vulnerable driver list + fetcher, hash-verified
gui/                  Electron + React frontend
tools/                provision_rizin.ps1
scripts/              smoke_bridge.py
tests/                208 pytest tests
docs/ARCHITECTURE.md  the four-layer model, in depth
```

`output/` holds dump and decompile artifacts and is gitignored.

## Engines

| Engine | Key | Notes |
|---|---|---|
| Unreal Engine 5 | `unreal5` / `unreal5_marvel` | GWorld/GNames/GObjects, compact FNamePool, game profiles |
| Unity Mono | `unity_mono` | Assembly + MonoClass walking |
| Unity IL2CPP | `unity_il2cpp` | GameAssembly metadata |
| Source 1 | `source` | ClientClass/RecvTable walk (netvars), x86 + x64 |
| Source 2 | `source` | CSchemaSystem via CUtlTSHash |
| Blizzard | `blizzard` | ECS entities, RTTI class enumeration |

`KNOWN_GAME_EXES` maps known executables to engines; anything unknown falls back to module-based detection in `core/process.py`.

Adding an engine: subclass `BaseDumper` in `engines/<engine>/dumper.py`, register it in `engines/registry.py`, add known exes to `KNOWN_GAME_EXES`. That's the whole diff.

## The Analyzer

The decompiler half. Point it at a file, or dump a module from a live process (hijack -> direct attach only; it never implicitly loads a driver), and it hands the image to rizin:

- `analyze` — load + auto-analysis, returns the function list ranked by size
- `decompile_fn` — decompile one address; results cache per session
- `analyze_export` — batch-decompiles the top functions to `.c` under `<source>/decomp/`
- **Address explorer** — hex+ascii dump, linear disassembly, and cross-references at any address (`analyzer_hexdump`, `analyzer_disasm_at`, `analyzer_xrefs`). Disasm is rizin-free iced-x86 (instant scrolling); xrefs are a real rizin `axtj` pass.

Every operation is a one-shot rizin process (Windows can't drive rizin interactively over a pipe — see the engine docstring), so a hung decompile dies with its process, never the SDK. Bodies cache on the analyzer side, so repeat clicks are instant. Rizin lives in `gui/extra/rizin/`; when it's absent the probe reports it and `analyze` degrades to iced-x86 with a warning.

## Stealth access modes

`dump` takes `stealth: auto | driver | hijack | direct`:

- `auto` — PT walker -> vulnerable driver -> handle hijack -> direct, degrading gracefully.
- `driver` — maps a signed-but-vulnerable driver (Intel iQVW64E, MSI RTCore64, Dell DBUtil/WDT, Corsair, Gigabyte) for physical reads.
- `hijack` — duplicates a `PROCESS_VM_READ` handle from a system process.
- `direct` — plain pymem. Fine for VAC-only games, useless against EAC/BE/Vanguard.

Bundled `.sys` files hash-verify against known-good SHA256 before mapping. Mismatch aborts unless you pass `force=True`.

## The bridge protocol

`contracts/bifrost_protocol.json` is the single source of truth for the Electron <-> Python surface — commands, streaming commands, event and error shapes. v1.3. Enforcement:

- `api_server.py` rejects unknown commands before dispatch, echoes the request `_id`, tags streaming events with their originating operation.
- `main.js` routes events per operation channel against an allow-list.
- `contracts/validate.py` is the loader + validator, shared with the smoke test and the pytest suite — the tests fail on drift between the Python allow-list and the JSON.

Change the protocol file first, always.

## Known limits

- `cancel` is cooperative: operations abort at checkpoints, not mid-read.
- Streaming commands have no timeout. Request/response uses 15s by default; `decompile_fn` gets 120s because big bodies are slow. Retry or use the export pass if you beat it.
- Anti-cheat is a moving target. Offsets and patterns in `engines/*/structs.py` are per-patch and need refreshing against a fresh dump.
- Module images are raw memory snapshots, not rebuilt PEs — section layout reflects the loader, and rizin's analysis is best-effort on those.
- The rz-ghidra plugin is built once per rizin pairing. Pin rizin and rz-ghidra to the same version (the provision script does).

## Security

The backend is an admin-elevated process with kernel access primitives. The threat model is in `SECURITY.md`; the short version is the renderer only reaches the backend through the validated stdio contract, drivers are hash-checked fail-closed, and nothing sensitive is stored beyond a spoof backup snapshot that self-deletes on the restore path.
