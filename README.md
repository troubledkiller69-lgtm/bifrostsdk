# BIFROST SDK

A reverse-engineering workstation that turns a running game into ready-to-compile C++ headers, `offsets.json`, or decompiled C. Attach to a process, walk its engine structures, and walk out with SDK code.

Covers Unreal Engine 5 (per-game profiles), Unity Mono and IL2CPP, Source 1 and 2, and Blizzard engines. When the game is behind a kernel anti-cheat, stealth access modes (vulnerable-driver reads, page-table walks, handle hijacking) get you in. A rizin + rz-ghidra backend does the IDA-style decompiling; without it, the Analyzer degrades to iced-x86 disassembly and tells you so.

## What it does

- **Dump** — pick a process, let the right engine walk its structures. Output is schema-validated: C++ headers, JSON, class/field lists.
- **Analyze** — decompile any function in a dumped module to readable C, or export the whole binary's top functions to `.c` files in one batch pass.
- **Boilerplate** — generate a C++ project scaffold from a dump's data.

The GUI is a frameless Electron app (React + Vite). The backend is a Python process that speaks line-delimited JSON over stdio — no HTTP, no ports.

## Requirements

- Windows 10/11 x64. Admin rights (opening protected processes; the installer asks).
- Dev only: Python 3.10+, Node 18+. The shipped app freezes the backend with PyInstaller.
- Decompiler: rizin + rz-ghidra ships with the installer when you've run `tools/provision_rizin.ps1` once before building. That's a ~10 min fetch + compile — rizinorg ships no prebuilt Windows plugin. Without it, Analyzer falls back to iced-x86 and tells you. IDA is optional on top: if you own a license, run `tools/provision_ida.ps1` — it mirrors your `idat.exe` into `gui/extra/ida` (gitignored, packed like rizin). We never redistribute IDA.

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
python -m pytest tests/ -q             # 242 tests, no game required
python scripts/smoke_bridge.py         # exercises the stdio IPC protocol end to end
```

Engine dumpers run against mock readers; the rizin path is covered through a fake-runner seam plus live backend tests that hit a real `api_server.py`.

## Output validation

Two CLI checks for dump artifacts (run against `output/` or a nested dump dir like `output/cs2/`):

```bash
python scripts/verify_output.py output\cs2 --headers output\cs2
python scripts/compare_dumps.py output\cs2 <newer-dump-dir>
```

`verify_output.py` loads `offsets.json`, validates it against `contracts/sdk_output_schema.json` (jsonschema when installed, a manual structural walk otherwise), cross-checks `_meta` totals against real content, and flags zero-field classes and case-collision field names. `--headers <dir>` globs `*.h` for balanced braces, missing struct/class declarations, empty struct bodies, and typeless member lines. Exit codes: 0 clean, 1 problems, 2 no `offsets.json`. Zero-field classes are reported but informational by default (real engine dumps carry them legitimately); `--strict` makes them fatal.

`compare_dumps.py` is the offset-drift watcher — diff two dump outputs and it reports removed/added/changed classes with a per-field `old_hex → new_hex` table. Hex strings and raw ints both normalize; null offsets (AS3-style) compare null-vs-null as unchanged. Exit codes: 0 no drift (new classes alone are fine), 1 drift (changed/removed offsets or classes), 2 missing/unparseable input.

Both are exercised by `tests/test_output_validation.py`. `build.ps1` runs `verify_output --strict` automatically when `output/` exists; `tools/verify_extra.ps1 -Strict` fails the build if `gui/extra/rizin` is missing (IDA is optional).

## Build

One script does the whole chain — PyInstaller backend, `gui/extra` staging, Electron installer, packaged smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Flags: `-SkipBackend` (reuse an existing `dist\api_server.exe`), `-SkipSmoke`.

Outputs:

- `dist/api_server.exe` — frozen backend
- `gui/dist-electron/win-unpacked/BIFROST SDK.exe` — unpacked app
- `gui/dist-electron/BIFROST-SDK-4.1.0-Setup.exe` — NSIS installer (admin-elevated)

## Repo map

```text
api_server.py         stdio JSON dispatcher
gui_bridge.py         command router + business logic (KNOWN_GAME_EXES)
core/                 memory readers, AOB scanner, signature gen
core/decomp/          analyzer: rizin-ghidra engine, iced fallback, module dumper
core/stealth/         driver / hijack / PT-walker readers
core/generator/       dump data -> C++ headers
engines/              unreal/, unity/, source/, blizzard/ dumpers behind a registry
contracts/            protocol JSON + schema + validator (single source of truth)
drivers/              vulnerable driver list + fetcher, hash-verified
gui/                  Electron + React frontend
tools/                provision_rizin.ps1
scripts/              smoke_bridge.py, verify_output.py, compare_dumps.py
tests/                242 pytest tests
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

`KNOWN_GAME_EXES` in `gui_bridge.py` maps known executables to engines; anything unknown falls back to module-based detection in `core/process.py`. The `engines/registry.py` is the single entry point — `create_dumper()` replaces the old `elif` chain.

Adding an engine: subclass `BaseDumper` in `engines/<engine>/dumper.py`, register it in `engines/registry.py`, add known exes to `KNOWN_GAME_EXES`. That's the whole diff — the full walkthrough (dumper contract, detection, output schema, tests) is in `docs/ENGINE_GUIDE.md`, with a copyable skeleton in `engines/template/`.

## The Analyzer

Point it at a file, or dump a module from a live process (hijack -> direct attach only). The Analyzer picks the best engine you've provisioned:

- `rizin-ghidra` — default, ships in the installer after `tools/provision_rizin.ps1`. One-shot `rizin` + `rz-ghidra` per job.
- `ida` — optional, your licensed `idat.exe` found at `Downloads\IDA_Test\IDA Professional 9.1\idat.exe` or `C:\Program Files\IDA*`, staged via `tools/provision_ida.ps1` into `gui/extra/ida`. Headless `idat -A -S` dump, same function ranking. No license bypass — if IDA needs activation, we log and fall back.
- `iced-x86` — always available, linear disassembly only. Used when neither decompiler is present.

In the UI the engine picker is a deck preset `Auto | Rizin | IDA | Iced` — `Auto` picks rizin first, then IDA, then iced. Probe at `analyze_probe` reports `{rizin:{available,version,decompiler}, ida:{available,exe,version}}`. IDA batch decompiles the top 100 biggest functions via hexrays in the same run — bodies serve from cache for decompile/export, so IDA is a full peer, not list-only. Re-analyze won't reach outside the top-N; use rizin for the long tail.

Operations:

- `analyze` — load + auto-analysis, returns function list ranked by size (`Auto` respects your picker)
- `decompile_fn` — decompile one address; results cache per session (rizin session stays open, IDA is batch — no session)
- `analyze_export` — batch-decompile top N under `<source>/decomp/` (`format: split` = one .c per fn, `single` = bundle.c; both write index.json). Works for IDA batch too (exports the analyze-time cache).
- `analyzer_callgraph` — callers + callees of one function with resolved names (`calls`, `called_by`); rizin only, surfaced in the explorer Calls tab.
- `analyzer_search` — call-site search: substring over import names + string contents, xrefs each hit (max 25 targets, refs capped). Rizin only, 5-min timeout; the analyzer deck has a search card with click-to-explore on every hit.
- **Address explorer** — hex+ascii, linear disasm, xrefs at any VA (`analyzer_hexdump`, `analyzer_disasm_at`, `analyzer_xrefs`). Disasm is rizin-free iced-x86; xrefs are real `axtj`.

Rizin/IDA ops are one-shot processes, so a hung decompile dies with its process, never the SDK. Bodies cache, so repeat clicks are instant. Missing engines degrade to iced-x86 with a warning.

## Access modes

`dump` takes `stealth: auto | direct | hijack | driver | cr3`:

- `auto` — direct attach. The only transport verified end to end; kernel transports are explicit opt-ins, never a fallback.
- `direct` — plain OpenProcess + ReadProcessMemory.
- `hijack` — duplicates a `PROCESS_VM_READ` handle from a system process.
- `driver` — maps a signed-but-vulnerable driver (Intel iQVW64E, MSI RTCore64, Dell DBUtil/WDT, Corsair, Gigabyte) for physical reads.
- `cr3` — driver plus manual page-table walk (CR3 bypass).

Every transport self-tests at connect time (open -> probe read -> verify) and reports the exact failing step. Bundled `.sys` files hash-verify against known-good SHA256 before mapping. Mismatch aborts unless you pass `force=True`.

**Batch queue** — Dump page `Queue Target` stacks engine+pid entries (persisted in session); `Run Queue` dumps the head and chains the rest on each completion. Errors log and skip ahead, never stall. `Cancel` clears the queue.

**Driver Bay `loaded`** — `driver_list` now reports `loaded` per profile via SCM `QueryServiceStatus` (true = service running right now, false = stopped/missing, null = query unavailable). A `LOADED` badge marks drivers a previous Test Load or dump left mapped.

## Dump history + drift

Every successful dump auto-archives `offsets.json` to `output/<game>/.history/<UTC-stamp>.json` (newest 20, sidecar with engine/class/field counts — archiving never breaks the dump result). `dump_history` lists them, `dump_diff` diffs any two via the same logic as `scripts/compare_dumps.py` (`drift` true when fields changed or classes removed). The Diff page has a History picker (game → before/after → Compare) next to the manual file loader.

**Watch mode** — Dump page `Watch` re-dumps the armed target every 5/15/30/60 min (timer lives in App, survives navigation, pauses for queues and running dumps). Each completion compares class/field counts against the previous run; drift logs `[WATCH]` and toasts. Pair with history: every watch cycle archives, so morning-after forensics is one diff away.

## IDA database cache

`%TEMP%/bifrost_ida_cache/<sha256>_<ida>/` keeps the `.idb` set between runs. Re-analyzing an unchanged binary restores it next to the target first, so IDA goes incremental instead of another 5–15 min full pass — then the set moves back to cache (your target dir stays clean). Fingerprint is hash + size, so a patched binary automatically re-analyzes from scratch. The analyze log says `database cache hit` when it kicks in.

## The bridge protocol

`contracts/bifrost_protocol.json` is the single source of truth for the Electron <-> Python surface — commands, streaming commands, event and error shapes. v1.3. Enforcement:

- `api_server.py` rejects unknown commands before dispatch, echoes the request `_id`, tags streaming events with their originating operation.
- `main.js` routes events per operation channel against an allow-list.
- `contracts/validate.py` is the loader + validator, shared with the smoke test and the pytest suite — the tests fail on drift between the Python allow-list and the JSON.

Change the protocol file first, always.

## MCP server

`mcp_server.py` exposes the backend as MCP tools over stdio — zero new dependencies (hand-rolled JSON-RPC, runs on the canonical 3.14). 19 tools: `list_processes`, `dump`, `dump_history`, `dump_diff`, `make_signature`, `analyze_probe`, `analyze`, `decompile_fn`, `analyze_export`, `hexdump`, `disasm`, `xrefs`, `callgraph`, `search_callsites`, `symbols`, `strings`, `read_memory`, `driver_list`, `driver_test`. Streaming ops block to completion and return the result plus a log tail; outputs cap at 100KB.

## Signature generation

The Memory page has a Signature section: paste 1–16 known-good hex addresses (the `+` button appends your current selection), hit Make Sig, get scored AOB candidates back — tight/balanced/loose strategies across 16/24/32/48-byte windows, each with concrete ratio, verification hit count, and score. Best first, one click to copy. `verify` on means a full-process scan per candidate (slow but honest — a 2-hit pattern on 2 addresses is unique); off is the fast path. Same thing over `make_signature` on the bridge and MCP, so agents can mint their own patterns.

Claude Code:

```
claude mcp add bifrost -- C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe C:\Users\howar\.gemini\antigravity\scratch\bifrostsdk\mcp_server.py
```

Claude Desktop (`claude_desktop_config.json`):

```
{"mcpServers": {"bifrost": {"command": "<canonical python>", "args": ["<repo>/mcp_server.py"]}}}
```

Sequential use only — one analyzer session and one shared cancel event, same as the GUI. Stray backend prints go to stderr so the JSON-RPC framing stays clean.

## Known limits

- `cancel` is cooperative: operations abort at checkpoints, not mid-read.
- Streaming commands have no timeout. Request/response uses 15s by default; `decompile_fn` gets 120s because big bodies are slow. Retry or use the export pass if you beat it.
- Anti-cheat is a moving target. Offsets and patterns in `engines/*/structs.py` are per-patch and need refreshing against a fresh dump.
- Module images are raw memory snapshots, not rebuilt PEs — section layout reflects the loader, and rizin's analysis is best-effort on those.
- The rz-ghidra plugin is built once per rizin pairing. Pin rizin and rz-ghidra to the same version (the provision script does).

## Security

The backend is an admin-elevated process with kernel access primitives. The threat model is in `SECURITY.md`; the short version is the renderer only reaches the backend through the validated stdio contract and drivers are hash-checked fail-closed.
