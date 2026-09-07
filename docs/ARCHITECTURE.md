# BIFROST SDK — Architecture

## Four-Layer Model

```
Layer 1: React UI          gui/src/components/*.jsx
Layer 2: Electron Shell    gui/electron/main.js, preload.js
Layer 3: IPC Dispatch      api_server.py, gui_bridge.py
Layer 4: Core + Engines    core/*, engines/*
```

### Layer 1: React UI (Renderer Process)

Page components managed by `App.jsx`. State is centralized in `App.jsx` and passed down via props. Session state persists to `localStorage` under a `bifrost_` prefix (migrated from `ouroboros_` in 4.0.0). The Analyzer page joins the same architecture: streaming events for the analyze job, request/response calls for per-function decompile.

The renderer talks to the main process through `window.bifrost` — a context-isolated API surface exposed by `preload.js`. Every listener registration returns an unsubscribe function; pages use them in `useEffect` cleanup instead of destructive `removeAllListeners`.

### Layer 2: Electron Shell (Main Process)

`main.js` creates a frameless `BrowserWindow`, spawns the Python backend as a child process, and bridges IPC between the renderer and Python.

Two communication patterns:

- **Request/Response** — `sendCommand()` with correlation IDs and a timeout (15s default; `decompile_fn` gets 120s — big rz-ghidra bodies are slow). Failures always resolve with a structured error (`{error, code}`); the promise never rejects.
- **Streaming** — `sendStreamingCommand()` for long-running operations (dump, spoof, generate, hunt, analyze, analyze_export). Each payload carries a `stream` tag; the backend echoes it on every event it emits.

**Stream routing** (4.0.0): events route by their `stream` tag to per-operation channels — `dump-log`, `dump-progress`, `dump-complete`, `dump-error`, plus parallel families for spoof/gen/hunt/analyze. `analyze_export` reuses the analyze channels. Before this, every log/result fanned out to all four operations, so a spoof completion could auto-navigate the dump UI to the results page.

**Cancellation** (4.0.0): `stop-dump` sends a `cancel` command; the backend sets a shared `CANCEL_EVENT` that scanners and dump stages check at checkpoints. Analyzer operations have their own stop handlers wired the same way.

### Layer 3: IPC Dispatch

`api_server.py` reads stdin line-delimited JSON, validates commands against the protocol allow-list (`contracts/validate.py`), and dispatches to `gui_bridge.py` handler functions.

The protocol contract lives in `contracts/bifrost_protocol.json` (v1.3). Request/response handlers capture emitted events and return the last `result`; streaming handlers get an emit wrapper that tags every event with the operation.

### Layer 4: Core + Engines

**Core modules** provide process-agnostic primitives:

- `core/memory.py` — Direct memory reader (pymem). PEB fallback only for the main exe; `module_base` never poisons the cache with the exe base for other modules.
- `core/stealth/reader.py` — Stealth reader with AUTO fallback chain: PT walker -> driver -> hijack -> direct. Driver-backed paths verify the mapper actually loaded before declaring success.
- `core/stealth/driver.py` — Polymorphic IOCTL interface over six vulnerable drivers; CR3/DTB resolution with per-build offset fallbacks; `read_virtual` raises on unmapped pages instead of zero-filling.
- `core/stealth/pt_walker.py` — Manual PML4->PT walk; page-crossing reads split and translated per page.
- `core/stealth/spoofer.py` — HWID spoofing across 20 targets in 5 phases, with backup/restore.
- `core/stealth/handle.py` — Handle hijacking from system processes.
- `core/scanner.py` — AOB pattern scanner with chunked scanning + cancel checks.
- `core/signature_generator.py` — Auto-generate AOB patterns from entities.
- `core/hunter/hunter.py` — Vulnerable-driver hunter (LOLDrivers + catalogs).
- `core/generator/` — SDKPackage -> C++ headers, schema-validated against `contracts/sdk_output_schema.json`.
- `core/decomp/` — Analyzer orchestration: rizin-ghidra engine (`rizin_engine.py`), iced-x86 disassembly fallback, module image dumper.

**The decompiler engine** deserves its own note. Windows cannot drive rizin interactively over stdin pipes (rizin only dispatches piped commands when it inherits a console, and console-less spawns sit silent), so `rizin_engine.py` never keeps a session process alive: every operation is a one-shot `rizin -q0 -c '<sleighhome; analysis; work>' <file>` spawn, ~2-4s cold each. Per-function bodies cache in the analyzer, repeat clicks are instant. Batch export decompiles in chunks of 16 per spawn with count-aligned `pdgj` output, falling back to per-address spawns on desync. `RizinSession` keeps a fake-runner seam so unit tests assert command sequences with no binary.

**Engine dumpers** implement `BaseDumper` (ABC):

- `engines/unreal/dumper.py` — UE5 GWorld/GNames/GObjects traversal, compact FNamePool, Marvel Rivals profile
- `engines/unity/mono.py` — Unity Mono assembly parsing
- `engines/unity/il2cpp.py` — IL2CPP binary metadata
- `engines/source/dumper.py` — Source 1 RecvTable walk + Source 2 CUtlTSHash SchemaSystem
- `engines/blizzard/dumper.py` — Blizzard ECS walk + RTTI enumeration

`engines/registry.py` maps engine keys to dumper classes and profile imports, eliminating the old elif chain.

## window.bifrost API Surface

### Request/Response

```js
window.bifrost.command(name, args)  // → Promise<result>  (never rejects)
```

### Streaming Operations

```js
window.bifrost.startDump(args)
window.bifrost.stopDump()            // sends cancel
window.bifrost.onDumpProgress(cb)    // → unsubscribe fn
window.bifrost.onDumpLog(cb)
window.bifrost.onDumpComplete(cb)    // receives {type:'result', data:{...}}
window.bifrost.onDumpError(cb)
```

Same pattern for the `spoof`, `gen`, `hunt` and `analyze` operations (log/progress/error/complete each).

### File Dialogs

```js
window.bifrost.saveFile(content, defaultName, filters)
window.bifrost.loadJson()
window.bifrost.selectDirectory()   // output dirs
window.bifrost.selectFilePath()    // analyzer: pick a binary to open
```

## Adding a New Engine

1. Create `engines/newengine/dumper.py` subclassing `BaseDumper`
2. Implement `validate()` and `dump()` methods
3. Register it in `engines/registry.py`
4. Add any known exe names to `KNOWN_GAME_EXES` in `gui_bridge.py`
5. Add module signatures to `core/process.py` `detect_engine_from_modules()` if module-based detection is possible

## Adding a New Command

1. Add handler in `gui_bridge.py` (e.g., `run_new_command(args)`)
2. Add dispatch case in `api_server.py`
3. Add to `commands` or `streaming_commands` in `contracts/bifrost_protocol.json`
4. Add to `ALLOWED_COMMANDS` in `gui/electron/main.js` if request/response
5. Call from React: `api.command('new_command', args)`
