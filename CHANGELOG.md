# BIFROST SDK — Changelog

## 4.1.0 — Stealth v2, Themes, Access Diagnostics (2026-09)

### Access pipeline (stealth v2)

- Driver Hunter removed entirely (page, `core/hunter/`, hunt IPC channels/commands, tests).
- No more AUTO fallback ladder. Transports are explicit: `auto` == direct attach; `hijack`, `driver`, `cr3` are opt-ins. Kernel modes never fire implicitly.
- Every StealthReader connect self-tests with a probe read of KUSER_SHARED_DATA and records ordered `attach_steps`; failures raise with the failing step named, and `gui_bridge` falls back to direct only with a log line saying so.
- New `dump-access` streaming event (contract `events.access`): attach resolution — requested mode, resolved transport, probe result, step trace, latency — rendered as an Access panel on the Dump page.
- "Re-dump <target>" one-click on the Dump page re-runs the last dump with the current access mode.
- Access-mode UI relabeled (`auto/direct/hijack/driver/cr3`, legacy `extreme` session value migrates to `cr3`).

### Themes & visuals

- Theme system over the existing token set: Midnight (dark, default), Paper (light), Terminal (CRT mono). Picker in Settings, persisted, applied before first paint to avoid flashes.
- Radius tokens tightened (6/4/8), hardcoded banner/status colors migrated to tokens so every theme renders correctly.

### Output tooling

- `scripts/verify_output.py`: schema-validate `offsets.json` against `contracts/sdk_output_schema.json`, report zero-field/collision classes, optional header sanity pass. Exit 0/1/2.
- `scripts/compare_dumps.py`: offset-drift watcher between two dumps — added/removed/changed classes with per-field hex diffs; exit code for CI gates.
- `tests/test_output_validation.py` (20 tests) covers both.
- Caught a real defect on first run: shipped CS2 dump `_meta` totals (3224/16428) disagree with actual file contents (2779/14772) — stale meta on disk, validator now flags it.

### Engines & docs

- `docs/ENGINE_GUIDE.md` + `engines/template/` scaffold: step-by-step path for adding a new engine family (registry, detection, output contract, tests).
- Live webhook 404 test no longer flakes: transport-level failures retry with backoff; real HTTP responses assert immediately; all-transport failure skips instead of failing the suite.

## 4.0.0 — Rebrand + Full Rework (2026-09)

Complete re-evaluation of the codebase. Brand consolidated to BIFROST SDK everywhere (the Ouroboros naming is gone from code, packaging, and persisted state).

### Analyzer / decompiler (new)

- IDA-style decompiler surface behind the same four-layer bridge: rizin + rz-ghidra (`pdg`/`pdgj`) when provisioned, iced-x86 linear disassembly otherwise. `analyze_probe` reports engine state up front.
- Protocol v1.3 adds `analyze` (streaming), `analyze_export` (streaming), `analyze_probe` and `decompile_fn` (request/response).
- Rizin sessions are one-shot spawns. Windows can't drive rizin interactively over a pipe, so every operation runs as `rizin -q0 -c <cmds> <file>` and exits; decompiled bodies cache per address and the export pass batches 16 functions per spawn. A hung decompile kills its own process, never the SDK.
- Module analysis sources dump the target module raw to `output/analyzer/<module>/` with hijack -> direct attach only — the no-implicit-driver rule from the kernel work extends here.
- `tools/provision_rizin.ps1` fetches the official rizin Windows shared64 build and compiles rz-ghidra v0.9.0 against it (rizinorg publishes no prebuilt Windows plugin — verified across the full release history). Shared, not static: a plugin built against the static archives embeds a second librz core and deadlocks rizin at load.
- Export pass batch-decompiles the top functions to `.c` files under `<source>/decomp/`.
- Covered by tests throughout: parsing and the fake-runner seam run without a binary; live backend tests drive a real rizin through `api_server.py`.

### Protocol (v1.3)

- v1.3 adds the analyzer command surface (see above), including the address explorer: `analyzer_hexdump` (hex+ascii rows at a VA), `analyzer_disasm_at` (iced-x86 linear window, no rizin spawn) and `analyzer_xrefs` (rizin `axtj` one-shot). VA mapping covers raw module dumps (base-relative) and on-disk PEs (section table via pefile).
- The v1.2 changes below remain as shipped:
- `cancel` command added. `stop-dump` now actually reaches the backend; operations abort at checkpoints via a shared `CANCEL_EVENT` (pattern scanner chunks, between dump stages).
- Validation-reject responses echo `_id` — previously they dropped the correlation id and every rejected command left the renderer hanging for the full timeout.
- `ping` reports the live build stamp and `protocol_version`; version drift (2.0.0 vs 3.0.0) fixed.
- Protocol document rewritten to match reality: `read_memory`/`ac_detect` are documented as implemented, `dump.stealth` is a string enum, error shape documented where it's actually emitted.

### GUI (Black Ice)

- Analyzer page: pick a binary, stream the analyze job, click functions to decompile, export to `.c`. `decompile_fn` gets a 120s IPC window (big bodies exceed the 15s default).
- Frameless titlebar, per-operation event routing (no more cross-op completion storms), listener registrations return unsubscribe functions.

### Kernel & stealth

- Unmapped pages raise instead of silent zero-fill; short physical reads raise; CR3 resolution failure raises instead of returning a placeholder.
- AUTO access chains never implicitly map drivers. Kernel-capable code stays dormant until the user explicitly picks a driver mode.

## Unreleased

### UI redesign (flat, minimal)

- Modern dark re-skin keeping the existing palette: gradients, glass blur, glow shadows, shimmer/pulse animations and lift-on-hover are gone; elevation is 1px hairlines and surface deltas only. Radius tightened (14/8 -> 8/6), Inter dropped for the native Segoe UI stack, scrollbars squared, focus = hairline hue shift instead of glow rings.
- Primary buttons are now solid emerald (read: actionable) instead of gray gradients; status/alert colors stay reserved for state. Engine cards keep identity via color-mixed tag chips. Removed decorative traffic-light dots from the hunter/analyzer console headers and the error boundary now uses theme tokens.
- Fixed a long-standing bug class: ~60 inline styles referenced undefined tokens (--frost-*, --shatter-*, --ice-*) that silently fell back to inherited colors. All mapped to real theme tokens.
- Designed blank states (empty-state panel in the decompile pane instead of raw dim text).
