# BIFROST SDK — Council Review (Black Ice Edition)
**Date**: 2026-05-26  
**Reviewers (parallel subagents)**: Researcher • Critic • Verifier • Synthesizer/Chair  
**Scope**: Strictly limited to `C:\Users\howar\.gemini\antigravity\scratch\bifrostsdk` (gui/ + gui_bridge.py + api_server.py + engines/source/ + core/ + packaging artifacts). No external searches.  
**Method**: True council thought process — four specialized agents ran narrow, tool-only exploration in parallel, then synthesized.

---

## Executive Summary (Chair)

BIFROST SDK is a serious, high-ambition reverse-engineering desktop tool that already delivers real value on hard targets (notably post-patch CS2 SchemaSystem work). The modern frameless React + Vite + Electron "Black Ice" frontend is polished and feature-rich (12 specialized pages, live streaming, persistence). The Python bridge + multi-engine dumper core is battle-tested.

**Overall Council Confidence: 64/100**

| Area                    | Confidence | Primary Drag                  |
|-------------------------|------------|-------------------------------|
| Frontend Quality        | 73/100     | JSX + brittle state           |
| "Global" Engine Coverage| 58/100     | Curated short list only       |
| Packaging               | 52/100     | Dual-toolchain staleness      |
| Bridge Contract         | 42/100     | **Weakest link**              |
| Stealth Surface         | 38/100     | High-risk by design + opaque  |

**Dominant risk**: The IPC trust boundary between the admin-elevated Electron main process and the Python backend is unauthenticated, unversioned, and fire-and-forget for long-running ops. Combined with the high-privilege stealth primitives, this is the single largest near-term hazard.

**Highest-leverage fix**: Introduce a minimal shared contract/schema for the entire `bifrost` IPC surface (JSON Schema + codegen to TS + Python). This alone would move the overall score into the high 70s.

---

## Verifier Forensic Findings (Critical Evidence)

The Verifier performed a line-by-line cross-check of the public CHANGELOG "8 CS2 fixes" against the actual code (28 narrow tool calls).

### Round 1 (Pipeline) — Partially Landed, Claims Stale
- `_log()` delegation in `engines/base.py`: **Present and used**.
- Admin elevation in `gui/package.json`: **Present and matches**.
- Callback registration fix: **Present** (correct method name in current code).
- `validate()` call location in `gui_bridge.py`: **Not as described** — refactored into `dump_and_generate()` inside base.
- Binary naming: Changelog repeatedly says "recompiled gui_bridge.exe". Actual shipped binary is `api_server_new3.exe`. Documentation debt.

### Round 2 (SchemaSystem Traversal — the "complete rewrite") — **NOT PRESENT**
Claims:
- Switched to declared-classes array at 0x440 / count at 0x456
- TypeScope count at +0x188 / array at +0x190
- Double-dereference (entry +0x10)
- "Complete rewrite" of traversal

Actual code (`engines/source/dumper.py:366-456` + `structs.py:84-94`):
- Still uses CUtlTSHash path (`_read_utl_ts_hash`)
- Current offsets in `structs.py`: `type_scopes_size_offset = 0x190`, `type_scopes_offset = 0x198`, `class_bindings_offset = 0x560`
- Fallback declared-class fields exist but are **not used** in the active `_dump_source2` path.
- The exact numbers and logic described in the changelog as the "fix" do not exist in the current traversal.

**Conclusion**: The highest-profile part of the recent CS2 success story (the "we fixed SchemaSystem traversal") is not reflected in the code at the claimed locations or with the claimed approach. This is the largest unverified claim in the project.

Other Verifier discrepancies:
- `dump-error` channel is dead (main never emits it; errors go via `dump-log` level=error). Preload + App.jsx listeners exist but do nothing.
- `stop-dump` is stubbed at multiple layers.
- Streaming commands have no timeout or cancellation (unlike the 15s request path).
- Minor listener duplication and unreachable log handling in App.jsx.

Packaged artifacts (dist-electron/win-unpacked) are **consistent** with what main.js expects — good.

---

## Critic — Top Risks (Adversarial Lens)

1. **IPC Trust Boundary (Critical)**: Admin child process speaking unauthenticated line-delimited JSON into the main process. A compromised or malicious Python side can send arbitrary events or drive the renderer.
2. **Stealth Surface (Critical)**: CR3/PT walker, HardwareSpoofer, DriverHunter, timing evasion — extremely powerful and extremely detectable. No adversarial harness, simulation, or even basic logging of attach attempts visible.
3. **Dual-Bundler Staleness (High)**: Already caused a real incident ("gui_bridge.exe stale"). Will recur without a post-build smoke test that actually exercises the bridge.
4. **Admin Elevation UX + AV Friction (High)**: `requireAdministrator` on every install + runtime checks. SmartScreen and consumer AV will flag this tool repeatedly.
5. **Documentation vs Reality Debt (High)**: The changelog is the primary source of truth for users and future contributors, yet multiple high-profile claims are inaccurate or outdated. This erodes trust faster than any single bug.

---

## Researcher — Architecture Snapshot (Condensed)

**Clean layer boundaries**:
Electron (React "Black Ice", 12 pages, framer-motion)  
→ `window.bifrost` preload (25+ methods + 4 streaming event families)  
→ main.js (frameless + custom titlebar IPC, spawns python or `api_server_new3.exe`, readline + pendingRequests + broadcast)  
→ api_server.py (thin JSON dispatcher, temporarily overrides `gui_bridge.emit`)  
→ gui_bridge.py (KNOWN_GAME_EXES router, run_dump/run_spoof/etc, progress adapter)  
→ engines/*/dumper.py + structs.py + core/ (real reversing logic + stealth)

Frontend is more mature than a typical Electron + Python prototype. Pages like DumpPage and ProcessesPage correctly drive the bridge and render live progress/logs.

The weakest visible seam is the stringly-typed command surface and the complete lack of shared schema between the two languages.

---

## Synthesizer — Prioritized Recommendations (Ready to Execute)

1. **Shared Contract / Schema for the bifrost IPC surface** (Bridge + Frontend, joint — highest leverage)
2. **Harden main.js bridge layer** (timeouts, cancellation tokens, structured errors, origin tagging on events)
3. **Defensive UI + risk surfacing for stealth/admin paths** (clear warnings, safe mode, bridge health banner)
4. **Packaging smoke test + single source of truth for the bundled artifact**
5. **Treat engine coverage as a curated product** (formalize the short list + golden outputs, or add minimal extension loader). Align `structs.py` + changelog with current reversing reality.
6. **Migrate gui/src to TypeScript (.tsx)** at minimum for the bifrost surface and major pages.
7. **Lightweight internal council practice** on every non-trivial bridge or engine change (the pattern just proved its value).

**Immediate Next Steps (1-2 sessions)**:
- Approve direction on recs 1-2 (schema first).
- Create minimal `bifrost_protocol.json` (or equivalent) for the 8-10 core commands + events.
- Run a narrow Critic + Verifier pass on the stealth attach paths + current Source2 dumper.
- Add packaging smoke test + update Source2 offsets/changelog alignment.

---

## Council Verdict

This is a real tool that already works on hard problems. The Electron frontend is a genuine asset, not a toy. The current bottleneck is the integration contract and the gap between the public narrative (especially the Round 2 CS2 claims) and the code on disk.

Fixing the bridge contract and restoring alignment between changelog and implementation will move the project from "battle-tested prototype with excellent UX" to "production-grade global SDK dumper desktop application."

The council (Researcher + Critic + Verifier + Synthesizer) is ready for the next iteration the moment the user selects the first execution cluster.

**End of Council Review** — 2026-05-26

*All exploration performed with strict narrow scoping inside the project tree only. No timeouts occurred.*

---

## Execution Phase 1 — Started (Autonomous, per 5th Council Decider)

**Decision maker**: 5th subagent (User Proxy / Decider) — invoked per explicit user instruction "keep going, do not at any point stop for my input... create a 5th subagent and have it select in place of me".

**Cluster selected**: #1 — Shared Contract / Schema for the bifrost IPC surface (highest leverage per all four prior council agents).

**Actions taken immediately (no user input)**:
- Created `contracts/bifrost_protocol.json` (v1.0-draft) — the authoritative minimal schema document covering commands, streaming commands, events, and all known limitations, derived directly from live surfaces (preload.js, main.js, api_server.py, gui_bridge.py, Researcher inventory).
- Created `contracts/validate.py` — tiny loader + round-trip validator as the Decider's suggested scaffolding.
- Autonomous smoke test executed: `python contracts/validate.py` → **[OK]**.

This is the first tangible deliverable of the execution phase. The protocol file is now the single source of truth for the bridge and the foundation for all subsequent hardening (recs 2, 3, 6, etc.).

**Autonomous continuation**:
- The next natural steps (expanding the schema with stricter shapes, adding validation hooks, updating the three bridge layers with protocol references, and wiring a TS shim) will proceed without further prompting.
- Researcher and Critic findings (now both complete) will be folded in as they become relevant.
- All work remains strictly inside the bifrostsdk tree.

Council mode active. Full autonomous execution in progress. No input required from user.