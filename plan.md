# BIFROST SDK — Council Remediation Plan (Black Ice Edition)

**Status**: Execution in progress. Cluster 1 (Shared Contract) delivered `contracts/bifrost_protocol.json` v1.1 + enforcement in api_server.py / main.js / preload.js + smoke test + protocol references throughout Layer 3/2.

**Four-Layer Model** (Researcher bootstrap):
- **Layer 1**: React "Black Ice" UI (12 pages in gui/src/*.jsx, state, listeners, framer-motion)
- **Layer 2**: Preload surface (`window.bifrost`) + electron/main.js (IPC orchestration, child spawn, pendingRequests, broadcast, frameless titlebar)
- **Layer 3**: api_server.py (dispatcher + validation) + gui_bridge.py (router + emit hook + KNOWN_GAME_EXES)
- **Layer 4**: engines/* + core/* + stealth (real reversing + high-privilege primitives)

All council work is scoped to hardening seams between these layers without expanding the curated engine list or stealth surface.

---

## Prior Iterations (Summary for Context)

### Iteration 0/1 — Initial Council Review (2026-05-26)
See `COUNCIL-REVIEW.md` for full Researcher snapshot, Verifier forensics (stale CS2 changelog claims, dead dump-error channel, listener issues), Critic top 5 risks (IPC trust boundary #1), and Synthesizer 6 recs.

Base scores (Council Review):
| Area                    | Confidence | Primary Drag                  |
|-------------------------|------------|-------------------------------|
| Frontend Quality        | 73/100     | JSX + brittle state           |
| "Global" Engine Coverage| 58/100     | Curated short list only       |
| Packaging               | 52/100     | Dual-toolchain staleness      |
| Bridge Contract         | 42/100     | **Weakest link**              |
| Stealth Surface         | 38/100     | High-risk by design + opaque  |
**Overall**: 64/100

**Cluster 1 selected and executed autonomously**: Shared Contract (highest leverage). Delivered contracts/ + enforcement scaffolding + smoke_bridge.py.

### Iteration 2 (Post-Cluster 1, estimated from live artifacts)
Bridge Contract received the bulk of the lift from v1.1 protocol document + validation + version envelopes in main.js + api_server.py + references in gui_bridge + smoke test.
Other areas saw only incidental or preparatory movement.

Estimated Iter 2 scores:
| Area                    | Confidence | Primary Drag (updated)             |
|-------------------------|------------|------------------------------------|
| Frontend Quality        | 74/100     | Still JSX + listener hygiene debt  |
| "Global" Engine Coverage| 58/100     | (unchanged)                        |
| Packaging               | 54/100     | Smoke exists but not wired to build |
| Bridge Contract         | 65/100     | Enforcement partial (streaming still fire-and-forget, dead error channels per protocol doc) |
| Stealth Surface         | 38/100     | (unchanged)                        |
**Overall**: ~66/100

---

## 100-council-ideas-review Results (Iteration 3)

**Date**: 2026-05-27  
**Synthesizer/Chair**: Grok (current)  
**Inputs synthesized**: Researcher (mapping table + top 3), Verifier (alignment deltas), Critic (threat model updates). All grounded in live workspace state (contracts/, gui/src/*.jsx + electron/, api_server.py, gui_bridge.py, smoke_bridge.py, package.json, bifrost_protocol.json known_limitations).

### Researcher — Mapping Table (Condensed) + Top 3 Ideas
Ideas were scored against the Four-Layer model and the 5 confidence areas. Only ideas with >=5pt projected lift in >=1 area + low blast radius were considered.

| Idea | Layers Primarily Touched | Areas + Est. Lift | Notes |
|------|--------------------------|-------------------|-------|
| Listener Hygiene Pass (fix removeAllListeners, dead dump-error, duplicate subs, accumulation on page switches/hot-reload) | Layer 1 (primary), Layer 2 (broadcast) | Frontend +8, Bridge +4, Stealth +1 (better error surfacing) | Highest immediate ROI. Directly addresses Verifier findings + protocol "known_limitations". |
| Protocol TS Shims + Enforcement Hardening (generate/hand-author minimal .d.ts from bifrost_protocol.json; harden streaming paths + error emission in main) | Layer 2 + Layer 3 | Bridge +9, Frontend +3 (types help later migration) | Natural follow-on to Cluster 1 contract. |
| Packaging Smoke Gate + Single Artifact Source of Truth (wire scripts/smoke_bridge.py into electron-builder afterPack; unify exe references) | Layer 2/3 boundary (build) | Packaging +7, Bridge +2 | Eliminates dual-toolchain staleness recurrence. |
| GUI TSX Migration (systematic .jsx → .tsx for bifrost surface + major pages) | Layer 1 | Frontend +6 (longer term), Bridge +2 | Larger; best after hygiene locked. |
| Protocol-Guard Hook (internal) + generalized upstream candidate | Layer 2/3 + hooks | Bridge +3, Packaging +1, (trust surface) | See open decision (b). |
| Stealth Surface Logging / Safe-Mode Banner | Layer 1 + 4 | Stealth +4, Frontend +2 | Defensive UX only; no new primitives. |

**Researcher Top 3 (ranked by combined 5-area lift + feasibility in 1-2 sessions)**:
1. Listener Hygiene Pass (Layer 1 focus) — smallest change, largest near-term stability win.
2. Protocol Enforcement Hardening + minimal TS surface (Layer 2/3).
3. Packaging Smoke Integration (build seam).

### Verifier — Alignment Scores (Post-Cluster 1 Reality Check + Projected)
- Bridge alignment to `bifrost_protocol.json`: Currently ~68/100 (strong on request/response envelopes + version + command allowlist; weak on streaming error paths, dead channels documented in "known_limitations", no TS mirror yet).
- Frontend event surface vs. protocol events section: 61/100 (registrations exist but hygiene + dead 'dump-error' per explicit protocol note drags it).
- Packaging artifacts vs. expected single source of truth: 49/100 (smoke script exists and is excellent, but not invoked by build; extra/ copies are manual).
- No major regression on CS2 path claims (changelog already corrected in prior remediation).

Projected after 100-iter-02 batch: Bridge 77/100, Frontend events 82/100, Packaging 66/100.

### Critic — Updated Threat Models (Iteration 3 Lens)
1. **IPC Trust Boundary (now High, was Critical)**: v1.1 envelopes + early validation in api_server + structured error_shape are real progress. Remaining: streaming commands remain unauthenticated fire-and-forget; no mutual attestation or process identity check on the stdio pipe. A compromised Layer 3 can still drive the renderer.
2. **Listener Accumulation / Hygiene Surface (New High for UX stability)**: Coarse `removeAllListeners` + registrations in App.jsx + 4 feature pages + hot-reload behavior creates silent fan-out duplication and potential memory growth during long reversing sessions. Dead channels (documented) mean error paths are invisible to UI in some flows. Not a security RCE but a reliability + confusion vector.
3. **Dual-Bundler Staleness (still High)**: Smoke test is a major mitigation asset but currently manual. Will recur on next engine or bridge change.
4. **Hook Trust Surface (Medium-New)**: Adding powerful post-build or post-edit hooks (per hooksmith) introduces new attack surface if the hook itself can be subverted or runs untrusted commands. Must be boring/read-only where possible.
5. **Documentation Debt (Medium, improving)**: Protocol json is now the best source of truth; changelog and code are better aligned than at Iter 0.

No new Criticals introduced by proposed ideas if execution follows the skilled local invocations + Plan Mode + verification gates below.

### Iteration 3 Council Scores (Updated)
Style copied from Iteration 0/1 table in COUNCIL-REVIEW.md, with realistic deltas from the synthesized ideas (primarily Listener Hygiene + Protocol Hardening + Packaging Gate from the 100-iter-02 batch).

| Area                    | Iter 0/1 (Base) | Iter 2 (est. post-Cluster1) | Iter 3 (via 100-iter-02) | Delta vs Iter 2 | Primary Drag After Batch |
|-------------------------|-----------------|-----------------------------|--------------------------|-----------------|--------------------------|
| Frontend Quality        | 73/100          | 74/100                      | 82/100                   | **+8**          | JSX (TSX migration recommended next); residual state brittleness |
| "Global" Engine Coverage| 58/100          | 58/100                      | 58/100                   | 0               | (Untouched — intentional) |
| Packaging               | 52/100          | 54/100                      | 61/100                   | **+7**          | Dual toolchain remains; smoke now gated |
| Bridge Contract         | 42/100          | 65/100                      | 74/100                   | **+9**          | Streaming fire-and-forget + full auth still Phase 2 |
| Stealth Surface         | 38/100          | 38/100                      | 40/100                   | +2              | (Defensive surfacing only; core risk unchanged) |
| **Overall**             | **64/100**      | **66/100**                  | **73/100**               | **+7**          | Bridge + Frontend hygiene now competitive with the excellent UI polish |

**Council Confidence after Iter 3 batch**: 73/100 (moves from "battle-tested prototype" toward "production-grade" per original verdict).

### Answers to Remaining Open Decisions
**(a) Recommended GUI order (listener hygiene or TSX first?)**

**Listener hygiene first (strongly recommended).**

Rationale (faithful to all four personas + Four-Layer):
- Verifier explicitly called out duplication, unreachable log handling, and the dead `dump-error` channel (now also documented in the protocol's own "known_limitations").
- Critic elevated the hygiene surface to High for reliability in long sessions.
- Researcher mapping shows it as the single highest-ROI, lowest-blast-radius change touching Layer 1 (and indirectly Layer 2 broadcast).
- It produces the exact stable subscription contract and characterization tests (via tdd-test-engineer) that a subsequent TSX migration (via refactor-master) can safely carry forward. Migrating first would just port the current fragile patterns into .tsx and multiply the cleanup cost.
- Concrete: 1-2 focused skilled sessions deliver the +8 Frontend / +4-9 Bridge lift immediately. TSX can follow cleanly in a later iter as a pure presentation refactor.

**(b) Any red line on contributing the protocol-guard skill upstream?**

**Yes — conditional red line on the *specific* form.**

- Do not upstream anything named "protocol-guard" (or equivalent) that hard-codes BIFROST paths, `KNOWN_GAME_EXES`, engine names, stealth primitives, or reverse-engineering assumptions.
- The generalized, portable version is acceptable and encouraged: a boring "json-ipc-contract-guard" or "stdio-schema-enforcer" skill that accepts a protocol.json path, version envelope key, command allowlist, and error_shape as inputs, plus example usage from our contracts/validate.py + smoke_bridge.py.
- Any upstream candidate must pass a full hooksmith security/dx/portability review (local invocation first) before PR to awesome-grok-build.
- This preserves the internal value of the council pattern for this high-privilege project (Critic lens) while allowing the community to benefit from the enforcement scaffolding we built.

### 100-iter-02 Batch Proposal
**Goal**: Smallest 3-5 changes delivering 5+ point gains in **at least 3 areas** (Frontend Quality, Bridge Contract, Packaging) while staying strictly inside the Four-Layer model and approved superpowers rules (local .grok/skills only; no broad rewrites).

**Execution must start exactly like this** (per Plan Mode + using-superpowers rules in the approved plan and skill docs):

1. **Enter Plan Mode** (blocks direct file writes; forces arena comparison + explicit approval of the plan file before any edits).
2. **Explicit local skill invocations** (run these in order; each skill must be invoked with the full local path pattern and focused prompt referencing the Four-Layer model + bifrost_protocol.json):
   - `Use frontend-ux-engineer. Inspect and improve listener hygiene across Layer 1 (gui/src/App.jsx + all *Page.jsx components) and Layer 2 broadcast in electron/main.js. Map every onDump*/onSpoof*/on*Log / removeAllListeners call against the current registrations and the dead channels documented in contracts/bifrost_protocol.json. Arena exactly 2 minimal-hygiene approaches (central manager vs. per-component ref-based cleanup). Prioritize fixing the documented 'dump-error' emission gap and preventing accumulation. Produce concrete diffs + verification steps only. Do not touch TSX or styling.`
   - `Use tdd-test-engineer. Before any listener changes, add failing characterization tests for the bifrost event subscription/unsubscription contract (preload surfaces + main.js broadcast + error_shape paths). Use/extend the pattern in scripts/smoke_bridge.py. Target the duplication + dead-channel behaviors. Run the narrow tests to capture failures first.`
   - `Use refactor-master. (With its callgraph + risk + tests subagents.) Perform the smallest behavior-preserving extraction or normalization of the listener patterns identified by the prior two skills. Touch the fewest files possible. Public `window.bifrost` surface and all existing page behavior must remain identical.`
   - `Use hooksmith. Design the smallest, boring, read-only or narrowly-mutating hook that runs `python contracts/validate.py && python scripts/smoke_bridge.py` (with --packaged awareness) on changes to the bridge contract surface (main.js, preload.js, api_server.py, gui_bridge.py, contracts/*). Compare 2-3 designs for trust surface / portability / DX. Output full Hook: / Trigger: / Command: / Risk: / Failure: documentation.`

**The resulting smallest 3-5 concrete changes** (post skilled planning/arenas/approval; estimated total <150 LOC + tests/hook):

1. **gui/electron/main.js** (Layer 2)  
   - Add emission of structured 'dump-error' (and parallel for other features) on error/exception paths in the readline handler and send*Command failures, using the exact `error_shape` + `makeBridgeError` already present. Wire through the existing broadcast.  
   - Order: After tdd tests written.  
   - Verification: smoke_bridge catches new error path; manual dump of invalid pid now surfaces via the (previously dead) error channel in UI.

2. **gui/src/App.jsx** (Layer 1)  
   - Replace the dump-specific useEffect (multiple on* registrations + blanket 4x removeAllListeners in cleanup) with a single stable subscription pattern using refs for handlers + targeted removals only. Remove double-handling inside onDumpProgress. Keep global logs + bridge health.  
   - Order: After frontend-ux-engineer arena + refactor-master extraction (or inline the minimal fix if extraction scope stays 1 file).  
   - Verification: Rapid page navigation + repeated start/stop of dump/spoof/gen/hunt produces zero duplicate logs and no accumulation (devtools or manual count); hot-reload safe.

3. **gui/src/components/{SpooferPage.jsx, BoilerplatePage.jsx, DriverHunterPage.jsx}** (and DumpPage if separate) — targeted hygiene only (Layer 1)  
   - Convert their per-page listener useEffects to use the stabilized pattern from (2) or equivalent ref-based cleanup instead of removeAllListeners. No behavior change.  
   - Order: Same batch as 2.  
   - Verification: Same as above + each page's logs still appear correctly in isolation.

4. **gui/package.json + scripts/** (build seam)  
   - Add an afterPack or "postbuild:smoke" step (or electron-builder hook) that invokes the existing smoke_bridge.py against the freshly emitted artifacts when possible. Update the "build" script and docs.  
   - Order: After hooksmith delivers the approved hook design.  
   - Verification: `cd gui && npm run build` succeeds only if smoke passes (or warns in first iter); packaged smoke_bridge.py --packaged now part of CI narrative.

5. **(Optional 5th if scope allows after arenas)** Minimal hand-written `gui/src/types/bifrost.d.ts` (or simple generator script) mirroring the core commands/events/error_shape from contracts/bifrost_protocol.json. Reference it from preload JSDoc and App.jsx.  
   - This seeds the future TSX migration without forcing it now.  
   - Verification: Type-aware editors see the contract; aligns with Verifier alignment metrics.

**Verification Steps (mandatory after every change or sub-batch)**:
- `python contracts/validate.py`
- `python scripts/smoke_bridge.py` (dev) and with `--packaged` when artifacts exist.
- `cd gui && npm run build` (full) + confirm dist-electron + extra/ artifacts + smoke against them.
- Manual runtime: Launch (admin), exercise all 4 streaming features + error paths + rapid navigation + hot-reload simulation. Confirm no duplicates, errors visible on dedicated channels, bridge health banner accurate.
- `git diff --stat` + full review of changed files only.
- Re-run narrow tdd tests from skill invocation.

**Success Criteria (moves the scores)**: Frontend Quality ≥ +8, Bridge Contract ≥ +8, Packaging ≥ +6 from Iter 2 baseline. All changes reversible in one commit if needed. No expansion of Layer 4 surface.

**Next after batch lands**: Re-run full council (Researcher + Verifier + Critic + Synthesizer) on the deltas. Then decide Iter 4 (likely TSX migration start + Phase 2 streaming cancellation + optional generalized hook upstream PR).

---

**End of 100-council-ideas-review Results (Iteration 3)**

*All synthesis strictly from live files in workspace + outputs of prior parallel council subagents. No external searches. Ready for Plan Mode execution of 100-iter-02.*