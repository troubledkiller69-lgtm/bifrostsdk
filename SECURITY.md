# BIFROST SDK — Security Model

## Why Administrator Privileges?

BIFROST SDK requires `requireAdministrator` elevation because:

1. **OpenProcess with PROCESS_VM_READ** — reading protected game process memory requires `SeDebugPrivilege`, only available to elevated processes.
2. **Kernel driver loading** — the stealth system optionally loads vulnerable signed drivers for physical memory access.
3. **SMBIOS physical memory access** — the hardware spoofer reads/writes physical memory tables via driver IOCTLs.

The whole Electron app runs elevated because the Python backend inherits the parent's elevation. Elevating only the backend would add complexity with no real boundary gain — both processes live on the same machine.

## IPC Trust Boundary

The Python backend talks to Electron main over **stdin/stdout JSON lines**. Properties:

- **Trust-by-launch, not authenticated** — the parent process spawns the child and owns its stdio pipes. Non-admin processes cannot reach the child's stdio.
- **Not encrypted** — plaintext JSON on a local pipe.
- **Version envelopes enforced** — requests must carry `protocol_version` (1.1+).
- **Command allow-list** — `contracts/validate.py` rejects anything not in `contracts/bifrost_protocol.json` before dispatch. Unknown commands return a structured `UNKNOWN_COMMAND` error with the correlation id intact.
- **Stream routing** — events are tagged with the operation that produced them; the renderer cannot subscribe to arbitrary channels, and `removeAllListeners` is restricted to the known streaming channel set.
- **Renderer is the only client** — `contextIsolation` on, `nodeIntegration` off, `window.bifrost` is the entire surface.

Residual risks:

- A compromised renderer can still drive any command the backend exposes. The renderer loads local code only (no remote content) and the pages treat all backend data as untrusted text, but a full XSS-to-kernel path is not formally blocked — it's mitigated by the absence of remote content and injection sinks.
- Streaming commands are fire-and-forget with no authentication token. Cancellation exists (`cancel` + `CANCEL_EVENT`) but a hostile actor with pipe access could also send `dump`. Pipe access requires the same elevation tier, so this is accepted.

## Input Validation

- PIDs validated as 32-bit positive ints; read sizes capped (1..65536).
- Process names sanitized against path traversal before use in `output/` paths (`sanitize_process_name`, tested in `tests/test_security.py`).
- Webhook URLs validated for prefix, snowflake ID, and token charset (`[A-Za-z0-9_-]+`), which closes the PowerShell string-interpolation injection that existed in the fallback sender. Tokens are redacted in logs.
- Boilerplate generator strips whitespace from project names; output paths are joined under the chosen root.
- Driver binaries are hash-verified **fail-closed** against known-good SHA256 values before mapping. Mismatch aborts unless `force=True`.

## Kernel Access Surface

The stealth subsystem is the highest-risk part of the tool by design:

- It maps signed-but-vulnerable drivers and performs physical memory reads, manual page-table walks, and CR3 bypass reads.
- Kernel-capable code stays dormant by default: transports are explicit (`direct`/`hijack`/`driver`/`cr3`), with no auto-fallback ladder that can silently escalate into a driver map. Every connect self-tests with a probe read and records the attach steps, so a failed kernel attach reports the exact failing step instead of pretending success.
- Failures were historically silent (zero-filled reads, swallowed exceptions). After 4.0.0, unmapped pages raise, short physical reads raise, and CR3 resolution failure raises instead of returning a placeholder.
- The spoofer's backup snapshot (including the SAM-derived value) is written next to the source tree during a spoof run. It's deleted on the restore happy path. A crash mid-run leaves it on disk — treat `core/stealth/.spoof_backup.json` as sensitive if you crash between spoof and restore.
- Attach attempts are logged through the dump log channel, so what the access pipeline did is visible in the UI.

## Data Storage

| Data | Location | Sensitivity |
|---|---|---|
| Discord webhook URL | `localStorage` (Electron AppData) | Low — user-provided, validated |
| Session state (page, engine, process) | `localStorage` | None |
| Dump output (.h, .json) | `output/` directory | Low — game offsets |
| Spoof backup snapshot | `core/stealth/.spoof_backup.json` | **High** — hardware identity + SAM-derived value |

No credentials, API keys, or tokens are otherwise stored.

## Distribution Notes

- The bundled `.sys` files are flagged by Windows Defender as `HackTool:Win32/DriverMapper`-family on sight. The installer ships them because the driver access mode needs them, but expect AV friction; document hashes and offer the drivers as an optional component if you redistribute.
- PyInstaller onefile bootloaders trigger generic AV heuristics. The backend is signed with nothing — SmartScreen will warn on first run. Signing is the known mitigation.
- Kernel transports are what they look like: they map a vulnerable driver with a known mapper. Intended for security research and authorized testing; users own their compliance posture.
