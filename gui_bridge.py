"""
BIFROST SDK — GUI Bridge
Backend for the Electron app. Called by api_server.py via stdin/stdout JSON IPC.

The shapes emitted via the `emit` hook (log, progress, result) are defined in
contracts/bifrost_protocol.json under the "events" section.

All long-running operations (dump, spoof, generate, hunt) and the normal
command surface are also governed by that protocol document.
"""

from __future__ import annotations

import os
import posixpath
import re
import sys
import time
import ctypes
import threading
import traceback

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# This is monkey-patched at runtime by api_server.py to either capture output
# for request-response commands or to emit JSON lines over stdout for
# streaming operations. See contracts/bifrost_protocol.json for the expected
# event shapes (log, progress, result).
emit = lambda obj: None

# Cooperative cancellation for long-running streaming operations.
# Set by api_server.py when the renderer sends a `cancel` command.
CANCEL_EVENT = threading.Event()


def cancel_operation(operation: str = ""):
    """Signal a streaming operation to stop at its next checkpoint."""
    CANCEL_EVENT.set()
    emit({"type": "log", "text": f"Cancelling {operation or 'operation'}...", "level": "warn"})

KNOWN_GAME_EXES = {
    # Unreal Engine 5
    "marvelrivals_win64_shipping.exe": "unreal5_marvel",
    "marvelrivals.exe": "unreal5_marvel",
    "fortniteclient-win64-shipping.exe": "unreal5",
    "valorant-win64-shipping.exe": "unreal5",
    "palworld-win64-shipping.exe": "unreal5",
    "deltacosforceclient-win64-shipping.exe": "unreal5",
    "squadgame.exe": "unreal5",
    "tekkengame-win64-shipping.exe": "unreal5",
    "hogwartslegacy.exe": "unreal5",
    "pubg.exe": "unreal5",
    "readyornot-win64-shipping.exe": "unreal5",
    # Source 1
    "csgo.exe": "source",
    "hl2.exe": "source",
    "tf2.exe": "source",
    "tf_win64.exe": "source",
    "css.exe": "source",
    "hl2dm.exe": "source",
    "dods.exe": "source",
    # Source 2
    "cs2.exe": "source",
    # Source + EAC (Apex)
    "r5apex.exe": "source_eac",
    # Blizzard
    "overwatchclient.exe": "blizzard",
    "overwatch.exe": "blizzard",
    # Unity Mono
    "escape from tarkov.exe": "unity_mono",
    "escapefromtarkov.exe": "unity_mono",
    # Unity IL2CPP
    "rustclient.exe": "unity_il2cpp",
    "phasmophobia.exe": "unity_il2cpp",
    "among us.exe": "unity_il2cpp",
    "lethal company.exe": "unity_il2cpp",
    "valheim.exe": "unity_il2cpp",
}


def list_processes():
    from core.process import ProcessEnumerator

    procs = ProcessEnumerator.list_all()
    result = []
    for p in procs:
        name = p.get("name", "")
        if name.lower() in (
            "system", "svchost.exe", "csrss.exe", "smss.exe",
            "wininit.exe", "services.exe", "lsass.exe",
            "conhost.exe", "explorer.exe", "dwm.exe",
        ):
            continue
        entry = {
            "pid": p["pid"],
            "name": name,
            "window": p.get("window", ""),
            "engine": KNOWN_GAME_EXES.get(name.lower(), ""),
        }
        result.append(entry)

    emit({"type": "result", "data": result})


def _log(text, level="info"):
    """Emit a log event. Shape defined in contracts/bifrost_protocol.json → events.log"""
    emit({"type": "log", "text": text, "level": level})


def _progress(stage, pct):
    """Emit a progress event. Shape defined in contracts/bifrost_protocol.json → events.progress"""
    emit({"type": "progress", "stage": stage, "pct": int(pct)})


_DISCORD_WEBHOOK_PREFIXES = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",       # legacy
    "https://canary.discord.com/api/webhooks/",
    "https://ptb.discord.com/api/webhooks/",
)


def _redact_webhook(url):
    """Return a token-redacted version of the URL for logging."""
    try:
        for prefix in _DISCORD_WEBHOOK_PREFIXES:
            if url.startswith(prefix):
                tail = url[len(prefix):].strip("/").split("/")
                if len(tail) >= 2:
                    return f"{prefix}{tail[0]}/<redacted-token>"
        return url[:60] + "..."  # safe fallback
    except Exception:
        return "<unparseable url>"


def _send_webhook(url, data):
    """POST a Discord embed with dump results.

    Hardened against the common 404 causes:
      * trailing/leading whitespace in pasted URLs
      * legacy/canary/ptb Discord domains
      * silent failures — surfaces HTTP status with a diagnostic hint
    """
    if not url:
        raise ValueError("No webhook URL provided")

    # Strip ALL whitespace (incl. trailing \n from clipboard paste).
    url = url.strip()
    if not url:
        raise ValueError("Webhook URL was empty after stripping whitespace")

    matched_prefix = next(
        (p for p in _DISCORD_WEBHOOK_PREFIXES if url.startswith(p)),
        None,
    )
    if not matched_prefix:
        raise ValueError(
            "URL must be a Discord webhook (discord.com / discordapp.com / "
            "canary.discord.com / ptb.discord.com)"
        )

    parts = url[len(matched_prefix):].strip("/").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("Incomplete URL — expected /ID/TOKEN after the webhooks/ path")

    # Discord webhook IDs are snowflakes (numeric). Token is base64-ish.
    if not parts[0].isdigit():
        raise ValueError(
            f"Webhook ID looks malformed (not numeric): '{parts[0]}'. "
            "Did the URL get truncated when you pasted it?"
        )
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", parts[1]):
        raise ValueError(
            "Webhook token contains invalid characters. Expected [A-Za-z0-9_-] "
            "only — a URL pasted with stray characters or quotes won't work."
        )

    import urllib.request
    import urllib.error
    import json as _json

    embed = {
        "title": "BIFROST SDK — Dump Complete",
        "color": 0x00E5FF,
        "fields": [
            {"name": "Engine", "value": str(data.get("engine", "?")), "inline": True},
            {"name": "Classes", "value": str(data.get("classes", 0)), "inline": True},
            {"name": "Fields", "value": str(data.get("fields", 0)), "inline": True},
            {"name": "Time", "value": f"{data.get('elapsed', 0)}s", "inline": True},
        ],
        "footer": {"text": "BIFROST SDK"},
    }
    if data.get("output_dir"):
        embed["fields"].append({"name": "Output", "value": str(data["output_dir"])[:1024], "inline": False})

    payload = _json.dumps({"embeds": [embed]}).encode("utf-8")
    # Discord-recommended User-Agent format. Cloudflare (which fronts Discord)
    # aggressively 403's unknown UAs like "Python-urllib/3.x" or vendor-only
    # strings. The "DiscordBot (url, version)" pattern is whitelisted.
    # https://discord.com/developers/docs/reference#user-agent
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "DiscordBot (bifrost-sdk, 3.0)",
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    _log(f"Discord POST → {_redact_webhook(url)}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(
                    f"Discord returned HTTP {resp.status} (expected 204 No Content)"
                )
    except urllib.error.HTTPError as e:
        # Surface the actual diagnostic. Discord ships JSON error bodies.
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass

        # 403 from a webhook URL is almost always Cloudflare bot detection,
        # not Discord auth. Try two fallback fingerprints in order:
        #   urllib (Python) → curl.exe → powershell Invoke-RestMethod
        # Each has a different TLS/HTTP fingerprint; Cloudflare accepts at
        # least one in nearly every observed config.
        if e.code == 403:
            for tier, sender in (("curl", _curl_send), ("powershell", _powershell_send)):
                try:
                    _log(f"Discord 403; trying {tier} fallback…")
                    sender(url, payload, headers)
                    _log(f"[+] {tier} fallback succeeded")
                    return
                except Exception as fb_err:
                    _log(f"[!] {tier} fallback failed: {fb_err}", "warn")
            raise RuntimeError(
                "403 — Cloudflare/Discord rejected the request on all "
                "three fingerprints (urllib, curl, powershell). "
                "If you VPN/proxy, try without it; if the channel uses "
                "AutoMod webhook filtering, check those rules."
            )

        if e.code == 404:
            hint = (
                "404 — the webhook ID/token doesn't match any live webhook. "
                "Most common causes: webhook was deleted in Discord, URL was "
                "truncated on paste, or you're using a stale URL from before "
                "the channel was reset. Open Settings → Test to verify."
            )
        elif e.code == 401:
            hint = "401 — webhook token is invalid. Regenerate the webhook in Discord."
        elif e.code == 429:
            hint = "429 — rate-limited by Discord. Wait a few seconds and retry."
        else:
            hint = f"HTTP {e.code}"
        raise RuntimeError(f"{hint} ({body or 'no body'})")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error reaching Discord: {e.reason}")


def _curl_send(url, payload, headers):
    """
    Fallback send via curl.exe — used when urllib gets 403'd by Cloudflare.
    curl's default HTTP fingerprint passes Cloudflare's basic bot checks.
    Returns silently on 2xx; raises with the response body on anything else.
    """
    import subprocess
    import tempfile
    import os

    # Write payload to a temp file so we don't have to escape JSON on the
    # command line (Windows cmd quoting is a minefield for nested quotes).
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

        header_args = []
        for k, v in headers.items():
            header_args.extend(["-H", f"{k}: {v}"])

        cmd = [
            "curl.exe",
            "-sS",                  # silent but show errors
            "-w", "%{http_code}",   # write status code to stdout after body
            "--max-time", "10",
            "-X", "POST",
            *header_args,
            "--data-binary", f"@{tmp_path}",
            url,
        ]
        # CREATE_NO_WINDOW so we don't flash a console on Windows
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=15, creationflags=creationflags,
        )
        if result.returncode != 0:
            raise RuntimeError(f"curl exit {result.returncode}: {result.stderr.strip()[:200]}")
        # Last 3 chars of stdout are the HTTP status code (from -w).
        out = result.stdout or ""
        status = out[-3:] if len(out) >= 3 else ""
        body = out[:-3].strip()[:300]
        if status not in ("200", "204"):
            raise RuntimeError(f"curl got HTTP {status}: {body or 'no body'}")
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def _powershell_send(url, payload, headers):
    """
    Third-tier fallback using PowerShell Invoke-RestMethod.
    Different TLS+HTTP fingerprint from both urllib and curl — useful when
    Cloudflare's bot rules are tuned against curl specifically.
    Ships on every Win10+ machine.
    """
    import subprocess
    import tempfile
    import os

    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

        # Build a PS hashtable for headers without touching the cmd-line
        # quoting minefield. -InFile streams the body verbatim.
        header_lines = "; ".join(
            f"'{k}' = '{v.replace(chr(39), chr(39)*2)}'" for k, v in headers.items()
        )
        # Defense in depth: the URL itself is quote-escaped even though
        # _send_webhook already enforces a strict character set on it.
        ps_url = url.replace(chr(39), chr(39) * 2)
        # Invoke-RestMethod throws on non-2xx; we catch and surface the body.
        ps_script = (
            f"$ErrorActionPreference = 'Stop'; "
            f"$h = @{{ {header_lines} }}; "
            f"try {{ "
            f"  Invoke-RestMethod -Uri '{ps_url}' -Method POST "
            f"    -Headers $h -ContentType 'application/json' "
            f"    -InFile '{tmp_path}' -TimeoutSec 10 | Out-Null; "
            f"  Write-Output 'OK' "
            f"}} catch {{ "
            f"  $code = $_.Exception.Response.StatusCode.value__; "
            f"  Write-Output \"FAIL $code $($_.Exception.Message)\" "
            f"}}"
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", ps_script],
            capture_output=True, text=True,
            timeout=15, creationflags=creationflags,
        )
        out = (result.stdout or "").strip()
        if result.returncode != 0:
            raise RuntimeError(f"powershell exit {result.returncode}: {result.stderr.strip()[:200]}")
        if not out.startswith("OK"):
            raise RuntimeError(f"powershell got {out[:200] or 'no output'}")
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def sanitize_process_name(name: str) -> str:
    """
    Sanitize a user-supplied process name into a safe directory name.

    Defends against path-traversal: an attacker (or a malicious shortcut)
    could pass `name="../../etc/passwd"` and `run_dump` would join it into
    `PROJECT_ROOT/output/` — escaping the project directory.

    Strategy:
      1. Collapse every run of 2+ consecutive dots → strips `..` tokens.
      2. Normalize backslashes to forward slashes so basename works
         portably on both Windows and POSIX runners.
      3. Take `posixpath.basename` — picks the final path segment after
         all the `..` removal + separator normalization.
      4. Strip the `.exe` suffix (purely cosmetic — output dirs without it
         read better in the UI).
      5. Fall back to "unknown" if the input collapses to empty.

    Tested by tests/test_security.py::TestPathTraversal — that test imports
    this function directly (no local mirror) so the implementation here is
    the single source of truth.
    """
    if not isinstance(name, str) or not name:
        return "unknown"
    # 1. Strip all `..`+ runs — primary path-traversal defense.
    cleaned = re.sub(r"\.{2,}", "", name)
    # 2. Normalize separators so basename works on both Windows and POSIX.
    cleaned = cleaned.replace("\\", "/")
    # 3. Final path segment — handles cases like `/etc/passwd` → `passwd`.
    cleaned = posixpath.basename(cleaned)
    # 4. Drop the .exe suffix (cosmetic only).
    if cleaned.endswith(".exe"):
        cleaned = cleaned[: -len(".exe")]
    # `.exe` mid-string is left intact — only the trailing suffix is removed,
    # because legitimate names like `foo.exe.bak` shouldn't collapse to `foo.bak`.
    return cleaned or "unknown"


def _process_exists(pid: int) -> bool:
    """Cheap psutil existence check — avoids kernel attach attempts on dead PIDs."""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return True  # fail open if psutil is unavailable; attach will surface real errors


def run_dump(args):
    engine = args.get("engine", "auto")
    pid = args.get("pid", 0)
    name = args.get("name", "")
    stealth_mode = args.get("stealth", "auto")
    force_discovery = args.get("force_discovery", True)
    regenerate = args.get("regenerate", False)
    webhook_url = args.get("webhook", "")

    CANCEL_EVENT.clear()

    # Input validation (council security finding T6)
    # Windows PIDs are 32-bit values; reject anything outside that range.
    if not isinstance(pid, int) or pid <= 0 or pid > 0xFFFFFFFF:
        _log(f"Invalid PID: {pid}", "error")
        emit({"type": "result", "data": {"error": f"Invalid PID: {pid}"}})
        return
    if not isinstance(name, str) or not name.strip():
        _log("Missing process name", "error")
        emit({"type": "result", "data": {"error": "Missing process name"}})
        return
    if not _process_exists(pid):
        _log(f"Process {pid} is not running", "error")
        emit({"type": "result", "data": {"error": f"Process {pid} is not running", "code": "NO_PROCESS"}})
        return

    _log(f"BIFROST SDK - Starting {engine} dump")
    _log(f"Target: {name} (PID {pid})")

    # Sanitize name to prevent path traversal (council security finding T6).
    # Real implementation lives at module level so tests can import it directly
    # instead of mirroring (which is how the original bug stayed hidden).
    safe_name = sanitize_process_name(name)
    output_dir = os.path.join(PROJECT_ROOT, "output", safe_name)
    os.makedirs(output_dir, exist_ok=True)

    reader = None
    stealth_config = None

    try:
        if stealth_mode == "direct":
            from core.memory import MemoryReader
            _log("Access: Direct (no stealth)")
            reader = MemoryReader(pid=pid)
        else:
            try:
                from core.stealth import StealthReader
                from core.stealth.config import AccessMethod, StealthConfig

                method_map = {
                    "auto": AccessMethod.AUTO,
                    "driver": AccessMethod.DRIVER,
                    "hijack": AccessMethod.HIJACK,
                    "direct": AccessMethod.DIRECT,
                }
                method = method_map.get(stealth_mode, AccessMethod.AUTO)
                stealth_config = StealthConfig(method=method)

                _log(f"Access: Stealth ({stealth_mode})")
                reader = StealthReader(pid=pid, config=stealth_config)
                _log(f"Connected via: {reader.method_name}")
            except Exception as e:
                _log(f"Stealth attach failed: {e}", "warn")
                _log("Falling back to direct attach...", "warn")
                from core.memory import MemoryReader
                reader = MemoryReader(pid=pid)
                stealth_config = None

        # Auto-detect engine
        if engine == "auto":
            from core.process import ProcessEnumerator
            try:
                detected = ProcessEnumerator.detect_engine_from_modules(reader.list_modules())
                if detected:
                    engine = detected
                    _log(f"Auto-detected engine: {engine}")
                else:
                    _log("Could not auto-detect engine, defaulting to unreal5", "warn")
                    engine = "unreal5"
            except Exception:
                engine = "unreal5"

        # Auto-switch by process name
        if engine in ("unreal5", "unreal") and "marvel" in name.lower():
            engine = "unreal5_marvel"
            _log("Auto-switched to UE5 Marvel Rivals profile")

        _log(f"Engine: {engine}")
        _progress("Initializing", 5)

        # Create dumper via registry (replaces elif chain)
        from engines.registry import create_dumper, is_known_engine

        if not is_known_engine(engine):
            _log(f"Unknown engine: {engine}", "error")
            emit({"type": "result", "data": {"error": f"Unknown engine: {engine}"}})
            return

        # Build extra kwargs for engines that need them
        extra = {}

        dumper = create_dumper(
            engine, reader, output_dir,
            stealth_config=stealth_config,
            target_module=name,
            logger=_log,
            **extra,
        )

        def on_progress(prog):
            _progress(f"{prog.stage}: {prog.detail}", prog.percent)

        dumper.set_progress_callback(on_progress)
        _log(f"Created {dumper.ENGINE_NAME} dumper")
        _log(f"Output: {output_dir}")

        result = dumper.dump_and_generate()

        if CANCEL_EVENT.is_set():
            _log("Dump cancelled by user", "warn")
            emit({"type": "result", "data": {"error": "Cancelled", "code": "CANCELLED"}})
            return

        _log(f"DUMP COMPLETE — {dumper.progress.classes_found} classes, "
             f"{dumper.progress.fields_found} fields in {dumper.progress.elapsed:.1f}s")

        if dumper.progress.errors:
            for err in dumper.progress.errors[:10]:
                _log(f"Warning: {err}", "warn")

        result_data = {
            "headers": result.get("headers", []),
            "json": result.get("json", ""),
            "classes": dumper.progress.classes_found,
            "fields": dumper.progress.fields_found,
            "elapsed": round(dumper.progress.elapsed, 1),
            "engine": engine,
            "output_dir": output_dir,
        }
        emit({"type": "result", "data": result_data})

        # Discord webhook notification
        if webhook_url:
            try:
                _send_webhook(webhook_url, result_data)
                _log("Discord webhook sent")
            except Exception as wh_err:
                _log(f"Webhook failed: {wh_err}", "warn")

    except Exception as e:
        _log(f"ERROR: {e}", "error")
        for line in traceback.format_exc().splitlines():
            _log(f"  {line}", "error")
        emit({"type": "result", "data": {"error": str(e)}})
    finally:
        if reader:
            try:
                reader.close()
            except Exception:
                pass


def run_spoof(args):
    try:
        from core.stealth.spoofer import HardwareSpoofer

        _log("Starting HWID Spoof Sequence...")
        # `dry_run` is plumbed through so future callers can preview without
        # writes; defaults to live behaviour for backward compatibility.
        spoofer = HardwareSpoofer(
            driver=None,
            dry_run=bool(args.get("dry_run", False)),
        )
        spoofer.set_logger(lambda msg: _log(msg))

        result = spoofer.run_all({
            "mode": args.get("mode", "random"),
            "custom_serials": args.get("custom_serials", {}),
            "advanced": bool(args.get("advanced", False)),
            "preset": args.get("preset"),
        })
        emit({"type": "result", "data": result})
    except Exception as e:
        _log(f"Spoofer error: {e}", "error")
        emit({"type": "result", "data": {"error": str(e)}})


def run_spoof_info(args):
    try:
        from core.stealth.spoofer import HardwareSpoofer

        spoofer = HardwareSpoofer(driver=None)
        values = spoofer.get_current_values()
        emit({"type": "result", "data": values})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e)}})


def run_spoof_restore(args):
    try:
        from core.stealth.spoofer import HardwareSpoofer

        spoofer = HardwareSpoofer(driver=None)
        spoofer.set_logger(lambda msg: _log(msg))
        ok = spoofer.restore_originals()
        emit({"type": "result", "data": {"success": ok}})
    except Exception as e:
        _log(f"Restore error: {e}", "error")
        emit({"type": "result", "data": {"success": False, "error": str(e)}})


def run_generate(args):
    try:
        from core.generator.generator import CppBoilerplateGenerator

        project_name = args.get("project_name", "BifrostProject")
        output_dir = args.get("output_dir", os.path.join(PROJECT_ROOT, "output"))
        sdk_data = args.get("sdk_data", {})

        _log(f"Generating C++ project: {project_name}")
        gen = CppBoilerplateGenerator(
            project_name, output_dir, sdk_data,
            logger_callback=lambda msg: _log(msg),
        )
        ok = gen.generate()
        emit({"type": "result", "data": {"success": ok, "path": gen.output_dir}})
    except Exception as e:
        _log(f"Generator error: {e}", "error")
        emit({"type": "result", "data": {"success": False, "error": str(e)}})


def run_hunt(args):
    try:
        from core.hunter.hunter import DriverHunter

        _log("Starting Vulnerable Driver Hunt...")
        hunter = DriverHunter()
        hunter.set_logger(lambda msg: _log(msg))
        max_drivers = min(int(args.get("max_drivers", 100)), 500)
        results = hunter.start_hunt(max_drivers=max_drivers)
        emit({"type": "result", "data": results})
    except Exception as e:
        _log(f"Hunter error: {e}", "error")
        emit({"type": "result", "data": {"error": str(e)}})


def run_read_memory(args):
    """Read raw bytes from a target process for the Memory Viewer page.

    args: {pid, address, size}
    Returns: {type:'result', data:{bytes: [int, ...], address, pid}}
    """
    pid = args.get("pid", 0)
    address = args.get("address", 0)
    size = args.get("size", 0)

    if not isinstance(pid, int) or pid <= 0 or pid > 0xFFFFFFFF:
        emit({"type": "result", "data": {"error": f"Invalid PID: {pid}", "code": "BAD_ARGS"}})
        return
    if not isinstance(address, int) or address <= 0:
        emit({"type": "result", "data": {"error": "Invalid address", "code": "BAD_ARGS"}})
        return
    if not isinstance(size, int) or size <= 0 or size > 0x10000:
        emit({"type": "result", "data": {"error": "Invalid size (1..65536)", "code": "BAD_ARGS"}})
        return
    if not _process_exists(pid):
        emit({"type": "result", "data": {"error": f"Process {pid} is not running", "code": "NO_PROCESS"}})
        return

    reader = None
    try:
        # Memory viewer reads are lightweight and never need a kernel driver:
        # direct attach with a hijack fallback covers every non-AC target.
        try:
            from core.stealth import StealthReader
            from core.stealth.config import AccessMethod, StealthConfig
            reader = StealthReader(pid=pid, config=StealthConfig(method=AccessMethod.HIJACK))
        except Exception as e:
            _log(f"Hijack attach failed ({e}); using direct read", "warn")
            from core.memory import MemoryReader
            reader = MemoryReader(pid=pid)

        raw = reader.read_bytes(address, size)
        emit({"type": "result", "data": {
            "pid": pid,
            "address": address,
            "size": len(raw),
            "bytes": list(raw),
        }})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "READ_FAILED"}})
    finally:
        if reader:
            try:
                reader.close()
            except Exception:
                pass


_AC_DEFINITIONS = {
    "eac": {
        "name": "Easy Anti-Cheat",
        "processes": ("easyanticheat.exe", "easyanticheat_eos_setup.exe"),
        "services": ("EasyAntiCheat", "EasyAntiCheatSvc"),
        "drivers": ("easyanticheat.sys", "easyanticheat_eos.sys"),
    },
    "battleye": {
        "name": "BattlEye",
        "processes": ("beservice.exe", "beservice_x64.exe"),
        "services": ("BEService", "BEDaisy"),
        "drivers": ("bedaisy.sys",),
    },
    "vanguard": {
        "name": "Riot Vanguard",
        "processes": ("vgc.exe", "vgtray.exe"),
        "services": ("vgc", "vgk"),
        "drivers": ("vgk.sys",),
    },
    "ricochet": {
        "name": "RICOCHET",
        "processes": ("cod.exe", "atvi-anti-cheat.exe"),
        "services": ("atvi-acfg", "hvb"),
        "drivers": ("atvi-re.sys",),
    },
    "nprotect": {
        "name": "nProtect GameGuard",
        "processes": ("nprotect gameguard npgl.exe", "gameguarden.des.exe"),
        "services": ("npggsvc",),
        "drivers": ("npptnt2.sys", "nppgg.sys"),
    },
}


def _query_service_state(service_name: str) -> str:
    """Query a Windows service via sc.exe. Returns RUNNING/STOPPED/NOT_FOUND/ERROR."""
    import subprocess
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        out = subprocess.run(
            ["sc", "query", service_name],
            capture_output=True, text=True, timeout=5, creationflags=creationflags,
        ).stdout.lower()
        if "does not exist" in out or "specified service" in out:
            return "NOT_FOUND"
        if "running" in out:
            return "RUNNING"
        return "STOPPED"
    except Exception:
        return "ERROR"


def run_ac_detect(args):
    """Detect running anti-cheat systems (processes, services, drivers).

    Returns data keyed by AC id: {running, driver_loaded, service_status}.
    Matches the shape ACMonitorPage.jsx expects.
    """
    try:
        import psutil

        procs = set()
        for p in psutil.process_iter(["name"]):
            try:
                procs.add(p.info["name"].lower())
            except Exception:
                continue

        loaded_drivers = set()
        try:
            import subprocess
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            out = subprocess.run(
                ["driverquery", "/fo", "csv"],
                capture_output=True, text=True, timeout=10, creationflags=creationflags,
            ).stdout.lower()
            loaded_drivers = {line.split(",")[0].strip('"') for line in out.splitlines() if "," in line}
        except Exception:
            loaded_drivers = set()

        result = {}
        for ac_id, ac in _AC_DEFINITIONS.items():
            running = any(proc in procs for proc in ac["processes"])
            driver_loaded = any(drv in loaded_drivers for drv in ac["drivers"])
            service_status = "NOT_FOUND"
            if running:
                service_status = "RUNNING"
            else:
                for svc in ac["services"]:
                    state = _query_service_state(svc)
                    if state == "RUNNING":
                        running = True
                        service_status = "RUNNING"
                        break
                    if state == "STOPPED":
                        service_status = "STOPPED"
            result[ac_id] = {
                "running": running,
                "driver_loaded": driver_loaded,
                "service_status": service_status,
            }
        emit({"type": "result", "data": result})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "AC_SCAN_FAILED"}})


def run_test_webhook(args):
    url = args.get("url", "")
    if not url:
        emit({"type": "result", "data": {"error": "No webhook URL provided"}})
        return
    try:
        _send_webhook(url, {
            "engine": "test",
            "classes": 42,
            "fields": 256,
            "elapsed": 1.3,
            "output_dir": os.path.join(PROJECT_ROOT, "output", "test"),
        })
        emit({"type": "result", "data": {"success": True}})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e)}})


def _decomp_sink():
    """Wire core.decomp sink callbacks to the bridge emit surface."""
    from core.decomp.analyzer import LogSink
    return LogSink(
        logger=lambda text, level="info": _log(text, level),
        progress=_progress,
        cancel=lambda: CANCEL_EVENT.is_set(),
    )


def run_analyze_probe(args):
    """Report decompiler engine availability (rizin+rz-ghidra vs iced fallback)."""
    try:
        from core.decomp.analyzer import probe
        emit({"type": "result", "data": probe()})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "PROBE_FAILED"}})


def _attach_light_reader(pid):
    """Lightweight attach for module dumps — never a kernel driver.

    Same policy as read_memory: hijack attach with direct fallback. AUTO
    chains must not implicitly load drivers; neither does this.
    """
    try:
        from core.stealth import StealthReader
        from core.stealth.config import AccessMethod, StealthConfig
        return StealthReader(pid=pid, config=StealthConfig(method=AccessMethod.HIJACK))
    except Exception as e:
        _log(f"Hijack attach failed ({e}); using direct read", "warn")
        from core.memory import MemoryReader
        return MemoryReader(pid=pid)


def run_analyze(args):
    """Open a binary for analysis. Streaming: logs + progress + result.

    source.type == 'file'   → analyze any on-disk PE/ELF/raw file
    source.type == 'module' → dump {pid, module} to disk first, then analyze
    """
    from core.decomp.analyzer import analyze, close_session

    CANCEL_EVENT.clear()

    source = args.get("source", {})
    stype = source.get("type")
    limit = args.get("limit", 400)

    if not isinstance(limit, int) or limit <= 0 or limit > 2000:
        emit({"type": "result", "data": {"error": "Invalid limit (1..2000)", "code": "BAD_ARGS"}})
        return

    reader = None
    try:
        if stype == "module":
            pid = source.get("pid", 0)
            module = source.get("module") or source.get("name") or ""
            if not isinstance(pid, int) or pid <= 0 or pid > 0xFFFFFFFF:
                emit({"type": "result", "data": {"error": f"Invalid PID: {pid}", "code": "BAD_ARGS"}})
                return
            if not isinstance(module, str) or not module.strip():
                emit({"type": "result", "data": {"error": "Missing module name", "code": "BAD_ARGS"}})
                return
            if not _process_exists(pid):
                emit({"type": "result", "data": {"error": f"Process {pid} is not running", "code": "NO_PROCESS"}})
                return

            safe = sanitize_process_name(module)
            module_out_dir = os.path.join(PROJECT_ROOT, "output", "analyzer", safe)
            os.makedirs(module_out_dir, exist_ok=True)

            _log(f"Dumping module {module} (PID {pid}) for analysis...")
            reader = _attach_light_reader(pid)
            source = {
                "type": "module",
                "reader": reader,
                "module": module,
                "module_out_dir": module_out_dir,
                "cancel_check": CANCEL_EVENT.is_set,
            }
        elif stype == "file":
            path = source.get("path", "")
            if not isinstance(path, str) or not path.strip():
                emit({"type": "result", "data": {"error": "Missing file path", "code": "BAD_ARGS"}})
                return
            _log(f"Analyzing file: {path}")
        else:
            emit({"type": "result", "data": {"error": "source.type must be 'file' or 'module'", "code": "BAD_ARGS"}})
            return

        _log("Analyzer: closing any previous session")
        close_session()
        sink = _decomp_sink()
        _log("Analyzer: starting analysis job")
        result = analyze(source, sink, limit=limit)
        emit({"type": "result", "data": result})
    except Exception as e:
        if CANCEL_EVENT.is_set():
            _log("Analysis cancelled by user", "warn")
            emit({"type": "result", "data": {"error": "Cancelled", "code": "CANCELLED"}})
            return
        _log(f"ERROR: {e}", "error")
        emit({"type": "result", "data": {"error": str(e)}})
    finally:
        if reader:
            try:
                reader.close()
            except Exception:
                pass


def run_decompile_fn(args):
    """Decompile one function from the open rizin session."""
    try:
        from core.decomp.analyzer import decompile_fn
        addr = args.get("addr", 0)
        if not isinstance(addr, int) or addr <= 0:
            emit({"type": "result", "data": {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}})
            return
        result = decompile_fn(addr)
        emit({"type": "result", "data": result})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "DECOMPILE_FAILED"}})


def run_hexdump_at(args):
    """Hex+ascii rows at an address in the open image (address explorer)."""
    try:
        from core.decomp.analyzer import hexdump_at
        addr = args.get("addr", 0)
        if not isinstance(addr, int) or addr <= 0:
            emit({"type": "result", "data": {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}})
            return
        size = args.get("size", 0)
        kwargs = {"addr": addr}
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            kwargs["size"] = size
        emit({"type": "result", "data": hexdump_at(**kwargs)})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "HEXDUMP_FAILED"}})


def run_disasm_at(args):
    """Linear disassembly at an address in the open image (explorer)."""
    try:
        from core.decomp.analyzer import disasm_at
        addr = args.get("addr", 0)
        if not isinstance(addr, int) or addr <= 0:
            emit({"type": "result", "data": {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}})
            return
        size = args.get("size", 0)
        kwargs = {"addr": addr}
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            kwargs["size"] = size
        emit({"type": "result", "data": disasm_at(**kwargs)})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "DISASM_FAILED"}})


def run_xrefs_at(args):
    """Cross-references to an address (rizin axtj one-shot)."""
    try:
        from core.decomp.analyzer import xrefs_at
        addr = args.get("addr", 0)
        if not isinstance(addr, int) or addr <= 0:
            emit({"type": "result", "data": {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}})
            return
        emit({"type": "result", "data": xrefs_at(addr=addr)})
    except Exception as e:
        emit({"type": "result", "data": {"error": str(e), "code": "XREFS_FAILED"}})


def run_analyze_export(args):
    """Batch-decompile the open session's top functions to .c files."""
    from core.decomp.analyzer import export_functions

    CANCEL_EVENT.clear()
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or limit <= 0 or limit > 2000:
        emit({"type": "result", "data": {"error": "Invalid limit (1..2000)", "code": "BAD_ARGS"}})
        return
    try:
        _log("Analyzer: export pass started")
        sink = _decomp_sink()
        result = export_functions(sink, limit=limit)
        _log(f"Export complete — {result['count']} files in {result['dir']}")
        emit({"type": "result", "data": result})
    except Exception as e:
        if CANCEL_EVENT.is_set():
            emit({"type": "result", "data": {"error": "Cancelled", "code": "CANCELLED"}})
            return
        _log(f"ERROR: {e}", "error")
        emit({"type": "result", "data": {"error": str(e)}})
