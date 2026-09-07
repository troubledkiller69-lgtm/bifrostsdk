#!/usr/bin/env python3
"""
BIFROST SDK — Bridge Smoke Test (Cluster 1 of council remediation plan)

Exercises the stdio JSON IPC bridge using the v1.1+ protocol envelope.

Usage:
    python scripts/smoke_bridge.py                 # dev mode (uses api_server.py)
    python scripts/smoke_bridge.py --packaged      # uses the bundled api_server.exe

This script is intended to become the post-build smoke test called by
electron-builder after packaging (see approved plan).

It validates:
- Protocol version envelope is accepted on both request/response and streaming paths
- Core commands (ping, list_processes) succeed
- Unknown commands are rejected with structured error_shape (code + message)
- Basic streaming command acceptance (start-dump with dummy args)
- Analyzer surface (analyze_probe result shape; analyze streams BAD_ARGS, not UNKNOWN_COMMAND)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
PROTOCOL_VERSION = "1.2"

# --- Helpers -----------------------------------------------------------------

def log(msg: str, level: str = "info"):
    prefix = {"info": "[*]", "pass": "[+]", "fail": "[-]", "warn": "[!]"}.get(level, "[*]")
    print(f"{prefix} {msg}", flush=True)


def make_envelope(command: str, args: Dict[str, Any], req_id: Optional[int] = None) -> str:
    """Create a v1.1 protocol envelope."""
    env = {
        "protocol_version": PROTOCOL_VERSION,
        "command": command,
        "args": args,
    }
    if req_id is not None:
        env["id"] = req_id
    return json.dumps(env) + "\n"


class BridgeSmoke:
    def __init__(self, use_packaged: bool = False):
        self.use_packaged = use_packaged
        self.proc: Optional[subprocess.Popen] = None
        self.responses: Dict[int, Dict[str, Any]] = {}
        self.events: list[Dict[str, Any]] = []
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_reader = threading.Event()

    def start(self):
        if self.use_packaged:
            candidates = [
                PROJECT_ROOT / "gui" / "extra" / "api_server.exe",
                PROJECT_ROOT / "gui" / "dist-electron" / "win-unpacked" / "api_server.exe",
            ]
            exe_path = next((p for p in candidates if p.exists()), None)
            if not exe_path:
                raise FileNotFoundError(
                    "Packaged api_server.exe not found in any expected location. "
                    "Run build.ps1 first, or use dev mode."
                )
            self.proc = subprocess.Popen(
                [str(exe_path)],
                cwd=exe_path.parent,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            log(f"Started packaged bridge: {exe_path}")
        else:
            script = PROJECT_ROOT / "api_server.py"
            self.proc = subprocess.Popen(
                [sys.executable, str(script)],
                cwd=PROJECT_ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            log(f"Started dev bridge via {script}")

        # Start background reader
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

        # Give it a moment
        time.sleep(0.4)

    def _read_loop(self):
        assert self.proc and self.proc.stdout
        while not self._stop_reader.is_set():
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if "_id" in msg:
                    self.responses[msg["_id"]] = msg
                else:
                    self.events.append(msg)
            except Exception:
                # Raw non-JSON line (debug)
                self.events.append({"type": "raw", "text": line})

    def send(self, command: str, args: Dict[str, Any], req_id: Optional[int] = None) -> int:
        assert self.proc and self.proc.stdin
        if req_id is None:
            req_id = int(time.time() * 1000) % 1000000
        payload = make_envelope(command, args, req_id)
        self.proc.stdin.write(payload)
        self.proc.stdin.flush()
        return req_id

    def wait_for_response(self, req_id: int, timeout: float = 8.0) -> Dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if req_id in self.responses:
                return self.responses.pop(req_id)
            time.sleep(0.05)
        raise TimeoutError(f"No response for id={req_id} within {timeout}s")

    def stop(self):
        self._stop_reader.set()
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    def get_recent_events(self, n: int = 5) -> list[Dict[str, Any]]:
        return self.events[-n:]


# --- Test Cases --------------------------------------------------------------

def test_ping(bridge: BridgeSmoke) -> bool:
    log("Testing ping...")
    rid = bridge.send("ping", {})
    resp = bridge.wait_for_response(rid)
    if resp.get("status") == "ok":
        log(f"ping OK — version={resp.get('version')}", "pass")
        return True
    log(f"ping FAILED: {resp}", "fail")
    return False


def test_list_processes(bridge: BridgeSmoke) -> bool:
    log("Testing list_processes...")
    rid = bridge.send("list_processes", {})
    resp = bridge.wait_for_response(rid)
    data = resp.get("data") or resp
    if isinstance(data, list):
        log(f"list_processes OK — {len(data)} processes returned", "pass")
        return True
    log(f"list_processes unexpected response: {resp}", "fail")
    return False


def test_unknown_command_rejected(bridge: BridgeSmoke) -> bool:
    log("Testing unknown command rejection (structured error)...")
    rid = bridge.send("definitely_not_a_real_command_12345", {"foo": 1})
    resp = bridge.wait_for_response(rid)
    data = resp.get("data", resp)
    err = data.get("error") if isinstance(data, dict) else None
    code = data.get("code") if isinstance(data, dict) else None

    if err and code == "UNKNOWN_COMMAND":
        log(f"Unknown command correctly rejected with structured error_shape (code + error)", "pass")
        return True
    log(f"Expected structured UNKNOWN_COMMAND error, got: {resp}", "fail")
    return False


def test_streaming_envelope_accepted(bridge: BridgeSmoke) -> bool:
    log("Testing streaming command envelope (start-dump with dummy args)...")
    # We don't want a real dump; just verify the envelope is accepted and
    # the bridge doesn't crash or send immediate protocol error.
    rid = bridge.send("dump", {
        "engine": "source",
        "pid": 999999,          # obviously invalid
        "name": "smoke-test.exe",
        "stealth": "direct",
    })

    # Give it a short time to react (it will probably error on the bad pid,
    # but the important thing is we didn't get an immediate UNKNOWN_COMMAND
    # or protocol violation).
    time.sleep(1.2)

    # Check recent events for any obvious protocol rejection
    recent = bridge.get_recent_events(8)
    bad = [e for e in recent if "UNKNOWN" in str(e) or "protocol" in str(e).lower()]
    if bad:
        log(f"Streaming envelope may have been rejected: {bad}", "fail")
        return False

    log("Streaming envelope accepted (no immediate protocol rejection)", "pass")
    return True


def test_analyze_probe(bridge: BridgeSmoke) -> bool:
    log("Testing analyze_probe (decompiler engine availability)...")
    rid = bridge.send("analyze_probe", {})
    resp = bridge.wait_for_response(rid)
    if resp.get("_id") != rid or resp.get("type") != "result":
        log(f"analyze_probe unexpected envelope: {resp}", "fail")
        return False
    data = resp.get("data") or {}
    rizin = data.get("rizin") or {}
    iced = data.get("iced") or {}
    if (isinstance(rizin.get("available"), bool)
            and isinstance(iced.get("available"), bool)
            and data.get("default_engine") in ("rizin-ghidra", "iced-x86")):
        log(f"analyze_probe OK — rizin.available={rizin.get('available')} "
            f"iced.available={iced.get('available')} "
            f"default_engine={data.get('default_engine')}", "pass")
        return True
    log(f"analyze_probe unexpected data: {data}", "fail")
    return False


def test_analyze_streaming_bad_source(bridge: BridgeSmoke) -> bool:
    log("Testing analyze streaming with invalid source (BAD_ARGS, not UNKNOWN_COMMAND)...")
    bridge.send("analyze", {"source": {"type": "smoke-invalid"}})
    deadline = time.time() + 8.0
    while time.time() < deadline:
        for msg in bridge.events:
            if not isinstance(msg, dict):
                continue
            if msg.get("type") == "result" and msg.get("stream") == "analyze":
                code = (msg.get("data") or {}).get("code")
                if code == "BAD_ARGS":
                    log("analyze streamed structured BAD_ARGS (command known, args rejected)", "pass")
                    return True
                log(f"analyze result unexpected code {code!r}: {msg}", "fail")
                return False
            if "UNKNOWN_COMMAND" in str(msg):
                log(f"analyze wrongly rejected as unknown: {msg}", "fail")
                return False
        time.sleep(0.05)
    log("No streamed result seen for analyze within timeout", "fail")
    return False


# --- Main --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packaged", action="store_true",
                        help="Use the bundled api_server.exe instead of dev python script")
    args = parser.parse_args()

    bridge = BridgeSmoke(use_packaged=args.packaged)
    all_passed = True

    try:
        bridge.start()

        tests = [
            ("ping", test_ping),
            ("list_processes", test_list_processes),
            ("unknown_command_rejected", test_unknown_command_rejected),
            ("streaming_envelope", test_streaming_envelope_accepted),
            ("analyze_probe", test_analyze_probe),
            ("analyze_streaming_bad_source", test_analyze_streaming_bad_source),
        ]

        for name, fn in tests:
            try:
                if not fn(bridge):
                    all_passed = False
            except Exception as e:
                log(f"{name} raised exception: {e}", "fail")
                all_passed = False

        if all_passed:
            log("All smoke tests PASSED", "pass")
            return 0
        else:
            log("One or more smoke tests FAILED", "fail")
            return 1

    except Exception as e:
        log(f"Fatal error during smoke: {e}", "fail")
        return 2
    finally:
        bridge.stop()


if __name__ == "__main__":
    sys.exit(main())