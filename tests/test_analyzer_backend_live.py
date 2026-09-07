"""
Live subprocess verification of the analyzer command surface (protocol v1.3).

Spawns the real api_server.py like test_backend_live.py does and exercises,
hermetically (no rizin install, no network, no real processes):

  1. analyze_probe returns the engine-availability shape with _id echo
  2. decompile_fn without an open session -> NO_SESSION; addr <= 0 -> BAD_ARGS
  3. streaming analyze rejects a bogus source.type, pid 0, and a nonexistent
     file path, each as a stream-tagged result (never a plain response)
  4. bridge_info advertises features.analyzer + protocol 1.3
  5. an unknown 'analyze_*' command is rejected by the allow-list

Run with: python -m pytest tests/test_analyzer_backend_live.py -v
"""

from __future__ import annotations

import json
import os
import tempfile
import time

from tests.test_backend_live import backend, _send

STREAM = "analyze"


def _send_stream(proc, args):
    """Fire-and-forget analyze envelope, then read stdout until the tagged
    result arrives. Logs/progress lines in between are skipped."""
    msg = {
        "protocol_version": "1.3",
        "command": "analyze",
        "args": args,
        "stream": STREAM,
    }
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()

    deadline = time.time() + 10.0
    seen = 0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        line = line.strip()
        if not line:
            continue
        seen += 1
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("type") == "result" and data.get("stream") == STREAM:
            return data
        if seen > 100:
            break
    raise TimeoutError("No stream-tagged analyze result within 10s")


# ----------------------------------------------------------------------
# analyze_probe — request/response shape
# ----------------------------------------------------------------------

def test_analyze_probe_returns_engine_availability(backend):
    """Probe must report availability, never spawn or assert rizin."""
    resp = _send(backend, "analyze_probe")
    assert resp.get("_id") == 1
    data = resp["data"]
    rizin = data.get("rizin", {})
    assert isinstance(rizin.get("available"), bool)
    assert isinstance(rizin.get("exe"), str)
    assert isinstance(rizin.get("version"), str)
    assert isinstance(rizin.get("decompiler"), bool)
    assert data.get("iced", {}).get("available") is True
    assert data.get("default_engine") in ("rizin-ghidra", "iced-x86")


# ----------------------------------------------------------------------
# decompile_fn — no-session / bad-args paths (rizin-dependent paths skipped)
# ----------------------------------------------------------------------

def test_decompile_fn_without_session_returns_no_session(backend):
    resp = _send(backend, "decompile_fn", {"addr": 0x401000})
    data = resp["data"]
    assert data.get("code") == "NO_SESSION", f"Got: {data}"
    assert "session" in (data.get("error") or "").lower()


def test_decompile_fn_rejects_nonpositive_addr(backend):
    for bad in (0, -1):
        resp = _send(backend, "decompile_fn", {"addr": bad})
        data = resp["data"]
        assert data.get("code") == "BAD_ARGS", f"addr={bad} got: {data}"


# ----------------------------------------------------------------------
# analyze (streaming) — validation failures, all hermetic
# ----------------------------------------------------------------------

def test_analyze_bogus_source_type_streams_bad_args(backend):
    resp = _send_stream(backend, {"source": {"type": "frobnicate"}})
    data = resp["data"]
    assert data.get("code") == "BAD_ARGS"
    assert "source.type" in (data.get("error") or "")
    assert resp.get("_id") is None, "Streaming result must not carry _id"


def test_analyze_module_pid_zero_streams_bad_args(backend):
    resp = _send_stream(backend, {"source": {"type": "module", "pid": 0,
                                             "module": "game.exe"}})
    data = resp["data"]
    assert data.get("code") == "BAD_ARGS"
    assert "PID" in (data.get("error") or "")


def test_analyze_nonexistent_file_streams_error(backend):
    path = os.path.join(tempfile.gettempdir(),
                        f"bifrost_no_such_{os.getpid()}_{int(time.time())}.bin")
    resp = _send_stream(backend, {"source": {"type": "file", "path": path}})
    data = resp["data"]
    assert data.get("error", "").startswith("File not found"), f"Got: {data}"


# ----------------------------------------------------------------------
# bridge_info — analyzer feature flag + protocol version
# ----------------------------------------------------------------------

def test_bridge_info_advertises_analyzer(backend):
    resp = _send(backend, "bridge_info")
    data = resp["data"]
    assert data.get("features", {}).get("analyzer") is True
    assert str(data.get("protocol_version", "")).startswith("1.3")


# ----------------------------------------------------------------------
# allow-list regression
# ----------------------------------------------------------------------

def test_unknown_analyze_command_rejected(backend):
    resp = _send(backend, "analyze_frobnicate")
    data = resp["data"]
    assert data.get("code") == "UNKNOWN_COMMAND", f"Got: {data}"
    assert "analyze_frobnicate" in (data.get("error") or "")
