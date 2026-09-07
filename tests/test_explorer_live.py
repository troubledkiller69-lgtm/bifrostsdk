"""Live end-to-end of the address explorer over the real IPC bridge.

Analyzes a real PE (the bundled rizin rz_core DLL), then drives
analyzer_hexdump / analyzer_disasm_at / analyzer_xrefs through
api_server.py and checks shapes. xrefs exercises a genuine rizin one-shot.
"""

import json
import os
import time

from tests.test_backend_live import backend, _send

RIZIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "gui", "extra", "rizin", "bin",
)
TARGET = os.path.join(RIZIN_DIR, "rz_core-0.9.dll")


def _stream_analyze(proc, source):
    msg = {
        "protocol_version": "1.3",
        "command": "analyze",
        "args": {"source": source, "limit": 10},
        "stream": "analyze",
    }
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    deadline = time.time() + 300.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("type") == "result" and data.get("stream") == "analyze":
            return data
    raise TimeoutError("no analyze result")


def test_explorer_hexdump_disasm_over_bridge(backend):
    if not os.path.isfile(TARGET):
        import pytest
        pytest.skip("rizin not provisioned in-tree")
    resp = _stream_analyze(backend, {"type": "file", "path": TARGET})
    payload = resp.get("data", {})
    assert payload.get("engine") == "rizin-ghidra", payload
    fns = payload.get("functions") or []
    assert fns, "analyze returned no functions"
    addr = fns[0]["addr"]

    h = _send(backend, "analyzer_hexdump", {"addr": addr, "size": 64})
    data = h.get("data", {})
    assert "rows" in data and len(data["rows"]) == 4, data
    assert data["rows"][0]["addr"] == addr
    assert data["arch"] == "x86_64"
    assert len(data["rows"][0]["hex"].split()) == 16

    d = _send(backend, "analyzer_disasm_at", {"addr": addr, "size": 64})
    data = d.get("data", {})
    assert "lines" in data and data["lines"], data
    assert data["lines"][0]["address"] == addr


def test_explorer_xrefs_over_bridge(backend):
    if not os.path.isfile(TARGET):
        import pytest
        pytest.skip("rizin not provisioned in-tree")
    resp = _stream_analyze(backend, {"type": "file", "path": TARGET})
    payload = resp.get("data", {})
    fns = payload.get("functions") or []
    assert fns
    # entry0 is referenced by the PE's loader config; even if zero xrefs
    # come back, the shape must be {addr, xrefs:[]} — never an error.
    target_addr = next((f["addr"] for f in fns if "entry" in (f.get("name") or "")), fns[0]["addr"])
    x = _send(backend, "analyzer_xrefs", {"addr": target_addr})
    data = x.get("data", {})
    assert data.get("error") is None, data
    assert isinstance(data.get("xrefs"), list), data
    if data["xrefs"]:
        assert all(isinstance(r["from"], int) for r in data["xrefs"])


def test_explorer_bad_args_over_bridge(backend):
    r = _send(backend, "analyzer_hexdump", {"addr": 0})
    assert r.get("data", {}).get("code") == "BAD_ARGS"
    r = _send(backend, "analyzer_disasm_at", {"addr": -5})
    assert r.get("data", {}).get("code") == "BAD_ARGS"
    r = _send(backend, "analyzer_xrefs", {"addr": "nope"})
    assert r.get("data", {}).get("code") == "BAD_ARGS"
