"""make_signature: bridge validation + generator fast path + protocol/MCP wiring."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import gui_bridge
from contracts.validate import validate_command, KNOWN_COMMANDS
from core.signature_generator import SignatureGenerator


def _capture(fn, args):
    out = []
    orig = gui_bridge.emit
    gui_bridge.emit = out.append
    try:
        fn(args)
    finally:
        gui_bridge.emit = orig
    assert out, "expected an emit"
    return out[-1]


def test_bad_pid():
    r = _capture(gui_bridge.run_make_signature, {"pid": -1, "addresses": [0x1000]})
    assert r["data"]["code"] == "BAD_ARGS"


def test_bad_addresses():
    for bad in ([], [0], list(range(17)), ["nope"], [0x1000, -5]):
        addrs = bad if isinstance(bad, list) and all(isinstance(x, int) for x in bad) else bad
        r = _capture(gui_bridge.run_make_signature, {"pid": 1234, "addresses": addrs})
        assert r["data"]["code"] == "BAD_ARGS", bad


def test_no_process(monkeypatch):
    monkeypatch.setattr(gui_bridge, "_process_exists", lambda pid: False)
    r = _capture(gui_bridge.run_make_signature, {"pid": 999999, "addresses": [0x1000]})
    assert r["data"]["code"] == "NO_PROCESS"


def test_success_with_fakes(monkeypatch):
    monkeypatch.setattr(gui_bridge, "_process_exists", lambda pid: True)

    class FakeReader:
        def read_bytes(self, addr, size):
            # stable prefix + per-address-varying dword (entity pointer) + padding
            import struct
            buf = bytearray(b"\x48\x8B\x05" + struct.pack("<I", addr) + b"\x90" * 9 + b"\xCC" * 8)
            buf = (bytes(buf) * ((size // len(buf)) + 1))[:size]
            return buf

        def close(self):
            pass

    class FakeScanner:
        def scan_all(self, pattern, **kw):
            return [1, 2]  # 2 verification hits

    import core.stealth as stealth_mod
    import core.scanner as scanner_mod
    monkeypatch.setattr(stealth_mod, "StealthReader", lambda pid, config: FakeReader())
    monkeypatch.setattr(scanner_mod, "PatternScanner", lambda reader: FakeScanner())

    r = _capture(gui_bridge.run_make_signature, {"pid": 4242, "addresses": [0x1000, 0x2000]})
    data = r["data"]
    assert data.get("code") is None, data
    assert data["pid"] == 4242 and data["verified"] is True
    assert data["candidates"], "expected candidates"
    top = data["candidates"][0]
    assert "??" in top["pattern"]
    assert top["scan_matches"] == 2
    # sorted best-first
    scores = [c["score"] for c in data["candidates"]]
    assert scores == sorted(scores, reverse=True)


def test_verify_false_skips_scan(monkeypatch):
    monkeypatch.setattr(gui_bridge, "_process_exists", lambda pid: True)

    class FakeReader:
        def read_bytes(self, addr, size):
            return (b"\x48\x8B\x05\x00\x90\x90\x90\x90" * 32)[:size]

        def close(self):
            pass

    class BoomScanner:
        def scan_all(self, pattern, **kw):
            raise AssertionError("verification scan must not run with verify=False")

    import core.stealth as stealth_mod
    import core.scanner as scanner_mod
    monkeypatch.setattr(stealth_mod, "StealthReader", lambda pid, config: FakeReader())
    monkeypatch.setattr(scanner_mod, "PatternScanner", lambda reader: BoomScanner())

    r = _capture(gui_bridge.run_make_signature,
                 {"pid": 4242, "addresses": [0x1000], "verify": False})
    data = r["data"]
    assert data.get("code") is None, data
    assert data["verified"] is False
    assert all(c["scan_matches"] == 0 for c in data["candidates"])


def test_generator_fast_path_scores_without_scan():
    gen = object.__new__(SignatureGenerator)

    class FakeReader:
        def read_bytes(self, addr, size):
            return (b"\x48\x8B\x05\x00\x90\x90\x90\x90" * 32)[:size]

    class BoomScanner:
        def scan_all(self, pattern, **kw):
            raise AssertionError("no scan on fast path")

    gen.reader = FakeReader()
    gen.scanner = BoomScanner()
    cands = gen.generate_from_addresses([0x1000], verify_matches=False)
    assert cands
    assert all(c.scan_matches == 0 and c.score > 0 for c in cands)


def test_protocol_allows_make_signature():
    assert "make_signature" in KNOWN_COMMANDS
    ok, _ = validate_command("make_signature", {"pid": 1, "addresses": [2]})
    assert ok
