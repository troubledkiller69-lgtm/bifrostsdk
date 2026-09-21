"""sigpacks: validate + disk-mode rescan (no game needed)."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.sigpacks import FileReader, rescan_pack, resolve_entry, validate_pack
from core.scanner import PatternScanner

BASE = 0x140000000
AT = 0x100  # file offset of the test instruction
DISP = 0x200
INSTR = b"\x48\x8B\x0D" + struct.pack("<i", DISP) + b"\x90\x90"


def _blob():
    buf = bytearray(b"\xCC" * 0x400)
    buf[AT:AT + len(INSTR)] = INSTR
    buf[0x300:0x302] = b"\x90\x90"
    return bytes(buf)


def _pack(entries):
    return {"name": "test", "entries": entries}


def test_validate_rejects_junk():
    assert validate_pack({})[0] is False
    assert validate_pack({"entries": []})[0] is False
    assert validate_pack(_pack([{"name": "x"}]))[0] is False
    assert validate_pack(_pack([{"name": "x", "pattern": "ZZ"}]))[0] is False
    assert validate_pack(_pack([{"name": "x", "pattern": "90", "rip": {"offset": 3, "insn_len": 5}}]))[0] is False
    assert validate_pack(_pack([{"name": "x", "pattern": "90", "expect": "sometimes"}]))[0] is False
    ok, _ = validate_pack(_pack([{"name": "x", "pattern": "48 ?? 0D", "rip": {"offset": 2, "insn_len": 7}}]))
    assert ok is True


def test_disk_ok_rip(tmp_path):
    p = tmp_path / "t.bin"
    p.write_bytes(_blob())
    out = rescan_pack(
        _pack([{"name": "Lea", "pattern": "48 8B 0D ?? ?? ?? ??",
                "rip": {"offset": 3, "insn_len": 7}, "expect": "unique"}]),
        file=str(p), image_base=BASE)
    assert out.get("code") is None, out
    assert out["healthy"] == 1 and out["broken"] == 0
    r = out["results"][0]
    assert r["status"] == "ok"
    assert r["resolved"] == BASE + AT + 7 + DISP


def test_disk_broken_ambiguous_any(tmp_path):
    p = tmp_path / "t.bin"
    p.write_bytes(_blob())
    out = rescan_pack(
        _pack([
            {"name": "Gone", "pattern": "FF FF FF FF 11 22", "expect": "unique"},
            {"name": "Twice", "pattern": "90 90", "expect": "unique"},
            {"name": "Multi", "pattern": "90 90", "expect": "any"},
        ]),
        file=str(p), image_base=BASE)
    assert out.get("code") is None, out
    by_name = {r["name"]: r for r in out["results"]}
    assert by_name["Gone"]["status"] == "broken"
    assert by_name["Twice"]["status"] == "ambiguous"
    assert len(by_name["Twice"]["hits"]) >= 2
    assert by_name["Multi"]["status"] == "ok"


def test_needs_exactly_one_source(tmp_path):
    pack = _pack([{"name": "x", "pattern": "90"}])
    assert rescan_pack(pack)["code"] == "BAD_ARGS"
    assert rescan_pack(pack, pid=1234, file="x")["code"] == "BAD_ARGS"
    assert rescan_pack(pack, file="nope.bin")["code"] == "NO_FILE"
    assert rescan_pack({"entries": []}, file="x")["code"] == "BAD_PACK"


def test_file_reader_bounds(tmp_path):
    p = tmp_path / "t.bin"
    p.write_bytes(b"\x90" * 16)
    r = FileReader(str(p), image_base=BASE)
    assert r.read_bytes(BASE, 4) == b"\x90" * 4
    assert r.module_base() == BASE and r.module_size() == 16
    try:
        r.read_bytes(BASE + 14, 4)
        assert False, "expected overrun"
    except RuntimeError:
        pass
    # rip resolve over file bytes
    p2 = tmp_path / "t2.bin"
    p2.write_bytes(_blob())
    r2 = FileReader(str(p2), image_base=BASE)
    assert r2.resolve_rip_relative(BASE + AT, 3, 7) == BASE + AT + 7 + DISP


def test_resolve_entry_scan_error():
    class BoomScanner:
        reader = FileReader.__new__(FileReader)
    out = resolve_entry(BoomScanner(), {"name": "x", "pattern": "90"}, module="m")
    assert out["status"] == "error"


def _bridge(fn, args):
    import gui_bridge
    out = []
    orig = gui_bridge.emit
    gui_bridge.emit = out.append
    try:
        fn(args)
    finally:
        gui_bridge.emit = orig
    assert out
    return out[-1]["data"]


def test_bridge_disk_mode(tmp_path):
    import gui_bridge
    p = tmp_path / "t.bin"
    p.write_bytes(_blob())
    data = _bridge(gui_bridge.run_rescan_signatures, {
        "pack": _pack([{"name": "Lea", "pattern": "48 8B 0D ?? ?? ?? ??",
                        "rip": {"offset": 3, "insn_len": 7}}]),
        "file": str(p), "image_base": BASE})
    assert data.get("code") is None, data
    assert data["healthy"] == 1
    assert data["results"][0]["resolved"] == BASE + AT + 7 + DISP


def test_bridge_validation(monkeypatch):
    import gui_bridge
    assert _bridge(gui_bridge.run_rescan_signatures, {"pack": []})["code"] == "BAD_ARGS"
    pack = _pack([{"name": "x", "pattern": "90"}])
    assert _bridge(gui_bridge.run_rescan_signatures, {"pack": pack})["code"] == "BAD_ARGS"
    assert _bridge(gui_bridge.run_rescan_signatures,
                    {"pack": pack, "pid": 1, "file": "x"})["code"] == "BAD_ARGS"
    assert _bridge(gui_bridge.run_rescan_signatures,
                    {"pack": pack, "file": "nope.bin"})["code"] == "NO_FILE"
    monkeypatch.setattr(gui_bridge, "_process_exists", lambda pid: True)
    assert _bridge(gui_bridge.run_rescan_signatures,
                    {"pack": {"entries": []}, "pid": 4242})["code"] == "BAD_PACK"
