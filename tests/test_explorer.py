"""Address explorer backend tests (image mapping + hexdump/disasm/xrefs).

Hexdump and disasm_at are pure file reads + iced decode — no rizin needed.
xrefs_at follows the rizin session seam like decompile_fn does. Image
mapping covers the two supported shapes: raw dumps (base) and PEs (sections
via pefile).
"""

import json
import os

import pytest

from core.decomp import analyzer, image_map, rizin_engine


class TestParseAxtj:
    def test_empty_and_invalid_payloads(self):
        assert rizin_engine.parse_axtj(None) == []
        assert rizin_engine.parse_axtj("") == []
        assert rizin_engine.parse_axtj("not json") == []

    def test_entries_normalized_and_sorted(self):
        payload = json.dumps([
            {"from": 0x180004000, "type": "CALL", "op": "sym.foo"},
            {"from": 0x180003000, "type": "LEA", "op": "str.bar"},
        ])
        out = rizin_engine.parse_axtj(payload)
        assert [x["from"] for x in out] == [0x180003000, 0x180004000]
        assert out[0]["type"] == "LEA"
        assert out[1]["op"] == "sym.foo"

    def test_junk_entries_skipped(self):
        payload = json.dumps([{"from": "not-an-int"}, {"type": "CALL"}, 42])
        assert rizin_engine.parse_axtj(payload) == []


class TestImageMapRaw:
    def test_raw_dump_mapping(self, tmp_path):
        p = os.path.join(str(tmp_path), "mod.bin")
        with open(p, "wb") as f:
            f.write(b"\x00" * 0x1000)
        win = image_map.va_to_window(p, 0x140000000, 0x140000100, 32)
        assert win["ok"] is True
        assert win["offset"] == 0x100
        assert win["arch"] == "x86_64"

    def test_raw_out_of_bounds(self, tmp_path):
        p = os.path.join(str(tmp_path), "mod.bin")
        with open(p, "wb") as f:
            f.write(b"\x00" * 0x1000)
        win = image_map.va_to_window(p, 0x140000000, 0x140001100, 32)
        assert win["ok"] is False
        assert "outside" in win["error"]

    def test_non_pe_without_base_rejected(self, tmp_path):
        p = os.path.join(str(tmp_path), "junk.txt")
        with open(p, "wb") as f:
            f.write(b"hello world, definitely not a PE" * 4)
        win = image_map.va_to_window(p, None, 0x400000, 16)
        assert win["ok"] is False


class TestAnalyzerExplorer:
    def _open_raw_session(self, tmp_path):
        """Seed CURRENT with a raw image: 0x1F0 bytes at base 0x140000000."""
        p = os.path.join(str(tmp_path), "mod.bin")
        # nop sled + ret + int3s: clean decode head
        data = b"\x90" * 0x100 + b"\xc3" + b"\xcc" * 0xEF
        with open(p, "wb") as f:
            f.write(data)
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = {"file": p, "base": 0x140000000}
            analyzer.CURRENT["session"] = None
            analyzer.CURRENT["engine"] = "iced-x86"
            analyzer.CURRENT["cache"] = {}
        return p

    def _clear(self):
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = None
            analyzer.CURRENT["session"] = None
            analyzer.CURRENT["engine"] = None
            analyzer.CURRENT["cache"] = {}

    def test_hexdump_at_rows(self, tmp_path):
        self._open_raw_session(tmp_path)
        try:
            out = analyzer.hexdump_at(0x140000000, size=48)
            assert out.get("code") is None
            assert len(out["rows"]) == 3
            assert out["rows"][0]["addr"] == 0x140000000
            assert out["rows"][0]["hex"].startswith("90 90 90 90")
            assert out["rows"][2]["ascii"].count(".") >= 0
        finally:
            self._clear()

    def test_hexdump_at_bounds(self, tmp_path):
        self._open_raw_session(tmp_path)
        try:
            out = analyzer.hexdump_at(0x140000100, size=512)  # runs past EOF (0x1F0)
            assert out.get("code") is None
            assert 0 < out["size"] <= 0x100
            assert len(out["rows"]) * 16 >= out["size"]
        finally:
            self._clear()

    def test_disasm_at_lines(self, tmp_path):
        self._open_raw_session(tmp_path)
        try:
            out = analyzer.disasm_at(0x1400000F8, size=64)  # window covers the ret at +8
            assert out.get("code") is None
            assert out["lines"][0]["address"] == 0x1400000F8
            assert out["lines"][0]["text"].lower().startswith("nop")
            assert any(l["text"].lower() == "ret" for l in out["lines"])
        finally:
            self._clear()

    def test_no_session_errors(self):
        out = analyzer.hexdump_at(0x140000000)
        assert out["code"] == "NO_SESSION"
        out = analyzer.disasm_at(0x140000000)
        assert out["code"] == "NO_SESSION"
        out = analyzer.xrefs_at(0x140000000)
        assert out["code"] == "NO_SESSION"

    def test_bad_args(self):
        assert analyzer.hexdump_at(0, 256)["code"] == "BAD_ARGS"
        assert analyzer.disasm_at(0x100, 0xFFFF)["code"] == "BAD_ARGS"

    def test_xrefs_at_requires_rizin_engine(self, tmp_path):
        self._open_raw_session(tmp_path)
        try:
            out = analyzer.xrefs_at(0x140000000)
            assert out["code"] == "NO_RIZIN"
        finally:
            self._clear()

    def test_xrefs_at_routes_through_session(self, tmp_path, monkeypatch):
        p = os.path.join(str(tmp_path), "mod.bin")
        with open(p, "wb") as f:
            f.write(b"\x90\xc3" * 0x800)
        runner = rizin_engine.FakeRunner()
        runner.responses["axtj @ 0x140000100"] = json.dumps(
            [{"from": 0x140001000, "type": "CALL", "op": "fcn.140001000"}]
        )
        session = rizin_engine.RizinSession(p, runner=runner)
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = {"file": p, "base": 0x140000000}
            analyzer.CURRENT["session"] = session
            analyzer.CURRENT["engine"] = "rizin-ghidra"
            analyzer.CURRENT["cache"] = {}
        try:
            out = analyzer.xrefs_at(0x140000100)
            assert out.get("code") is None
            assert out["xrefs"][0]["from"] == 0x140001000
            assert out["xrefs"][0]["type"] == "CALL"
            assert runner.commands == ["axtj @ 0x140000100"]
        finally:
            self._clear()
