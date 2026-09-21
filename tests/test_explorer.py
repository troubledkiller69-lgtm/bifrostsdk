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


class TestParseIij:
    def test_empty_and_invalid_payloads(self):
        assert rizin_engine.parse_iij(None) == []
        assert rizin_engine.parse_iij("not json") == []

    def test_imports_normalized(self):
        payload = json.dumps([
            {"ordinal": 1, "bind": "NONE", "type": "FUNC", "name": "CreateFileW",
             "libname": "KERNEL32.dll", "plt": 0x180001000},
            {"ordinal": 2, "type": "FUNC", "name": "", "libname": "X.dll"},
            "junk",
        ])
        out = rizin_engine.parse_iij(payload)
        assert out == [{"name": "CreateFileW", "lib": "KERNEL32.dll", "plt": 0x180001000}]


class TestParsePdfjCalls:
    def test_empty_and_invalid_payloads(self):
        assert rizin_engine.parse_pdfj_calls(None) == []
        assert rizin_engine.parse_pdfj_calls("") == []
        assert rizin_engine.parse_pdfj_calls("not json") == []

    def test_calls_extracted_sorted_unique(self):
        payload = json.dumps({"ops": [
            {"offset": 0x1000, "type": "CALL", "jump": 0x2000},
            {"offset": 0x1005, "type": "MOV", "jump": 0},
            {"offset": 0x100A, "type": "UCALL", "jump": 0x3000},
            {"offset": 0x100F, "type": "CALL", "jump": 0x2000},
            {"offset": 0x1014, "type": "CALL"},  # thunk, no target
            {"offset": 0x1019, "type": "JMP", "jump": 0x4000},
        ]})
        assert rizin_engine.parse_pdfj_calls(payload) == [0x2000, 0x3000]


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

    def _open_rizin_session(self, tmp_path):
        p = os.path.join(str(tmp_path), "mod.bin")
        with open(p, "wb") as f:
            f.write(b"\x90\xc3" * 0x800)
        runner = rizin_engine.FakeRunner()
        runner.responses["pdfj @ 0x140000100"] = json.dumps({"ops": [
            {"offset": 0x140000100, "type": "CALL", "jump": 0x140001000},
            {"offset": 0x140000105, "type": "RET"},
        ]})
        runner.responses["axtj @ 0x140000100"] = json.dumps([
            {"from": 0x140002000, "type": "CALL", "op": "caller"},
            {"from": 0x140002010, "type": "LEA", "op": "data"},
        ])
        session = rizin_engine.RizinSession(p, runner=runner)
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = {"file": p, "base": 0x140000000}
            analyzer.CURRENT["session"] = session
            analyzer.CURRENT["engine"] = "rizin-ghidra"
            analyzer.CURRENT["cache"] = {}
            analyzer.CURRENT["symbols"] = {"callee": 0x140001000, "caller": 0x140002000}
        return runner

    def test_callgraph_at_merges_calls_and_callers(self, tmp_path):
        runner = self._open_rizin_session(tmp_path)
        try:
            out = analyzer.callgraph_at(0x140000100)
            assert out.get("code") is None
            assert out["calls"] == [{"addr": 0x140001000, "name": "callee"}]
            # LEA xref excluded — callers are CALL only
            assert out["called_by"] == [{"from": 0x140002000, "name": "caller"}]
            assert runner.commands == ["pdfj @ 0x140000100", "axtj @ 0x140000100"]
        finally:
            self._clear()

    def test_callgraph_at_requires_rizin(self, tmp_path):
        self._open_raw_session(tmp_path)
        try:
            assert analyzer.callgraph_at(0x140000000)["code"] == "NO_RIZIN"
        finally:
            self._clear()

    def test_callgraph_bad_args(self):
        assert analyzer.callgraph_at(0)["code"] == "BAD_ARGS"


class TestSearchCallsites:
    def _open_search_session(self, tmp_path):
        p = os.path.join(str(tmp_path), "mod.bin")
        with open(p, "wb") as f:
            f.write(b"\x90" * 0x40 + b"SuperSecretPassword123" + b"\x90" * 0x40)
        runner = rizin_engine.FakeRunner()
        runner.responses["iij"] = json.dumps([
            {"name": "CreateFileW", "libname": "KERNEL32.dll", "plt": 0x140000500},
            {"name": "CloseHandle", "libname": "KERNEL32.dll", "plt": 0x140000510},
        ])
        runner.responses["axtj @ 0x140000500"] = json.dumps([
            {"from": 0x140000100, "type": "CALL", "op": "call CreateFileW"},
        ])
        session = rizin_engine.RizinSession(p, runner=runner)
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = {"file": p, "base": 0x140000000}
            analyzer.CURRENT["session"] = session
            analyzer.CURRENT["engine"] = "rizin-ghidra"
            analyzer.CURRENT["cache"] = {}
            analyzer.CURRENT["symbols"] = {"caller": 0x140000100}
        return runner

    def _clear(self):
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = None
            analyzer.CURRENT["session"] = None
            analyzer.CURRENT["engine"] = None
            analyzer.CURRENT["cache"] = {}
            analyzer.CURRENT["symbols"] = {}

    def test_search_finds_import_string_and_ref(self, tmp_path):
        self._open_search_session(tmp_path)
        try:
            out = analyzer.search_callsites("createfile")
            assert out.get("code") is None
            assert [i["name"] for i in out["imports"]] == ["CreateFileW"]
            assert out["references"][0]["from"] == 0x140000100
            assert out["references"][0]["from_name"] == "caller"
            out2 = analyzer.search_callsites("supersecret")
            assert any("SuperSecret" in s["text"] for s in out2["strings"])
        finally:
            self._clear()

    def test_search_bad_args(self):
        assert analyzer.search_callsites("")["code"] == "BAD_ARGS"
        assert analyzer.search_callsites("x" * 129)["code"] == "BAD_ARGS"
        assert analyzer.search_callsites("ok", cap=0)["code"] == "BAD_ARGS"

    def test_search_requires_rizin(self, tmp_path):
        p = os.path.join(str(tmp_path), "mod.bin")
        with open(p, "wb") as f:
            f.write(b"\x90" * 64)
        with analyzer.CURRENT["lock"]:
            analyzer.CURRENT["source"] = {"file": p, "base": 0x140000000}
            analyzer.CURRENT["session"] = None
            analyzer.CURRENT["engine"] = "iced-x86"
        try:
            assert analyzer.search_callsites("nop")["code"] == "NO_RIZIN"
        finally:
            self._clear()
