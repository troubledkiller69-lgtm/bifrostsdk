"""Decompiler/analyzer engine tests.

None of these require a real rizin install: parsing, fallback discovery,
module dumping and the iced engine are exercised against fakes. The rizin
path only needs rzpipe's own machinery, which this suite deliberately avoids
so CI without a provisioned rizin stays meaningful.
"""

import json
import os
import tempfile

import pytest

from core.decomp import analyzer, disasm, module_io, rizin_engine


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

class TestParseAflj:
    def test_empty_and_none_payloads(self):
        assert rizin_engine.parse_aflj(None) == []
        assert rizin_engine.parse_aflj("") == []

    def test_invalid_json_returns_empty(self):
        assert rizin_engine.parse_aflj("not json at all") == []

    def test_list_of_dicts_normalized(self):
        payload = json.dumps([
            {"offset": 0x140001000, "size": 128, "name": "f1", "realname": "sub_140001000"},
            {"offset": 0x140002000, "size": 64, "name": "f2"},
            {"offset": 0, "size": 32, "name": "bad_zero_addr"},
            "not a dict",
        ])
        result = rizin_engine.parse_aflj(payload)
        assert len(result) == 2
        assert result[0] == {"addr": 0x140001000, "size": 128, "name": "sub_140001000"}
        assert result[1]["name"] == "f2"

    def test_payload_object_form(self):
        result = rizin_engine.parse_aflj([{"offset": 0x1000, "size": 4}])
        assert result == [{"addr": 0x1000, "size": 4, "name": ""}]


class TestParsePdgj:
    def test_code_extraction(self):
        payload = json.dumps({"code": "int f(void) { return 1; }", "other": 1})
        assert rizin_engine.parse_pdgj(payload)["code"].startswith("int f")

    def test_garbage_never_raises(self):
        for bad in (None, "", "{{{", 42, {"code": 123}):
            assert rizin_engine.parse_pdgj(bad) == {"code": ""}


# ---------------------------------------------------------------------------
# Engine discovery
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_no_rizin_means_no_binary(self, monkeypatch):
        monkeypatch.setenv("BIFROST_RIZIN_DIR", "C:\\definitely\\not\\here")
        assert rizin_engine.find_rizin_dir() is None
        assert rizin_engine.rizin_binary() is None
        assert rizin_engine.rizin_version() == ""

    def test_env_dir_wins_when_binary_exists(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "rizin.exe").write_bytes(b"MZ")
        monkeypatch.setenv("BIFROST_RIZIN_DIR", str(tmp_path))
        assert rizin_engine.find_rizin_dir() == str(tmp_path)
        assert rizin_engine.rizin_binary() == str(bin_dir / "rizin.exe")


# ---------------------------------------------------------------------------
# Fake-runner session (command sequence assertions, no rizin binary)
# ---------------------------------------------------------------------------

class TestRizinSessionFakeRunner:
    def _session(self):
        runner = rizin_engine.FakeRunner()
        session = rizin_engine.RizinSession("C:\\fake\\mod.dll", runner=runner)
        return session, runner

    def test_open_and_command_flow(self):
        session, runner = self._session()
        runner.responses["aflj"] = "[]"
        session.open()  # runner seam: no pipe created
        session.analyze()
        assert session.functions() == []
        assert runner.commands == ["aaa", "aflj"]

    def test_decompiler_probe_detects_missing_plugin(self):
        session, runner = self._session()
        runner.responses["pdgs"] = "Unknown command: 'pdgs'\n"
        assert session.decompiler_available() is False

    def test_decompiler_probe_ok_on_output(self):
        session, runner = self._session()
        runner.responses["pdgs"] = "x86:LE:32:default\n"
        assert session.decompiler_available() is True

    def test_decompile_routes_pdgj(self):
        session, runner = self._session()
        runner.responses["pdgj @ 0x140001000"] = json.dumps({"code": "int x() { return 0; }"})
        result = session.decompile(0x140001000)
        assert result["addr"] == 0x140001000
        assert "return 0" in result["code"]

    def test_real_session_without_binary_raises(self):
        session = rizin_engine.RizinSession("C:\\fake\\mod.dll")
        with pytest.raises(RuntimeError, match="not provisioned"):
            session.open()


# ---------------------------------------------------------------------------
# Module image dumper
# ---------------------------------------------------------------------------

class MockReader:
    """Reader with a poisoned region + a module table."""

    def __init__(self, size=0x10000, poison_at=None):
        self.base = 0x140000000
        self.size = size
        self.poison_at = poison_at or set()

    def module_base(self, name):
        return self.base

    def module_size(self, name):
        return self.size

    def list_modules(self):
        return [{"name": "game.dll", "base": self.base, "size": self.size}]

    def read_bytes(self, addr, size):
        if addr in self.poison_at:
            raise OSError("guard page")
        return b"X" * size

    def close(self):
        pass


class TestModuleDump:
    def test_full_dump(self, tmp_path):
        target = os.path.join(str(tmp_path), "game.bin")
        stats = module_io.dump_module(MockReader(), "game.dll", target)
        assert stats["complete"] is True
        assert stats["bytes_read"] == 0x10000
        assert stats["missing_chunks"] == 0
        assert os.path.getsize(target) == 0x10000

    def test_poisoned_region_zero_filled_and_counted(self, tmp_path):
        target = os.path.join(str(tmp_path), "game.bin")
        stats = module_io.dump_module(MockReader(poison_at={0x140000000}), "game.dll", target)
        assert stats["complete"] is False
        assert stats["missing_chunks"] == 1
        with open(target, "rb") as f:
            assert f.read(0x4000) == b"\x00" * 0x4000

    def test_cancel_aborts_partial(self, tmp_path):
        target = os.path.join(str(tmp_path), "game.bin")

        def cancel():
            return True  # stop at the first chunk boundary

        stats = module_io.dump_module(
            MockReader(size=0x20000), "game.dll", target, cancel_check=cancel
        )
        assert stats["bytes_read"] == 0x4000
        assert stats["complete"] is False

    def test_resolve_module_image_via_list_fallback(self, tmp_path):
        class NoSizeReader(MockReader):
            def module_size(self, name):
                raise RuntimeError("nope")

        target = os.path.join(str(tmp_path), "game.bin")
        stats = module_io.dump_module(NoSizeReader(), "game.dll", target)
        assert stats["base"] == 0x140000000
        assert stats["size"] == 0x10000
        assert stats["complete"] is True


# ---------------------------------------------------------------------------
# iced-x86 fallback
# ---------------------------------------------------------------------------

class TestIcedFallback:
    def test_nop_sled_decodes(self):
        data = b"\x90\x90\x90" + b"\xcc"
        lines = disasm.disasm_region(data, 0x1000, "x86_64")
        assert len(lines) == 4
        assert lines[0]["address"] == 0x1000
        assert lines[0]["text"].lower().startswith("nop")

    def test_ret_is_recognized(self):
        lines = disasm.disasm_region(b"\xc3", 0x140000000)
        assert lines[0]["text"].lower() == "ret"
        assert lines[0]["bytes"] == "c3"

    def test_unsupported_arch_raises(self):
        with pytest.raises(disasm.IcedError):
            disasm.disasm_region(b"\x90", 0, arch="m68k")

    def test_file_window_respects_base_offset(self, tmp_path):
        p = os.path.join(str(tmp_path), "blob.bin")
        with open(p, "wb") as f:
            f.write(b"\x00" * 0x10 + b"\xc3")
        result = disasm.disasm_file(p, offset=0x10, file_base=0x140000000)
        assert result["lines"][0]["address"] == 0x140000010

    def test_bad_window_args(self, tmp_path):
        p = os.path.join(str(tmp_path), "blob.bin")
        with open(p, "wb") as f:
            f.write(b"\xc3")
        with pytest.raises(disasm.IcedError):
            disasm.disasm_file(p, size=0)  # size must be 1+
        with pytest.raises(disasm.IcedError):
            disasm.disasm_file(p, offset=-1)


# ---------------------------------------------------------------------------
# Analyzer orchestration
# ---------------------------------------------------------------------------

class CollectingSink(analyzer.LogSink):
    def __init__(self):
        super().__init__()
        self.logs = []
        self.stages = []
        self._cancelled = False

    def log(self, text, level="info"):
        self.logs.append((level, text))

    def progress(self, stage, pct):
        self.stages.append((stage, pct))

    def cancelled(self):
        return self._cancelled


class TestAnalyzer:
    def _file(self, tmp_path):
        p = os.path.join(str(tmp_path), "payload.bin")
        with open(p, "wb") as f:
            f.write(b"\x90\xc3" * 512)
        return p

    def test_iced_forced_without_rizin(self, tmp_path, monkeypatch):
        monkeypatch.delenv("BIFROST_RIZIN_DIR", raising=False)
        sink = CollectingSink()
        result = analyzer.analyze(
            {"type": "file", "path": self._file(tmp_path), "engine": "iced"}, sink
        )
        assert result["engine"] == "iced-x86"
        assert result["decompiler"] is False
        assert result["session"] is False
        assert result["functions"] == []
        assert result["warnings"]

    def test_auto_falls_back_when_rizin_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("BIFROST_RIZIN_DIR", "C:\\no\\such\\dir")
        sink = CollectingSink()
        result = analyzer.analyze(
            {"type": "file", "path": self._file(tmp_path), "engine": "auto"}, sink
        )
        assert result["engine"] == "iced-x86"
        assert any("provision" in text for _, text in sink.logs)

    def test_unknown_source_type_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown source type"):
            analyzer.analyze({"type": "carrier-pigeon"}, CollectingSink())

    def test_missing_file_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="File not found"):
            analyzer.analyze(
                {"type": "file", "path": os.path.join(str(tmp_path), "gone.bin")},
                CollectingSink(),
            )

    def test_decompile_fn_without_session(self):
        result = analyzer.decompile_fn(0x140001000)
        assert result["code"] == "NO_SESSION"
        assert result["error"]

    def test_decompile_fn_rejects_bad_addr(self):
        result = analyzer.decompile_fn(0)
        assert result["code"] == "BAD_ARGS"

    def test_module_source_requires_reader(self, tmp_path):
        sink = CollectingSink()
        with pytest.raises(ValueError, match="requires an attached reader"):
            analyzer.analyze({"type": "module", "module": "game.dll"}, sink)

    def test_probe_shapes(self, monkeypatch):
        monkeypatch.setenv("BIFROST_RIZIN_DIR", "C:\\no\\such\\dir")
        probe = analyzer.probe()
        assert probe["rizin"]["available"] is False
        assert probe["iced"]["available"] is True
        assert probe["default_engine"] == "iced-x86"

    def test_close_session_is_idempotent(self):
        assert analyzer.close_session() is None
        assert analyzer.close_session() is None
