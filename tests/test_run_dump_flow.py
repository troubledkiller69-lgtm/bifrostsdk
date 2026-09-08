"""
run_dump end-to-end regression tests.

Guarantees the dump body is reachable past the attach step: a silent
restructure once stranded every line after attach inside an except block
(dead code), and the op "succeeded" in 0.0s with no engine logs, no result,
and no dump. These tests mock the reader + dumper and assert the full
signal chain: access event -> engine log -> DUMP COMPLETE -> result event.
"""
import core.memory
import engines.registry
import gui_bridge


class FakeProgress:
    classes_found = 7
    fields_found = 42
    elapsed = 1.5
    errors = []


class FakeDumper:
    ENGINE_NAME = "Fake"

    def __init__(self, *a, **kw):
        self.progress = FakeProgress()

    def set_progress_callback(self, cb):
        pass

    def dump_and_generate(self):
        return {"headers": [], "json": ""}


class FakeReader:
    def __init__(self, pid=0, **kw):
        self.attach_steps = [("open process", True, "ok")]

    @property
    def method_name(self):
        return "Direct (OpenProcess)"

    def list_modules(self):
        return []

    def close(self):
        pass


def _patch_env(emits, logs, monkeypatch, tmp_path, reader_cls):
    monkeypatch.setattr(gui_bridge, "PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr(gui_bridge, "_process_exists", lambda pid: True)
    monkeypatch.setattr(gui_bridge, "_log", lambda text, level="info": logs.append(text))
    monkeypatch.setattr(gui_bridge, "_progress", lambda *a, **k: None)
    monkeypatch.setattr(gui_bridge, "_op_result_error", lambda *a, **k: None)
    monkeypatch.setattr(gui_bridge, "_op_end", lambda *a, **k: None)
    monkeypatch.setattr(gui_bridge, "emit", lambda obj: emits.append(obj))
    monkeypatch.setattr(core.memory, "MemoryReader", reader_cls)
    monkeypatch.setattr(
        engines.registry,
        "create_dumper",
        lambda engine, reader, output_dir, **kw: FakeDumper(),
    )
    monkeypatch.setattr(engines.registry, "is_known_engine", lambda e: True)


def test_dump_runs_past_attach_and_emits_result(monkeypatch, tmp_path):
    emits, logs = [], []
    _patch_env(emits, logs, monkeypatch, tmp_path, FakeReader)

    gui_bridge.run_dump({
        "engine": "source",
        "pid": 20120,
        "name": "cs2.exe",
        "stealth": "auto",
        "force_discovery": True,
        "webhook": "",
    })

    assert any("Engine: source" in l for l in logs), f"engine log missing: {logs}"
    assert any("DUMP COMPLETE" in l for l in logs), f"complete log missing: {logs}"

    kinds = [e.get("type") for e in emits]
    assert "access" in kinds, f"no access event: {emits}"
    assert "result" in kinds, f"no result event: {emits}"

    access = next(e for e in emits if e.get("type") == "access")
    assert access["data"]["transport"] == "direct"
    assert access["data"]["requested"] == "auto"
    assert access["data"]["probed"] is True
    assert access["data"]["fallback"] is False

    result = next(e for e in emits if e.get("type") == "result")
    assert "error" not in result.get("data", {})
    assert result["data"]["classes"] == 7


def test_attach_failure_reports_access_and_error_result(monkeypatch, tmp_path):
    def exploding_reader(*a, **kw):
        raise RuntimeError("probe read failed at 0x7FFE0000")

    emits, logs = [], []
    _patch_env(emits, logs, monkeypatch, tmp_path, exploding_reader)

    gui_bridge.run_dump({
        "engine": "source",
        "pid": 1,
        "name": "dead.exe",
        "stealth": "auto",
        "force_discovery": True,
        "webhook": "",
    })

    assert not any("DUMP COMPLETE" in l for l in logs)

    access = next(e for e in emits if e.get("type") == "access")
    assert access["data"]["fallback"] is True
    assert any(not s["ok"] for s in access["data"]["steps"]), access

    result = next(e for e in emits if e.get("type") == "result")
    assert "error" in result.get("data", {})
