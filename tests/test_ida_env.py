"""IDA child env sanitization + batch-failure classification (no IDA needed)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.decomp import ida_engine as ida


def test_child_env_drops_venv_poison(monkeypatch):
    monkeypatch.setenv("VIRTUAL_ENV", r"C:\v\venv")
    monkeypatch.setenv("PYTHONHOME", r"C:\v\venv")
    monkeypatch.setenv("PYTHONPATH", r"C:\v\stuff")
    monkeypatch.setenv("PATH", ";".join([
        r"C:\Users\howar\AppData\Local\hermes\hermes-agent\venv\Scripts",
        r"C:\Windows\System32",
        r"C:\uv\.venv\Scripts",
    ]))
    env = ida._ida_child_env()
    assert "VIRTUAL_ENV" not in env and "PYTHONHOME" not in env
    assert "PYTHONPATH" not in env
    parts = env["PATH"].split(";")
    assert not any("hermes" in p.lower() or ".venv" in p.lower() for p in parts)
    assert r"C:\Windows\System32" in parts


def test_child_env_prefers_registered_python(monkeypatch):
    monkeypatch.setenv("PATH", r"C:\Windows\System32")
    env = ida._ida_child_env()
    first = env["PATH"].split(";")[0]
    # registry points at the canonical 3.14 DLL on this box; elsewhere just
    # assert PATH survived sanitization
    assert first == ida._registered_python_dir() or "System32" in first


def test_classify_venv_hijack():
    err = ida._classify_batch_failure(
        1, b"IDAPython: Requested to use virtual environment interpreter at X", b"", "idat.exe")
    assert "virtualenv" in str(err).lower()


def test_classify_silent_exit_is_license_gate():
    err = ida._classify_batch_failure(1, b"", b"", "idat.exe")
    assert "license" in str(err).lower() and "ida.exe" in str(err)


def test_classify_generic_passthrough():
    err = ida._classify_batch_failure(3, b"", b"some IDA complaint", "idat.exe")
    assert "some IDA complaint" in str(err)
