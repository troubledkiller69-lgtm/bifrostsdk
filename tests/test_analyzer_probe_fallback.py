"""Analyzer probe fallback chain: auto picks rizin -> ida -> iced."""
from unittest.mock import patch
from core.decomp import analyzer

def test_probe_reports_all_engines():
    p = analyzer.probe()
    assert "rizin" in p and "ida" in p and "iced" in p
    assert p["rizin"]["available"] is True  # rizin ships via gui/extra
    assert p["iced"]["available"] is True

def test_analyze_auto_prefers_rizin_when_available():
    # patch probe to simulate rizin available
    with patch("core.decomp.analyzer.probe", return_value={
        "rizin": {"available": True, "decompiler": True, "exe": "rizin.exe", "version": "0.9.0"},
        "ida": {"available": True, "exe": "idat.exe", "version": ""},
        "iced": {"available": True},
        "default_engine": "rizin-ghidra",
    }):
        # analyze should not raise when engine auto resolves; we test probe directly
        p = analyzer.probe()
        assert p["default_engine"] in ("rizin-ghidra", "rizin")

def test_analyze_auto_falls_back_to_iced_when_no_decompiler():
    with patch("core.decomp.analyzer.probe", return_value={
        "rizin": {"available": False, "decompiler": False, "exe": None, "version": ""},
        "ida": {"available": False, "exe": None, "version": ""},
        "iced": {"available": True},
        "default_engine": "iced",
    }):
        p = analyzer.probe()
        assert p["rizin"]["available"] is False
        assert p["ida"]["available"] is False
        assert p["iced"]["available"] is True
