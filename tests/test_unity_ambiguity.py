"""
Unity Mono/IL2CPP profile ambiguity regression tests.

The 'unity' engine alias means Mono, which is wrong for IL2CPP titles
(Pixel Gun 3D, Rust...). _resolve_unity_ambiguity cross-checks the pick
against loaded module names so a wrong profile auto-corrects before
validation can fail.
"""
from gui_bridge import _resolve_unity_ambiguity


def test_mono_profile_with_gameassembly_switches_to_il2cpp():
    engine, note = _resolve_unity_ambiguity(
        "unity", {"gameassembly.dll", "unityplayer.dll", "kernel32.dll"})
    assert engine == "unity_il2cpp"
    assert "Auto-switched" in note


def test_legacy_unity_alias_behaves_like_mono_profile():
    engine, note = _resolve_unity_ambiguity(
        "unity", {"gameassembly.dll", "unityplayer.dll"})
    assert engine == "unity_il2cpp"
    assert note


def test_mono_profile_with_actual_mono_dll_untouched():
    engine, note = _resolve_unity_ambiguity(
        "unity_mono", {"mono.dll", "unityplayer.dll"})
    assert engine == "unity_mono"
    assert note == ""


def test_il2cpp_profile_with_mono_only_switches_back():
    engine, note = _resolve_unity_ambiguity(
        "unity_il2cpp", {"mono-2.0-bdwgc.dll", "unityplayer.dll"})
    assert engine == "unity_mono"
    assert "Auto-switched" in note


def test_il2cpp_profile_with_gameassembly_untouched():
    engine, note = _resolve_unity_ambiguity(
        "unity_il2cpp", {"gameassembly.dll", "unityplayer.dll"})
    assert engine == "unity_il2cpp"
    assert note == ""


def test_unrelated_engine_untouched():
    engine, note = _resolve_unity_ambiguity("source", {"client.dll"})
    assert engine == "source"
    assert note == ""


def test_empty_module_scan_does_not_second_guess():
    engine, note = _resolve_unity_ambiguity("unity_mono", set())
    assert engine == "unity_mono"
    assert note == ""
