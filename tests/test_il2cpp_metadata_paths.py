"""
Disk metadata search regression tests for the IL2CPP dumper.

The old code only searched self._game_dir, which run_dump never sets —
the canonical location is next to the target exe, so every dump fell
straight to the memory scan. Verify candidate discovery, depth cap and
canonical-layout ordering.
"""
import os

from engines.unity.il2cpp import IL2CPPDumper
from engines.unity.structs import IL2CPPConfig


def _make_dumper(game_dir=None):
    dumper = IL2CPPDumper.__new__(IL2CPPDumper)
    dumper.config = IL2CPPConfig()
    dumper._game_dir = game_dir
    dumper._guess_game_dir = lambda: None
    return dumper


def test_finds_metadata_in_canonical_layout(tmp_path):
    meta_dir = tmp_path / "Game_Data" / "il2cpp_data" / "Metadata"
    meta_dir.mkdir(parents=True)
    meta_file = meta_dir / "global-metadata.dat"
    meta_file.write_bytes(b"\xAF\x1B\xB1\xFA")

    dumper = _make_dumper(game_dir=str(tmp_path))
    paths = dumper._find_metadata_paths()

    assert paths == [str(meta_file)]


def test_canonical_layout_hits_sort_first(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    other_file = other / "global-metadata.dat"
    other_file.write_bytes(b"x")

    meta_dir = tmp_path / "Game_Data" / "il2cpp_data" / "Metadata"
    meta_dir.mkdir(parents=True)
    canonical = meta_dir / "global-metadata.dat"
    canonical.write_bytes(b"y")

    dumper = _make_dumper(game_dir=str(tmp_path))
    paths = dumper._find_metadata_paths()

    assert len(paths) == 2
    assert "il2cpp_data" in paths[0]
    assert paths[1] == str(other_file)


def test_depth_cap_skips_deep_nesting(tmp_path):
    deep = tmp_path
    for _ in range(10):
        deep = deep / "sub"
    deep.mkdir(parents=True)
    deep_file = deep / "global-metadata.dat"
    deep_file.write_bytes(b"x")

    dumper = _make_dumper(game_dir=str(tmp_path))
    assert dumper._find_metadata_paths() == []


def test_no_game_dir_and_no_guess_returns_empty(tmp_path):
    dumper = _make_dumper(game_dir=None)
    assert dumper._find_metadata_paths() == []


def test_no_duplicates_across_overlapping_roots(tmp_path):
    meta_dir = tmp_path / "il2cpp_data" / "Metadata"
    meta_dir.mkdir(parents=True)
    meta_file = meta_dir / "global-metadata.dat"
    meta_file.write_bytes(b"\xAF\x1B\xB1\xFA")

    dumper = IL2CPPDumper.__new__(IL2CPPDumper)
    dumper.config = IL2CPPConfig()
    dumper._game_dir = str(tmp_path)
    dumper._guess_game_dir = lambda: str(tmp_path)  # same root twice

    paths = dumper._find_metadata_paths()
    assert len(paths) == 1
    assert str(meta_file) in paths
