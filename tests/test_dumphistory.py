"""Dump history archive/list/diff + IDA db-cache unit tests."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import dump_history
from core.decomp import ida_engine


def _offsets(classes):
    return {"_meta": {"engine": "test"},
            "offsets": {n: {"fields": f} for n, f in classes.items()}}


def _write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def test_archive_and_list(tmp_path):
    game = os.path.join(str(tmp_path), "output", "cs2")
    os.makedirs(game)
    _write(os.path.join(game, "offsets.json"), _offsets({
        "A": {"x": {"offset": "0x10", "size": 4, "type": "int"}}}))
    r = dump_history.archive_dump(game, engine="source")
    assert r["archived"] is True
    assert r["classes"] == 1 and r["fields"] == 1
    hist = dump_history.list_history(str(tmp_path))
    assert "cs2" in hist["games"]
    assert hist["games"]["cs2"][0]["engine"] == "source"


def test_archive_missing_is_honest(tmp_path):
    r = dump_history.archive_dump(str(tmp_path), engine="x")
    assert r["archived"] is False


def test_diff_detects_drift(tmp_path):
    old = os.path.join(str(tmp_path), "old")
    new = os.path.join(str(tmp_path), "new")
    os.makedirs(old)
    os.makedirs(new)
    _write(os.path.join(old, "offsets.json"), _offsets({
        "A": {"x": {"offset": "0x10", "size": 4, "type": "int"}},
        "Gone": {"y": {"offset": "0x0", "size": 4, "type": "int"}}}))
    _write(os.path.join(new, "offsets.json"), _offsets({
        "A": {"x": {"offset": "0x18", "size": 4, "type": "int"}},
        "Fresh": {"z": {"offset": "0x0", "size": 1, "type": "bool"}}}))
    out = dump_history.diff_snapshots(old, new)
    assert out.get("code") is None
    assert out["drift"] is True
    assert out["removed"] == ["Gone"] and out["added"] == ["Fresh"]
    assert "A" in out["changed"]
    assert out["changed_fields"] == 1


def test_diff_no_drift(tmp_path):
    d1 = os.path.join(str(tmp_path), "a")
    d2 = os.path.join(str(tmp_path), "b")
    os.makedirs(d1)
    os.makedirs(d2)
    data = _offsets({"A": {"x": {"offset": "0x10", "size": 4, "type": "int"}}})
    _write(os.path.join(d1, "offsets.json"), data)
    _write(os.path.join(d2, "offsets.json"), data)
    out = dump_history.diff_snapshots(d1, d2)
    assert out["drift"] is False and out["changed"] == {}


def test_diff_missing_snapshot(tmp_path):
    out = dump_history.diff_snapshots(str(tmp_path), str(tmp_path))
    assert out["code"] == "NO_SNAPSHOT"


def test_ida_fingerprint_and_slot(tmp_path):
    p = os.path.join(str(tmp_path), "x.dll")
    with open(p, "wb") as f:
        f.write(b"\x90" * 1024)
    fp = ida_engine._file_fingerprint(p)
    assert fp and "_" in fp
    slot = ida_engine._cache_slot(p, r"C:\x\idat.exe")
    assert slot and os.path.isdir(slot)


def test_ida_cache_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(ida_engine, "_ida_cache_dir", lambda: str(tmp_path))
    p = os.path.join(str(tmp_path), "game.dll")
    with open(p, "wb") as f:
        f.write(b"\xcc" * 512)
    slot = ida_engine._cache_slot(p, "idat.exe")
    # nothing cached yet
    assert ida_engine._restore_cached_idb(p, slot) is False
    # simulate IDA droppings next to the target
    for ext in (".idb", ".til"):
        with open(os.path.join(str(tmp_path), "game" + ext), "w") as f:
            f.write("db")
    before = ida_engine._snapshot_siblings(p)
    before.discard("game.idb")
    before.discard("game.til")
    ida_engine._store_idb_to_cache(p, slot, before)
    assert not os.path.exists(os.path.join(str(tmp_path), "game.idb"))
    # next run restores them
    assert ida_engine._restore_cached_idb(p, slot) is True
    assert os.path.isfile(os.path.join(str(tmp_path), "game.idb"))
