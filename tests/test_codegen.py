"""Multi-target codegen: offsets preserved in C#, Python ctypes, Rust."""
import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.generator import SDKClass, SDKField, SDKPackage
from core.generator.emitters import (
    emit_all, emit_csharp, emit_python, emit_rust, package_from_dict,
)


def _pkg() -> SDKPackage:
    cls = SDKClass(name="AActor", full_name="/Script/Engine.Actor",
                   super_name="UObject", size=0x2C, package="Engine")
    cls.fields = [
        SDKField(name="bTick", type_name="BoolProperty", offset=0x08, size=1, bit_offset=3),
        SDKField(name="Health", type_name="FloatProperty", offset=0x10, size=4),
        SDKField(name="Tags", type_name="ArrayProperty", offset=0x14, size=8),
        SDKField(name="Owner", type_name="ObjectProperty", offset=0x1C, size=8),
        SDKField(name="Ids", type_name="IntProperty", offset=0x24, size=8, array_dim=2),
    ]
    return SDKPackage(name="Engine", classes=[cls],
                      enums=[{"name": "EMode", "members": [{"name": "Idle", "value": 0}, {"name": "Run", "value": 2}]}])


def test_offsets_in_all_targets():
    pkg = _pkg()
    for text in (emit_csharp(pkg), emit_python(pkg), emit_rust(pkg)):
        for off in ("0x0008", "0x0010", "0x0014", "0x001C", "0x0024"):
            assert off in text, f"{off} missing"
    assert "EMode" in emit_csharp(pkg) and "EMode" in emit_rust(pkg)


def test_python_output_is_loadable_and_exact(tmp_path=None):
    import tempfile
    pkg = _pkg()
    src = emit_python(pkg)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(src)
        path = f.name
    try:
        ns: dict = {}
        with open(path) as f:
            exec(compile(f.read(), path, "exec"), ns)
        AActor = ns["AActor"]
        assert ctypes.sizeof(AActor) == 0x2C
        offs = {n: getattr(AActor, n).offset for n, _ in AActor._fields_ if not n.startswith("_pad")}
        assert offs["Health"] == 0x10 and offs["Owner"] == 0x1C and offs["Ids"] == 0x24
        assert ns["EMode"].Run == 2
    finally:
        os.unlink(path)


def test_emit_all_writes_files(tmp_path):
    written = emit_all([_pkg()], str(tmp_path), targets=["csharp", "python", "rust"])
    assert set(written) == {"csharp", "python", "rust"}
    for p in written.values():
        assert os.path.getsize(p) > 200


def test_emit_all_rejects_unknown(tmp_path):
    try:
        emit_all([_pkg()], str(tmp_path), targets=["cobol"])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_package_from_dict():
    pkg = package_from_dict({"name": "Engine", "classes": [
        {"name": "A", "full_name": "A", "size": 8,
         "fields": [{"name": "X", "type_name": "IntProperty", "offset": 4, "size": 4}]}]})
    assert pkg.classes[0].fields[0].offset == 4
    assert "0x4" in emit_rust(pkg)
