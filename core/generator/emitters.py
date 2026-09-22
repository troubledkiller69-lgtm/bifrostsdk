"""
BIFROST SDK — multi-target SDK emitters (C# / Python ctypes / Rust).

Renders the same SDKPackage model used by SDKGenerator (C++ headers) into
languages cheat devs actually consume: C# for external overlays/trainers,
Python ctypes for scripting/prototyping, Rust for modern internals.

Every emitter preserves exact field offsets with explicit padding so the
generated layouts are binary-identical to the C++ output. Pointer-sized
UE references (ObjectProperty/ClassProperty/StructProperty/...) become the
target language's pointer word — never a guessed struct expansion.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from . import SDKClass, SDKField, SDKPackage


# ---------------------------------------------------------------------------
# Shared layout math (mirrors SDKGenerator.generate_header gap logic)
# ---------------------------------------------------------------------------

def _sorted_fields(cls: SDKClass) -> list[SDKField]:
    return sorted(cls.fields, key=lambda f: f.offset)


def _layout(cls: SDKClass) -> list[tuple]:
    """Flatten a class into ('pad', offset, size) / ('field', SDKField) ops."""
    ops: list[tuple] = []
    prev_end = 0
    for fld in _sorted_fields(cls):
        if fld.offset > prev_end:
            ops.append(("pad", prev_end, fld.offset - prev_end))
        ops.append(("field", fld))
        prev_end = max(prev_end, fld.offset + fld.size)
    if prev_end < cls.size:
        ops.append(("pad", prev_end, cls.size - prev_end))
    return ops


def _pad_name(offset: int) -> str:
    return f"_pad_0x{offset:04X}"


def _safe_ident(name: str) -> str:
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in name)
    if out and out[0].isdigit():
        out = "_" + out
    return out or "_unnamed"


def package_from_dict(d: dict) -> SDKPackage:
    """Coerce a plain-dict package (bridge/JSON shape) into an SDKPackage."""
    pkg = SDKPackage(
        name=str(d.get("name", "Unknown")),
        enums=list(d.get("enums", []) or []),
    )
    for c in d.get("classes", []) or []:
        cls = SDKClass(
            name=str(c.get("name", "Unknown")),
            full_name=str(c.get("full_name", c.get("name", "Unknown"))),
            super_name=str(c.get("super_name", "") or ""),
            size=int(c.get("size", 0) or 0),
            package=str(c.get("package", "") or ""),
        )
        for f in c.get("fields", []) or []:
            cls.fields.append(SDKField(
                name=str(f.get("name", "field")),
                type_name=str(f.get("type_name", f.get("type", "uint8"))),
                offset=int(f.get("offset", 0) or 0),
                size=int(f.get("size", 1) or 1),
                array_dim=int(f.get("array_dim", 1) or 1),
                bit_offset=int(f.get("bit_offset", -1)),
                comment=str(f.get("comment", "") or ""),
            ))
        pkg.classes.append(cls)
    return pkg


# ---------------------------------------------------------------------------
# Per-language primitive maps (UE property name -> target primitive)
# ---------------------------------------------------------------------------

_PTR_TYPES = {
    "ObjectProperty", "ClassProperty", "WeakObjectProperty",
    "LazyObjectProperty", "SoftObjectProperty", "StructProperty",
    "InterfaceProperty", "DelegateProperty", "MulticastDelegateProperty",
}

_CS_MAP = {
    "BoolProperty": "bool", "ByteProperty": "byte", "Int8Property": "sbyte",
    "Int16Property": "short", "UInt16Property": "ushort",
    "IntProperty": "int", "UInt32Property": "uint",
    "Int64Property": "long", "UInt64Property": "ulong",
    "FloatProperty": "float", "DoubleProperty": "double",
    "NameProperty": "FName", "StrProperty": "FString", "TextProperty": "FText",
    "ArrayProperty": "TArray", "MapProperty": "TMap", "SetProperty": "TSet",
    "EnumProperty": "byte",
}

_PY_MAP = {
    "BoolProperty": "c_bool", "ByteProperty": "c_ubyte", "Int8Property": "c_int8",
    "Int16Property": "c_int16", "UInt16Property": "c_uint16",
    "IntProperty": "c_int32", "UInt32Property": "c_uint32",
    "Int64Property": "c_int64", "UInt64Property": "c_uint64",
    "FloatProperty": "c_float", "DoubleProperty": "c_double",
    "EnumProperty": "c_ubyte",
}

_RS_MAP = {
    "BoolProperty": "bool", "ByteProperty": "u8", "Int8Property": "i8",
    "Int16Property": "i16", "UInt16Property": "u16",
    "IntProperty": "i32", "UInt32Property": "u32",
    "Int64Property": "i64", "UInt64Property": "u64",
    "FloatProperty": "f32", "DoubleProperty": "f64",
    "EnumProperty": "u8",
}


def _stamp(engine: str) -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# C#
# ---------------------------------------------------------------------------

def emit_csharp(pkg: SDKPackage, engine_name: str = "Unknown") -> str:
    L: list[str] = [
        "// BIFROST SDK — Auto-generated C# SDK",
        f"// Package: {pkg.name}  |  Engine: {engine_name}  |  {_stamp(engine_name)}",
        "// LayoutKind.Explicit keeps every field at its dumped offset.",
        "using System;",
        "using System.Runtime.InteropServices;",
        "",
        "namespace Bifrost.SDK",
        "{",
    ]
    for enum_data in pkg.enums:
        ename = _safe_ident(enum_data.get("name", "UnknownEnum"))
        L.append(f"    public enum {ename} : byte")
        L.append("    {")
        for m in enum_data.get("members", []):
            L.append(f"        {_safe_ident(m['name'])} = {m['value']},")
        L.append("    }")
        L.append("")

    for cls in pkg.classes:
        cname = _safe_ident(cls.name)
        L.append(f"    // {cls.full_name} — Size: 0x{cls.size:04X}")
        L.append(f"    [StructLayout(LayoutKind.Explicit, Size = 0x{cls.size:X})]")
        L.append(f"    public unsafe struct {cname}")
        L.append("    {")
        for op in _layout(cls):
            if op[0] == "pad":
                _, off, size = op
                L.append(f"        [FieldOffset(0x{off:X})] public fixed byte {_pad_name(off)}[{size}]; // 0x{off:04X}")
                continue
            fld = op[1]
            fname = _safe_ident(fld.name)
            t = fld.type_name
            if t in _PTR_TYPES:
                cs_t = "nint"
            else:
                cs_t = _CS_MAP.get(t, "byte")
            comment = f" // 0x{fld.offset:04X}"
            if fld.bit_offset >= 0:
                comment += f" (Bit: {fld.bit_offset})"
                L.append(f"        [FieldOffset(0x{fld.offset:X})] public byte {fname};{comment}")
            elif fld.array_dim > 1:
                total = fld.size
                L.append(f"        [FieldOffset(0x{fld.offset:X})] public fixed byte {fname}[{total}];{comment} // {cs_t}[{fld.array_dim}]")
            else:
                L.append(f"        [FieldOffset(0x{fld.offset:X})] public {cs_t} {fname};{comment}")
        L.append("    }")
        L.append("")
    L.append("}")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Python ctypes
# ---------------------------------------------------------------------------

def emit_python(pkg: SDKPackage, engine_name: str = "Unknown") -> str:
    L: list[str] = [
        '"""BIFROST SDK — Auto-generated ctypes SDK.',
        f"Package: {pkg.name}  |  Engine: {engine_name}  |  {_stamp(engine_name)}",
        "Every field lands at its dumped offset via explicit padding.",
        '"""',
        "from ctypes import Structure, c_bool, c_ubyte, c_int8, c_int16, \\",
        "    c_uint16, c_int32, c_uint32, c_int64, c_uint64, c_float, c_double, \\",
        "    c_void_p",
        "from enum import IntEnum",
        "",
        "",
    ]
    for enum_data in pkg.enums:
        ename = _safe_ident(enum_data.get("name", "UnknownEnum"))
        L.append(f"class {ename}(IntEnum):")
        members = enum_data.get("members", [])
        if not members:
            L.append("    pass")
        for m in members:
            L.append(f"    {_safe_ident(m['name'])} = {m['value']}")
        L.append("")
        L.append("")

    for cls in pkg.classes:
        cname = _safe_ident(cls.name)
        L.append(f"# {cls.full_name} — Size: 0x{cls.size:04X}")
        L.append(f"class {cname}(Structure):")
        L.append("    _pack_ = 1")
        L.append("    _fields_ = [")
        for op in _layout(cls):
            if op[0] == "pad":
                _, off, size = op
                L.append(f'        ("{_pad_name(off)}", c_ubyte * 0x{size:X}),  # 0x{off:04X}')
                continue
            fld = op[1]
            fname = _safe_ident(fld.name)
            t = fld.type_name
            if t in _PTR_TYPES:
                py_t = "c_void_p"
            else:
                py_t = _PY_MAP.get(t, "c_ubyte")
            note = f"0x{fld.offset:04X}"
            if fld.bit_offset >= 0:
                note += f" Bit {fld.bit_offset}"
                L.append(f'        ("{fname}", c_ubyte),  # {note} (bitfield backing byte)')
            elif fld.array_dim > 1:
                L.append(f'        ("{fname}", c_ubyte * 0x{fld.size:X}),  # {note} ({py_t}[{fld.array_dim}])')
            else:
                if py_t in ("c_bool", "c_float", "c_double") or py_t.startswith("c_int") or py_t.startswith("c_uint"):
                    L.append(f'        ("{fname}", {py_t}),  # {note}')
                else:
                    L.append(f'        ("{fname}", c_ubyte * 0x{fld.size:X}),  # {note} ({t})')
        L.append("    ]")
        L.append("")
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

def emit_rust(pkg: SDKPackage, engine_name: str = "Unknown") -> str:
    L: list[str] = [
        "//! BIFROST SDK — Auto-generated Rust SDK.",
        f"//! Package: {pkg.name}  |  Engine: {engine_name}  |  {_stamp(engine_name)}",
        "//! `#[repr(C)]` + explicit padding keeps every field at its dumped offset.",
        "",
    ]
    for enum_data in pkg.enums:
        ename = _safe_ident(enum_data.get("name", "UnknownEnum"))
        L.append(f"#[repr(u8)] #[derive(Debug, Clone, Copy, PartialEq, Eq)]")
        L.append(f"pub enum {ename} {{")
        for m in enum_data.get("members", []):
            L.append(f"    {_safe_ident(m['name'])} = {m['value']},")
        L.append("}")
        L.append("")

    for cls in pkg.classes:
        cname = _safe_ident(cls.name)
        L.append(f"/// {cls.full_name} — Size: 0x{cls.size:04X}")
        L.append("#[repr(C)] #[derive(Debug, Clone, Copy)]")
        L.append(f"pub struct {cname} {{")
        for op in _layout(cls):
            if op[0] == "pad":
                _, off, size = op
                L.append(f"    pub {_pad_name(off).lower()}: [u8; 0x{size:X}], // 0x{off:04X}")
                continue
            fld = op[1]
            fname = _safe_ident(fld.name)
            t = fld.type_name
            if t in _PTR_TYPES:
                rs_t = "*mut u8"
            else:
                rs_t = _RS_MAP.get(t, "u8")
            doc = f"/// 0x{fld.offset:04X}"
            if fld.bit_offset >= 0:
                doc += f" (Bit: {fld.bit_offset})"
                L.append(f"    {doc}")
                L.append(f"    pub {fname}: u8,")
            elif fld.array_dim > 1:
                L.append(f"    {doc} ({rs_t}[{fld.array_dim}], {fld.size} bytes)")
                L.append(f"    pub {fname}: [u8; 0x{fld.size:X}],")
            elif rs_t in ("bool", "f32", "f64") or rs_t.startswith(("i", "u")):
                L.append(f"    {doc}")
                L.append(f"    pub {fname}: {rs_t},")
            else:
                L.append(f"    {doc} ({t})")
                L.append(f"    pub {fname}: [u8; 0x{fld.size:X}],")
        L.append("}")
        L.append("")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Multi-target entry point
# ---------------------------------------------------------------------------

_EMITTERS = {
    "csharp": ("cs", emit_csharp),
    "python": ("py", emit_python),
    "rust": ("rs", emit_rust),
}


def emit_all(packages: list[SDKPackage], output_dir: str,
             targets: Optional[list[str]] = None,
             engine_name: str = "Unknown") -> dict[str, str]:
    """Render targets for every package. Returns {target_key: path}."""
    targets = targets or list(_EMITTERS)
    os.makedirs(output_dir, exist_ok=True)
    written: dict[str, str] = {}
    for key in targets:
        if key not in _EMITTERS:
            raise ValueError(f"unknown codegen target: {key!r} (want {sorted(_EMITTERS)})")
        ext, fn = _EMITTERS[key]
        chunks = [fn(pkg, engine_name) for pkg in packages]
        safe = "sdk" if len(packages) != 1 else packages[0].name.replace("/", "_").replace("\\", "_").replace(" ", "_")
        path = os.path.join(output_dir, f"{safe}.{ext}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(chunks))
        written[key] = path
    return written
