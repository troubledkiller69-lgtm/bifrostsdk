from __future__ import annotations

import json
import logging
import os
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SchemaValidationError(Exception):
    """Raised when SDKGenerator output doesn't conform to sdk_output_schema.json."""
    def __init__(self, message: str, bad_subtree: Optional[dict] = None,
                 path: Optional[list] = None):
        super().__init__(message)
        self.bad_subtree = bad_subtree
        self.path = path or []


# Lazy schema cache — loaded once on first validation
_SCHEMA_CACHE: Optional[dict] = None
_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "contracts"
    / "sdk_output_schema.json"
)


def _load_output_schema() -> Optional[dict]:
    """Load the JSON Schema, caching it. Returns None if schema file or
    jsonschema module is unavailable — production should not crash on this."""
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is not None:
        return _SCHEMA_CACHE
    if not _SCHEMA_PATH.exists():
        logger.warning(
            "sdk_output_schema.json not found at %s — skipping output validation",
            _SCHEMA_PATH,
        )
        return None
    try:
        _SCHEMA_CACHE = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        return _SCHEMA_CACHE
    except Exception as e:
        logger.warning("Failed to load output schema: %s", e)
        return None


@dataclass
class SDKField:
    name: str
    type_name: str
    offset: int
    size: int
    array_dim: int = 1
    bit_offset: int = -1
    comment: str = ""


@dataclass
class SDKClass:
    name: str
    full_name: str
    super_name: str = ""
    size: int = 0
    fields: list[SDKField] = field(default_factory=list)
    package: str = ""

    @property
    def header_guard(self) -> str:
        safe = self.name.upper().replace(" ", "_").replace(".", "_")
        return f"SDK_{safe}_H"


@dataclass
class SDKPackage:
    name: str
    classes: list[SDKClass] = field(default_factory=list)
    enums: list[dict] = field(default_factory=list)


class SDKGenerator:
    TYPE_MAP: dict[str, str] = {
        "BoolProperty": "bool",
        "ByteProperty": "uint8_t",
        "Int8Property": "int8_t",
        "Int16Property": "int16_t",
        "UInt16Property": "uint16_t",
        "IntProperty": "int32_t",
        "UInt32Property": "uint32_t",
        "Int64Property": "int64_t",
        "UInt64Property": "uint64_t",
        "FloatProperty": "float",
        "DoubleProperty": "double",
        "NameProperty": "FName",
        "StrProperty": "FString",
        "TextProperty": "FText",
        "ObjectProperty": "class UObject*",
        "ClassProperty": "class UClass*",
        "WeakObjectProperty": "TWeakObjectPtr<UObject>",
        "LazyObjectProperty": "TLazyObjectPtr<UObject>",
        "SoftObjectProperty": "TSoftObjectPtr<UObject>",
        "StructProperty": "STRUCT",
        "ArrayProperty": "TArray<void*>",
        "MapProperty": "TMap<void*, void*>",
        "SetProperty": "TSet<void*>",
        "DelegateProperty": "FDelegate",
        "MulticastDelegateProperty": "FMulticastDelegate",
        "InterfaceProperty": "FScriptInterface",
        "EnumProperty": "uint8_t",
    }

    def __init__(self, output_dir: str, engine_name: str = "Unknown"):
        self.output_dir = output_dir
        self.engine_name = engine_name
        os.makedirs(output_dir, exist_ok=True)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_header(self, pkg: SDKPackage) -> str:
        lines: list[str] = []
        lines.append(f"#pragma once")
        lines.append(f"// BIFROST SDK — Auto-generated from {self.engine_name}")
        lines.append(f"// Package: {pkg.name}")
        lines.append(f"// Generated: {self._timestamp()}")
        lines.append(f"// Classes: {len(pkg.classes)}")
        lines.append("")

        for enum_data in pkg.enums:
            lines.append(f"enum class {enum_data.get('name', 'UnknownEnum')} : uint8_t")
            lines.append("{")
            for member in enum_data.get("members", []):
                lines.append(f"    {member['name']} = {member['value']},")
            lines.append("};")
            lines.append("")

        for cls in pkg.classes:
            inherit = f" : public {cls.super_name}" if cls.super_name else ""
            lines.append(f"// Size: 0x{cls.size:04X}")
            lines.append(f"class {cls.name}{inherit}")
            lines.append("{")
            lines.append("public:")

            prev_end = 0
            for fld in sorted(cls.fields, key=lambda f: f.offset):
                if fld.offset > prev_end:
                    gap = fld.offset - prev_end
                    lines.append(f"    char _pad_0x{prev_end:04X}[0x{gap:X}]; // 0x{prev_end:04X}")

                cpp_type = self.TYPE_MAP.get(fld.type_name, fld.type_name)
                if fld.array_dim > 1:
                    lines.append(
                        f"    {cpp_type} {fld.name}[{fld.array_dim}];"
                        f" // 0x{fld.offset:04X} (Size: 0x{fld.size:X})"
                    )
                elif fld.bit_offset >= 0:
                    lines.append(
                        f"    {cpp_type} {fld.name} : 1;"
                        f" // 0x{fld.offset:04X} (Bit: {fld.bit_offset})"
                    )
                else:
                    comment = fld.comment or f"Size: 0x{fld.size:X}"
                    lines.append(
                        f"    {cpp_type} {fld.name};"
                        f" // 0x{fld.offset:04X} ({comment})"
                    )
                prev_end = fld.offset + fld.size

            if prev_end < cls.size:
                gap = cls.size - prev_end
                lines.append(f"    char _pad_0x{prev_end:04X}[0x{gap:X}]; // 0x{prev_end:04X}")

            lines.append("};")
            lines.append(f"static_assert(sizeof({cls.name}) == 0x{cls.size:X});")
            lines.append("")

        return "\n".join(lines)

    def write_header(self, pkg: SDKPackage) -> str:
        header = self.generate_header(pkg)
        safe_name = pkg.name.replace("/", "_").replace("\\", "_").replace(" ", "_")
        path = os.path.join(self.output_dir, f"{safe_name}.h")
        with open(path, "w", encoding="utf-8") as f:
            f.write(header)
        return path

    def generate_json(self, packages: list[SDKPackage]) -> dict:
        out: dict = {
            "_meta": {
                "generator": "BIFROST SDK",
                "engine": self.engine_name,
                "timestamp": self._timestamp(),
                "total_classes": sum(len(p.classes) for p in packages),
                "total_fields": sum(
                    len(c.fields) for p in packages for c in p.classes
                ),
            },
            "offsets": {},
        }
        for pkg in packages:
            for cls in pkg.classes:
                class_key = cls.full_name or cls.name
                fields_map = {}
                for fld in cls.fields:
                    fields_map[fld.name] = {
                        "offset": f"0x{fld.offset:X}",
                        "size": fld.size,
                        "type": fld.type_name,
                    }
                out["offsets"][class_key] = {
                    "size": f"0x{cls.size:X}",
                    "super": cls.super_name,
                    "fields": fields_map,
                }
        return out

    def write_json(self, packages: list[SDKPackage], filename: str = "offsets.json") -> str:
        data = self.generate_json(packages)
        # Engine-agnostic correctness check (Tier 1 dumper validation).
        # If the schema isn't present or jsonschema isn't installed, the
        # validator returns quietly and we skip the check — production
        # never crashes on missing infra. See contracts/sdk_output_schema.json.
        self._validate_output(data)
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def _validate_output(self, data: dict) -> None:
        """Validate generated dump against contracts/sdk_output_schema.json.

        Raises SchemaValidationError on schema violation. Silently no-ops if
        jsonschema or the schema file is unavailable (logged as warning).
        """
        schema = _load_output_schema()
        if schema is None:
            return
        try:
            from jsonschema import Draft7Validator
        except ImportError:
            logger.warning(
                "jsonschema not installed — skipping dump output validation. "
                "Install with: pip install jsonschema"
            )
            return
        validator = Draft7Validator(schema)
        errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
        if not errors:
            return
        # Build a useful diagnostic from the first error
        first = errors[0]
        # Walk to the offending subtree
        bad_subtree = data
        try:
            for key in first.absolute_path:
                bad_subtree = bad_subtree[key]
        except (KeyError, IndexError, TypeError):
            bad_subtree = None
        path_str = "/".join(str(p) for p in first.absolute_path) or "<root>"
        message = (
            f"Dump output failed schema validation at '{path_str}': "
            f"{first.message}"
        )
        if len(errors) > 1:
            message += f" (+{len(errors) - 1} more validation errors)"
        logger.error(message)
        raise SchemaValidationError(
            message,
            bad_subtree=bad_subtree if isinstance(bad_subtree, dict) else None,
            path=list(first.absolute_path),
        )

    def write_all(self, packages: list[SDKPackage]) -> dict:
        header_paths = []
        for pkg in packages:
            if pkg.classes or pkg.enums:
                header_paths.append(self.write_header(pkg))
        json_path = self.write_json(packages)
        return {"headers": header_paths, "json": json_path}
