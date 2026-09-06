"""
BIFROST SDK — Engine Registry
Central registry mapping engine keys to their dumper classes and constructor kwargs.
Eliminates the elif chain in gui_bridge.py and provides a single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Type


@dataclass(frozen=True)
class EngineEntry:
    """Describes how to construct a dumper for a specific engine variant."""
    dumper_import: str          # e.g. "engines.unreal.dumper.UnrealDumper"
    extra_imports: dict[str, str] = field(default_factory=dict)  # kwarg_name -> import_path
    extra_kwargs: dict[str, Any] = field(default_factory=dict)   # static kwargs


# --------------------------------------------------------------------------
# Registry: engine_key → EngineEntry
# --------------------------------------------------------------------------
ENGINE_REGISTRY: dict[str, EngineEntry] = {
    "unreal5": EngineEntry(
        dumper_import="engines.unreal.dumper.UnrealDumper",
        extra_imports={"profile": "engines.unreal.structs.UE5_DEFAULT"},
    ),
    "unreal": EngineEntry(
        dumper_import="engines.unreal.dumper.UnrealDumper",
        extra_imports={"profile": "engines.unreal.structs.UE5_DEFAULT"},
    ),
    "unreal5_marvel": EngineEntry(
        dumper_import="engines.unreal.dumper.UnrealDumper",
        extra_imports={"profile": "engines.unreal.structs.UE5_MARVEL_RIVALS"},
    ),
    "unity_mono": EngineEntry(
        dumper_import="engines.unity.mono.MonoDumper",
    ),
    "unity": EngineEntry(
        dumper_import="engines.unity.mono.MonoDumper",
    ),
    "unity_il2cpp": EngineEntry(
        dumper_import="engines.unity.il2cpp.IL2CPPDumper",
    ),
    "source": EngineEntry(
        dumper_import="engines.source.dumper.SourceDumper",
    ),
    "source_eac": EngineEntry(
        dumper_import="engines.source.dumper.SourceDumper",
    ),
    "blizzard": EngineEntry(
        dumper_import="engines.blizzard.dumper.BlizzardDumper",
    ),
}


def _import_attr(dotted_path: str) -> Any:
    """
    Import an attribute from a dotted module path.
    e.g. "engines.unreal.dumper.UnrealDumper" → <class UnrealDumper>
    """
    module_path, _, attr_name = dotted_path.rpartition(".")
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, attr_name)


def create_dumper(
    engine_key: str,
    reader,
    output_dir: str,
    stealth_config=None,
    **extra_kwargs,
):
    """
    Create and return a dumper instance for the given engine key.
    Raises KeyError if the engine is unknown.
    """
    # Auto-detect game-specific profiles for Unreal engines
    effective_key = engine_key
    if engine_key in ("unreal", "unreal5"):
        # Check if the target process is a known game with a specific profile
        try:
            modules = reader.list_modules()
            exe_names = [m["name"].lower() for m in modules if m["name"].lower().endswith(".exe")]
            for exe_name in exe_names:
                if "marvel" in exe_name:
                    effective_key = "unreal5_marvel"
                    break
        except Exception:
            pass  # Fall through to default profile

    if effective_key not in ENGINE_REGISTRY:
        raise KeyError(f"Unknown engine: {effective_key}")

    entry = ENGINE_REGISTRY[effective_key]

    # Import dumper class
    dumper_cls = _import_attr(entry.dumper_import)

    # Build kwargs
    kwargs = {"reader": reader, "output_dir": output_dir}

    # Add stealth_config if the dumper accepts it
    kwargs["stealth_config"] = stealth_config

    # Resolve extra imports (e.g. profile objects)
    for kwarg_name, import_path in entry.extra_imports.items():
        kwargs[kwarg_name] = _import_attr(import_path)

    # Add static extra kwargs from the entry
    kwargs.update(entry.extra_kwargs)

    # Add caller-provided extra kwargs (e.g. force_discovery, regenerate)
    kwargs.update(extra_kwargs)

    return dumper_cls(**kwargs)


def is_known_engine(engine_key: str) -> bool:
    """Check if an engine key is registered."""
    return engine_key in ENGINE_REGISTRY


def list_engines() -> list[str]:
    """Return all registered engine keys."""
    return list(ENGINE_REGISTRY.keys())
