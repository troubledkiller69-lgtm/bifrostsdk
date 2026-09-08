"""
BIFROST SDK — New Engine Layout Definitions

Placeholder for the target engine's in-memory layout dataclasses: module
names, struct field offsets, AOB patterns.

See docs/ENGINE_GUIDE.md, "Reference shapes", for how existing engines split
config between structs.py and the dumper:
- engines/source/structs.py — config dataclasses (SourceConfig, Source2Config)
- engines/unreal/structs.py — per-game profile dataclasses injected by the
  registry via extra_imports
- engines/blizzard/structs.py — patterns + game constants

Rules that keep these files healthy:
- Every magic offset lives here, never in dumper.py.
- Per-patch churn (new game build = new offsets) lands in this file.
- One dataclass per game/variant when layouts drift; the registry entry
  selects it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class YourEngineConfig:
    """Empty placeholder — replace with the engine's real layout config.

    Fill in, mirroring SourceConfig in engines/source/structs.py:

        core_module: str = "engine_core.dll"   # checked by validate()
        # class table layout offsets, e.g.:
        # type_db_size_offset: int = 0x08
        # class_binding_array_offset: int = 0x10
        # patterns: list[str] = field(default_factory=lambda: [
        #     "48 8B 0D ?? ?? ?? ?? 48 85 C9 74",   # one AOB per game build
        # ])
    """
