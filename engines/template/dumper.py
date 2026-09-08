"""
BIFROST SDK — New Engine Dumper (template)

Copy engines/template/ to engines/<your_engine>/ and implement the two
abstract methods below. This file imports cleanly and satisfies the
BaseDumper ABC, but it is NOT registered anywhere — it must never be
selectable from the GUI.

Implementing checklist, one map to docs/ENGINE_GUIDE.md per step:

1. validate()    -> ENGINE_GUIDE.md "The dumper contract" / "Reference shapes"
2. dump()        -> ENGINE_GUIDE.md "Output contract" (SDKPackage/SDKClass/SDKField)
3. detection     -> ENGINE_GUIDE.md "Selection" (registry key, core/process.py,
                    KNOWN_GAME_EXES)
4. registry      -> engines/registry.py (see ENGINE_GUIDE.md "Registration")
5. tests         -> tests/test_<your_engine>_mock.py (see ENGINE_GUIDE.md
                    "Testing conventions")
"""

from __future__ import annotations

from typing import Optional

from core.generator import SDKPackage, SDKClass, SDKField
from engines.base import BaseDumper

from .structs import YourEngineConfig


class YourDumper(BaseDumper):
    """
    Dump <engine> class/field offsets.

    Strategy outline (fill in against the real engine):
        1. validate() — confirm the target process loads the engine modules
        2. Locate the reflection/type-database global (pattern scan)
        3. Walk class table(s), reading names, sizes, super classes
        4. Read per-class field lists (names, types, offsets, sizes)
        5. Assemble SDKPackage(s) and let dump_and_generate() write headers
           + offsets.json
    """

    ENGINE_NAME = "Your Engine"

    # Module(s) that prove the target is this engine, checked in validate().
    # Keep in structs.py, not here — see ENGINE_GUIDE.md "Registration".
    def __init__(
        self,
        reader,
        output_dir: str = "output",
        config: YourEngineConfig | None = None,
        stealth_config=None,
        **kwargs,
    ):
        super().__init__(reader, output_dir, stealth_config=stealth_config, **kwargs)
        self.config = config or YourEngineConfig()
        # Cached addresses resolved during dump, e.g.:
        # self._type_db: int = 0
        # self._module_base: int = 0

    # ------------------------------------------------------------------
    # Engine detection
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Return True if the attached process is running this engine.

        Idiom used by every real dumper: scan reader.list_modules() for the
        engine's module names, cache the module base, and confirm before any
        pattern scan. See BlizzardDumper.validate() and SourceDumper.validate()
        — Source branches Source1 vs Source2 on module presence right here.
        """
        # TODO(engine-guide): module-presence check, e.g.:
        #   modules = {m["name"].lower() for m in self.reader.list_modules()}
        #   if self.config.core_module.lower() not in modules:
        #       self._log_error("No <engine> modules found")
        #       return False
        #   return True
        self._log_error("validate() not implemented — this is the template engine")
        return False

    # ------------------------------------------------------------------
    # Dump
    # ------------------------------------------------------------------

    def _resolve_class_table(self) -> int:
        """Locate the class/type database global in the target process.

        Options, cheapest first:
        - reader.resolve_rip_relative() on a scanner hit (see
          SourceDumper._find_client_class_head)
        - self.scanner.scan_module() / find_address() for a global-load
          pattern (see BlizzardDumper._resolve_globals)
        - known export / vtable anchoring when no AOB survives patches

        Patterns live in structs.py, keyed per game build.
        """
        # TODO(engine-guide): pattern scan + pointer resolve.
        #   ENGINE_GUIDE.md "Reader API" covers scanner usage.
        return 0

    def dump(self) -> list[SDKPackage]:
        """Perform the full SDK dump. Returns SDKPackage objects only —
        header/JSON writing happens upstream in dump_and_generate()."""
        self._update_progress("dumping", "Resolving class table...", 5)
        # table_addr = self._resolve_class_table()
        # if not table_addr: log_error + return []

        # Phase walks: per-class reads go through try/except + _log_warn,
        # progress updates at phase boundaries, and counters increment per
        # class/field — EMPTY_DUMP is treated as failure by the bridge, so
        # a walk that finds nothing must report nothing, not zero.
        pkg = SDKPackage(name="your_engine")

        # TODO(engine-guide): walk the table, appending for each class:
        #   self.progress.classes_found += 1
        #   self.progress.fields_found += len(fields)
        #   pkg.classes.append(SDKClass(
        #       name=cls_name,
        #       full_name=f"YourEngine.{cls_name}",   # offsets.json key
        #       super_name=parent_name,
        #       size=cls_size,
        #       fields=[SDKField(name, type_name, offset, size), ...],
        #       package=pkg.name,
        #   ))

        self._update_progress("dumping", "Done — 0 classes (template)", 100)
        return [pkg]

    # Optional phase helpers live below; engines with multi-phase walks
    # (Unreal, Blizzard) split them into private methods or sibling modules.
