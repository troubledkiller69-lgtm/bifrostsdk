"""
BIFROST SDK — Abstract Base Dumper
All engine-specific dumpers inherit from this.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from core.memory import MemoryReader, ReaderProtocol
from core.scanner import PatternScanner
from core.generator import SDKPackage, SDKGenerator
from core.stealth.config import StealthConfig, STEALTH_OFF


@dataclass
class DumpProgress:
    """Tracks dump progress for the UI."""
    stage: str = "idle"
    detail: str = ""
    percent: float = 0.0
    classes_found: int = 0
    fields_found: int = 0
    errors: list[str] = field(default_factory=list)
    start_time: float = 0.0

    @property
    def elapsed(self) -> float:
        if self.start_time <= 0:
            return 0
        return time.time() - self.start_time


class BaseDumper(ABC):
    """
    Abstract base for engine-specific SDK dumpers.
    
    Subclasses implement:
        - validate()  : confirm the target is the right engine
        - dump()       : perform the full SDK dump
    """

    ENGINE_NAME: str = "Unknown"

    def __init__(
        self,
        reader: ReaderProtocol,
        output_dir: str = "output",
        stealth_config: Optional[StealthConfig] = None,
        target_module: Optional[str] = None,
        logger: Optional[Callable] = None,
    ):
        self.reader = reader
        self.output_dir = output_dir
        self._stealth_config = stealth_config or STEALTH_OFF
        # Target process name as the user picked it (cs2.exe etc). Engines
        # that need per-game profile switches read this; it is optional so
        # direct engine tests never have to supply it.
        self.target_module = target_module
        self._logger = logger or (lambda msg, level="info": None)

        # Create scanner with stealth parameters
        stealth_on = self._stealth_config is not None and self._stealth_config != STEALTH_OFF
        self.scanner = PatternScanner(
            reader,
            stealth=stealth_on,
            chunk_size=self._stealth_config.scan_chunk_size if stealth_on else 0,
            inter_chunk_delay_ms=self._stealth_config.scan_inter_chunk_delay_ms if stealth_on else 0,
        )

        self.progress = DumpProgress()
        self._on_progress: Optional[Callable[[DumpProgress], None]] = None

    def set_progress_callback(self, cb: Callable[[DumpProgress], None]):
        """Register a callback that fires on progress updates (for UI)."""
        self._on_progress = cb

    def _update_progress(self, stage: str, detail: str = "", percent: float = -1):
        self.progress.stage = stage
        self.progress.detail = detail
        if percent >= 0:
            self.progress.percent = percent
        if self._on_progress:
            self._on_progress(self.progress)

    def _log_error(self, msg: str):
        self.progress.errors.append(msg)

    def _log(self, msg: str):
        self._update_progress(self.progress.stage, msg)

    def _log_warn(self, msg: str):
        self.progress.errors.append(f"[WARN] {msg}")
        self._update_progress(self.progress.stage, msg)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def validate(self) -> bool:
        """Return True if the attached process matches this engine."""
        ...

    @abstractmethod
    def dump(self) -> list[SDKPackage]:
        """
        Perform the full SDK dump.
        Returns a list of SDKPackage objects ready for header generation.
        """
        ...

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def dump_and_generate(self) -> dict:
        """Full pipeline: validate -> dump -> generate headers + JSON.

        Raises:
            RuntimeError: process is not the expected engine.
            SchemaValidationError: dumper produced output that violates the
                engine-agnostic SDK schema (contracts/sdk_output_schema.json).
                The exception carries `path` and `bad_subtree` so the bridge
                can surface a useful error code to the UI.
        """
        from core.generator import SchemaValidationError

        self.progress = DumpProgress(start_time=time.time())

        self._update_progress("validating", "Checking engine compatibility...")
        if not self.validate():
            err_msg = f"Process does not appear to be a {self.ENGINE_NAME} game."
            if self.progress.errors:
                err_msg += f"\nValidation errors:\n" + "\n".join(self.progress.errors)
            raise RuntimeError(err_msg)

        self._update_progress("dumping", "Walking object hierarchy...")
        packages = self.dump()

        self._update_progress("generating", "Writing SDK files...")
        gen = SDKGenerator(self.output_dir, self.ENGINE_NAME)
        try:
            result = gen.write_all(packages)
        except SchemaValidationError as e:
            # Surface a structured error to the progress stream so the bridge
            # can emit a "SCHEMA_VIOLATION" result instead of a raw stack trace.
            err_path = "/".join(str(p) for p in e.path) or "<root>"
            self._update_progress(
                "error",
                f"Dumper produced invalid output at {err_path}",
                self.progress.percent,
            )
            self.progress.errors.append(f"SCHEMA_VIOLATION at {err_path}: {e}")
            raise

        self._update_progress("complete", f"Done — {len(result['headers'])} headers", 100.0)
        return result

    # ------------------------------------------------------------------
    # Debug info
    # ------------------------------------------------------------------

    def get_debug_info(self) -> dict:
        """Return debug information for the debug panel."""
        info = {
            "engine": self.ENGINE_NAME,
            "output_dir": self.output_dir,
            "stealth_enabled": self._stealth_config != STEALTH_OFF,
            "scanner_stats": self.scanner.get_stats(),
            "progress": {
                "stage": self.progress.stage,
                "percent": self.progress.percent,
                "classes_found": self.progress.classes_found,
                "fields_found": self.progress.fields_found,
                "errors": self.progress.errors[-20:],  # last 20 errors
                "elapsed": round(self.progress.elapsed, 2),
            },
        }

        # If reader is a StealthReader, include its stats
        if hasattr(self.reader, "get_debug_stats"):
            info["stealth_stats"] = self.reader.get_debug_stats()

        return info
