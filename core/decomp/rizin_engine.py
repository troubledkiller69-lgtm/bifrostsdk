"""
BIFROST SDK — rizin + rz-ghidra engine wrapper.

Thin, testable seam over rzpipe (0.6.2 API: `rzpipe.open(file, flags,
rizin_home=)` which spawns `rizin.exe <flags> -q0 <file>` and speaks the
\0-terminated command protocol over pipes).

Every rizin interaction funnels through `_run()` so tests can inject a fake
runner and assert command sequences without a rizin binary on PATH.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

# Binary discovery ------------------------------------------------------------

def find_rizin_dir() -> str | None:
    """Resolve the bundled rizin install dir, if any.

    Probe order:
      1. BIFROST_RIZIN_DIR env override
      2. <repo>/gui/extra/rizin            (dev tree)
      3. <exe dir>/rizin                   (frozen: extra staged beside exe)
      4. <exe dir>/../extra/rizin          (frozen fallback layout)

    A dir "counts" only when bin/rizin.exe exists inside it.
    """
    candidates = []
    env_dir = os.environ.get("BIFROST_RIZIN_DIR", "")
    if env_dir:
        candidates.append(env_dir)
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))
    candidates.append(os.path.join(repo_root, "gui", "extra", "rizin"))
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, "rizin"))
        candidates.append(os.path.join(exe_dir, "..", "extra", "rizin"))
    for cand in candidates:
        if cand and os.path.isfile(os.path.join(cand, "bin", "rizin.exe")):
            return cand
    return None


def rizin_binary() -> str | None:
    """Full path to rizin.exe, or None when the engine is not provisioned."""
    rz_dir = find_rizin_dir()
    if not rz_dir:
        return None
    return os.path.join(rz_dir, "bin", "rizin.exe")


def rizin_version(exe: str | None = None) -> str:
    """Ask rizin for its version. Never raises — returns '' on any failure."""
    exe = exe or rizin_binary()
    if not exe:
        return ""
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        out = subprocess.run(
            [exe, "-v"], capture_output=True, text=True,
            timeout=10, creationflags=creationflags,
        )
        first = (out.stdout or "").splitlines()[0] if out.stdout else ""
        return first.strip()
    except Exception:
        return ""


# Parsing helpers (pure — unit tested without rizin) --------------------------

def parse_aflj(payload) -> list[dict]:
    """Normalize an `aflj` payload into [{addr, size, name}, ...].

    Handles the common failure shapes: None payload, invalid JSON, and
    rizin entries where the meaningful name lives in `realname`.
    """
    if not payload:
        return []
    try:
        if isinstance(payload, str):
            entries = json.loads(payload)
        else:
            entries = payload
    except (ValueError, TypeError):
        return []
    if not isinstance(entries, list):
        return []
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        addr = entry.get("offset", entry.get("vaddr"))
        size = entry.get("size", 0)
        if not isinstance(addr, int) or addr <= 0:
            continue
        name = entry.get("realname") or entry.get("name") or ""
        out.append({
            "addr": addr,
            "size": int(size or 0),
            "name": str(name),
        })
    return out


def parse_pdgj(payload) -> dict:
    """Extract {code} from a `pdgj @ addr` payload. Never raises."""
    if not payload:
        return {"code": ""}
    try:
        if isinstance(payload, str):
            data = json.loads(payload)
        else:
            data = payload
    except (ValueError, TypeError):
        return {"code": ""}
    if isinstance(data, dict) and isinstance(data.get("code"), str):
        return data
    return {"code": ""}


# Session ---------------------------------------------------------------------

class FakeRunner:
    """Stub runner recording commands for tests. Real engine swaps it out."""

    def __init__(self):
        self.commands: list[str] = []
        self.responses: dict[str, str] = {}

    def __call__(self, command: str) -> str:
        self.commands.append(command)
        for key, value in self.responses.items():
            if command.startswith(key):
                return value
        return ""


class RizinSession:
    """One rizin pipe on one file.

    The session is what makes per-function decompile cheap: analysis runs
    once per file, then `pdgj` round-trips are tens of ms each.
    """

    ENGINE_NAME = "rizin-ghidra"

    def __init__(
        self,
        file_path: str,
        exe: str | None = None,
        base: int | None = None,
        runner=None,
        cmd_timeout_secs: int = 120,
        plugin_dir: str | None = None,
    ):
        self.file_path = os.path.abspath(file_path)
        self.base = base
        self._exe = exe or rizin_binary()
        self._runner = runner
        self._cmd_timeout_secs = cmd_timeout_secs
        self._plugin_dir = plugin_dir
        self._pipe = None

    # -- lifecycle ----------------------------------------------------------

    def open(self) -> None:
        if self._runner is not None:
            return  # test seam: fake runner needs no pipe or binary
        if not self._exe:
            raise RuntimeError(
                "rizin is not provisioned. Run tools/provision_rizin.ps1 once, "
                "or set BIFROST_RIZIN_DIR."
            )

        import rzpipe  # lazy: module must not import rzpipe at package load

        flags = ["-e", "bin.cache=true"] if self.base else []
        if self.base:
            flags = ["-B", hex(self.base)] + flags
        prev_plugins = os.environ.get("RIZIN_PLUGINS")
        if self._plugin_dir:
            os.environ["RIZIN_PLUGINS"] = self._plugin_dir
        try:
            self._pipe = rzpipe.open(
                self.file_path,
                flags=flags,
                rizin_home=os.path.dirname(self._exe),
            )
            if self._cmd_timeout_secs and self._cmd_timeout_secs > 0:
                self._pipe.set_timeout(self._cmd_timeout_secs)
        finally:
            if prev_plugins is None:
                os.environ.pop("RIZIN_PLUGINS", None)
            else:
                os.environ["RIZIN_PLUGINS"] = prev_plugins

    def close(self) -> None:
        if self._pipe is not None:
            try:
                self._pipe.quit()
            except Exception:
                pass
            self._pipe = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- command surface -----------------------------------------------------

    def run(self, command: str) -> str:
        if self._runner is not None:
            return self._runner(command)
        if self._pipe is None:
            raise RuntimeError("session not open")
        result = self._pipe.cmd(command)
        return result if result is not None else ""

    def decompiler_available(self) -> bool:
        """rz-ghidra registers `pdgs` when its plugin is loaded.

        An unknown-command response means the plugin is missing and every
        pdg* call would fail — report that as unavailable.
        """
        try:
            out = self.run("pdgs")
        except Exception:
            return False
        if not out:
            return True  # loaded but no sleigh langs yet is still "available"
        lowered = out.lower()
        if "unknown command" in lowered or "error" in lowered:
            return False
        return True

    def analyze(self) -> None:
        """Run rizin auto-analysis. Heavy on big modules — callers stream."""
        self.run("aaa")

    def functions(self) -> list[dict]:
        return parse_aflj(self.run("aflj"))

    def decompile(self, addr: int) -> dict:
        payload = parse_pdgj(self.run(f"pdgj @ {addr:#x}"))
        payload["addr"] = addr
        return payload
