"""
BIFROST SDK — rizin + rz-ghidra engine wrapper.

Interactive rzpipe over stdin is unreliable on Windows: rizin only
dispatches piped commands when it inherits a console, and console-less
spawns (CREATE_NO_WINDOW, detached, new-console) all sit silent on their
input pipe. The one-shot form works everywhere — `rizin -q0 -c '<cmds>'
<file>` executes, prints to stdout, exits.

So this engine never keeps a session process alive. Every operation is a
fresh spawn with the full command chain in `-c` (sleighhome + analysis +
work), which costs ~2-4s per call on a cold start. Correctness and leak
freedom beat round-trip latency here; per-function results are cached on
the analyzer side so repeated clicks stay cheap.

The runner seam (`runner=` param) keeps unit tests binary-free: methods
route through `run()` when a runner is present, exactly like the old
persistent-session design.
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


def _sleighhome_for(exe: str) -> str:
    """Sleigh language dir next to the binary, '' when absent.

    rz-ghidra needs ghidra.sleighhome pointed at the bundled .sla/.cspec
    set; the official zip keeps it under <prefix>/share/rizin/sleigh.
    """
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(exe)))
    cand = os.path.join(prefix, "share", "rizin", "sleigh")
    return cand if os.path.isdir(cand) else ""


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


def parse_axtj(payload) -> list[dict]:
    """Normalize an `axtj @ addr` payload into [{from, type, op}, ...].

    rizin xref entries carry the referencing instruction under `from`,
    the kind of reference under `type` (CALL/JUMP/LEA/DATA/STRING/...)
    and the raw operand under `op` (when the backend knows one).
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
        src = entry.get("from", 0)
        if not isinstance(src, int) or src <= 0:
            continue
        out.append({
            "from": src,
            "type": str(entry.get("type") or "UNKNOWN"),
            "op": str(entry.get("op") or ""),
        })
    out.sort(key=lambda x: x["from"])
    return out


_MARKER = "BIFROST_MARKER_9f3a"


def _split_json_docs(payload: str) -> list[str]:
    """Split a stream of concatenated JSON documents into a list.

    pdgj emits one JSON object per decompile with no separators between
    documents. Repeated raw_decode walks the buffer document by document;
    garbage that can't parse ends the walk so callers can detect desync by
    comparing document count to the number of addresses requested.
    """
    docs: list[str] = []
    if not payload:
        return docs
    decoder = json.JSONDecoder()
    index = 0
    size = len(payload)
    while index < size:
        while index < size and payload[index] in " \r\n\t":
            index += 1
        if index >= size:
            break
        if payload[index] != "{":
            break
        try:
            obj, end = decoder.raw_decode(payload, index)
        except ValueError:
            break
        docs.append(json.dumps(obj))
        index = end
    return docs


def parse_batch_payload(payload) -> dict[int, str]:
    """Legacy marker-stream parser — kept for API stability, superseded by
    count-aligned chunk parsing in batch_decompile."""
    out: dict[int, str] = {}
    if not payload:
        return out
    current_addr: int | None = None
    buffer = ""
    for raw_line in payload.splitlines():
        line = raw_line.rstrip()
        if line.startswith(_MARKER):
            if current_addr is not None and buffer.strip():
                parsed = parse_pdgj(buffer)
                if parsed.get("code"):
                    out[current_addr] = parsed["code"]
            try:
                current_addr = int(line[len(_MARKER):].strip(), 16)
            except ValueError:
                current_addr = None
            buffer = ""
            continue
        if current_addr is None:
            continue
        buffer += line + "\n"
    if current_addr is not None and buffer.strip():
        parsed = parse_pdgj(buffer)
        if parsed.get("code"):
            out[current_addr] = parsed["code"]
    return out


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
    """One file, one logical rizin session — implemented as one-shot spawns.

    Windows cannot drive rizin interactively over a pipe (see module
    docstring), so there is no persistent process. The seam contract is
    unchanged: `analyze()` issues `aaa`, `functions()` issues `aflj`,
    `decompile()` issues `pdgj @ <addr>`, and everything routes through
    `run()` when a runner is injected.
    """

    ENGINE_NAME = "rizin-ghidra"

    def __init__(
        self,
        file_path: str,
        exe: str | None = None,
        base: int | None = None,
        runner=None,
        cmd_timeout_secs: int = 300,
        plugin_dir: str | None = None,
    ):
        self.file_path = os.path.abspath(file_path)
        self.base = base
        self._exe = exe or rizin_binary()
        self._runner = runner
        self._cmd_timeout_secs = cmd_timeout_secs
        self._plugin_dir = plugin_dir
        self._fnlist: list[dict] | None = None
        self._sleigh = _sleighhome_for(self._exe) if self._exe else ""

    # -- lifecycle ----------------------------------------------------------

    def open(self) -> None:
        if self._runner is not None:
            return  # test seam: fake runner needs no binary
        if not self._exe:
            raise RuntimeError(
                "rizin is not provisioned. Run tools/provision_rizin.ps1 once, "
                "or set BIFROST_RIZIN_DIR."
            )
        # Nothing to hold open: every operation spawns its own rizin.

    def close(self) -> None:
        pass

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- spawn machinery ------------------------------------------------------

    def _argv(self, commands: str, target: str | None = None) -> list[str]:
        argv = [self._exe, "-q0"]
        if self.base:
            argv += ["-B", hex(self.base)]
        argv += ["-c", commands, target or self.file_path]
        return argv

    def _spawn(self, commands: str, target: str | None = None) -> str:
        """One-shot rizin run. Raises RuntimeError on non-zero exit."""
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            result = subprocess.run(
                self._argv(commands, target),
                capture_output=True, text=True,
                timeout=self._cmd_timeout_secs, creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"rizin timed out after {self._cmd_timeout_secs}s "
                f"on: {commands!r}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"failed to start rizin: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or "").strip().splitlines()
            tail = detail[-1] if detail else f"exit {result.returncode}"
            raise RuntimeError(f"rizin command failed: {commands!r} — {tail}")
        return (result.stdout or "").replace("\r\n", "\n")

    def _prelude(self) -> str:
        """Commands every spawn needs: sleighhome so rz-ghidra can speak."""
        parts = []
        if self._sleigh:
            parts.append(f"e ghidra.sleighhome={self._sleigh}")
        return "; ".join(parts)

    # -- command surface ------------------------------------------------------

    def run(self, command: str) -> str:
        if self._runner is not None:
            return self._runner(command)
        chain = "; ".join(p for p in (self._prelude(), command) if p)
        return self._spawn(chain)

    def decompiler_available(self) -> bool:
        """rz-ghidra registers `pdgs` when its plugin is loaded."""
        if self._runner is not None:
            out = self.run("pdgs")
            if not out:
                return True
            lowered = out.lower()
            if "unknown command" in lowered or "error" in lowered:
                return False
            return True
        # Real probe on a scratch file; nonzero rc means the plugin (or
        # rizin itself) is missing. A loaded plugin answers even with no
        # sleigh languages configured.
        try:
            argv = [self._exe, "-q0", "-c", "pdgs", "malloc://1024"]
            result = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return False
        if result.returncode != 0:
            return False
        lowered = (result.stdout or "").lower() + (result.stderr or "").lower()
        return "unknown command" not in lowered and "cannot open" not in lowered

    def analyze(self) -> None:
        """Auto-analysis. Results are cached inside the session so the
        follow-up functions() call needs no second spawn."""
        if self._runner is not None:
            self.run("aaa")
            return
        if self._fnlist is None:
            chain = "; ".join(p for p in (self._prelude(), "aaa; aflj") if p)
            self._fnlist = parse_aflj(self._spawn(chain))

    def functions(self) -> list[dict]:
        if self._runner is not None:
            return parse_aflj(self.run("aflj"))
        if self._fnlist is None:
            chain = "; ".join(p for p in (self._prelude(), "aaa; aflj") if p)
            self._fnlist = parse_aflj(self._spawn(chain))
        return [dict(fn) for fn in self._fnlist]

    def decompile(self, addr: int) -> dict:
        if self._runner is not None:
            payload = parse_pdgj(self.run(f"pdgj @ {addr:#x}"))
            payload["addr"] = addr
            return payload
        chain = "; ".join(
            p for p in (self._prelude(), f"aaa; pdgj @ {addr:#x}") if p
        )
        payload = parse_pdgj(self._spawn(chain))
        payload["addr"] = addr
        return payload

    def xrefs(self, addr: int) -> list[dict]:
        """Cross-references to *addr* (code + data). Empty list = none."""
        if self._runner is not None:
            return parse_axtj(self.run(f"axtj @ {addr:#x}"))
        chain = "; ".join(
            p for p in (self._prelude(), f"aaa; axtj @ {addr:#x}") if p
        )
        return parse_axtj(self._spawn(chain))

    def batch_decompile(self, addrs: list[int]) -> dict[int, str]:
        """Decompile many functions with as few spawns as possible.

        Each spawn runs `pdgj` for a chunk of addresses; every successful
        decompile prints exactly one JSON document, so documents align with
        the requested order by count. A chunk whose document count comes up
        short (a function rz-ghidra refused) is retried address-by-address —
        one slow spawn is cheaper than silently wrong results.
        """
        if not addrs:
            return {}
        if self._runner is not None:
            out: dict[int, str] = {}
            for addr in addrs:
                result = self.decompile(addr)
                if result.get("code"):
                    out[addr] = result["code"]
            return out
        results: dict[int, str] = {}
        chunk_size = 16
        for start in range(0, len(addrs), chunk_size):
            chunk = addrs[start:start + chunk_size]
            cmds = "; ".join(f"pdgj @ {addr:#x}" for addr in chunk)
            chain = "; ".join(p for p in (self._prelude(), "aaa; " + cmds) if p)
            payload = self._spawn(chain)
            docs = _split_json_docs(payload)
            if len(docs) == len(chunk):
                for addr, doc in zip(chunk, docs):
                    code = parse_pdgj(doc).get("code")
                    if code:
                        results[addr] = code
                continue
            for addr in chunk:  # desync — do them one at a time
                result = self.decompile(addr)
                if result.get("code"):
                    results[addr] = result["code"]
        return results
