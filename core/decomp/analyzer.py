"""
BIFROST SDK — analyzer orchestration.

Coordinates the two engines behind one job surface:

  * rizin-ghidra: load image -> auto-analysis -> function list -> per-fn
    decompile (each operation is a one-shot rizin spawn; results cache on
    the analyzer side so repeat decompile calls are cheap)
  * iced-x86: linear disassembly fallback (no decompiler)

One logical session is tracked at a time (`CURRENT`): a new analyze()
replaces the old source, and decompile requests that don't match the open
file get NO_SESSION. Idle sessions are closed so abandoned state can't
leak rizin child processes.
"""

from __future__ import annotations

import os
import threading

from .rizin_engine import (
    RizinSession,
    find_rizin_dir,
    rizin_binary,
    rizin_version,
)

_DEFAULT_FN_LIMIT = 400
_EXPORT_FN_CAP = 500        # hard cap for the batch export pass
_CACHE_CAP = 512            # decompiled-body cache entries per session
_IDLE_TIMEOUT_SECS = 300    # close abandoned rizin sessions after 5 min

# One live session per backend process (analyzer module is imported once).
CURRENT = {
    "session": None,          # RizinSession or None
    "source": None,           # dict describing what was loaded
    "engine": None,           # 'rizin-ghidra' | 'iced-x86'
    "cache": {},              # addr(int) -> {"code","name"}
    "lock": threading.Lock(),
}


class LogSink:
    """Adapter that turns bridge callbacks into no-ops when absent."""

    def __init__(self, logger=None, progress=None, cancel=None):
        self._logger = logger or (lambda text, level="info": None)
        self._progress = progress or (lambda stage, pct: None)
        self._cancel = cancel or (lambda: False)

    def log(self, text, level="info"):
        self._logger(text, level)

    def progress(self, stage, pct):
        self._progress(stage, pct)

    def cancelled(self) -> bool:
        return bool(self._cancel())


def _default_plugin_dir(rizin_dir: str | None) -> str | None:
    if not rizin_dir:
        return None
    cand = os.path.join(rizin_dir, "plugins")
    return cand if os.path.isdir(cand) else None


def _close_current():
    with CURRENT["lock"]:
        session = CURRENT["session"]
        CURRENT["session"] = None
        CURRENT["source"] = None
        CURRENT["engine"] = None
        CURRENT["cache"] = {}
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        return session


def close_session():
    """Public close — used by cancel paths and shutdown hooks."""
    return _close_current()


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------

def _path_for_source(source: dict) -> tuple[str, dict]:
    """Resolve *source* to an on-disk file the engines can open.

    Returns (file_path, extra) where extra carries {base} for raw module
    dumps. `reader` is consumed here: module images are dumped to disk and
    the reader is closed by the caller.
    """
    stype = source.get("type")
    if stype == "file":
        path = source.get("path", "")
        if not path or not os.path.isfile(path):
            raise ValueError(f"File not found: {path!r}")
        return os.path.abspath(path), {}
    if stype == "module":
        reader = source.get("reader")
        if reader is None:
            raise ValueError("module source requires an attached reader")
        name = source.get("module") or source.get("name") or ""
        if not name:
            raise ValueError("module source requires a module name")
        import tempfile

        from .module_io import dump_module

        # The bridge passes its output root through; fall back to the temp
        # dir so a misconfigured caller never writes next to the repo.
        out_dir = source.get("module_out_dir") or tempfile.gettempdir()
        os.makedirs(out_dir, exist_ok=True)
        target = os.path.join(out_dir, f"{os.path.splitext(os.path.basename(name))[0]}.bin")
        stats = dump_module(
            reader,
            name,
            target,
            cancel_check=source.get("cancel_check"),
        )
        if not stats.get("complete"):
            raise RuntimeError(
                f"Module image incomplete: {stats['bytes_read']}/{stats['size']} "
                f"bytes ({stats['missing_chunks']} unreadable chunks)"
            )
        return os.path.abspath(target), {"base": stats["base"], "module": name}
    raise ValueError(f"Unknown source type: {stype!r}")


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

def probe() -> dict:
    """What can this backend do right now? Cheap — no process spawned when
    rizin is missing; version + plugin checks run against the real binary
    only when present."""
    exe = rizin_binary()
    rz_dir = find_rizin_dir()
    out = {
        "rizin": {
            "available": exe is not None,
            "exe": exe or "",
            "version": rizin_version(exe) if exe else "",
            "decompiler": False,
        },
        "iced": {"available": True},
        "default_engine": "rizin-ghidra" if exe else "iced-x86",
    }
    if exe:
        try:
            with RizinSession(
                "malloc://1024", exe=exe, plugin_dir=_default_plugin_dir(rz_dir)
            ) as session:
                out["rizin"]["decompiler"] = session.decompiler_available()
        except Exception:
            out["rizin"]["decompiler"] = False
    return out


# ---------------------------------------------------------------------------
# Analyze job
# ---------------------------------------------------------------------------

def analyze(source: dict, sink: LogSink, limit: int = _DEFAULT_FN_LIMIT) -> dict:
    """Full analyze pass. Returns the result dict for the bridge to emit."""
    file_path, extra = _path_for_source(source)

    if source.get("engine") == "iced":
        return _analyze_iced(file_path, extra, sink)

    exe = rizin_binary()
    if not exe:
        sink.log(
            "rizin engine not provisioned — falling back to iced-x86 linear "
            "disassembly (no decompiler). Run tools/provision_rizin.ps1 once "
            "for full Ghidra decompilation.",
            "warn",
        )
        return _analyze_iced(file_path, extra, sink)

    return _analyze_rizin(file_path, extra, sink, limit)


def _analyze_iced(file_path: str, extra: dict, sink: LogSink) -> dict:
    """Fallback path — verify readability, report engine, no session."""
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path!r}")
    size = os.path.getsize(file_path)
    sink.log(f"iced-x86 fallback: {file_path} ({size:,} bytes)", "warn")
    sink.progress("Loaded", 100)
    return {
        "engine": "iced-x86",
        "decompiler": False,
        "session": False,
        "file": file_path,
        "size": size,
        "base": extra.get("base"),
        "functions": [],
        "warnings": [
            "iced-x86 engine is disassembly-only. Provision rizin + rz-ghidra "
            "for decompiled C output."
        ],
    }


def _analyze_rizin(file_path: str, extra: dict, sink: LogSink, limit: int) -> dict:
    rz_dir = find_rizin_dir()
    exe = rizin_binary()

    sink.progress("Opening", 5)
    sink.log(f"rizin: {exe}")
    session = RizinSession(
        file_path,
        exe=exe,
        base=extra.get("base"),
        plugin_dir=_default_plugin_dir(rz_dir),
    )
    try:
        session.open()
    except Exception as exc:
        raise RuntimeError(f"Failed to start rizin: {exc}") from exc

    # Replace any previous session with this one immediately so decompile
    # requests can never hit a half-swapped state.
    _close_current()
    with CURRENT["lock"]:
        CURRENT["session"] = session
        CURRENT["source"] = {"file": file_path, **extra}
        CURRENT["engine"] = "rizin-ghidra"
        CURRENT["cache"] = {}

    sink.log("Running auto-analysis (aaa)... this is the slow part")
    sink.progress("Analysis", 10)
    session.analyze()

    if sink.cancelled():
        raise _Cancelled("analysis cancelled")

    sink.progress("Enumerating functions", 45)
    functions = session.functions()
    sink.log(f"analysis found {len(functions)} functions")

    # Keep the useful ones: named or big enough to matter, biggest first.
    named = [f for f in functions if f["name"]]
    anonymous = sorted(
        (f for f in functions if not f["name"] and f["size"] >= 8),
        key=lambda f: f["size"], reverse=True,
    )
    ranked = sorted(named, key=lambda f: f["size"], reverse=True) + anonymous
    trimmed = ranked[: max(1, int(limit))]
    sink.log(f"listing {len(trimmed)} functions (cap {limit})")

    sink.progress("Loaded", 100)
    _schedule_idle_close()
    return {
        "engine": "rizin-ghidra",
        "decompiler": session.decompiler_available(),
        "session": True,
        "file": file_path,
        "size": os.path.getsize(file_path),
        "base": extra.get("base"),
        "functions": trimmed,
        "total_functions": len(functions),
    }


# ---------------------------------------------------------------------------
# Per-function decompile + export
# ---------------------------------------------------------------------------

def decompile_fn(addr: int) -> dict:
    """Decompile one function from the open session. Stateless callers only
    need the addr — the session remembers its file."""
    if not isinstance(addr, int) or addr <= 0:
        return {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}
    with CURRENT["lock"]:
        session = CURRENT["session"]
        source = CURRENT["source"]
        if session is None or source is None:
            return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
        cache = CURRENT["cache"]
        if addr in cache:
            return {"addr": addr, **cache[addr]}

    try:
        result = session.decompile(addr)
    except Exception as exc:
        return {"error": f"Decompiler failed: {exc}", "code": "DECOMPILE_FAILED"}

    code = result.get("code", "")
    if not code.strip():
        code = _comment_header(addr) + "/* no decompilation produced — "
        code += "function may be a thunk or data */"
    body = {"code": code, "name": ""}
    with CURRENT["lock"]:
        if len(CURRENT["cache"]) >= _CACHE_CAP and CURRENT["cache"]:
            CURRENT["cache"].pop(next(iter(CURRENT["cache"])))
        CURRENT["cache"][addr] = body
    return {"addr": addr, **body}


def _comment_header(addr: int) -> str:
    return f"// BIFROST decompile @ {addr:#x}\n"


def export_functions(sink: LogSink, limit: int = _EXPORT_FN_CAP) -> dict:
    """Batch-decompile the top *limit* functions to .c files on disk."""
    with CURRENT["lock"]:
        session = CURRENT["session"]
        source = CURRENT["source"]
        if session is None or source is None:
            raise RuntimeError("No analysis session open")
        file_path = source.get("file", "")
        base = source.get("base")

    out_dir = os.path.join(
        os.path.dirname(os.path.abspath(file_path)), "decomp"
    )
    os.makedirs(out_dir, exist_ok=True)

    functions = session.functions()
    ranked = sorted(
        [f for f in functions if f["name"] or f["size"] >= 8],
        key=lambda f: f["size"], reverse=True,
    )
    chosen = ranked[: max(1, min(int(limit), _EXPORT_FN_CAP))]
    sink.log(f"exporting {len(chosen)} functions to {out_dir}")

    # One rizin spawn for the whole batch — per-fn spawns would cost
    # ~3s x N. Markers in the stream keep partial failures in place.
    results = {}
    addrs = [fn["addr"] for fn in chosen]
    try:
        results = session.batch_decompile(addrs)
    except Exception as exc:
        sink.log(f"batch decompile failed: {exc} — falling back per function", "warn")
        for fn in chosen:
            if sink.cancelled():
                raise _Cancelled("export cancelled")
            try:
                result = session.decompile(fn["addr"])
            except Exception:
                continue
            if result.get("code"):
                results[fn["addr"]] = result["code"]

    written = []
    total = len(chosen)
    for index, fn in enumerate(chosen):
        if sink.cancelled():
            raise _Cancelled("export cancelled")
        addr = fn["addr"]
        code = results.get(addr)
        if not code:
            continue
        name = fn["name"]
        if not name:
            name = f"sub_{addr - base:#x}" if base else f"sub_{addr:#x}"
        name = _slug(name)
        path = os.path.join(out_dir, f"{index + 1:04d}_{name}.c")
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"// {fn['name'] or '(anonymous)'} @ {addr:#x} "
                    f"size {fn['size']}\n")
            f.write(code)
            f.write("\n")
        written.append({"addr": addr, "name": name, "path": path})
        with CURRENT["lock"]:
            CURRENT["cache"][addr] = {"code": code, "name": fn["name"]}
        sink.progress("Decompiling", 50 + int(50 * (index + 1) / total))

    sink.progress("Done", 100)
    return {"count": len(written), "dir": out_dir, "files": written}


def _slug(name: str) -> str:
    keep = [c if (c.isalnum() or c in "_-") else "_" for c in name]
    return "".join(keep).strip("_")[:64] or "fn"


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

def _schedule_idle_close():
    timer = threading.Timer(_IDLE_TIMEOUT_SECS, _idle_close_guard)
    timer.daemon = True
    timer.start()


def _idle_close_guard():
    # Only close if the session nobody touched in the window. The cache write
    # time approximates last use; simpler: refuse to close when cache is warm
    # is wrong (a fresh analyze restarts the timer anyway), so just close and
    # let the next request say NO_SESSION — honest and leak-free.
    session = CURRENT["session"]
    if session is not None:
        try:
            session.close()
        except Exception:
            pass
    with CURRENT["lock"]:
        if CURRENT["session"] is session:
            CURRENT["session"] = None
            CURRENT["source"] = None
            CURRENT["cache"] = {}


class _Cancelled(RuntimeError):
    pass
