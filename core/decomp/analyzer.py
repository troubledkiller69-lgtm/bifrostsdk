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
try:
    from .ida_engine import (
        find_ida_exe, ida_available, ida_version, ida_analyze, _IdaCancelled,
    )
except Exception:
    find_ida_exe = lambda: None
    ida_available = lambda: False
    ida_version = lambda exe=None: ""
    ida_analyze = None
    class _IdaCancelled(RuntimeError):
        pass

_DEFAULT_FN_LIMIT = 400
_EXPORT_FN_CAP = 500        # hard cap for the batch export pass
_CACHE_CAP = 512            # decompiled-body cache entries per session
_IDLE_TIMEOUT_SECS = 300    # close abandoned rizin sessions after 5 min

# One live session per backend process (analyzer module is imported once).
CURRENT = {
    "session": None,          # RizinSession or None (None for ida batch / iced)
    "source": None,           # dict describing what was loaded
    "engine": None,           # 'rizin-ghidra' | 'ida' | 'iced-x86'
    "cache": {},              # addr(int) -> {"code","name"}
    "symbols": {},            # name(str) -> addr(int) — full binary fn map
    "functions": [],          # ranked function list (ida export needs it sans session)
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
        CURRENT["symbols"] = {}
        CURRENT["functions"] = []
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
    ida_exe = find_ida_exe()
    out = {
        "rizin": {
            "available": exe is not None,
            "exe": exe or "",
            "version": rizin_version(exe) if exe else "",
            "decompiler": False,
        },
        "ida": {
            # exe-found only: IDA Pro needs a one-time ida.exe activation +
            # EULA accept before batch runs work headless. A real analyze is
            # the only true verification — failures now explain themselves.
            "available": bool(ida_exe and ida_available()),
            "exe": ida_exe or "",
            "version": ida_version(ida_exe) if ida_exe else "",
            "batch_verified": False,
        },
        "iced": {"available": True},
        "default_engine": "rizin-ghidra" if exe else ("ida" if ida_exe else "iced-x86"),
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
    if source.get("engine") == "ida":
        return _analyze_ida(file_path, extra, sink, limit)

    # Auto-pick: rizin-ghidra first (we ship it), IDA if user has it and rizin missing
    exe = rizin_binary()
    if not exe:
        ida_exe = find_ida_exe()
        if ida_exe and ida_available() and ida_analyze:
            sink.log(f"rizin missing — trying IDA at {ida_exe}", "warn")
            try:
                return _analyze_ida(file_path, extra, sink, limit)
            except Exception as exc:
                sink.log(f"IDA batch failed ({exc}) — falling back to iced-x86", "warn")
        else:
            sink.log(
                "rizin engine not provisioned — falling back to iced-x86 linear "
                "disassembly (no decompiler). Run tools/provision_rizin.ps1 once "
                "for full Ghidra decompilation.",
                "warn",
            )
        return _analyze_iced(file_path, extra, sink)

    return _analyze_rizin(file_path, extra, sink, limit)


def _analyze_ida(file_path: str, extra: dict, sink: LogSink, limit: int) -> dict:
    ida_exe = find_ida_exe()
    if not ida_exe or not ida_analyze:
        raise RuntimeError("IDA not found — checked Downloads\\IDA_Test and Program Files")
    sink.progress("Opening", 5)
    sink.log(f"ida: {ida_exe}")
    sink.log("Running IDA auto-analysis (batch)... this is the slow part (first run on a real binary can take 5-15 min; Cancel works)")
    sink.progress("Analysis", 10)
    try:
        # Decompile bodies for the top-N in the same run (hexrays) —
        # IDA is one-shot, so there is no second chance per function.
        data = ida_analyze(file_path, timeout=1500,
                           cancel=sink.cancelled, log=lambda t: sink.log(t, "info"),
                           decompile_limit=min(max(1, int(limit)), 100))
    except Exception as exc:
        if isinstance(exc, _IdaCancelled) or "cancelled" in str(exc).lower():
            raise _Cancelled("IDA batch cancelled") from exc
        raise
    functions = data.get("functions") or []
    imagebase = data.get("imagebase")
    bodies = data.get("bodies") or {}
    has_decompiler = bool(data.get("decompiler")) and len(bodies) > 0
    if data.get("db_reused"):
        sink.log("IDA database cache hit — incremental analysis, should be fast")
    sink.log(f"IDA found {len(functions)} functions (imagebase {imagebase:#x} if mapped)")
    if bodies:
        sink.log(f"IDA decompiled {len(bodies)} functions via hexrays")
    elif not data.get("decompiler"):
        sink.log("IDA hexrays unavailable — function list only, no bodies", "warn")

    # Rank like rizin: named first biggest, anonymous >=8 bytes
    named = [f for f in functions if f["name"]]
    anonymous = sorted((f for f in functions if not f["name"] and f["size"] >= 8), key=lambda f: f["size"], reverse=True)
    ranked = sorted(named, key=lambda f: f["size"], reverse=True) + anonymous
    trimmed = ranked[: max(1, int(limit))]

    # No persistent session for IDA batch — but bodies serve from cache,
    # and the ranked list is kept so export works without a session.
    _close_current()
    with CURRENT["lock"]:
        CURRENT["session"] = None
        CURRENT["source"] = {"file": file_path, **extra}
        CURRENT["engine"] = "ida"
        CURRENT["functions"] = list(trimmed)
        CURRENT["cache"] = {}
        CURRENT["symbols"] = {f["name"]: f["addr"] for f in functions if f.get("name")}
        for addr, code in bodies.items():
            if len(CURRENT["cache"]) >= _CACHE_CAP:
                break
            name = next((f["name"] for f in trimmed if f["addr"] == addr), "")
            CURRENT["cache"][addr] = {"code": code, "name": name}

    sink.progress("Loaded", 100)
    return {
        "engine": "ida",
        "decompiler": has_decompiler,
        "session": False,
        "ida_exe": ida_exe,
        "file": file_path,
        "size": os.path.getsize(file_path),
        "base": extra.get("base") or imagebase,
        "functions": trimmed,
        "total_functions": len(functions),
        "bodies": len(bodies),
    }


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
    with CURRENT["lock"]:
        # Full name map for clickable identifiers in decompiled bodies.
        # The GUI only receives `trimmed` below; this keeps every name
        # resolvable so any sub_140001000 in the C text can become a link.
        CURRENT["symbols"] = {
            f["name"]: f["addr"] for f in functions if f.get("name")
        }

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
    need the addr — the session remembers its file.

    IDA batch has no live session: bodies decompiled during analyze serve
    straight from cache. Anything not in cache was outside the top-N batch —
    re-analyze won't help (same top-N); it needs the rizin engine instead.
    """
    if not isinstance(addr, int) or addr <= 0:
        return {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}
    with CURRENT["lock"]:
        session = CURRENT["session"]
        source = CURRENT["source"]
        engine = CURRENT["engine"]
        if source is None:
            return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
        cache = CURRENT["cache"]
        if addr in cache:
            return {"addr": addr, **cache[addr]}
        if session is None:
            if engine == "ida":
                return {"error": "Not in the IDA batch top-N — decompile it with the rizin engine instead.", "code": "NOT_DECOMPILED"}
            return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}

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


def _current_context() -> tuple:
    """(file_path, base, session, engine) from CURRENT, no raises."""
    with CURRENT["lock"]:
        source = CURRENT["source"]
        if source is None:
            return (None, None, None, None)
        return (
            source.get("file"),
            source.get("base"),
            CURRENT["session"],
            CURRENT["engine"],
        )


def hexdump_at(addr: int, size: int = 256) -> dict:
    """Hex + ASCII rows for *size* bytes at *addr* in the open image.

    Rows are [{addr, hex, ascii}] with 16 bytes each, IDA-hexdump style.
    Works for any analyzed source — this is a plain file read, no rizin.
    """
    if not isinstance(addr, int) or addr <= 0:
        return {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}
    if not isinstance(size, int) or size <= 0 or size > 0x1000:
        return {"error": "size must be 1..4096", "code": "BAD_ARGS"}
    file_path, base, _session, _engine = _current_context()
    if not file_path:
        return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}

    from . import image_map

    window = image_map.va_to_window(file_path, base, addr, size)
    if not window.get("ok"):
        return {"error": window.get("error", "mapping failed"), "code": "UNMAPPED"}
    try:
        with open(file_path, "rb") as f:
            f.seek(window["offset"])
            data = f.read(window["length"])
    except OSError as exc:
        return {"error": f"read failed: {exc}", "code": "READ_FAILED"}
    if not data:
        return {"error": "nothing to read at that address", "code": "READ_FAILED"}

    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart.ljust(16 * 3 - 1) if i + 16 < len(data) else hexpart
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append({
            "addr": addr + i,
            "hex": hexpart,
            "ascii": ascii_part,
        })
    return {"addr": addr, "size": len(data), "arch": window["arch"], "rows": rows}


def disasm_at(addr: int, size: int = 128) -> dict:
    """Linear disassembly at *addr* in the open image (iced-x86).

    Deliberately rizin-free — the explorer should answer in milliseconds
    while scrolling, not in spawn seconds. Best-effort on junk bytes: the
    decode stops at the first invalid instruction.
    """
    if not isinstance(addr, int) or addr <= 0:
        return {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}
    if not isinstance(size, int) or size <= 0 or size > 0x1000:
        return {"error": "size must be 1..4096", "code": "BAD_ARGS"}
    file_path, base, _session, _engine = _current_context()
    if not file_path:
        return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}

    from . import disasm, image_map

    window = image_map.va_to_window(file_path, base, addr, size)
    if not window.get("ok"):
        return {"error": window.get("error", "mapping failed"), "code": "UNMAPPED"}
    try:
        with open(file_path, "rb") as f:
            f.seek(window["offset"])
            data = f.read(window["length"])
    except OSError as exc:
        return {"error": f"read failed: {exc}", "code": "READ_FAILED"}
    if not data:
        return {"error": "nothing to disassemble at that address", "code": "READ_FAILED"}
    try:
        lines = disasm.disasm_region(data, addr, arch=window["arch"])
    except disasm.IcedError as exc:
        return {"error": str(exc), "code": "DISASM_FAILED"}
    return {"addr": addr, "arch": window["arch"], "lines": lines}


def xrefs_at(addr: int) -> dict:
    """Cross-references to *addr* — rizin axtj. Needs the rizin engine."""
    if not isinstance(addr, int) or addr <= 0:
        return {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}
    file_path, _base, session, engine = _current_context()
    if not file_path:
        return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
    if engine != "rizin-ghidra" or session is None:
        return {"error": "xrefs need rizin (axtj). Re-analyze with rizin provisioned.", "code": "NO_RIZIN"}
    try:
        xrefs = session.xrefs(addr)
    except Exception as exc:
        return {"error": f"xref scan failed: {exc}", "code": "XREFS_FAILED"}
    return {"addr": addr, "xrefs": xrefs}


def callgraph_at(addr: int) -> dict:
    """Callers + callees of the function at *addr* — rizin only.

    Callers come from axtj (CALL type), callees from pdfj. Names resolve
    through the session symbol map; unknown targets stay bare addresses.
    IDA batch has no live rizin session — re-analyze with rizin for graphs.
    """
    if not isinstance(addr, int) or addr <= 0:
        return {"error": f"Invalid address: {addr}", "code": "BAD_ARGS"}
    file_path, _base, session, engine = _current_context()
    if not file_path:
        return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
    if engine != "rizin-ghidra" or session is None:
        return {"error": "call graph needs rizin (pdfj/axtj). Re-analyze with rizin provisioned.", "code": "NO_RIZIN"}
    with CURRENT["lock"]:
        symbols_map = dict(CURRENT["symbols"])
    addr_name = {a: n for n, a in symbols_map.items()}
    try:
        callees = session.calls(addr)
    except Exception as exc:
        return {"error": f"callee scan failed: {exc}", "code": "CALLS_FAILED"}
    try:
        refs = session.xrefs(addr)
    except Exception as exc:
        return {"error": f"caller scan failed: {exc}", "code": "XREFS_FAILED"}
    callers = [
        {"from": x["from"], "name": addr_name.get(x["from"], "")}
        for x in refs if str(x.get("type", "")).upper() == "CALL"
    ]
    return {
        "addr": addr,
        "name": addr_name.get(addr, ""),
        "calls": [{"addr": c, "name": addr_name.get(c, "")} for c in callees],
        "called_by": callers,
    }


_SEARCH_TARGETS_CAP = 25   # max string/import hits to xref (each costs a spawn)
_SEARCH_REFS_CAP = 100     # max code references returned


def search_callsites(query: str, cap: int = _SEARCH_REFS_CAP) -> dict:
    """Where is `query` used? Searches import names + string contents, then
    xrefs each hit to find the code that references it.

    Returns {query, imports:[{name, lib, plt}], strings:[{addr, text}],
    references:[{target, target_name, from, from_name, type}]}. Rizin only —
    strings come from the file scan, imports + xrefs from one-shot spawns.
    Bounded: at most 25 targets xref'd, refs stop at `cap`.
    """
    if not isinstance(query, str) or not query.strip():
        return {"error": "Missing search query", "code": "BAD_ARGS"}
    query = query.strip()
    if len(query) > 128:
        return {"error": "Query too long (max 128)", "code": "BAD_ARGS"}
    if not isinstance(cap, int) or cap < 1 or cap > 500:
        return {"error": "cap must be 1..500", "code": "BAD_ARGS"}
    file_path, _base, session, engine = _current_context()
    if not file_path:
        return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
    if engine != "rizin-ghidra" or session is None:
        return {"error": "call-site search needs rizin (iij/axtj). Re-analyze with rizin provisioned.", "code": "NO_RIZIN"}

    q = query.lower()
    with CURRENT["lock"]:
        symbols_map = dict(CURRENT["symbols"])
    addr_name = {a: n for n, a in symbols_map.items()}

    # 1. imports matching the query (one spawn)
    try:
        all_imports = session.imports()
    except Exception as exc:
        return {"error": f"import scan failed: {exc}", "code": "IMPORTS_FAILED"}
    imports = [i for i in all_imports if q in i["name"].lower()][:25]

    # 2. strings matching the query (pure file scan, no spawn)
    strings_hit = strings_all(min_len=4, cap=2000)
    if strings_hit.get("error"):
        return {"error": strings_hit["error"], "code": strings_hit.get("code", "STRINGS_FAILED")}
    strings = [s for s in strings_hit["strings"] if q in s["text"].lower()][:25]

    # 3. xref each hit (bounded — each is a ~3s spawn)
    targets = ([(i["plt"], i["name"]) for i in imports if i["plt"]] +
               [(s["addr"], s["text"][:48]) for s in strings])[:_SEARCH_TARGETS_CAP]
    references = []
    scanned = 0
    for target, target_name in targets:
        if len(references) >= cap:
            break
        scanned += 1
        try:
            refs = session.xrefs(target)
        except Exception:
            continue
        for x in refs:
            if len(references) >= cap:
                break
            references.append({
                "target": target,
                "target_name": target_name,
                "from": x["from"],
                "from_name": addr_name.get(x["from"], ""),
                "type": str(x.get("type", "UNKNOWN")),
            })

    return {
        "query": query,
        "imports": imports,
        "imports_total": len([i for i in all_imports if q in i["name"].lower()]),
        "strings": [{"addr": s["addr"], "text": s["text"][:128]} for s in strings],
        "references": references,
        "targets_scanned": scanned,
        "truncated": len(references) >= cap,
    }


def symbols() -> dict:
    """Full name -> addr map for the open session.

    Populated during analyze from the complete rizin function list (the
    GUI gets a trimmed view, this is the whole binary). Used to turn
    function identifiers in decompiled C into clickable jumps. Lazy
    fallback refetches aflj if the map is empty but a session exists.
    """
    with CURRENT["lock"]:
        session = CURRENT["session"]
        source = CURRENT["source"]
        engine = CURRENT["engine"]
        if source is None:
            return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
        if session is None and engine != "ida":
            return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
        symbols_map = dict(CURRENT["symbols"])
    if not symbols_map and engine == "rizin-ghidra":
        try:
            functions = session.functions()
            symbols_map = {f["name"]: f["addr"] for f in functions if f.get("name")}
            with CURRENT["lock"]:
                CURRENT["symbols"] = dict(symbols_map)
        except Exception as exc:
            return {"error": f"symbol scan failed: {exc}", "code": "SYMBOLS_FAILED"}
    return {"count": len(symbols_map), "symbols": symbols_map, "engine": engine}


def strings_all(min_len: int = 6, cap: int = 2000) -> dict:
    """IDA-style strings table scan across the whole open image.

    Pure file scan (no rizin spawn) — ASCII runs plus UTF-16LE, mapped to
    VAs through the image section map so every hit can feed the address
    explorer. `cap` bounds the returned rows; scanning stops at it.
    """
    if not isinstance(min_len, int) or min_len < 1 or min_len > 64:
        return {"error": "min_len must be 1..64", "code": "BAD_ARGS"}
    if not isinstance(cap, int) or cap < 1 or cap > 10000:
        return {"error": "cap must be 1..10000", "code": "BAD_ARGS"}
    with CURRENT["lock"]:
        source = CURRENT["source"]
        if source is None:
            return {"error": "No analysis session open. Run an analyze job first.", "code": "NO_SESSION"}
        file_path = source.get("file")
        base = source.get("base")
    if not file_path or not os.path.isfile(file_path):
        return {"error": "analysis file is missing from disk", "code": "NO_SESSION"}

    from . import image_map
    import re

    windows = image_map.scan_windows(file_path, base)
    if not windows:
        return {"error": "unsupported image: no section map (raw dump needs a base)", "code": "UNMAPPED"}

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    # Windows share the cap fairly. Scanned in address order, .text always
    # comes first and pure-code byte runs would otherwise crowd out the
    # actual strings sitting in .rdata/.data.
    per_window = max(1, cap // max(1, len(windows)))

    def junk_ascii(text: str) -> bool:
        # Code-noise runs are uniform byte garbage without word shape —
        # 't!f;T$(w' and 'SUVWATAUAVAWH' are opcode accidents. Keep runs
        # with a real separator (space/path/dot/underscore) or lowercase
        # vowels, which byte noise almost never spells ('kernel32',
        # 'GetFileType'). Long runs stay regardless.
        if len(text) >= 20:
            return False
        if any(c in text for c in " /\\:._"):
            return False
        return not any(c in text for c in "aeiouy")

    rows = []
    try:
        with open(file_path, "rb") as f:
            for off_start, va_start, length in windows:
                window_rows = 0
                f.seek(off_start)
                data = f.read(length)
                # ASCII runs
                for m in ascii_re.finditer(data):
                    text = m.group().decode("latin-1")
                    if junk_ascii(text):
                        continue
                    rows.append({
                        "addr": va_start + m.start(),
                        "offset": off_start + m.start(),
                        "size": m.end() - m.start(),
                        "enc": "ascii",
                        "text": text,
                    })
                    window_rows += 1
                    if window_rows >= per_window:
                        break
                if len(rows) >= cap:
                    break
                # UTF-16LE runs (skip where an ASCII twin already covered it)
                for m in wide_re.finditer(data):
                    text = m.group().decode("utf-16-le", errors="ignore")
                    rows.append({
                        "addr": va_start + m.start(),
                        "offset": off_start + m.start(),
                        "size": m.end() - m.start(),
                        "enc": "wide",
                        "text": text,
                    })
                    window_rows += 1
                    if window_rows >= per_window:
                        break
                if len(rows) >= cap:
                    break
    except OSError as exc:
        return {"error": f"read failed: {exc}", "code": "READ_FAILED"}

    rows.sort(key=lambda r: r["addr"])
    return {"count": len(rows), "min_len": min_len, "strings": rows}


def export_functions(sink: LogSink, limit: int = _EXPORT_FN_CAP, format: str = "split") -> dict:
    """Batch-decompile the top *limit* functions to disk.

    format 'split' (default): one .c file per function + index.json.
    format 'single': all functions concatenated into bundle.c + index.json.
    IDA batch has no session — exports straight from the analyze-time cache.
    """
    with CURRENT["lock"]:
        session = CURRENT["session"]
        source = CURRENT["source"]
        engine = CURRENT["engine"]
        if source is None or (session is None and engine != "ida"):
            raise RuntimeError("No analysis session open")
        file_path = source.get("file", "")
        base = source.get("base")
        ida_cached = dict(CURRENT["cache"]) if session is None else None
        ida_functions = list(CURRENT.get("functions") or []) if session is None else None

    out_dir = os.path.join(
        os.path.dirname(os.path.abspath(file_path)), "decomp"
    )
    os.makedirs(out_dir, exist_ok=True)

    if session is None:
        # IDA path: ranked list + bodies cached at analyze time
        functions = ida_functions or []
        results = {addr: body["code"] for addr, body in (ida_cached or {}).items()
                   if body.get("code")}
        sink.log(f"exporting {len(functions)} cached IDA functions to {out_dir}")
    else:
        functions = session.functions()
    ranked = sorted(
        [f for f in functions if f["name"] or f["size"] >= 8],
        key=lambda f: f["size"], reverse=True,
    )
    chosen = ranked[: max(1, min(int(limit), _EXPORT_FN_CAP))]
    fmt = str(format or "split").lower()
    if fmt not in ("split", "single"):
        raise ValueError(f"Unknown export format: {format!r} (split|single)")
    sink.log(f"exporting {len(chosen)} functions to {out_dir} [{fmt}]")

    # One rizin spawn for the whole batch — per-fn spawns would cost
    # ~3s x N. Markers in the stream keep partial failures in place.
    # (IDA path already filled `results` from the analyze-time cache.)
    if session is not None:
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

    def _display_name(fn) -> str:
        addr = fn["addr"]
        name = fn["name"]
        if not name:
            name = f"sub_{addr - base:#x}" if base else f"sub_{addr:#x}"
        return _slug(name)

    written = []
    total = len(chosen)
    for index, fn in enumerate(chosen):
        if sink.cancelled():
            raise _Cancelled("export cancelled")
        addr = fn["addr"]
        code = results.get(addr)
        if not code:
            continue
        name = _display_name(fn)
        header = (f"// {fn['name'] or '(anonymous)'} @ {addr:#x} "
                  f"size {fn['size']}\n")
        if fmt == "split":
            path = os.path.join(out_dir, f"{index + 1:04d}_{name}.c")
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(header)
                f.write(code)
                f.write("\n")
            written.append({"addr": addr, "name": name, "path": path})
        else:
            written.append({"addr": addr, "name": name, "code": header + code})
        with CURRENT["lock"]:
            CURRENT["cache"][addr] = {"code": code, "name": fn["name"]}
        sink.progress("Decompiling", 50 + int(50 * (index + 1) / total))

    files_out = written
    bundle_path = ""
    if fmt == "single" and written:
        bundle_path = os.path.join(out_dir, "bundle.c")
        with open(bundle_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"// BIFROST bundle — {len(written)} functions\n")
            for w in written:
                f.write(f"\n// ==== {w['name']} @ {w['addr']:#x} ====\n")
                f.write(w.pop("code"))
                f.write("\n")
                w["path"] = bundle_path
        files_out = written

    # index.json in both modes: addr/name/size/path for tooling
    import json as _json2

    index = [
        {"addr": w["addr"], "name": w["name"],
         "size": next((fn["size"] for fn in chosen if fn["addr"] == w["addr"]), 0),
         "path": w["path"]}
        for w in files_out
    ]
    index_path = os.path.join(out_dir, "index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        _json2.dump({"count": len(index), "format": fmt, "functions": index}, f, indent=1)

    sink.progress("Done", 100)
    return {"count": len(files_out), "dir": out_dir, "files": files_out,
            "format": fmt, "index": index_path,
            **({"bundle": bundle_path} if bundle_path else {})}


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
            CURRENT["symbols"] = {}


class _Cancelled(RuntimeError):
    pass
