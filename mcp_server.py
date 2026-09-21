#!/usr/bin/env python3
r"""BIFROST SDK — MCP server (stdio, zero dependencies).

Exposes the backend to MCP clients (Claude Code, Claude Desktop, Cursor, …)
as tools. Speaks JSON-RPC 2.0 over stdio with newline-delimited messages —
the MCP stdio transport — hand-rolled so the canonical interpreter needs no
new packages.

Every tool maps to an existing `gui_bridge.run_*` handler. Emit is
thread-local, so each call captures its own events: request/response tools
return the payload, streaming tools (dump/analyze/export) run to completion
and return the final result plus a log tail.

Usage (Claude Code):
    claude mcp add bifrost -- C:\...\pythoncore-3.14-64\python.exe C:\...\bifrostsdk\mcp_server.py

Usage (Claude Desktop config):
    {"mcpServers": {"bifrost": {"command": "<canonical python>",
                                "args": ["<repo>/mcp_server.py"]}}}

Sequential use only: the backend has one analyzer session and one shared
CANCEL_EVENT — concurrent streaming calls return BUSY, same as the GUI.
"""
from __future__ import annotations

import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gui_bridge
from gui_bridge import (
    list_processes,
    run_dump, run_dump_history, run_dump_diff, run_make_signature, run_rescan_signatures,
    run_analyze_probe, run_analyze, run_decompile_fn, run_analyze_export,
    run_hexdump_at, run_disasm_at, run_xrefs_at, run_callgraph_at, run_search_callsites, run_symbols, run_strings,
    run_read_memory, run_driver_list, run_driver_test,
)

SERVER_NAME = "bifrost-sdk"
SERVER_VERSION = "4.1.0"
MCP_PROTOCOL = "2024-11-05"

# Long enough for IDA first-run auto-analysis; streaming tools block.
STREAM_TIMEOUT_NOTE = "Blocks until the operation finishes (dumps/IDA can take 10+ min)."


def _capture(fn, args):
    """Run a gui_bridge handler with a thread-local emit hook, collect events.

    Returns (final_result_dict_or_None, all_events). The last
    {"type": "result"} event is the terminal signal; everything before it
    is progress/logs.
    """
    events = []
    gui_bridge._set_emit(events.append)
    try:
        fn(args)
    except Exception as exc:  # handlers usually emit errors instead of raising
        events.append({"type": "result", "data": {"error": str(exc), "code": "EXCEPTION"}})
    finally:
        gui_bridge._set_emit(None)
    final = None
    for ev in reversed(events):
        if isinstance(ev, dict) and ev.get("type") == "result":
            final = ev.get("data")
            break
    return final, events


def _log_tail(events, limit=30):
    tail = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "log":
            tail.append(ev.get("text", ""))
        elif ev.get("type") == "progress":
            tail.append(f"[{ev.get('stage', '')} {ev.get('pct', 0)}%]")
    return tail[-limit:]


def _tool_result(payload, events=None):
    """Shape a handler outcome as MCP content. Errors stay data, not protocol errors."""
    text = json.dumps(payload, indent=1, default=str)
    if events:
        tail = _log_tail(events)
        if tail:
            text += "\n\n--- log tail ---\n" + "\n".join(tail)
    # Cap at ~100KB so a big decompile doesn't blow the context window
    if len(text) > 100_000:
        text = text[:100_000] + "\n…[truncated at 100KB]"
    return {"content": [{"type": "text", "text": text}]}


# ---------------------------------------------------------------------------
# Tool definitions: name -> (description, json-schema, handler)
# ---------------------------------------------------------------------------

def _t_processes(a):
    # list_processes emits its result (returns None) — capture like the rest
    final, _ = _capture(lambda _a: list_processes(), a or {})
    procs = final if isinstance(final, list) else []
    return _tool_result({"count": len(procs), "processes": procs})


def _t_probe(a):
    final, ev = _capture(run_analyze_probe, a or {})
    return _tool_result(final or {"error": "no result"})


def _t_analyze(a):
    # run_analyze reads args.source{type,path,engine} + args.limit; the inner
    # analyzer picks the engine from the source dict, not top level.
    final, ev = _capture(run_analyze, {
        "source": {"type": "file", "path": a["path"],
                   **({"engine": a["engine"]} if a.get("engine") else {})},
        "limit": int(a.get("limit", 400)),
    })
    return _tool_result(final or {"error": "no result"}, ev)


def _addr(v):
    """Accept 0x-hex strings or ints from JSON (MCP clients send both)."""
    if isinstance(v, str):
        return int(v.strip(), 0)
    return int(v)


def _t_decompile(a):
    final, _ = _capture(run_decompile_fn, {"addr": _addr(a["addr"])})
    return _tool_result(final or {"error": "no result"})


def _t_export(a):
    final, ev = _capture(run_analyze_export, {
        "limit": int(a.get("limit", 500)),
        "format": str(a.get("format", "split")),
    })
    return _tool_result(final or {"error": "no result"}, ev)


def _t_hexdump(a):
    final, _ = _capture(run_hexdump_at, {"addr": _addr(a["addr"]), "size": int(a.get("size", 256))})
    return _tool_result(final or {"error": "no result"})


def _t_disasm(a):
    final, _ = _capture(run_disasm_at, {"addr": _addr(a["addr"]), "size": int(a.get("size", 128))})
    return _tool_result(final or {"error": "no result"})


def _t_xrefs(a):
    final, _ = _capture(run_xrefs_at, {"addr": _addr(a["addr"])})
    return _tool_result(final or {"error": "no result"})


def _t_callgraph(a):
    final, _ = _capture(run_callgraph_at, {"addr": _addr(a["addr"])})
    return _tool_result(final or {"error": "no result"})


def _t_search(a):
    args = {"query": str(a["query"])}
    if a.get("cap"):
        args["cap"] = int(a["cap"])
    final, _ = _capture(run_search_callsites, args)
    return _tool_result(final or {"error": "no result"})


def _t_symbols(a):
    final, _ = _capture(run_symbols, a or {})
    return _tool_result(final or {"error": "no result"})


def _t_strings(a):
    final, _ = _capture(run_strings, {
        "min_len": int(a.get("min_len", 6)),
        "cap": int(a.get("cap", 500)),
    })
    return _tool_result(final or {"error": "no result"})


def _t_readmem(a):
    addr = _addr(a["address"])
    final, _ = _capture(run_read_memory, {
        "pid": int(a["pid"]), "address": addr,
        "size": int(a.get("size", 64)),
    })
    return _tool_result(final or {"error": "no result"})


def _t_makesig(a):
    addrs = a["addresses"]
    if isinstance(addrs, str):
        addrs = [x.strip() for x in addrs.split(",") if x.strip()]
    final, _ = _capture(run_make_signature, {
        "pid": int(a["pid"]),
        "addresses": [_addr(x) for x in addrs],
        "anchor_offset": _addr(a.get("anchor_offset", 0)),
        "read_size": int(a.get("read_size", 256)),
        "verify": bool(a.get("verify", True)),
    })
    return _tool_result(final or {"error": "no result"})


def _t_rescansigs(a):
    args = {"pack": a["pack"]}
    if a.get("pid"):
        args["pid"] = int(a["pid"])
    if a.get("file"):
        args["file"] = str(a["file"])
    if a.get("image_base"):
        args["image_base"] = _addr(a["image_base"])
    if a.get("module"):
        args["module"] = str(a["module"])
    final, _ = _capture(run_rescan_signatures, args)
    return _tool_result(final or {"error": "no result"})


def _t_dump(a):
    # run_dump validates pid/name itself and emits structured errors —
    # pass through so the agent sees NO_PROCESS/BAD_ARGS, not exceptions.
    args = {
        "engine": str(a.get("engine", "auto")),
        "pid": int(a["pid"]),
        "name": str(a["name"]),
        "stealth": str(a.get("stealth", "auto")),
        "force_discovery": bool(a.get("force_discovery", True)),
        "regenerate": bool(a.get("regenerate", False)),
    }
    if a.get("driver"):
        args["driver"] = str(a["driver"])
    if a.get("webhook"):
        args["webhook"] = str(a["webhook"])
    final, ev = _capture(run_dump, args)
    return _tool_result(final or {"error": "no result"}, ev)


def _t_dumphistory(a):
    final, _ = _capture(run_dump_history, a or {})
    return _tool_result(final or {"error": "no result"})


def _t_dumpdiff(a):
    final, _ = _capture(run_dump_diff, {"old": str(a["old"]), "new": str(a["new"])})
    return _tool_result(final or {"error": "no result"})


def _t_drivers(a):
    final, _ = _capture(run_driver_list, a or {})
    return _tool_result(final or {"error": "no result"})


def _t_drivertest(a):
    final, ev = _capture(run_driver_test, {
        "driver": a["driver"], "force": bool(a.get("force", False)),
    })
    return _tool_result(final or {"error": "no result"}, ev)


_ADDR = {"type": "integer", "description": "Virtual address (decimal or 0x hex)"}

TOOLS = {
    "list_processes": (
        "List running processes (system processes filtered). Returns [{pid, name}].",
        {"type": "object", "properties": {}},
        _t_processes,
    ),
    "analyze_probe": (
        "Which decompiler engines are available (rizin/ida/iced) + default.",
        {"type": "object", "properties": {}},
        _t_probe,
    ),
    "analyze": (
        "Analyze a binary file (auto-analysis + function list). " + STREAM_TIMEOUT_NOTE,
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Absolute path to the binary"},
            "engine": {"type": "string", "enum": ["auto", "rizin", "ida", "iced"],
                       "description": "Decompiler engine (default auto: rizin → ida → iced)"},
            "limit": {"type": "integer", "description": "Function list cap 1..2000 (default 400)"},
        }, "required": ["path"]},
        _t_analyze,
    ),
    "decompile_fn": (
        "Decompile one function from the open analysis session.",
        {"type": "object", "properties": {"addr": _ADDR}, "required": ["addr"]},
        _t_decompile,
    ),
    "analyze_export": (
        "Batch-decompile top N functions to <source>/decomp/ (split .c files or single bundle.c + index.json).",
        {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Max functions 1..2000 (default 500)"},
            "format": {"type": "string", "enum": ["split", "single"], "description": "split or single bundle.c (default split)"},
        }},
        _t_export,
    ),
    "hexdump": (
        "Hex+ASCII rows at a VA in the open analysis image.",
        {"type": "object", "properties": {"addr": _ADDR, "size": {"type": "integer"}}, "required": ["addr"]},
        _t_hexdump,
    ),
    "disasm": (
        "Linear disassembly (iced-x86) at a VA in the open analysis image.",
        {"type": "object", "properties": {"addr": _ADDR, "size": {"type": "integer"}}, "required": ["addr"]},
        _t_disasm,
    ),
    "xrefs": (
        "Cross-references to a VA (needs rizin session).",
        {"type": "object", "properties": {"addr": _ADDR}, "required": ["addr"]},
        _t_xrefs,
    ),
    "callgraph": (
        "Callers + callees of one function (names resolved). Needs rizin session.",
        {"type": "object", "properties": {"addr": _ADDR}, "required": ["addr"]},
        _t_callgraph,
    ),
    "search_callsites": (
        "Find where a name is used: matches imports + strings, xrefs each hit. Rizin session needed; slow on many hits (~3s per target, max 25).",
        {"type": "object", "properties": {
            "query": {"type": "string", "description": "Case-insensitive substring (e.g. CreateFileW, password)"},
            "cap": {"type": "integer", "description": "Max code references (default 100)"},
        }, "required": ["query"]},
        _t_search,
    ),
    "symbols": (
        "Full name→addr map of the open analysis session (powers decompiled-code navigation).",
        {"type": "object", "properties": {}},
        _t_symbols,
    ),
    "strings": (
        "Scan the open analysis image for ASCII/UTF-16LE strings with VAs.",
        {"type": "object", "properties": {
            "min_len": {"type": "integer"}, "cap": {"type": "integer", "description": "Max rows (default 500)"},
        }},
        _t_strings,
    ),
    "read_memory": (
        "Read live process memory (direct attach). Needs pid + address.",
        {"type": "object", "properties": {
            "pid": {"type": "integer"}, "address": _ADDR,
            "size": {"type": "integer", "description": "Bytes (default 64)"},
        }, "required": ["pid", "address"]},
        _t_readmem,
    ),
    "make_signature": (
        "Generate AOB signatures from 1-16 known-good addresses in a live process. Returns scored candidates (tight/balanced/loose).",
        {"type": "object", "properties": {
            "pid": {"type": "integer"},
            "addresses": {"type": "array", "items": _ADDR, "description": "Known-good addresses (more = better classification)"},
            "anchor_offset": _ADDR,
            "read_size": {"type": "integer", "description": "Bytes per address, 64..4096 (default 256)"},
            "verify": {"type": "boolean", "description": "Full-process verification scan (default true; false = fast)"},
        }, "required": ["pid", "addresses"]},
        _t_makesig,
    ),
    "rescan_signatures": (
        "Revalidate a JSON signature pack against a live pid or a file on disk. Reports ok/broken/ambiguous per entry with RIP-resolved addresses.",
        {"type": "object", "properties": {
            "pack": {"type": "object", "description": "{name, module?, entries:[{name, pattern, rip?, expect?, module?}]}"},
            "pid": {"type": "integer"},
            "file": {"type": "string", "description": "Disk mode path (no game needed)"},
            "image_base": _ADDR,
            "module": {"type": "string", "description": "Default module for live mode"},
        }, "required": ["pack"]},
        _t_rescansigs,
    ),
    "dump": (
        "Dump engine offsets from a live process (Source/UE/Unity...). Blocks until done (minutes). Needs a running game + matching engine.",
        {"type": "object", "properties": {
            "engine": {"type": "string", "description": "Engine key (unreal, unity, source, ...) or auto"},
            "pid": {"type": "integer", "description": "Target process id"},
            "name": {"type": "string", "description": "Process name (e.g. cs2.exe)"},
            "stealth": {"type": "string", "enum": ["auto", "direct", "hijack", "driver", "cr3"],
                        "description": "Transport (default auto = direct attach)"},
            "driver": {"type": "string", "description": "BYO driver key (only with stealth driver/cr3)"},
            "force_discovery": {"type": "boolean", "description": "Re-run offset discovery (default true)"},
            "regenerate": {"type": "boolean", "description": "Regenerate even if dump exists (default false)"},
        }, "required": ["pid", "name"]},
        _t_dump,
    ),
    "dump_history": (
        "List archived offsets.json snapshots per game (auto-saved on every successful dump).",
        {"type": "object", "properties": {}},
        _t_dumphistory,
    ),
    "dump_diff": (
        "Offset drift between two dumps (snapshot paths or dump dirs). Same logic as scripts/compare_dumps.py.",
        {"type": "object", "properties": {
            "old": {"type": "string", "description": "Older snapshot path or dump dir"},
            "new": {"type": "string", "description": "Newer snapshot path or dump dir"},
        }, "required": ["old", "new"]},
        _t_dumpdiff,
    ),
    "driver_list": (
        "List known + BYO vulnerable-driver profiles with file presence, hash and SCM loaded status.",
        {"type": "object", "properties": {}},
        _t_drivers,
    ),
    "driver_test": (
        "Map a driver, open its device, probe one ioctl, unload. Needs Admin + SeLoadDriverPrivilege.",
        {"type": "object", "properties": {
            "driver": {"type": "string", "description": "Driver key from driver_list"},
            "force": {"type": "boolean", "description": "Skip hash mismatch (default false)"},
        }, "required": ["driver"]},
        _t_drivertest,
    ),
}


# ---------------------------------------------------------------------------
# JSON-RPC loop
# ---------------------------------------------------------------------------

_RPC_OUT = sys.stdout


def _respond(req_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result if result is not None else {}
    _RPC_OUT.write(json.dumps(msg) + "\n")
    _RPC_OUT.flush()


def _err(code, message, req_id):
    _respond(req_id, error={"code": code, "message": message})


def handle(msg):
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        _respond(req_id, {
            "protocolVersion": MCP_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
    elif method in ("notifications/initialized", "notifications/cancelled"):
        pass  # no response for notifications
    elif method == "ping":
        _respond(req_id, {})
    elif method == "tools/list":
        _respond(req_id, {"tools": [
            {"name": n, "description": d, "inputSchema": s}
            for n, (d, s, _) in TOOLS.items()
        ]})
    elif method == "tools/call":
        name = params.get("name", "")
        entry = TOOLS.get(name)
        if entry is None:
            _err(-32602, f"unknown tool: {name}", req_id)
            return
        _, _, fn = entry
        try:
            _respond(req_id, fn(params.get("arguments") or {}))
        except KeyError as exc:
            _err(-32602, f"missing argument: {exc}", req_id)
        except Exception as exc:
            _err(-32603, f"tool failed: {exc}", req_id)
    else:
        if req_id is not None:
            _err(-32601, f"method not found: {method}", req_id)


def main():
    # The backend's background threads print straight to stdout (driver
    # auto-fetcher, mapper warnings). On a stdio RPC transport any non-JSON
    # line corrupts framing, so stray prints go to stderr (which MCP clients
    # treat as logs) and only _respond writes to the real stdout.
    sys.stdout = sys.stderr
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            handle(msg)
        except Exception as exc:
            req_id = msg.get("id") if isinstance(msg, dict) else None
            if req_id is not None:
                _err(-32603, str(exc), req_id)


if __name__ == "__main__":
    main()
