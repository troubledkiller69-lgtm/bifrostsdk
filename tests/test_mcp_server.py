"""MCP server framing + dispatch tests (no subprocess, no backend side effects)."""
import io
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server


def _call(method, params=None, req_id=1):
    buf = io.StringIO()
    old = mcp_server._RPC_OUT
    mcp_server._RPC_OUT = buf
    try:
        mcp_server.handle({"jsonrpc": "2.0", "id": req_id, "method": method,
                           "params": params or {}})
    finally:
        mcp_server._RPC_OUT = old
    return json.loads(buf.getvalue())


def test_initialize_handshake():
    r = _call("initialize", {"protocolVersion": "2024-11-05"})
    assert r["result"]["protocolVersion"] == mcp_server.MCP_PROTOCOL
    assert r["result"]["serverInfo"]["name"] == "bifrost-sdk"
    assert "tools" in r["result"]["capabilities"]


def test_tools_list_covers_bridge():
    r = _call("tools/list")
    names = {t["name"] for t in r["result"]["tools"]}
    for expected in ("list_processes", "dump", "dump_history", "dump_diff", "make_signature", "rescan_signatures", "analyze", "decompile_fn", "analyze_export",
                     "hexdump", "disasm", "xrefs", "callgraph", "search_callsites", "symbols", "strings",
                     "read_memory", "driver_list", "driver_test", "analyze_probe"):
        assert expected in names
    for t in r["result"]["tools"]:
        assert t["description"] and t["inputSchema"]["type"] == "object"


def test_unknown_tool_is_protocol_error():
    r = _call("tools/call", {"name": "nope", "arguments": {}})
    assert r["error"]["code"] == -32602


def test_missing_arg_is_protocol_error():
    r = _call("tools/call", {"name": "decompile_fn", "arguments": {}})
    assert r["error"]["code"] == -32602


def test_unknown_method():
    r = _call("frobnicate")
    assert r["error"]["code"] == -32601


def test_notifications_get_no_response():
    buf = io.StringIO()
    old = mcp_server._RPC_OUT
    mcp_server._RPC_OUT = buf
    try:
        mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    finally:
        mcp_server._RPC_OUT = old
    assert buf.getvalue() == ""


def test_addr_coercion():
    assert mcp_server._addr("0x140001000") == 0x140001000
    assert mcp_server._addr(1234) == 1234
    assert mcp_server._addr("5678") == 5678


def test_tool_result_truncates():
    out = mcp_server._tool_result({"blob": "x" * 200_000})
    text = out["content"][0]["text"]
    assert len(text) < 110_000 and "truncated" in text


def test_log_tail_order():
    evs = [{"type": "log", "text": "a"}, {"type": "progress", "stage": "S", "pct": 50},
           {"type": "result", "data": {}}]
    tail = mcp_server._log_tail(evs)
    assert tail == ["a", "[S 50%]"]
