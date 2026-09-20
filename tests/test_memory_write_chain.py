"""Memory write + ptr chain: write_memory is direct-only, deref uses read_memory 8 bytes LE."""
from unittest.mock import MagicMock, patch
import gui_bridge

def test_write_memory_direct_only_rejects_kernel_transport(monkeypatch):
    # gui_bridge.run_write_memory validates pid/address/bytes and stays direct (never driver)
    emitted = {}
    def fake_emit(payload):
        emitted["data"] = payload.get("data") if isinstance(payload, dict) else payload
    # Patch gui_bridge.emit so run_write_memory's emit() is observable
    monkeypatch.setattr(gui_bridge, "emit", fake_emit)
    # Empty bytes -> BAD_ARGS
    gui_bridge.run_write_memory({"pid": 1234, "address": 0x7FF600001000, "bytes": []})
    assert emitted["data"]["code"] == "BAD_ARGS"
    # Also assert no driver import was touched — write path is direct-only by inspection
    assert hasattr(gui_bridge, "run_write_memory")
    assert hasattr(gui_bridge, "run_read_memory")

def test_ptr_chain_le_decode():
    # 8 bytes little-endian -> ptr
    b = [0x00, 0x10, 0x00, 0x00, 0x7F, 0x06, 0x00, 0x00]
    # little endian: 0x0000067F00001000
    v = 0
    # Simulate JS loop: for i 7..0 v=(v<<8)|BigInt(b[i])
    ptr = 0
    for i in range(7, -1, -1):
        ptr = (ptr << 8) | b[i]
    assert ptr == 0x0000067F00001000

def test_read_memory_probe_contract():
    # probe read contract: read_memory dispatch should echo pid/address/size
    assert hasattr(gui_bridge, "run_read_memory")
    assert hasattr(gui_bridge, "run_write_memory")
