"""
Contract validator and loader for bifrost_protocol.json

This module is the canonical consumer of the BIFROST IPC contract.
It is used for:
- Smoke / CI validation of the protocol document itself
- Runtime enforcement hooks in api_server.py (and eventually main.js shims)

Part of Cluster 1 of the council remediation plan.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROTOCOL_PATH = Path(__file__).parent / "bifrost_protocol.json"


def load_protocol() -> dict[str, Any]:
    """Load and return the protocol document. Raises on missing/invalid JSON."""
    if not PROTOCOL_PATH.exists():
        raise FileNotFoundError(f"Protocol file not found: {PROTOCOL_PATH}")
    with PROTOCOL_PATH.open(encoding="utf-8") as f:
        return json.load(f)


# Auto-derive known commands from protocol JSON to prevent drift (council T5/T6 fix).
# Defined after load_protocol — this call used to NameError and silently fall
# back to the hardcoded lists, which kept the drift tests passing against the
# fallback instead of the contract.
def _load_command_lists() -> Tuple[List[str], List[str]]:
    """Load command names from bifrost_protocol.json. Falls back to hardcoded if file missing."""
    try:
        proto = load_protocol()
        cmds = list(proto.get("commands", {}).keys())
        streaming = list(proto.get("streaming_commands", {}).keys())
        return cmds, streaming
    except Exception:
        # Fallback for environments where protocol JSON is not available
        return (
            ["ping", "bridge_info", "list_processes", "spoof_info", "spoof_restore",
             "read_memory", "ac_detect", "test_webhook", "cancel",
             "analyze_probe", "decompile_fn", "analyzer_hexdump",
             "analyzer_disasm_at", "analyzer_xrefs"],
            ["dump", "spoof", "generate", "analyze", "analyze_export"],
        )

KNOWN_COMMANDS, KNOWN_STREAMING = _load_command_lists()


def validate_protocol_document() -> Tuple[bool, str]:
    """
    Load the protocol and perform structural + version checks suitable for v1.1 enforcement.
    Returns (ok, message).
    """
    try:
        proto = load_protocol()
    except Exception as e:
        return False, f"Failed to load: {e}"

    # Required top-level sections for v1.1
    required = ["protocol", "commands", "streaming_commands", "events", "known_limitations", "error_shape", "enforcement"]
    missing = [k for k in required if k not in proto]
    if missing:
        return False, f"Protocol missing required top-level sections: {missing}"

    pmeta = proto["protocol"]
    if pmeta.get("schema_version") != 1:
        return False, f"Unsupported schema_version: {pmeta.get('schema_version')} (expected 1)"

    version = pmeta.get("version", "")
    if not (version.startswith("1.1") or version.startswith("1.2") or version.startswith("1.3")):
        return False, f"Protocol version must be 1.1+ for enforcement (got {version})"

    # Basic command surface sanity
    cmds = proto.get("commands", {})
    streaming = proto.get("streaming_commands", {})
    if "ping" not in cmds or "dump" not in streaming:
        return False, "Core command 'ping' or streaming 'dump' missing from protocol"

    # error_shape must be defined
    if "code" not in proto.get("error_shape", {}):
        return False, "error_shape definition incomplete"

    return True, f"Protocol v{pmeta.get('version')} validated successfully (schema v{pmeta.get('schema_version')})"


def validate_command(command: str, args: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Lightweight allow-list + basic presence check.
    Intended to be called early in api_server dispatch.
    Does not yet perform deep JSON Schema validation (future iteration).
    """
    if command in KNOWN_COMMANDS:
        return True, "ok"
    if command in KNOWN_STREAMING:
        return True, "ok (streaming)"
    return False, f"Unknown or unlisted command: {command}"


def validate_roundtrip_example() -> bool:
    """Legacy smoke test name kept for backward compatibility with direct runs."""
    ok, msg = validate_protocol_document()
    if not ok:
        raise ValueError(msg)
    # Extra sanity on enforcement section (new in v1.1)
    proto = load_protocol()
    if "Cluster 1" not in proto.get("enforcement", {}).get("current_phase", ""):
        raise ValueError("enforcement.current_phase does not reference Cluster 1")
    return True


if __name__ == "__main__":
    try:
        validate_roundtrip_example()
        print("[OK] bifrost_protocol.json loaded and v1.1 enforcement validation passed.")
    except Exception as e:
        print(f"[FAIL] Protocol validation error: {e}")
        raise
