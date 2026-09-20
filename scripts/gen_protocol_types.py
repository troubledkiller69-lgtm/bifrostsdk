#!/usr/bin/env python3
"""Generate gui/src/types/protocol.d.ts from contracts/bifrost_protocol.json."""
import json, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
proto = json.loads((ROOT / "contracts/bifrost_protocol.json").read_text())
commands = list(proto.get("commands", {}).keys())
streaming = list(proto.get("streaming_commands", {}).keys())

out = pathlib.Path(ROOT / "gui/src/types/protocol.d.ts")
out.parent.mkdir(parents=True, exist_ok=True)
# Keep header stable — content above is the source of truth.
print(f"commands: {commands}")
print(f"streaming: {streaming}")
print(f"wrote {out} ({out.stat().st_size} bytes)")
