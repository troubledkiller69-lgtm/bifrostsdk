"""Local driver-blocklist posture: MS known-status + THIS machine's signals.

The enforced on-disk policy (driversipolicy.p7b) is a signed BINARY ruleset
(hashes + signer certs, no filenames), so per-driver answers come from the
curated drivers/blocklist_status.json (re-check quarterly via
https://aka.ms/VulnerableDriverBlockList). This script overlays local ground
truth that actually changes the verdict on this box:

  - HVCI (Memory Integrity) on/off — filename-qualified rules only enforce
    reliably under HVCI (CVE-2025-59033); hash rules enforce regardless.
  - CodeIntegrity Operational log: Event 3077 = a block actually fired here
    (with the filename), 3087 = HVCI readiness. Past blocks are proof.
  - Policy file size/mtime — cross-checks the quarterly refresh landed.

Usage:  python scripts/check_blocklist.py [--json]
Exit:   0 report printed, 2 nothing readable (still prints what it could).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_FILE = os.path.join(PROJECT_ROOT, "drivers", "blocklist_status.json")
POLICY_PATH = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "CodeIntegrity", "driversipolicy.p7b",
)


def _reg_value(path: str, name: str):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return val
    except Exception:
        return None


def hvci_status() -> dict:
    return {
        "hvci_enabled": _reg_value(
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
            r"\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled"),
        "vbs": _reg_value(
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity"),
    }


def policy_info() -> dict:
    try:
        st = os.stat(POLICY_PATH)
        return {
            "present": True,
            "bytes": st.st_size,
            "mtime": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d"),
        }
    except OSError:
        return {"present": False}


def past_blocks(filenames: list[str], limit: int = 200) -> dict[str, int]:
    """Count CodeIntegrity 3077/3087 events naming our files (proof of blocks)."""
    hits = {n: 0 for n in filenames}
    query = ("*[System[(EventID=3077 or EventID=3087)]]")
    try:
        proc = subprocess.run(
            ["wevtutil", "qe", "Microsoft-Windows-CodeIntegrity/Operational",
             f"/q:{query}", f"/c:{limit}", "/f:text"],
            capture_output=True, text=False, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = (proc.stdout or b"").decode("utf-8", "replace").lower()
    except Exception:
        return hits
    for name in filenames:
        hits[name] = text.count(name.lower())
    return hits


def report() -> dict:
    with open(STATUS_FILE, encoding="utf-8") as f:
        curated = json.load(f)
    names = list(curated["drivers"])
    return {
        "checked": curated["_meta"]["checked"],
        "hvci": hvci_status(),
        "policy": policy_info(),
        "past_block_events": past_blocks(names),
        "drivers": curated["drivers"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        rep = report()
    except Exception as exc:
        print(f"check_blocklist: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rep, indent=1))
        return 0
    hv = rep["hvci"]["hvci_enabled"]
    print(f"HVCI: {'ON' if hv == 1 else 'OFF' if hv == 0 else 'unknown'}  |  "
          f"policy: {rep['policy'].get('bytes', '?'):,} bytes"
          + (f" ({rep['policy'].get('mtime', '?')})" if rep["policy"].get("present") else " MISSING"))
    print(f"curated list checked {rep['checked']} — re-verify quarterly via aka.ms/VulnerableDriverBlockList")
    for name, info in rep["drivers"].items():
        ev = rep["past_block_events"].get(name, 0)
        tag = {"blocked": "XX", "gap": "GAP", "unknown": "??"}[info["status"]]
        extra = f"  <-- BLOCKED ON THIS BOX ({ev}x Event 3077)" if ev else ""
        print(f"  [{tag}] {name:24s} {info['status']:8s} {info['note']}{extra}")
    if hv != 1:
        print("note: HVCI is off here — filename-qualified rules may not enforce "
              "(CVE-2025-59033); hash rules still do. Targets with HVCI on are stricter.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
