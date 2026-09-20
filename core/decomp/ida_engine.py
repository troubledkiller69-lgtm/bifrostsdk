r"""
BIFROST — IDA bridge (optional, local install).

Prefers the copy you already have in Downloads\IDA_Test\IDA Professional 9.1
so you don't need to install system-wide. Falls back to any
C:\Program Files\IDA* install. No license bypass — if IDA won't start
headless without a valid license, we log and fall back to rizin.

Headless flow (batch):
  idat.exe -A -S<bifrost_ida_dump.py> <target>

where bifrost_ida_dump.py walks Functions(), writes JSON to %TEMP%\bifrost_ida_*.json,
and qexit. The host then reads JSON and closes.

We keep this one-shot like rizin — no persistent ida IPC.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap

_IDA_CANDIDATES = [
    r"C:\Users\howar\Downloads\IDA_Test\IDA Professional 9.1\idat.exe",
    r"C:\Users\howar\Downloads\IDA_Test\IDA Professional 9.1\ida.exe",
    r"C:\Program Files\IDA Professional 9.1\idat.exe",
    r"C:\Program Files\IDA Professional 9.1\idat64.exe",
    r"C:\Program Files\IDA Pro 9.1\idat64.exe",
    r"C:\IDA\idat64.exe",
    r"C:\IDA\idat.exe",
]

def find_ida_exe() -> str | None:
    for p in _IDA_CANDIDATES:
        if os.path.isfile(p):
            return os.path.abspath(p)
    # fuzzy scan Downloads\IDA_Test
    base = r"C:\Users\howar\Downloads\IDA_Test"
    if os.path.isdir(base):
        for root, _, files in os.walk(base):
            for f in files:
                if f.lower() in ("idat.exe", "idat64.exe", "ida.exe", "ida64.exe"):
                    cand = os.path.join(root, f)
                    # prefer idat (text batch) over gui
                    if "idat" in f.lower():
                        return os.path.abspath(cand)
            # break after first hit
            break
    return None

def ida_available() -> bool:
    exe = find_ida_exe()
    return bool(exe and os.path.isfile(exe))

def ida_version(exe: str | None = None) -> str:
    exe = exe or find_ida_exe()
    if not exe:
        return ""
    try:
        r = subprocess.run([exe, "-h"], capture_output=True, text=True, timeout=6)
        out = (r.stdout or "") + (r.stderr or "")
        # first line like "IDA Professional 9.1"
        for line in out.splitlines():
            if "IDA" in line:
                return line.strip()[:64]
        return out[:64].strip()
    except Exception:
        return ""

# ------------------------------------------------------------------
# One-shot dump: run IDA headless, emit functions JSON
# ------------------------------------------------------------------

_IDA_SCRIPT = textwrap.dedent(r"""
import json, os, idaapi, ida_funcs, ida_nalt, idautils
out = r"{OUT_JSON}"
info = idaapi.get_inf_structure()
imgbase = ida_nalt.get_imagebase()
funcs = []
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if not f: continue
    name = ida_funcs.get_func_name(ea) or ""
    size = int(f.end_ea - f.start_ea)
    funcs.append({{"addr": int(f.start_ea), "end": int(f.end_ea), "size": size, "name": name}})
# sort biggest first for consistency with rizin path
funcs.sort(key=lambda x: x["size"], reverse=True)
payload = {{"imagebase": int(imgbase), "functions": funcs, "count": len(funcs)}}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
idaapi.qexit(0)
""")

def ida_analyze(file_path: str, timeout: int = 120) -> dict:
    """Run IDA batch on file_path, return {imagebase, functions, count}."""
    exe = find_ida_exe()
    if not exe:
        raise RuntimeError("IDA not found — checked Downloads\\IDA_Test and Program Files")
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path!r}")

    # temp JSON + script
    fd_json, out_json = tempfile.mkstemp(prefix="bifrost_ida_", suffix=".json")
    os.close(fd_json)
    fd_py, script_py = tempfile.mkstemp(prefix="bifrost_ida_", suffix=".py")
    try:
        script = _IDA_SCRIPT.replace("{OUT_JSON}", out_json.replace("\\", "\\\\"))
        with os.fdopen(fd_py, "w", encoding="utf-8") as fh:
            fh.write(script)

        # IDA batch: -A autonomous, -S script
        # idat needs -c to create database, but auto-creates .idb next to file
        cmd = [exe, "-A", f"-S{script_py}", file_path]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        # IDA may still emit JSON even if returncode !=0
        if not os.path.isfile(out_json) or os.path.getsize(out_json) == 0:
            out = (r.stdout or b"").decode(errors="ignore")[:800] + (r.stderr or b"").decode(errors="ignore")[:800]
            raise RuntimeError(f"IDA batch produced no JSON (rc={r.returncode}): {out[:400]}")

        with open(out_json, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # normalize
        funcs = data.get("functions") or []
        for f in funcs:
            # ensure addr int
            f["addr"] = int(f["addr"])
            f["size"] = int(f.get("size", 0))
        data["functions"] = funcs
        data["ida_exe"] = exe
        return data
    finally:
        for p in (out_json, script_py):
            try: os.remove(p)
            except: pass
        # IDA creates .idb / .til alongside target — leave them, caller cleans
