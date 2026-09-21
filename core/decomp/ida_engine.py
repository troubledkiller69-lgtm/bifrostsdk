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
# decompile the top-N biggest functions (BIFROST_IDA_DECOMP_N, default 50).
# Per-function failures are skipped — a thunk without pseudocode still
# leaves its entry in the function list.
bodies = {{}}
decompiler = False
try:
    n = int(os.environ.get("BIFROST_IDA_DECOMP_N", "50"))
except ValueError:
    n = 50
if n > 0:
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            decompiler = True
    except Exception:
        decompiler = False
if decompiler:
    for fn in funcs[:max(0, n)]:
        try:
            cfunc = ida_hexrays.decompile(fn["addr"])
            if cfunc is None: continue
            code = str(cfunc)
            if len(code) > 100000:
                code = code[:100000] + "\n/* ... truncated at 100KB ... */"
            bodies[str(fn["addr"])] = code
        except Exception:
            continue
payload = {{"imagebase": int(imgbase), "functions": funcs, "count": len(funcs),
            "decompiler": decompiler, "bodies": bodies, "bodies_count": len(bodies)}}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
idaapi.qexit(0)
""")

class _IdaCancelled(RuntimeError):
    pass


# ------------------------------------------------------------------
# Database reuse: IDA's auto-analysis is the slow part (5-15 min on a
# real binary). Keep the .idb set in %TEMP%/bifrost_ida_cache/<sha256>/
# keyed by file hash + size + IDA exe, so re-analyzing an unchanged
# binary goes incremental. The cache restores next to the target before
# the run and moves back after; anything else still gets deleted.
# ------------------------------------------------------------------

def _ida_cache_dir() -> str:
    d = os.path.join(tempfile.gettempdir(), "bifrost_ida_cache")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _file_fingerprint(file_path: str) -> str | None:
    """sha256 + size of the target. 12MB hashes in ~50ms — negligible."""
    try:
        import hashlib
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return f"{h.hexdigest()}_{os.path.getsize(file_path)}"
    except OSError:
        return None


def _cache_slot(file_path: str, exe: str) -> str | None:
    fp = _file_fingerprint(file_path)
    if not fp:
        return None
    exe_tag = os.path.basename(exe).lower().replace(".exe", "")
    safe = "".join(c if (c.isalnum() or c in "_-") else "_" for c in exe_tag)[:32]
    slot = os.path.join(_ida_cache_dir(), f"{fp[:32]}_{safe}")
    try:
        os.makedirs(slot, exist_ok=True)
    except OSError:
        return None
    return slot


def _restore_cached_idb(file_path: str, slot: str) -> bool:
    """Copy the cached .idb set next to the target. True if anything restored."""
    stem, _ = os.path.splitext(os.path.basename(file_path))
    target_dir = os.path.dirname(os.path.abspath(file_path))
    restored = False
    try:
        names = os.listdir(slot)
    except OSError:
        return False
    if not any(n.startswith(stem) for n in names):
        return False  # slot belongs to a different filename — don't mix
    for n in names:
        if n == "meta.json" or not n.startswith(stem):
            continue
        try:
            import shutil
            shutil.copy2(os.path.join(slot, n), os.path.join(target_dir, n))
            restored = True
        except OSError:
            pass
    return restored


def _store_idb_to_cache(file_path: str, slot: str, before: set) -> None:
    """Move newly-created IDA files next to the target into the cache slot."""
    stem, _ = os.path.splitext(os.path.basename(file_path))
    target_dir = os.path.dirname(os.path.abspath(file_path))
    fp = _file_fingerprint(file_path)
    try:
        names = os.listdir(target_dir)
    except OSError:
        return
    for n in names:
        if n in before or not n.startswith(stem):
            continue
        if not n[len(stem):].lower() in _IDB_EXTS:
            continue
        try:
            import shutil
            shutil.move(os.path.join(target_dir, n), os.path.join(slot, n))
        except OSError:
            pass
    try:
        with open(os.path.join(slot, "meta.json"), "w", encoding="utf-8") as f:
            json.dump({"file": os.path.basename(file_path), "fp": fp}, f)
    except OSError:
        pass


_IDB_EXTS = (".idb", ".i64", ".til", ".nam", ".id0", ".id1", ".id2")


def _snapshot_siblings(file_path: str) -> set:
    """Files next to the target before IDA runs, so we only clean up what we created."""
    try:
        d = os.path.dirname(os.path.abspath(file_path))
        return set(os.listdir(d))
    except OSError:
        return set()


def _cleanup_idb_droppings(file_path: str, before: set) -> None:
    """Remove IDA database files created alongside the target (keeps Downloads clean)."""
    try:
        d = os.path.dirname(os.path.abspath(file_path))
        stem, _ = os.path.splitext(os.path.basename(file_path))
        for name in os.listdir(d):
            if name in before:
                continue
            if name.startswith(stem) and name[len(stem):].lower() in _IDB_EXTS:
                try:
                    os.remove(os.path.join(d, name))
                except OSError:
                    pass
    except OSError:
        pass


_IDA_DECOMP_CAP = 300  # max functions decompiled per batch run


def ida_analyze(file_path: str, timeout: int = 1500, cancel=None, log=None,
                decompile_limit: int = 50) -> dict:
    """Run IDA batch on file_path, return {imagebase, functions, count, bodies}.

    timeout defaults to 25 min — first-time auto-analysis of a real binary
    routinely takes 5-15 min. The wait is polling (1s) so `cancel()` aborts
    promptly and `log(text)` gets a heartbeat every 60s while IDA is silent.
    decompile_limit (0..300): top-N biggest functions decompiled via hexrays
    in the same run; bodies keyed by str(addr). 0 skips decompilation.
    """
    exe = find_ida_exe()
    if not exe:
        raise RuntimeError("IDA not found — checked Downloads\\IDA_Test and Program Files")
    if not os.path.isfile(file_path):
        raise ValueError(f"File not found: {file_path!r}")

    # temp JSON + script
    fd_json, out_json = tempfile.mkstemp(prefix="bifrost_ida_", suffix=".json")
    os.close(fd_json)
    fd_py, script_py = tempfile.mkstemp(prefix="bifrost_ida_", suffix=".py")
    before = _snapshot_siblings(file_path)
    # Reuse: restore the cached database so IDA goes incremental
    slot = _cache_slot(file_path, exe)
    reused = bool(slot) and _restore_cached_idb(file_path, slot)
    try:
        script = _IDA_SCRIPT.replace("{OUT_JSON}", out_json.replace("\\", "\\\\"))
        with os.fdopen(fd_py, "w", encoding="utf-8") as fh:
            fh.write(script)

        # IDA batch: -A autonomous, -S script (auto-creates .idb next to file)
        cmd = [exe, "-A", f"-S{script_py}", file_path]
        env = dict(os.environ)
        try:
            n = max(0, min(int(decompile_limit), _IDA_DECOMP_CAP))
        except (TypeError, ValueError):
            n = 50
        env["BIFROST_IDA_DECOMP_N"] = str(n)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env)
        elapsed = 0
        rc = None
        try:
            while True:
                rc = proc.poll()
                if rc is not None:
                    break
                if cancel and cancel():
                    proc.kill()
                    try:
                        proc.wait(timeout=10)
                    except Exception:
                        pass
                    raise _IdaCancelled("IDA batch cancelled")
                if elapsed >= timeout:
                    proc.kill()
                    try:
                        proc.wait(timeout=10)
                    except Exception:
                        pass
                    raise TimeoutError(
                        f"IDA batch timed out after {timeout}s on "
                        f"{os.path.basename(file_path)} — binary may need longer; "
                        f"retry or analyze a smaller module first"
                    )
                if elapsed and elapsed % 60 == 0 and log:
                    try:
                        log(f"IDA still analyzing… ({elapsed // 60}m elapsed, no output yet — this is normal for first-run auto-analysis)")
                    except Exception:
                        pass
                import time as _time
                _time.sleep(1)
                elapsed += 1
        finally:
            # Reap pipes so no handle leaks even on raise paths
            try:
                _out, _err = proc.communicate(timeout=5)
            except Exception:
                _out, _err = b"", b""
        # IDA may still emit JSON even if returncode !=0
        if not os.path.isfile(out_json) or os.path.getsize(out_json) == 0:
            out = ((_out or b"").decode(errors="ignore")[:800]
                   + (_err or b"").decode(errors="ignore")[:800])
            raise RuntimeError(f"IDA batch produced no JSON (rc={rc}): {out[:400]}")

        with open(out_json, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # normalize
        funcs = data.get("functions") or []
        for f in funcs:
            # ensure addr int
            f["addr"] = int(f["addr"])
            f["size"] = int(f.get("size", 0))
        data["functions"] = funcs
        # bodies arrive keyed by str(addr) — normalize to int keys
        raw_bodies = data.get("bodies") or {}
        bodies = {}
        for k, code in raw_bodies.items():
            try:
                bodies[int(k)] = str(code)
            except (TypeError, ValueError):
                continue
        data["bodies"] = bodies
        data["ida_exe"] = exe
        data["db_reused"] = bool(reused)
        return data
    finally:
        for p in (out_json, script_py):
            try: os.remove(p)
            except: pass
        if slot:
            # Move the database into the cache (keeps the target dir clean
            # AND makes the next run incremental)
            _store_idb_to_cache(file_path, slot, before)
            _cleanup_idb_droppings(file_path, before)  # stragglers
        else:
            _cleanup_idb_droppings(file_path, before)
