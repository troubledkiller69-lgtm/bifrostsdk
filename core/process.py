"""
BIFROST SDK — Process Enumerator & Engine Detector
Lists running processes and attempts to auto-detect the game engine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import psutil


@dataclass
class GameProcess:
    """Represents a detected game process."""
    pid: int
    name: str
    exe_path: str
    engine: Optional[str] = None  # "unreal5", "unity_mono", "unity_il2cpp", "source", None
    engine_modules: list[str] = None

    def __post_init__(self):
        if self.engine_modules is None:
            self.engine_modules = []


# Module signatures used to fingerprint the engine
ENGINE_SIGNATURES: dict[str, dict] = {
    "blizzard": {
        "indicator_modules": [
            "Overwatch.exe", "OverwatchOB.exe",
        ],
        "indicator_dlls": [],
        "required_exports": [],
        "process_names": ["overwatch.exe", "overwatchob.exe"],
    },
    "source_eac": {
        "indicator_modules": [
            "r5apex.exe", "EasyAntiCheat_EOS.dll",
        ],
        "indicator_dlls": ["tier0.dll"],
        "required_exports": [],
        "process_names": ["r5apex.exe"],
    },
    "unreal5": {
        "indicator_modules": [
            "UnrealEditor.dll", "UE4Editor.dll",
        ],
        "indicator_dlls": [],
        "required_exports": [],
        "heuristic_strings": [
            "GIsRequestingExit", "FNamePool", "FUObjectArray",
        ],
    },
    "unity_mono": {
        "indicator_modules": [
            "mono.dll", "mono-2.0-bdwgc.dll",
        ],
        "indicator_dlls": ["UnityPlayer.dll"],
        "required_exports": [],
    },
    "unity_il2cpp": {
        "indicator_modules": [
            "GameAssembly.dll",
        ],
        "indicator_dlls": ["UnityPlayer.dll"],
        "required_exports": [],
    },
    "source": {
        "indicator_modules": [
            "client.dll", "engine.dll", "server.dll",
        ],
        "indicator_dlls": ["tier0.dll", "vstdlib.dll"],
        "required_exports": [],
    },
}


class ProcessEnumerator:
    """Enumerate running processes and detect game engines."""

    _window_titles: dict = None  # pid -> title cache

    @classmethod
    def _collect_window_titles(cls) -> dict:
        """Map visible top-level window titles to their PIDs (one ctypes pass)."""
        if cls._window_titles is not None:
            return cls._window_titles
        titles: dict = {}
        try:
            import ctypes
            user32 = ctypes.windll.user32
            EnumWindowsProc = ctypes.WINFUNCTYPE(
                ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

            def _cb(hwnd, _):
                if not user32.IsWindowVisible(hwnd):
                    return True
                length = user32.GetWindowTextLengthW(hwnd)
                if length == 0:
                    return True
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                title = buf.value.strip()
                if title and pid.value:
                    titles[pid.value] = title
                return True

            user32.EnumWindows(EnumWindowsProc(_cb), 0)
        except Exception:
            pass
        cls._window_titles = titles
        return titles

    @staticmethod
    def list_all() -> list[dict]:
        """Return all running processes as dicts (with window titles)."""
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = p.info
                procs.append({
                    "pid": info["pid"],
                    "name": info["name"] or "?",
                    "exe": info["exe"] or "",
                })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        titles = ProcessEnumerator._collect_window_titles()
        for p in procs:
            p["window"] = titles.get(p["pid"], "")
        return sorted(procs, key=lambda x: x["name"].lower())

    @staticmethod
    def find_by_name(name: str) -> list[dict]:
        """Find processes matching *name* (case-insensitive substring)."""
        needle = name.lower()
        return [
            p for p in ProcessEnumerator.list_all()
            if needle in p["name"].lower()
        ]

    @staticmethod
    def detect_engine(pid: int) -> GameProcess:
        """
        Inspect a process's loaded modules and return a GameProcess
        with engine detection filled in.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess) as exc:
            raise RuntimeError(f"Cannot access pid {pid}: {exc}")

        # Gather loaded module names (lowercase)
        try:
            loaded = {os.path.basename(dll.path).lower() for dll in proc.memory_maps()}
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            loaded = set()

        # If psutil memory_maps fails (common without elevation), try a
        # lightweight ctypes fallback later when we attach via pymem.
        # For now, check what we have.

        detected_engine: Optional[str] = None
        matched_modules: list[str] = []

        # Check each engine signature
        for engine_key, sig in ENGINE_SIGNATURES.items():
            # Check indicator modules
            for mod in sig["indicator_modules"]:
                if mod.lower() in loaded:
                    detected_engine = engine_key
                    matched_modules.append(mod)
                    break
            if detected_engine:
                break

        # Heuristic: if we only have Unity indicators, distinguish Mono vs IL2CPP
        if detected_engine is None:
            if "unityplayer.dll" in loaded:
                if "gameassembly.dll" in loaded:
                    detected_engine = "unity_il2cpp"
                    matched_modules.append("GameAssembly.dll")
                elif any(m in loaded for m in ("mono.dll", "mono-2.0-bdwgc.dll")):
                    detected_engine = "unity_mono"
                    matched_modules.append("mono.dll")

        # Heuristic: if nothing matched, default UE5 guess for shipping builds
        # (many UE5 shipping exes don't have obvious DLL names)
        # We'll confirm later with pattern scans.

        return GameProcess(
            pid=pid,
            name=name,
            exe_path=exe,
            engine=detected_engine,
            engine_modules=matched_modules,
        )

    @staticmethod
    def get_main_module_path(pid: int) -> Optional[str]:
        """
        Return the full filesystem path of the process's main executable.

        Used by SWF locator to find the install directory of AIR-based games
        (the .swf files live alongside the .exe). Returns None if the
        process is gone or we lack permission to read its path.

        psutil.Process.exe() wraps PSAPI's GetModuleFileNameExW on Windows;
        no need for direct ctypes plumbing.
        """
        try:
            return psutil.Process(pid).exe() or None
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None

    @staticmethod
    def detect_engine_from_modules(module_list: list[dict]) -> Optional[str]:
        """
        Given a list of module dicts (from MemoryReader.list_modules()),
        detect the engine. More reliable than psutil since it uses
        an attached handle.
        """
        names = {m["name"].lower() for m in module_list}

        # Blizzard (Overwatch 2)
        if "overwatch.exe" in names or "overwatchob.exe" in names:
            return "blizzard"
        # Apex Legends (Source + EAC)
        if "r5apex.exe" in names:
            return "source_eac"
        if "easyanticheat_eos.dll" in names and "tier0.dll" in names:
            return "source_eac"
        # Unity IL2CPP
        if "gameassembly.dll" in names and "unityplayer.dll" in names:
            return "unity_il2cpp"
        # Unity Mono
        if ("mono.dll" in names or "mono-2.0-bdwgc.dll" in names) and "unityplayer.dll" in names:
            return "unity_mono"
        # Source 2
        if "engine2.dll" in names:
            return "source"
        # Source 1
        if "client.dll" in names and "engine.dll" in names:
            return "source"
        # Unreal — check for common UE modules
        for n in names:
            if "unrealcefsubprocess" in n or "ue4" in n.lower():
                return "unreal5"
        return None
