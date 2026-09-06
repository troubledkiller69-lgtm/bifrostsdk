import sys

if sys.platform == "win32":
    import ctypes
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass
