# BIFROST SDK — Quick Start

A universal SDK offset dumper with an Electron GUI frontend and Python backend.
Supports Unreal Engine 5, Unity (Mono/IL2CPP), Source 1, Source 2, and Blizzard engines.

## Prerequisites

- **Python 3.10+** with pip
- **Node.js 18+** with npm
- **Windows 10/11 x64** (required for memory access APIs)
- **Administrator privileges** (required for `OpenProcess` on protected games)

## Development Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install dev/test dependencies (optional, for running tests)
pip install -r requirements-dev.txt

# 3. Install Node dependencies
cd gui
npm install

# 4. Run in development mode (Vite + Electron)
npm run dev
```

The app opens at `localhost:5173` and the Electron window launches automatically.

## Running Tests

```bash
# From project root
python -m pytest tests/ -v
```

## Verifying the Bridge

```bash
# Smoke test — exercises the stdio JSON IPC protocol
python scripts/smoke_bridge.py
```

## Production Build

```powershell
# One-shot build (backend + installer + smoke gate)
powershell -ExecutionPolicy Bypass -File build.ps1
```

Output: `gui/dist-electron/win-unpacked/BIFROST SDK.exe`
Installer: `gui/dist-electron/BIFROST-SDK-4.0.0-Setup.exe`

## Project Structure

```
bifrostsdk/
  api_server.py         # JSON IPC dispatcher (stdin/stdout)
  api_server.spec       # PyInstaller spec
  build.ps1             # one-shot build script
  gui_bridge.py         # Command router, business logic
  core/                 # Memory readers, scanners, stealth
  engines/              # Engine-specific dumpers (UE5, Unity, Source, etc.)
  contracts/            # IPC protocol schema + validator
  gui/                  # Electron + React frontend
  tests/                # pytest test suite
  scripts/              # Smoke test
  output/               # Dump artifacts
```

## Key Commands

| GUI Page | What it does |
|----------|--------------|
| Engines | Select the game engine type |
| Processes | Enumerate and select a running game |
| Dump | Execute the offset dump |
| Results | View dumped classes, fields, offsets |
| Spoofer | Hardware ID spoofing |
| Boilerplate | Generate C++ project from dump data |
| Driver Hunter | Search for vulnerable signed drivers |
| Diff | Compare two dump outputs |
| Memory Viewer | Hex view of process memory |
| AC Monitor | Anti-cheat detection status |
| Config Editor | Edit engine config profiles |
| Settings | Discord webhook, preferences |
