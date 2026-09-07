# BIFROST SDK — one-shot build
# Produces dist/api_server.exe, gui/extra/ bundle, and the Electron installer.
#
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
#   -SkipBackend    skip the PyInstaller step (reuse existing api_server.exe)
#   -SkipSmoke      skip the packaged smoke test

param(
    [switch]$SkipBackend,
    [switch]$SkipSmoke
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "[*] BIFROST SDK build starting at $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

# ---- 1. Backend (PyInstaller) -------------------------------------------
# Run PyInstaller under the canonical interpreter (same one the smoke test
# uses below). Bare `pyinstaller` on PATH resolves to other Python installs
# (e.g. the Python 3.9 Scripts dir) whose site-packages lack iced_x86 —
# collect_submodules() then silently bundles nothing and packaged disasm
# dies with DISASM_FAILED at runtime.
$CanonicalPy = "C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if (-not $SkipBackend) {
    Write-Host "[*] Building api_server.exe via PyInstaller (canonical 3.14)..."
    & $CanonicalPy -m PyInstaller api_server.spec --noconfirm --clean
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)" }
    if (-not (Test-Path "$Root\dist\api_server.exe")) {
        throw "PyInstaller did not produce dist\api_server.exe"
    }
    Write-Host "[+] api_server.exe built"
} else {
    if (-not (Test-Path "$Root\dist\api_server.exe")) {
        throw "-SkipBackend given but dist\api_server.exe does not exist"
    }
    Write-Host "[*] Reusing existing dist\api_server.exe"
}

# ---- 2. Stage the gui/extra bundle (backend + runtime data) -------------
Write-Host "[*] Staging gui/extra bundle..."
$Extra = "$Root\gui\extra"
New-Item -ItemType Directory -Path $Extra -Force | Out-Null

Copy-Item "$Root\dist\api_server.exe" "$Extra\api_server.exe" -Force

# drivers + config live next to the exe at runtime (read from disk, not frozen)
if (Test-Path "$Extra\drivers") { Remove-Item "$Extra\drivers" -Recurse -Force }
Copy-Item "$Root\drivers" "$Extra\drivers" -Recurse -Force
if (Test-Path "$Extra\config") { Remove-Item "$Extra\config" -Recurse -Force }
Copy-Item "$Root\config" "$Extra\config" -Recurse -Force
Write-Host "[+] gui/extra staged (api_server.exe + drivers + config)"

# ---- 3. Electron build (vite + electron-builder NSIS) -------------------
Write-Host "[*] Building Electron app..."
Set-Location "$Root\gui"
npm run build
if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
Set-Location $Root

# ---- 4. Packaged smoke test ---------------------------------------------
if (-not $SkipSmoke) {
    Write-Host "[*] Running packaged smoke test..."
    & $CanonicalPy "$Root\scripts\smoke_bridge.py" --packaged
    if ($LASTEXITCODE -ne 0) { throw "Packaged smoke test failed" }
    Write-Host "[+] Smoke test passed"
}

Write-Host ""
Write-Host "[+] Build complete."
Write-Host "    Backend : dist\api_server.exe"
Write-Host "    App     : gui\dist-electron\win-unpacked\BIFROST SDK.exe"
Write-Host "    Installer: gui\dist-electron\BIFROST-SDK-4.0.0-Setup.exe"
