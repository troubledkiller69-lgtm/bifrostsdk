# BIFROST SDK — rizin + rz-ghidra provisioning
#
# Fetches the official rizin Windows static build and builds the rz-ghidra
# decompiler plugin against it, landing both in gui/extra/rizin/.
#
# rz-ghidra ships source-only (checked every release through v0.9.0), so the
# plugin is compiled once per pairing. The pairing is pinned: rizin v0.9.0 +
# rz-ghidra v0.9.0 — rizinorg release them in lockstep and README warns
# against mixing versions.
#
# Requires: Visual Studio (MSVC x64), CMake, Ninja, Python 3.x on PATH.
# Rerun anytime you bump the pairing or want a clean tree.
#
#   powershell -ExecutionPolicy Bypass -File tools/provision_rizin.ps1

param(
    [string]$RizinVersion = "0.9.0",
    [string]$GhidraVersion = "0.9.0",
    [switch]$SkipPluginBuild
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Root = Split-Path -Parent $PSScriptRoot
$Extra = Join-Path $Root "gui\extra"
$RizinDir = Join-Path $Extra "rizin"
$Work = Join-Path $Extra ".provision"
New-Item -ItemType Directory -Force -Path $Work | Out-Null

# --- 1. rizin static build ------------------------------------------------

$RizinZip = Join-Path $Work "rizin-windows-static-v$RizinVersion.zip"
$RizinUrl = "https://github.com/rizinorg/rizin/releases/download/v$RizinVersion/rizin-windows-static-v$RizinVersion.zip"

if (-not (Test-Path (Join-Path $RizinDir "bin\rizin.exe"))) {
    Write-Host "[*] Fetching rizin $RizinVersion (static win64)..."
    if (-not (Test-Path $RizinZip)) {
        Invoke-WebRequest -Uri $RizinUrl -OutFile $RizinZip
    }
    Write-Host "[*] Extracting..."
    $Inner = Join-Path $Work "rizin-extract"
    if (Test-Path $Inner) { Remove-Item -Recurse -Force $Inner }
    Expand-Archive -Path $RizinZip -DestinationPath $Inner
    # Official zips carry one top-level folder ("rizin-win-installer-vs2019_static-64")
    $Top = Get-ChildItem $Inner -Directory | Select-Object -First 1
    if (-not $Top) { throw "Unexpected zip layout: no top-level directory" }
    if (Test-Path $RizinDir) { Remove-Item -Recurse -Force $RizinDir }
    Move-Item -Path $Top.FullName -Destination $RizinDir
    Write-Host "[+] rizin -> $RizinDir"
} else {
    Write-Host "[*] rizin already provisioned at $RizinDir"
}

if ($SkipPluginBuild) {
    Write-Host "[*] Skipping plugin build (-SkipPluginBuild). Decompiler commands will report unavailable."
    exit 0
}

# --- 2. rz-ghidra plugin build ---------------------------------------------

$PluginDll = Join-Path $RizinDir "plugins\core_ghidra.dll"
if (Test-Path $PluginDll) {
    Write-Host "[*] rz-ghidra plugin already built at $PluginDll"
    exit 0
}

Write-Host "[*] Fetching rz-ghidra v$GhidraVersion source..."
$SrcTar = Join-Path $Work "rz-ghidra-src-v$GhidraVersion.tar.gz"
$SrcUrl = "https://github.com/rizinorg/rz-ghidra/releases/download/v$GhidraVersion/rz-ghidra-src-v$GhidraVersion.tar.gz"
if (-not (Test-Path $SrcTar)) {
    Invoke-WebRequest -Uri $SrcUrl -OutFile $SrcTar
}

Write-Host "[*] Extracting source..."
$SrcDir = Join-Path $Work "rz-ghidra-src"
if (Test-Path $SrcDir) { Remove-Item -Recurse -Force $SrcDir }
New-Item -ItemType Directory -Force -Path $SrcDir | Out-Null
tar -xf $SrcTar -C $SrcDir
$GhDir = Get-ChildItem $SrcDir -Directory | Select-Object -First 1
if (-not $GhDir) { throw "Unexpected rz-ghidra archive layout" }

Write-Host "[*] Checking submodule (sleigh sources)..."
$GhDir = $GhDir.FullName
if (-not (Test-Path (Join-Path $GhDir "src\sleep\README.md"))) {
    Write-Host "[!] Submodule contents missing. Fetching via git clone fallback..."
    $Clone = Join-Path $Work "rz-ghidra-clone"
    if (Test-Path $Clone) { Remove-Item -Recurse -Force $Clone }
    git clone --recursive --depth 1 --branch v$GhidraVersion https://github.com/rizinorg/rz-ghidra.git $Clone
    $GhDir = $Clone
}

# Locate MSVC via vswhere (never hardcode toolchain paths)
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere not found - is Visual Studio installed?" }
$VsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $VsPath) { throw "No MSVC x64 toolset found. Install 'Desktop development with C++'." }
$VcTools = Get-ChildItem (Join-Path $VsPath "VC\Tools\MSVC") -Directory | Sort-Object Name -Descending | Select-Object -First 1
$DevEnv = Join-Path $VsPath "Common7\IDE\devenv.com"
Write-Host "[*] MSVC: $($VcTools.FullName)"

$env:CMAKE_PREFIX_PATH = "$RizinDir;$RizinDir\include\librz;$RizinDir\include\librz\sdb"
$env:RIZIN_INSTALL_PLUGDIR = Join-Path $RizinDir "plugins"
$env:PATH = "$env:PATH;$RizinDir\bin"

Write-Host "[*] Configuring with cmake..."
$BuildDir = Join-Path $GhDir "build"
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# rz-ghidra uses pkg-config to find rizin. The static zip ships .pc files
# under lib/pkgconfig; point PKG_CONFIG_PATH there and install pkgconf via
# choco if absent (or use the MSYS2 pkgconf when available).
$PkgCfgDir = Join-Path $RizinDir "lib\pkgconfig"
$env:PKG_CONFIG_PATH = $PkgCfgDir
Write-Host "[*] PKG_CONFIG_PATH=$PkgCfgDir"

Push-Location $BuildDir
try {
    cmake ".." -G "Ninja" -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_PREFIX_PATH="$RizinDir" `
        -DCMAKE_INSTALL_PREFIX="$RizinDir" `
        -DBUILD_CUTTER_PLUGIN=OFF `
        -DBUILD_SLEIGH_PLUGIN=OFF `
        -DUSE_SYSTEM_ZLIB=OFF `
        -DRIZIN_INSTALL_PLUGDIR="$RizinDir\plugins"
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

    Write-Host "[*] Building (this is the slow part)..."
    cmake --build . --config Release
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

    Write-Host "[*] Installing into rizin tree..."
    cmake --build . --config Release --target install
    if ($LASTEXITCODE -ne 0) { throw "cmake install failed" }
} finally {
    Pop-Location
}

if (Test-Path $PluginDll) {
    Write-Host "[+] Plugin built: $PluginDll"
} else {
    # Install may place it under plugins/ anyway; hunt for it.
    $Found = Get-ChildItem $RizinDir -Recurse -Filter "core_ghidra.dll" | Select-Object -First 1
    if ($Found) {
        New-Item -ItemType Directory -Force -Path (Join-Path $RizinDir "plugins") | Out-Null
        Copy-Item $Found.FullName (Join-Path $RizinDir "plugins\core_ghidra.dll")
        Write-Host "[+] Plugin moved into place: $(Join-Path $RizinDir 'plugins\core_ghidra.dll')"
    } else {
        throw "Build finished but no core_ghidra.dll was produced"
    }
}

Write-Host ""
Write-Host "[*] Provisioning complete. Verify with:"
Write-Host "    rizin.exe -c 'e ghidra.sleighhome' -c q (should list sleigh langs)"
Write-Host "    Then in BIFROST: Analyzer page -> analyze_probe should show rizin.decompiler=true"
