# BIFROST SDK — rizin + rz-ghidra provisioning
#
# Fetches the official rizin Windows SHARED build and builds the rz-ghidra
# decompiler plugin against it, landing both in gui/extra/rizin/.
#
# rz-ghidra ships source-only (checked every release through v0.9.0), so the
# plugin is compiled once per pairing. The pairing is pinned: rizin v0.9.0 +
# rz-ghidra v0.9.0 — rizinorg release them in lockstep and README warns
# against mixing versions.
#
# Why shared64 and not static: a plugin compiled against the static build's
# archives embeds a second copy of librz. Loading that into rizin gives two
# librz cores in one process — exactly the deadlock seen in the v0.9.0
# pairing (rizin sat silent on its stdin pipe). The shared64 zip ships the
# per-module DLLs plus import libs; the plugin links against those and binds
# to the already-loaded librz at runtime.
#
# Requires: Visual Studio with the MSVC x64 toolset (Desktop development with
# C++). CMake (VS-bundled or on PATH), Ninja and pkgconf are bootstrapped into
# gui/extra/.provision/tools automatically when missing.
#
# Re-run anytime you bump the pairing or want a clean tree. The rizin download,
# the extracted tree and a started plugin build all survive re-runs.
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

# --- 1. rizin shared build -------------------------------------------------

$RizinZip = Join-Path $Work "rizin-windows-shared64-v$RizinVersion.zip"
$RizinUrl = "https://github.com/rizinorg/rizin/releases/download/v$RizinVersion/rizin-windows-shared64-v$RizinVersion.zip"

if (-not (Test-Path (Join-Path $RizinDir "bin\rizin.exe"))) {
    Write-Host "[*] Fetching rizin $RizinVersion (shared win64)..."
    if (-not (Test-Path $RizinZip)) {
        Invoke-WebRequest -Uri $RizinUrl -OutFile $RizinZip
    }
    Write-Host "[*] Extracting..."
    $Inner = Join-Path $Work "rizin-extract"
    if (Test-Path $Inner) { Remove-Item -Recurse -Force $Inner }
    Expand-Archive -Path $RizinZip -DestinationPath $Inner
    # Official zips carry one top-level folder (e.g. "rizin-win-shared64")
    $Top = Get-ChildItem $Inner -Directory | Select-Object -First 1
    if (-not $Top) { throw "Unexpected zip layout: no top-level directory" }
    if (Test-Path $RizinDir) { Remove-Item -Recurse -Force $RizinDir }
    Move-Item -Path $Top.FullName -Destination $RizinDir
    Write-Host "[+] rizin -> $RizinDir"
} else {
    Write-Host "[*] rizin already provisioned at $RizinDir"
}

# --- 1b. Synthesize the rizin CMake package -------------------------------
# rz-ghidra's root CMakeLists does `find_package(Rizin REQUIRED Core)`. The
# rizin meson install normally generates lib/cmake/{Rizin,RzModules...}, but
# the official windows static zip omits the whole lib/cmake tree. Without it
# cmake configure fails immediately. We generate a minimal RizinConfig.cmake
# that maps every shipped rz_*.lib to a Rizin::<Component> imported target;
# Rizin::Core additionally links the full dependency closure read from the
# shipped rz_core.pc (its Requires/Libs lines), so no pkg-config call or
# hardcoded ordering lives in the generated file.
$RizinCmakeDir = Join-Path $RizinDir "lib\cmake\Rizin"
$RizinCmakeFile = Join-Path $RizinCmakeDir "RizinConfig.cmake"
if (-not (Test-Path $RizinCmakeFile)) {
    Write-Host "[*] Synthesizing rizin CMake package (absent from static zip)..."
    $PcDir = Join-Path $RizinDir "lib\pkgconfig"
    $CorePc = Join-Path $PcDir "rz_core.pc"
    if (-not (Test-Path $CorePc)) { throw "rz_core.pc missing - cannot synthesize Rizin CMake package" }
    $CoreLines = Get-Content $CorePc
    $RequiresLine = ($CoreLines | Where-Object { $_ -like "Requires:*" } | Select-Object -First 1)
    $LibsLine = ($CoreLines | Where-Object { $_ -like "Libs:*" } | Select-Object -First 1)
    $ReqModules = @()
    if ($RequiresLine) {
        $ReqModules = (($RequiresLine -replace "^Requires:\s*", "") -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    $SysLibs = @()
    if ($LibsLine) {
        $SysLibs = [regex]::Matches($LibsLine, "-l([A-Za-z0-9_\.]+)") | ForEach-Object { $_.Groups[1].Value }
    }
    $AllComponents = @("Analysis","Asm","Bin","Bp","Config","Cons","Core","Crypto","Debug","Demangler","Diff","Egg","Flag","Hash","Il","IO","Lang","Librz","Magic","Main","Parse","Reg","Search","Sign","Socket","Syscall","Type","Util")
    $CompBlocks = New-Object System.Text.StringBuilder
    foreach ($Comp in $AllComponents) {
        $LibName = $Comp.ToLower()
        $LibFile = Join-Path $RizinDir "lib\rz_$LibName.lib"
        if (-not (Test-Path $LibFile)) { continue }
        # All literals below are single-quoted: ${_rizin_prefix} must reach the
        # generated cmake file verbatim, never interpolate in PowerShell.
        [void]$CompBlocks.AppendLine('  add_library(Rizin::' + $Comp + ' UNKNOWN IMPORTED)')
        [void]$CompBlocks.AppendLine('  set_target_properties(Rizin::' + $Comp + ' PROPERTIES')
        if ($LibName -eq "core") {
            # INTERFACE_LINK_LIBRARIES must be ONE list-valued argument here
            # (set_target_properties pairs props with values positionally).
            $Link = New-Object System.Collections.Generic.List[string]
            $Link.Add('${_rizin_prefix}/lib/rz_core.lib')
            foreach ($M in $ReqModules) { $Link.Add('${_rizin_prefix}/lib/' + $M + '.lib') }
            foreach ($S in $SysLibs) {
                if ($S -ne "rz_core" -and $ReqModules -notcontains $S) { $Link.Add($S) }
            }
            $LinkStr = $Link -join ";"
            [void]$CompBlocks.AppendLine('    IMPORTED_LOCATION "${_rizin_prefix}/lib/rz_core.lib"')
            [void]$CompBlocks.AppendLine('    INTERFACE_LINK_LIBRARIES "' + $LinkStr + '"')
        } else {
            [void]$CompBlocks.AppendLine('    IMPORTED_LOCATION "${_rizin_prefix}/lib/rz_' + $LibName + '.lib"')
        }
        [void]$CompBlocks.AppendLine('    INTERFACE_INCLUDE_DIRECTORIES "${_rizin_prefix}/include/librz;${_rizin_prefix}/include/librz/sdb")')
    }
    $Tmpl = @'
# BIFROST-generated rizin CMake package (see tools/provision_rizin.ps1).
# The official rizin windows static zip ships no lib/cmake tree; upstream
# meson installs would provide this. Mirrors librz/RizinConfig.cmake.in for
# find_package(Rizin COMPONENTS Core) consumers like rz-ghidra.
set(Rizin_VERSION 0.9.0)
if(NOT Rizin_FIND_COMPONENTS)
  set(Rizin_FIND_COMPONENTS Core)
endif()
get_filename_component(_rizin_prefix "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
__COMPONENTS__
set(Rizin_FOUND TRUE)
set(Rizin_PLUGINDIR "lib/rizin/plugins")
'@
    $Tmpl = $Tmpl.Replace("__COMPONENTS__", $CompBlocks.ToString())
    New-Item -ItemType Directory -Force -Path $RizinCmakeDir | Out-Null
    [System.IO.File]::WriteAllText($RizinCmakeFile, $Tmpl, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Wrote $RizinCmakeFile"
} else {
    Write-Host "[*] Rizin CMake package already present at $RizinCmakeFile"
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

Write-Host "[*] Checking submodule contents..."
$GhDir = $GhDir.FullName
# The release src tarball is built AFTER `git submodule update` (see
# .github/workflows/dist.yml), so ghidra/ and third-party/pugixml are inline.
# Markers: ghidra/ghidra is a plain (NSA-layout) Ghidra checkout — its root
# has gradle files, no CMakeLists.txt; the build needs the Decompiler C++
# tree. pugixml is vendored under third-party/. (v0.9.0 has no src/sleep.)
$HasGhidra = Test-Path (Join-Path $GhDir "ghidra\ghidra\Ghidra\Features\Decompiler\src\decompile\cpp")
$HasPugixml = Test-Path (Join-Path $GhDir "third-party\pugixml\src\pugixml.cpp")
if (-not ($HasGhidra -and $HasPugixml)) {
    Write-Host "[!] Submodule contents missing. Fetching via git clone fallback..."
    $Clone = Join-Path $Work "rz-ghidra-clone"
    if (Test-Path $Clone) { Remove-Item -Recurse -Force $Clone }
    # Ghidra's Java source trees blow past MAX_PATH on checkout; longpaths
    # must be on for the submodule checkout or the clone dies mid-way.
    git -c core.longpaths=true clone --recursive --depth 1 --branch v$GhidraVersion https://github.com/rizinorg/rz-ghidra.git $Clone
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

# --- 2a. MSVC env (Ninja needs cl.exe on PATH; vswhere discovery alone is
# not enough). Same mechanism as upstream CI's msvc-dev-cmd/vsdevenv.ps1.
$DevShellModule = Join-Path $VsPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
if (-not (Test-Path $DevShellModule)) { throw "DevShell module not found: $DevShellModule" }
Import-Module $DevShellModule
Enter-VsDevShell -VsInstallPath $VsPath -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64 -no_logo"
Write-Host "[*] MSVC x64 environment active"

# --- 2b. Toolchain bootstrap (cmake / ninja / pkgconf). Everything self-
# contained under .provision\tools so no machine-wide installs are needed.
$ToolsBin = Join-Path $Work "tools\bin"
New-Item -ItemType Directory -Force -Path $ToolsBin | Out-Null

$CmakeExe = $null
if ($env:CMAKE_BIN -and (Test-Path $env:CMAKE_BIN)) { $CmakeExe = $env:CMAKE_BIN }
if (-not $CmakeExe) { $CmakeExe = (Get-Command cmake.exe -ErrorAction SilentlyContinue).Source }
if (-not $CmakeExe) {
    $VsCmake = Join-Path $VsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path $VsCmake) { $CmakeExe = $VsCmake }
}
if (-not $CmakeExe) { throw "cmake not found. Set CMAKE_BIN, install CMake, or enable the VS 'CMake tools' component." }
Write-Host "[*] cmake: $CmakeExe"

$NinjaExe = (Get-Command ninja.exe -ErrorAction SilentlyContinue).Source
if (-not $NinjaExe) {
    $NinjaZip = Join-Path $Work "ninja-win-v1.13.2.zip"
    $NinjaDir = Join-Path $Work "tools\ninja"
    if (-not (Test-Path (Join-Path $NinjaDir "ninja.exe"))) {
        Write-Host "[*] Fetching ninja (official release zip)..."
        if (-not (Test-Path $NinjaZip)) {
            Invoke-WebRequest -Uri "https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-win.zip" -OutFile $NinjaZip
        }
        if (Test-Path $NinjaDir) { Remove-Item -Recurse -Force $NinjaDir }
        Expand-Archive -Path $NinjaZip -DestinationPath $NinjaDir
    }
    $NinjaExe = Join-Path $NinjaDir "ninja.exe"
}
Write-Host "[*] ninja: $NinjaExe"
Copy-Item -Force $NinjaExe (Join-Path $ToolsBin "ninja.exe")

# pkgconf: rz-ghidra v0.9.0's cmake resolves rizin via RizinConfig.cmake (no
# find_package(PkgConfig) in-tree), but several rizin helpers and any .pc
# consumer still want a pkg-config on PATH; upstream CI calls pkg-config
# directly. Bootstrap the official pkgconf MSI (admin-extract, no install).
$PkgCfgProbe = (Get-Command pkg-config.exe -ErrorAction SilentlyContinue).Source
if (-not $PkgCfgProbe) { $PkgCfgProbe = (Get-Command pkgconf.exe -ErrorAction SilentlyContinue).Source }
if (-not $PkgCfgProbe) {
    $PkgMsi = Join-Path $Work "pkgconf-x64-3.0.7.msi"
    if (-not (Test-Path $PkgMsi)) {
        Write-Host "[*] Fetching pkgconf (official x64 MSI)..."
        Invoke-WebRequest -Uri "https://github.com/pkgconf/pkgconf/releases/download/pkgconf-3.0.7/pkgconf-x64-3.0.7.msi" -OutFile $PkgMsi
    }
    $PkgX = Join-Path $Work "tools\pkgconf"
    $Found = Get-ChildItem $PkgX -Recurse -Filter "pkgconf.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $Found) {
        Write-Host "[*] Extracting pkgconf (msiexec administrative install)..."
        $P = Start-Process msiexec.exe -ArgumentList "/a `"$PkgMsi`" /qn TARGETDIR=`"$PkgX`"" -Wait -PassThru
        if ($P.ExitCode -ne 0) { throw "pkgconf MSI admin extract failed (exit $($P.ExitCode))" }
        $Found = Get-ChildItem $PkgX -Recurse -Filter "pkgconf.exe" | Select-Object -First 1
    }
    if (-not $Found) { throw "pkgconf extracted but pkgconf.exe not found under $PkgX" }
    $PkgCfgProbe = $Found.FullName
}
Write-Host "[*] pkg-config: $PkgCfgProbe"
Copy-Item -Force $PkgCfgProbe (Join-Path $ToolsBin "pkgconf.exe")
Copy-Item -Force $PkgCfgProbe (Join-Path $ToolsBin "pkg-config.exe")

$env:PATH = "$ToolsBin;$env:PATH"
$env:PKG_CONFIG = Join-Path $ToolsBin "pkgconf.exe"

$env:CMAKE_PREFIX_PATH = "$RizinDir;$RizinDir\include\librz;$RizinDir\include\librz\sdb"
$env:RIZIN_INSTALL_PLUGDIR = Join-Path $RizinDir "plugins"
$env:PATH = "$env:PATH;$RizinDir\bin"

Write-Host "[*] Configuring with cmake..."
$BuildDir = Join-Path $GhDir "build"
if (Test-Path (Join-Path $BuildDir "CMakeCache.txt")) {
    # Re-run (e.g. after an interrupted build): keep the cache so the ninja
    # build resumes instead of restarting from zero.
    Write-Host "[*] Reusing existing build dir (interrupted run resumes): $BuildDir"
} else {
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}

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

# rizin 0.9 scans <prefix>/lib/rizin/plugins by default (see `rizin -hh`:
# RZ_LIB_PLUGINS). Mirror the plugin there so plain rizin invocations (no
# env var, other tooling) pick it up as well.
$LibPluginsDir = Join-Path $RizinDir "lib\rizin\plugins"
New-Item -ItemType Directory -Force -Path $LibPluginsDir | Out-Null
Copy-Item -Force (Join-Path $RizinDir "plugins\core_ghidra.dll") (Join-Path $LibPluginsDir "core_ghidra.dll")
if (Test-Path (Join-Path $RizinDir "plugins\core_ghidra.lib")) {
    Copy-Item -Force (Join-Path $RizinDir "plugins\core_ghidra.lib") (Join-Path $LibPluginsDir "core_ghidra.lib")
}
Write-Host "[+] Plugin mirrored to $LibPluginsDir (default rizin scan dir)"

Write-Host ""
Write-Host "[*] Provisioning complete. Verify with:"
Write-Host "    rizin.exe -c 'e ghidra.sleighhome' -c q (should list sleigh langs)"
Write-Host "    Then in BIFROST: Analyzer page -> analyze_probe should show rizin.decompiler=true"
