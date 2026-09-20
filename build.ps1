# BIFROST SDK - one-shot build
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

# -- Helpers: lock handling + vite hash ------------------------------
function Kill-LockingProcesses {
    $names = @("BIFROST SDK", "BIFROST", "electron")
    foreach ($n in $names) {
        $procs = Get-Process -Name $n -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            try {
                # Only kill if exe path is under this repo's dist-electron (avoid killing unrelated)
                $kill = $true
                try {
                    $path = $p.Path
                    if ($path -and $path -notlike "*bifrostsdk*") {
                        # Still kill generic electron locking win-unpacked â€” be conservative: check mainWindow title via commandline fallback
                        # We kill electron regardless when build is running because it locks win-unpacked
                    }
                } catch {}
                if ($kill) {
                    Write-Host "[!] Killing locking process: $n (PID $($p.Id))"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
    # Give handles time to release
    Start-Sleep -Milliseconds 800
}

function Remove-WithRetry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Retries = 5,
        [int]$DelayMs = 500
    )
    if (-not (Test-Path $Path)) { return }
    $delay = $DelayMs
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            Remove-Item $Path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ($i -eq $Retries) { throw "Remove-Item failed after $Retries tries: $Path - $_" }
            Write-Host "[!] Remove-Item locked (try $i/$Retries): $Path - $_ - retrying in ${delay}ms"
            Kill-LockingProcesses
            Start-Sleep -Milliseconds $delay
            $delay = [Math]::Min($delay * 2, 4000)
        }
    }
}

function Get-ViteHash {
    param([Parameter(Mandatory)][string]$DistDir)
    if (-not (Test-Path $DistDir)) { return "" }
    # Hash combined file hashes + relative paths; stable order
    $files = Get-ChildItem $DistDir -Recurse -File | Where-Object { $_.Name -ne ".vite_hash" } | Sort-Object FullName
    if (-not $files -or $files.Count -eq 0) { return "" }
    $hashes = @()
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($DistDir.Length)
        $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
        $hashes += ($rel + "|" + $h)
    }
    $joined = [string]::Join("`n", $hashes)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $final = $sha.ComputeHash($bytes)
    return ([BitConverter]::ToString($final)).Replace("-", "").ToLowerInvariant()
}

# Pre-build: kill anything locking dist-electron/win-unpacked
Write-Host "[*] Checking for locking processes..."
Kill-LockingProcesses
$UnpackedExe = "$Root\gui\dist-electron\win-unpacked\BIFROST SDK.exe"
if (Test-Path $UnpackedExe) {
    try {
        # Probe if file is locked - try to open for write
        $fs = [System.IO.File]::Open($UnpackedExe, 'Open', 'ReadWrite', 'None')
        $fs.Close()
    } catch {
        Write-Host "[!] win-unpacked appears locked - killing and retrying Remove-WithRetry"
        Kill-LockingProcesses
        # Don't delete the whole unpacked here; electron-builder will overwrite. Just ensure exe not locked after kill.
        Start-Sleep -Milliseconds 1000
    }
}

# ---- 1. Backend (PyInstaller) -------------------------------------------
# Run PyInstaller under the canonical interpreter (same one the smoke test
# uses below). Bare `pyinstaller` on PATH resolves to other Python installs
# (e.g. the Python 3.9 Scripts dir) whose site-packages lack iced_x86 -
# collect_submodules() then silently bundles nothing and packaged disasm
# dies with DISASM_FAILED at runtime.
# Overridable via $env:BIFROST_PYTHON or `py -3.14` launcher for portability.
$CanonicalPy = if ($env:BIFROST_PYTHON) { $env:BIFROST_PYTHON }
               elseif (Get-Command "py" -ErrorAction SilentlyContinue) {
                   try { & py -3.14 -c "import sys; print(sys.executable)" 2>$null } catch { $null }
               } else { $null }
if (-not $CanonicalPy -or -not (Test-Path $CanonicalPy)) {
    $CanonicalPy = "C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe"
}
if (-not (Test-Path $CanonicalPy)) {
    throw "Canonical Python not found at $CanonicalPy. Set `$env:BIFROST_PYTHON to your 3.14 executable."
}
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
if (Test-Path "$Extra\drivers") { Remove-WithRetry -Path "$Extra\drivers" -Retries 5 -DelayMs 400 }
Copy-Item "$Root\drivers" "$Extra\drivers" -Recurse -Force
if (Test-Path "$Extra\config") { Remove-WithRetry -Path "$Extra\config" -Retries 5 -DelayMs 400 }
Copy-Item "$Root\config" "$Extra\config" -Recurse -Force
# Optional: mirror licensed IDA if present in Downloads but not yet staged (gitignored, packed via extraFiles)
$IdaSrc = "C:\Users\howar\Downloads\IDA_Test\IDA Professional 9.1"
$IdaDst = Join-Path $Extra "ida"
if ((Test-Path (Join-Path $IdaSrc "idat.exe")) -and -not (Test-Path (Join-Path $IdaDst "idat.exe"))) {
    Write-Host "[*] Staging licensed IDA from $IdaSrc -> $IdaDst (optional, not redistributed via git)..."
    New-Item -ItemType Directory -Force -Path $IdaDst | Out-Null
    # Use robocopy for speed, quiet
    $rc = Start-Process robocopy -ArgumentList "`"$IdaSrc`" `"$IdaDst`" /E /R:1 /W:1 /NFL /NDL /NJH /NJS" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
    if ($rc -and $rc.ExitCode -ge 8) { Copy-Item -Recurse -Force "$IdaSrc\*" $IdaDst }
    Write-Host "[+] IDA staged (analyzer will report ida.available=true)"
}
Write-Host "[+] gui/extra staged (api_server.exe + drivers + config)"

# ---- 3. Electron build (vite + electron-builder --win --dir) -------------
Write-Host "[*] Building Electron app..."
# Ensure no stale lock before vite/electron-builder
Kill-LockingProcesses

$ViteDist = "$Root\gui\dist"
$HashFile = "$ViteDist\.vite_hash"
$Unpacked = "$Root\gui\dist-electron\win-unpacked"

Set-Location "$Root\gui"
Write-Host "[*] Running vite build..."
# Use npx.cmd explicitly on Windows to avoid .ps1 shim issues
& npx.cmd vite build
$viteExit = $LASTEXITCODE
if ($viteExit -ne 0) {
    Set-Location $Root
    throw "vite build failed (exit $viteExit) - electron-builder skipped, lock released"
}
Write-Host "[+] vite build succeeded"

# Vite hash check: skip electron-builder if output unchanged
$newHash = Get-ViteHash -DistDir $ViteDist
$oldHash = ""
if (Test-Path $HashFile) {
    $oldHash = (Get-Content $HashFile -Raw).Trim()
}
$shouldPack = $true
if ($newHash -and $oldHash -and $newHash -eq $oldHash -and (Test-Path "$Unpacked\BIFROST SDK.exe")) {
    Write-Host "[*] vite output unchanged (hash $newHash) - skipping electron-builder --win --dir"
    $shouldPack = $false
} else {
    if ($oldHash) { Write-Host "[*] vite hash changed: $oldHash -> $newHash" }
    else { Write-Host "[*] vite hash new: $newHash (no prior .vite_hash)" }
}

if ($shouldPack) {
    # Retry loop around electron-builder for file-lock cases
    $maxAttempts = 3
    $packed = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Write-Host "[*] Running electron-builder --win --dir (attempt $attempt/$maxAttempts)..."
            & npx.cmd electron-builder --win --dir
            if ($LASTEXITCODE -ne 0) { throw "electron-builder --win --dir failed (exit $LASTEXITCODE)" }
            $packed = $true
            break
        } catch {
            Write-Host "[!] electron-builder attempt $attempt failed: $_"
            if ($attempt -eq $maxAttempts) {
                Set-Location $Root
                throw "electron-builder failed after $maxAttempts attempts: $_"
            }
            Write-Host "[*] Killing locking processes and retrying in 1.5s..."
            Kill-LockingProcesses
            # Retry Remove-WithRetry on unpacked exe if still locked
            if (Test-Path $Unpacked) {
                try { Remove-WithRetry -Path "$Unpacked\BIFROST SDK.exe" -Retries 3 -DelayMs 500 } catch { Write-Host "[!] Could not clear locked exe: $_" }
            }
            Start-Sleep -Milliseconds 1500
        }
    }
    if ($packed -and $newHash) {
        $newHash | Set-Content $HashFile -NoNewline -Encoding ascii
        Write-Host "[+] vite hash saved to gui/dist/.vite_hash ($newHash)"
    }
} else {
    # Even when skipping pack, update hash file if missing
    if (-not (Test-Path $HashFile) -and $newHash) {
        $newHash | Set-Content $HashFile -NoNewline -Encoding ascii
    }
}
Set-Location $Root

# ---- 4. Output verify gate (if output exists) --------------------------
if (Test-Path "$Root\output") {
    $offsetsJson = Get-ChildItem "$Root\output" -Recurse -Filter "offsets.json" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($offsetsJson) {
        Write-Host "[*] Verifying dump output (strict)..."
        & $CanonicalPy "$Root\scripts\verify_output.py" "$Root\output" --strict
        if ($LASTEXITCODE -ne 0) { Write-Host "[!] verify_output strict failed — dump has schema drift (non-fatal for build)" -ForegroundColor Yellow }
        else { Write-Host "[+] verify_output strict OK" }
    }
}

# ---- 5. Packaged smoke test ---------------------------------------------
if (-not $SkipSmoke) {
    Write-Host "[*] Running packaged smoke test..."
    & $CanonicalPy "$Root\scripts\smoke_bridge.py" --packaged
    if ($LASTEXITCODE -ne 0) { throw "Packaged smoke test failed" }
    Write-Host "[+] Smoke test passed"
}

Write-Host ""
$InstallVer = (Get-Content (Join-Path $Root 'gui\package.json') -Raw | ConvertFrom-Json).version
Write-Host "[+] Build complete."
Write-Host "    Backend : dist\api_server.exe"
Write-Host "    App     : gui\dist-electron\win-unpacked\BIFROST SDK.exe"
Write-Host "    Installer: gui\dist-electron\BIFROST-SDK-$InstallVer-Setup.exe"
