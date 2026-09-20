# BIFROST SDK - IDA provisioning (optional, licensed)
# Copies a locally-licensed IDA install into gui/extra/ida so the
# analyzer can use headless batch (idat.exe -A -S). IDA is NOT
# redistributed - this just mirrors your existing license into the
# staged tree that electron-builder packs as extraFiles.
# IDA remains licensed software. This script never downloads IDA.

param(
    [string]$IdaPath = "",
    [switch]$Clear
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ExtraIda = Join-Path $Root "gui\extra\ida"
if ($Clear) {
    if (Test-Path $ExtraIda) { Remove-Item -Recurse -Force $ExtraIda; Write-Host "[+] Removed $ExtraIda" }
    else { Write-Host "[*] Nothing to clear at $ExtraIda" }
    exit 0
}
function Find-IdaExe {
    param([string]$Hint)
    if ($Hint -and (Test-Path $Hint)) {
        $d = if ((Get-Item $Hint).PSIsContainer) { $Hint } else { Split-Path -Parent $Hint }
        return (Get-Item $d).FullName
    }
    $cands = @(
        "C:\Users\howar\Downloads\IDA_Test\IDA Professional 9.1",
        "C:\Program Files\IDA Pro 9.1",
        "C:\Program Files\IDA Professional 9.1",
        "C:\Program Files\IDA",
        "C:\IDA"
    )
    foreach ($c in $cands) { if (Test-Path (Join-Path $c "idat.exe")) { return $c } }
    foreach ($c in $cands) { if (Test-Path (Join-Path $c "ida.exe")) { return $c } }
    return $null
}
$IdaDir = Find-IdaExe -Hint $IdaPath
if (-not $IdaDir) {
    Write-Host "[!] No IDA found. Checked:"
    Write-Host "    - C:\Users\howar\Downloads\IDA_Test\IDA Professional 9.1\idat.exe"
    Write-Host "    - C:\Program Files\IDA*"
    Write-Host "    Pass -IdaPath to point at idat.exe if elsewhere."
    Write-Host "    This is expected - rizin+rz-ghidra is the default engine."
    exit 0
}
$Exe = Join-Path $IdaDir "idat.exe"
if (-not (Test-Path $Exe)) { $Exe = Join-Path $IdaDir "ida.exe" }
Write-Host "[*] Found IDA at $IdaDir"
Write-Host "[*] exe: $Exe"
if (Test-Path $ExtraIda) { Remove-Item -Recurse -Force $ExtraIda }
New-Item -ItemType Directory -Force -Path $ExtraIda | Out-Null
Write-Host "[*] Staging IDA to $ExtraIda (licensed copy, not redistributed via git)..."
Copy-Item -Recurse -Force "$IdaDir\*" $ExtraIda
$hasIdat = Test-Path (Join-Path $ExtraIda "idat.exe")
$hasIda = Test-Path (Join-Path $ExtraIda "ida.exe")
if (-not $hasIdat -and -not $hasIda) {
    throw "Stage failed - no idat.exe/ida.exe at $ExtraIda"
}
Write-Host "[+] IDA staged at $ExtraIda (gitignored, packed via gui/extra to installer)"
Write-Host "    Verify: gui/extra/ida/idat.exe -h"
Write-Host "    Analyzer probe should now show ida.available=true"
Write-Host "    To clear use -Clear flag"
