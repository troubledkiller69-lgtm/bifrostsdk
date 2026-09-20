param([switch]$Strict)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot/.."
$extra = Join-Path $root "gui/extra"
$rizin = Join-Path $extra "rizin/bin/rizin.exe"
$ida = Join-Path $extra "ida/idat.exe"
$ok = $true
function Check($path, $label) {
  if (Test-Path $path) {
    $sz = (Get-Item $path).Length
    Write-Host "OK $label $sz bytes $path" -ForegroundColor Green
    return $true
  } else {
    Write-Host "MISSING $label $path" -ForegroundColor Yellow
    return $false
  }
}
$hasRizin = Check $rizin "rizin"
$hasIda = Check $ida "ida"
if (-not $hasRizin) { Write-Host "Run tools/provision_rizin.ps1 to ship rizin" -ForegroundColor Yellow; if ($Strict) { $ok = $false } }
if (-not $hasIda)  { Write-Host "Optional: tools/provision_ida.ps1 to stage licensed ida (gitignored, packed via extraFiles)" -ForegroundColor DarkGray }
if ($Strict -and -not $hasRizin) { exit 1 }
exit 0
