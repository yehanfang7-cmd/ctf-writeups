<#
.SYNOPSIS
  One-shot hardened build for the sentinel demo, in the spec's required order
  (spec §8). Automatable layers only; VMProtect (layer 6) and signing (layer 9)
  are manual and are called out at the end.

.DESCRIPTION
  Pipeline:
    1. securegen            (layer 3) regenerate encrypted secrets, fresh key
    2. garble -literals -tiny build -ldflags "-s -w" -trimpath   (layers 1+2)
         -> bin\sentinel_garbled.exe
    3. [MANUAL] VMProtect packing  -> bin\sentinel_vmp.exe
    4. backfill-integrity.ps1 (layer 4) on the FINAL exe
    5. [MANUAL] code signing

.PARAMETER Out
  Output path for the garbled exe. Default bin\sentinel_garbled.exe.

.PARAMETER Dev
  Skip garble (plain go build) for fast iteration. Never ship a -Dev build.

.PARAMETER VMProtect
  If given a path to an already-VMProtect-packed exe, skip straight to backfill
  on that file instead of building.

.EXAMPLE
  powershell -File scripts\build.ps1
  powershell -File scripts\build.ps1 -Dev
#>
param(
  [string]$Out = "bin\sentinel_garbled.exe",
  [switch]$Dev,
  [string]$VMProtect = ""
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Locate the Go toolchain.
$goCandidates = @(
  "go",
  "C:\Program Files\Go\bin\go.exe",
  "$env:LOCALAPPDATA\Programs\Go\bin\go.exe"
)
$go = $null
foreach ($c in $goCandidates) {
  if (Get-Command $c -ErrorAction SilentlyContinue) { $go = (Get-Command $c).Source; break }
  if (Test-Path $c) { $go = $c; break }
}
if (-not $go) { throw "Go toolchain not found. Install Go 1.27+." }
$gobin = Join-Path (Split-Path (& $go env GOPATH)) 'go\bin'
$env:Path = "$(Split-Path $go);$env:USERPROFILE\go\bin;$env:Path"
$env:CGO_ENABLED = "1"
New-Item -ItemType Directory -Force -Path bin | Out-Null

Write-Host "==> [layer 3] regenerating encrypted secrets (fresh per-build key)" -ForegroundColor Cyan
& $go run ./tools/securegen
if ($LASTEXITCODE -ne 0) { throw "securegen failed" }

if ($VMProtect) {
  if (-not (Test-Path $VMProtect)) { throw "VMProtect exe not found: $VMProtect" }
  Write-Host "==> [layer 4] backfilling integrity baseline on $VMProtect" -ForegroundColor Cyan
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\backfill-integrity.ps1 -Path $VMProtect
  Write-Host "`nDONE. Next MANUAL step: sign $VMProtect (see docs/hardening-report.md layer 9)." -ForegroundColor Green
  return
}

if ($Dev) {
  Write-Host "==> [DEV] plain go build (NO garble) -> $Out" -ForegroundColor Yellow
  & $go build -o $Out ./cmd/sentinel
} else {
  if (-not (Get-Command garble -ErrorAction SilentlyContinue)) {
    throw "garble not found. Run: go install mvdan.cc/garble@latest"
  }
  Write-Host "==> [layers 1+2] garble -literals -tiny build -> $Out" -ForegroundColor Cyan
  & garble -literals -tiny build -ldflags "-s -w" -trimpath -o $Out ./cmd/sentinel
}
if ($LASTEXITCODE -ne 0) { throw "build failed" }

Write-Host "`nBuilt: $Out ($("{0:N0}" -f (Get-Item $Out).Length) bytes)" -ForegroundColor Green
Write-Host @"

Remaining steps (spec order):
  [MANUAL] layer 6  VMProtect: open $Out, mark functions per docs\vmprotect-manual.md,
                    export packed exe, then re-run:
                      powershell -File scripts\build.ps1 -VMProtect bin\sentinel_vmp.exe
  [AUTO]   layer 4  If NOT using VMProtect, backfill integrity on the garbled exe now:
                      powershell -File scripts\backfill-integrity.ps1 -Path $Out
  [MANUAL] layer 9  Code-sign the final exe; optionally scan with scripts\scan-virustotal.ps1
"@ -ForegroundColor Green
