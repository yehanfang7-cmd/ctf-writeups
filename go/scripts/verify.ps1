<#
.SYNOPSIS
  Automated regression for the hardening acceptance checklist (spec §10).
  Builds, backfills integrity, then asserts every machine-checkable item.

.DESCRIPTION
  Runs end-to-end and prints PASS/FAIL per check. Non-zero exit if any FAIL.
  Covers the items that do NOT need a real debugger / VMProtect / signing:
    - strings scrub (symbols, paths, username)
    - sensitive plaintext absent (layer 3)
    - licensed vs unlicensed output diverges
    - tampering .text triggers silent degrade (layer 4)
    - go test ./... green

.PARAMETER Dev
  Verify the plain (-Dev) build instead of the garbled one. The strings-scrub
  checks are EXPECTED to fail on a -Dev build (no garble); they are reported as
  informational there, not counted as failures.

.EXAMPLE
  powershell -File scripts\verify.ps1
#>
param([switch]$Dev)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# ---- toolchain ----
$go = $null
foreach ($c in @("go","C:\Program Files\Go\bin\go.exe","$env:LOCALAPPDATA\Programs\Go\bin\go.exe")) {
  if (Get-Command $c -ErrorAction SilentlyContinue) { $go = (Get-Command $c).Source; break }
  if (Test-Path $c) { $go = $c; break }
}
if (-not $go) { throw "Go toolchain not found." }
$env:Path = "$(Split-Path $go);$env:USERPROFILE\go\bin;$env:Path"
$env:CGO_ENABLED = "1"

$script:fails = 0
$script:series = "0.9,1.3,0.7,1.1,0.6,1.4,0.8,1.2"
function Check($name, [bool]$ok, [string]$detail = "") {
  $tag = if ($ok) { "PASS" } else { "FAIL"; $script:fails++ }
  $color = if ($ok) { "Green" } else { "Red" }
  Write-Host ("  [{0}] {1}" -f $tag, $name) -ForegroundColor $color
  if ($detail) { Write-Host ("         {0}" -f $detail) -ForegroundColor DarkGray }
}
function Info($name, [bool]$ok, [string]$detail = "") {
  $tag = if ($ok) { "ok  " } else { "info" }
  Write-Host ("  [{0}] {1}" -f $tag, $name) -ForegroundColor DarkGray
  if ($detail) { Write-Host ("         {0}" -f $detail) -ForegroundColor DarkGray }
}

Write-Host "==> go test ./..." -ForegroundColor Cyan
& $go test ./... 2>&1 | Out-Null
Check "go test ./... green" ($LASTEXITCODE -eq 0)

Write-Host "==> building" -ForegroundColor Cyan
$exe = "bin\sentinel_verify.exe"
New-Item -ItemType Directory -Force -Path bin | Out-Null
& $go run ./tools/securegen | Out-Null
if ($Dev) {
  & $go build -o $exe ./cmd/sentinel
} else {
  if (-not (Get-Command garble -ErrorAction SilentlyContinue)) { throw "garble not found." }
  & garble -literals -tiny build -ldflags "-s -w" -trimpath -o $exe ./cmd/sentinel
}
if ($LASTEXITCODE -ne 0) { throw "build failed" }

# ---- strings scrub ----
Write-Host "==> §10 strings scrub" -ForegroundColor Cyan
$txt = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($exe))
$symbols = @("ComputeSignal","CriticalCombine","parseToken","sentinel/internal/license")
$paths   = @("twkk5","OneDrive\Desktop\code")
$secrets = @("feature.algo.full_precision","api.sentinel-licensing","s3nt1nel::grant","d3v1ce-fp")

$symLeak  = @($symbols | Where-Object { $txt.Contains($_) })
$pathLeak = @($paths   | Where-Object { $txt.Contains($_) })
$secLeak  = @($secrets | Where-Object { $txt.Contains($_) })

if ($Dev) {
  Info "symbols scrubbed (N/A on -Dev build)" ($symLeak.Count -eq 0) ("leaked: " + ($symLeak -join ", "))
  Info "paths scrubbed (N/A on -Dev build)"   ($pathLeak.Count -eq 0) ("leaked: " + ($pathLeak -join ", "))
} else {
  Check "function symbols scrubbed" ($symLeak.Count -eq 0) ("leaked: " + ($symLeak -join ", "))
  Check "paths/username scrubbed"   ($pathLeak.Count -eq 0) ("leaked: " + ($pathLeak -join ", "))
}
# Layer-3 secrets must be absent in BOTH build modes (plaintext never compiled).
Check "sensitive plaintext absent (layer 3)" ($secLeak.Count -eq 0) ("leaked: " + ($secLeak -join ", "))

# ---- integrity backfill ----
Write-Host "==> layer 4 integrity backfill" -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\backfill-integrity.ps1 -Path $exe | Out-Null
Check "integrity baseline backfilled" ($LASTEXITCODE -eq 0)

# ---- functional scenarios ----
Write-Host "==> §10 functional scenarios" -ForegroundColor Cyan
$tok = (& $go run ./tools/mocklicense mint 2>$null | Select-Object -Last 1).Trim()
function Signal($file, $argv) {
  $out = (& $file @argv 2>$null | Out-String)
  if ($out -match 'signal=([\-0-9.]+)') { return [double]$Matches[1] }
  return $null
}
$unl = Signal $exe @("--series",$script:series)
$lic = Signal $exe @("--token",$tok,"--series",$script:series)
Check "licensed output differs from unlicensed" ($null -ne $lic -and $null -ne $unl -and $lic -ne $unl) ("licensed=$lic unlicensed=$unl")

# tamper a .text padding byte -> expect degrade to the unlicensed value
$b = [IO.File]::ReadAllBytes($exe)
$peOff=[BitConverter]::ToInt32($b,0x3C); $optSize=[BitConverter]::ToUInt16($b,$peOff+20); $num=[BitConverter]::ToUInt16($b,$peOff+6); $st=$peOff+24+$optSize
$ptr=0;$sz=0
for($i=0;$i -lt $num;$i++){$o=$st+$i*40;$n=[Text.Encoding]::ASCII.GetString($b,$o,8).TrimEnd([char]0);if($n -eq '.text'){$ptr=[BitConverter]::ToUInt32($b,$o+20);$sz=[BitConverter]::ToUInt32($b,$o+16)}}
$b[[int]$ptr+[int]$sz-6] = $b[[int]$ptr+[int]$sz-6] -bxor 0xFF
$tamExe = "bin\sentinel_verify_tampered.exe"
[IO.File]::WriteAllBytes($tamExe,$b)
$tam = Signal $tamExe @("--token",$tok,"--series",$script:series)
Check "tampered .text triggers silent degrade" ($null -ne $tam -and $tam -eq $unl) ("tampered=$tam (expected unlicensed=$unl)")

# ---- cleanup ----
Remove-Item $exe,$tamExe -ErrorAction SilentlyContinue

Write-Host ""
if ($script:fails -eq 0) {
  Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
  exit 0
} else {
  Write-Host ("$($script:fails) CHECK(S) FAILED") -ForegroundColor Red
  exit 1
}
