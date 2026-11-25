<#
.SYNOPSIS
  Layer 9 helper: submit the final exe to VirusTotal and summarise detections,
  so packer/obfuscator false positives are known BEFORE distribution.

.DESCRIPTION
  Requires a VirusTotal API key in $env:VT_API_KEY (free community key works,
  rate-limited to 4 req/min). Uploads the file (or reuses an existing report by
  hash), waits for analysis, and prints the engines that flagged it.

  This only MEASURES false positives. Reducing them is manual: code signing
  (biggest win), avoiding aggressive packer options, and submitting false-positive
  reports to AV vendors. See docs/hardening-report.md layer 9.

.EXAMPLE
  $env:VT_API_KEY = "..."; powershell -File scripts\scan-virustotal.ps1 -Path bin\sentinel_final.exe
#>
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
if (-not $env:VT_API_KEY) { throw "Set `$env:VT_API_KEY first (https://www.virustotal.com/gui/my-apikey)" }
if (-not (Test-Path $Path)) { throw "file not found: $Path" }

$headers = @{ "x-apikey" = $env:VT_API_KEY }
$sha256 = (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLower()
Write-Host "[vt] sha256 = $sha256"

function Get-Report($hash) {
  try {
    return Invoke-RestMethod -Headers $headers -Method Get -Uri "https://www.virustotal.com/api/v3/files/$hash"
  } catch { return $null }
}

$report = Get-Report $sha256
if (-not $report) {
  Write-Host "[vt] no existing report; uploading (this sends your binary to VirusTotal)..." -ForegroundColor Yellow
  # NOTE: uploading shares the sample with AV vendors. Do not upload builds that
  # embed real secrets. (This demo keeps secrets server-side; see layer 5.)
  $form = @{ file = Get-Item $Path }
  $up = Invoke-RestMethod -Headers $headers -Method Post -Uri "https://www.virustotal.com/api/v3/files" -Form $form
  $analysisId = $up.data.id
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    Start-Sleep -Seconds 15
    $an = Invoke-RestMethod -Headers $headers -Method Get -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId"
    $status = $an.data.attributes.status
    Write-Host "[vt] analysis status: $status"
  } while ($status -ne "completed" -and (Get-Date) -lt $deadline)
  $report = Get-Report $sha256
}

if (-not $report) { throw "no report available (timeout or API error)" }

$stats = $report.data.attributes.last_analysis_stats
Write-Host ""
Write-Host "=== VirusTotal summary ===" -ForegroundColor Cyan
Write-Host ("  malicious:  {0}" -f $stats.malicious)
Write-Host ("  suspicious: {0}" -f $stats.suspicious)
Write-Host ("  undetected: {0}" -f $stats.undetected)
Write-Host ("  harmless:   {0}" -f $stats.harmless)

$results = $report.data.attributes.last_analysis_results.PSObject.Properties
$flagged = $results | Where-Object { $_.Value.category -in @("malicious","suspicious") }
if ($flagged) {
  Write-Host "`n  Flagged by:" -ForegroundColor Yellow
  foreach ($f in $flagged) {
    Write-Host ("    {0,-22} {1} ({2})" -f $f.Name, $f.Value.result, $f.Value.category)
  }
  Write-Host "`n  These are likely packer/obfuscator false positives. Mitigation: sign the exe," -ForegroundColor Yellow
  Write-Host "  soften packer options, and file FP reports with the listed vendors." -ForegroundColor Yellow
} else {
  Write-Host "`n  No engines flagged this build." -ForegroundColor Green
}
