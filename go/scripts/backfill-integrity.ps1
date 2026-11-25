<#
.SYNOPSIS
  Layer 4 post-build step: compute the SHA-256 of the final binary's .text
  section and append the integrity baseline trailer the runtime (internal/guard)
  looks for.

.DESCRIPTION
  Build order (spec §8): this MUST run AFTER garble AND after VMProtect packing,
  because those stages rewrite .text. Run it before code signing; the runtime
  locates the trailer by scanning from EOF, so a trailing Authenticode signature
  does not hide it.

  Trailer layout appended at end of file:
      magic "S3NTxINT" (8 bytes) | sha256(.text raw bytes) (32 bytes)

.EXAMPLE
  pwsh scripts/backfill-integrity.ps1 -Path bin\sentinel_vmp.exe
#>
param(
  [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Stop'
$magic = [byte[]]@(0x53,0x33,0x4E,0x54,0x78,0x49,0x4E,0x54)  # "S3NTxINT"

if (-not (Test-Path $Path)) { throw "file not found: $Path" }
$bytes = [IO.File]::ReadAllBytes($Path)

function Get-TextSection([byte[]]$b) {
  if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { throw "not a PE (no MZ)" }
  $peOff = [BitConverter]::ToInt32($b, 0x3C)
  if ($b[$peOff] -ne 0x50 -or $b[$peOff+1] -ne 0x45) { throw "no PE signature" }
  $numSections = [BitConverter]::ToUInt16($b, $peOff + 6)
  $optSize     = [BitConverter]::ToUInt16($b, $peOff + 20)
  $secTable    = $peOff + 24 + $optSize
  for ($i = 0; $i -lt $numSections; $i++) {
    $off  = $secTable + ($i * 40)
    $name = [Text.Encoding]::ASCII.GetString($b, $off, 8).TrimEnd([char]0)
    $rawSize = [BitConverter]::ToUInt32($b, $off + 16)
    $rawPtr  = [BitConverter]::ToUInt32($b, $off + 20)
    if ($name -eq '.text') {
      return [pscustomobject]@{ Ptr = $rawPtr; Size = $rawSize }
    }
  }
  throw ".text section not found"
}

# Strip an existing trailer (idempotent re-runs on an UNSIGNED exe only).
function Strip-Trailer([byte[]]$b) {
  if ($b.Length -ge 40) {
    $tailMagicAt = $b.Length - 40
    $isMagic = $true
    for ($i = 0; $i -lt 8; $i++) { if ($b[$tailMagicAt + $i] -ne $magic[$i]) { $isMagic = $false; break } }
    if ($isMagic) { return $b[0..($tailMagicAt - 1)] }
  }
  return $b
}

$bytes = [byte[]](Strip-Trailer $bytes)
$text  = Get-TextSection $bytes

$sha = [Security.Cryptography.SHA256]::Create()
$slice = New-Object byte[] $text.Size
[Array]::Copy($bytes, [int]$text.Ptr, $slice, 0, [int]$text.Size)
$hash = $sha.ComputeHash($slice)

$out = New-Object System.Collections.Generic.List[byte]
$out.AddRange([byte[]]$bytes); $out.AddRange([byte[]]$magic); $out.AddRange([byte[]]$hash)
[IO.File]::WriteAllBytes($Path, $out.ToArray())

$hex = ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
Write-Host "[backfill] .text @ 0x$("{0:X}" -f $text.Ptr) size=$($text.Size)"
Write-Host "[backfill] baseline sha256(.text) = $hex"
Write-Host "[backfill] trailer appended to $Path (+40 bytes)"
