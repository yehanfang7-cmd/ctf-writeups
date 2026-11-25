param([switch]$DownloadOnly)
$ErrorActionPreference = 'Stop'
$vmpRoot = Split-Path -Parent $PSScriptRoot
$researchPython = Join-Path $vmpRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $researchPython)) {
    & py -3.11 -m venv (Join-Path $vmpRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 is required to create the research environment.' }
}
& $researchPython -c "import sys; from importlib.metadata import distributions; installed = {d.metadata['Name'].lower(): d.version for d in distributions()}; sys.exit(0 if installed.get('triton-library') == '1.0.0rc4' and installed.get('llvmlite') == '0.46.0' else 1)"
if ($LASTEXITCODE -ne 0) {
    & $researchPython -m pip install --index-url https://pypi.org/simple -r (Join-Path $PSScriptRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Research dependencies could not be installed.' }
}
$researchArguments = @('-u', (Join-Path $PSScriptRoot 'run.py'))
if ($DownloadOnly) { $researchArguments += '--download-only' }
& $researchPython @researchArguments
exit $LASTEXITCODE
