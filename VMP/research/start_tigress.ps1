param([int]$RandomCases = 64)
$ErrorActionPreference = 'Stop'
$vmpRoot = Split-Path -Parent $PSScriptRoot
$researchPython = Join-Path $vmpRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $researchPython)) {
    & py -3.11 -m venv (Join-Path $vmpRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 is required.' }
}
& $researchPython -c "import importlib.util,sys; sys.exit(0 if all(importlib.util.find_spec(n) for n in ('triton','llvmlite','lief','unicorn')) else 1)"
if ($LASTEXITCODE -ne 0) {
    & $researchPython -m pip install --index-url https://pypi.org/simple -r (Join-Path $PSScriptRoot 'requirements-tigress.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Tigress dependencies could not be installed.' }
}
& $researchPython -u (Join-Path $PSScriptRoot 'fetch_tigress.py')
if ($LASTEXITCODE -ne 0) { throw 'Tigress input verification failed.' }
& $researchPython -u (Join-Path $PSScriptRoot 'tigress_vm0.py') --random-cases $RandomCases
exit $LASTEXITCODE
