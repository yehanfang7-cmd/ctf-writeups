param([int]$ExtraCases = 256)
$ErrorActionPreference = 'Stop'
$vmpRoot = Split-Path -Parent $PSScriptRoot
$researchPython = Join-Path $vmpRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $researchPython)) {
    & (Join-Path $PSScriptRoot 'start_tigress.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Tigress baseline setup failed.' }
}
& $researchPython -c "import importlib.util,sys; sys.exit(0 if all(importlib.util.find_spec(n) for n in ('triton','llvmlite','lief','unicorn','ziglang')) else 1)"
if ($LASTEXITCODE -ne 0) {
    & $researchPython -m pip install --index-url https://pypi.org/simple -r (Join-Path $PSScriptRoot 'requirements-tigress-c.txt')
    if ($LASTEXITCODE -ne 0) { throw 'C reconstruction dependencies could not be installed.' }
}
& $researchPython -c "import json,pathlib,sys; root=pathlib.Path(sys.argv[1]); good=False;`nfor p in root.glob('*/results.json'):`n r=json.loads(p.read_text()); good=good or (len(r)==5 and all(v['status']=='passed' for v in r))`nsys.exit(0 if good else 1)" (Join-Path $PSScriptRoot 'generated/tigress')
if ($LASTEXITCODE -ne 0) {
    & (Join-Path $PSScriptRoot 'start_tigress.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'A complete Tigress baseline is required.' }
}
& $researchPython -u (Join-Path $PSScriptRoot 'tigress_c.py') --extra-cases $ExtraCases
exit $LASTEXITCODE
