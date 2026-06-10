$ErrorActionPreference = "Stop"

$PackageRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PackageRoot "bin/win-x64/Incursa.Http3.Samples.TechEmpower.exe") @args
exit $LASTEXITCODE
