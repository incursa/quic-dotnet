[CmdletBinding()]
param(
    [string] $TracePath,
    [string] $TraceRoot,
    [string] $OutputRoot,
    [int] $Top = 50,
    [int] $MaxFrames = 32,
    [int] $SampleEvents = 3,
    [string[]] $ProjectFramePrefix = @("Incursa."),
    [switch] $NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Format-CommandLine([string] $FileName, [string[]] $Arguments) {
    $escaped = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argument
        }
    }

    "$FileName $($escaped -join ' ')"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

if ([string]::IsNullOrWhiteSpace($TracePath)) {
    if ([string]::IsNullOrWhiteSpace($TraceRoot)) {
        throw "Specify either -TracePath or -TraceRoot."
    }

    $TracePath = Join-Path $TraceRoot "trace.nettrace"
}

$TracePath = (Resolve-Path -LiteralPath $TracePath).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path (Split-Path -Parent $TracePath) "exception-attribution"
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$project = Join-Path $repoRoot "eng/tools/Incursa.Quic.TraceAnalysis/Incursa.Quic.TraceAnalysis.csproj"
if (-not $NoBuild) {
    & dotnet build $project -c Release
    if ($LASTEXITCODE -ne 0) {
        throw "Trace analysis tool build failed with exit code $LASTEXITCODE."
    }
}

$arguments = @(
    "run",
    "--project", $project,
    "-c", "Release",
    "--no-build",
    "--",
    "--trace", $TracePath,
    "--output", $OutputRoot,
    "--top", $Top.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--max-frames", $MaxFrames.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--sample-events", $SampleEvents.ToString([Globalization.CultureInfo]::InvariantCulture)
)

foreach ($prefix in $ProjectFramePrefix) {
    $arguments += @("--project-frame-prefix", $prefix)
}

Set-Content -Path (Join-Path $OutputRoot "exception-attribution-command.txt") -Value (Format-CommandLine "dotnet" $arguments)
Push-Location $repoRoot
try {
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Trace analysis tool failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
