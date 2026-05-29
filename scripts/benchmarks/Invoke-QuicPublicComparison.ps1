<#
Runs the public QUIC comparison surface:
- loopback connection establishment
- loopback bidirectional request/response stream transfer

Use -Job Dry to validate the harness quickly or -Job Short for repeatable
comparison measurements. This script runs the public comparison in-process so
BenchmarkDotNet does not discover artifact-staged duplicate project names.
#>

[CmdletBinding()]
param(
    [ValidateSet("Dry", "Short", "Medium", "Long")]
    [string]$Job = "Short",

    [string]$Configuration = "Release",

    [switch]$NoRestore,

    [switch]$NoBuild,

    [string]$ArtifactsRoot = ".artifacts\bdn\public-comparison",

    [string[]]$BenchmarkFilter = @(
        "*QuicPublicApiLoopbackBenchmarks*",
        "*QuicPublicApiStreamTransferBenchmarks*"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$benchmarksProject = Join-Path $repoRoot "benchmarks\Incursa.Quic.Benchmarks.csproj"
$benchmarksDirectory = Split-Path -Parent $benchmarksProject
$resolvedArtifactsRoot = if ([System.IO.Path]::IsPathRooted($ArtifactsRoot)) {
    $ArtifactsRoot
}
else {
    Join-Path $repoRoot $ArtifactsRoot
}

if (-not $NoBuild) {
    $buildArgs = @(
        "build"
        $benchmarksProject
        "-c"
        $Configuration
    )

    if ($NoRestore) {
        $buildArgs += "--no-restore"
    }

    Write-Host "Building benchmark project..." -ForegroundColor Cyan
    & dotnet @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark project build failed with exit code $LASTEXITCODE."
    }
}

foreach ($filter in $BenchmarkFilter) {
    $sliceName = $filter.Trim("*")
    $sliceName = [System.Text.RegularExpressions.Regex]::Replace($sliceName, "[^A-Za-z0-9_.-]+", "-").Trim("-")
    if ([string]::IsNullOrWhiteSpace($sliceName)) {
        $sliceName = "benchmarks"
    }

    $filterArtifactsRoot = Join-Path (Join-Path $resolvedArtifactsRoot $Job) $sliceName
    $runArgs = @(
        "run"
        "-c"
        $Configuration
        "--no-build"
        "--project"
        $benchmarksProject
    )

    if ($NoRestore) {
        $runArgs += "--no-restore"
    }

    $runArgs += @(
        "--"
        "--job"
        $Job
        "--filter"
        $filter
        "--artifacts"
        $filterArtifactsRoot
        "--inProcess"
    )

    Write-Host ""
    Write-Host "Running public comparison slice: $filter" -ForegroundColor Cyan
    Write-Host "Artifacts: $filterArtifactsRoot" -ForegroundColor Yellow
    Write-Host "Command: dotnet $($runArgs -join ' ')" -ForegroundColor Yellow

    Push-Location $benchmarksDirectory
    try {
        & dotnet @runArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Benchmark run failed for '$filter' with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}
