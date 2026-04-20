<#
Runs the current QUIC baseline surface:
- congestion-control update paths
- RTT estimation update paths
- sender-adjacent stream-credit and stream-state paths

Use -Job Dry to validate the harness quickly or -Job Short for repeatable
baseline measurements.
#>

[CmdletBinding()]
param(
    [ValidateSet("Dry", "Short", "Medium", "Long")]
    [string]$Job = "Short",

    [string]$Configuration = "Release",

    [switch]$NoRestore,

    [switch]$NoBuild,

    [string[]]$BenchmarkFilter = @(
        "*QuicCongestionControlBenchmarks*",
        "*QuicRttEstimatorBenchmarks*",
        "*QuicConnectionStreamStateBenchmarks*"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$benchmarksProject = Join-Path $repoRoot "benchmarks\Incursa.Quic.Benchmarks.csproj"

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
    )

    Write-Host ""
    Write-Host "Running baseline slice: $filter" -ForegroundColor Cyan
    Write-Host "Command: dotnet $($runArgs -join ' ')" -ForegroundColor Yellow

    & dotnet @runArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark run failed for '$filter' with exit code $LASTEXITCODE."
    }
}
