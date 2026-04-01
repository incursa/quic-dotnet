param(
    [string]$Configuration = "Release",
    [switch]$NoRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "QualityLane.Common.ps1")

Assert-DotNetAvailable

$repoRoot = Get-QualityRepoRoot
$benchmarksProject = Resolve-RepoPath -RepoRoot $repoRoot -Path "benchmarks/Incursa.Quic.Benchmarks.csproj"
$evidenceRoot = Resolve-RepoPath -RepoRoot $repoRoot -Path "quality/benchmarks"
$summaryPath = Join-Path $evidenceRoot "header-parsing-benchmarks.md"
$logPath = Join-Path $evidenceRoot "header-parsing-benchmarks.log"
$benchmarkFilter = "*QuicHeaderParsingBenchmarks*"

Initialize-ArtifactDirectory -Path $evidenceRoot | Out-Null

$runArgs = @(
    "run"
    "-c"
    $Configuration
    "--project"
    $benchmarksProject
)

if ($NoRestore) {
    $runArgs += "--no-restore"
}

$runArgs += @(
    "--"
    "--job"
    "Dry"
    "--filter"
    $benchmarkFilter
)

Write-Host "Running benchmark evidence wrapper..." -ForegroundColor Cyan
Write-Host "Project: $benchmarksProject" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow
Write-Host "Filter: $benchmarkFilter" -ForegroundColor Yellow

$benchmarkOutput = & dotnet @runArgs 2>&1
$exitCode = $LASTEXITCODE
$benchmarkOutputText = ($benchmarkOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
$benchmarkOutputText | Set-Content -Path $logPath -Encoding UTF8

$status = if ($exitCode -eq 0) { "passing" } else { "failing" }
$observedAt = (Get-Date).ToUniversalTime().ToString("O", [System.Globalization.CultureInfo]::InvariantCulture)
$relativeLogPath = Get-RelativeArtifactPath -RepoRoot $repoRoot -Path $logPath

$summaryLines = New-Object System.Collections.Generic.List[string]
$summaryLines.Add("---")
$summaryLines.Add("status: $status")
$summaryLines.Add("kind: benchmarks")
$summaryLines.Add("suite: header-parsing")
$summaryLines.Add("observed_at: $observedAt")
$summaryLines.Add("---")
$summaryLines.Add("")
$summaryLines.Add("# Header Parsing Benchmarks")
$summaryLines.Add("")
$summaryLines.Add([string]::Format("- Command: dotnet {0}", ($runArgs -join " ")))
$summaryLines.Add([string]::Format("- Filter: {0}", $benchmarkFilter))
$summaryLines.Add([string]::Format("- Log: {0}", $relativeLogPath))
$summaryLines.Add([string]::Format("- Exit code: {0}", $exitCode))
$summaryLines.Add("")
$summaryLines.Add("## Result")
$summaryLines.Add("")
$summaryLines.Add([string]::Format("- Status: {0}", $status))

$summaryLines | Set-Content -Path $summaryPath -Encoding UTF8

if ($exitCode -ne 0) {
    throw "Benchmark evidence run failed with exit code $exitCode."
}

Write-Host "Benchmark evidence wrapper completed successfully." -ForegroundColor Green
