param(
    [string]$Solution = "Incursa.Quic.slnx",
    [string]$Configuration = "Release",
    [string]$Runsettings = "runsettings/blocking.runsettings",
    [string]$ResultsDirectory = "artifacts/quality/raw/test-results/blocking",
    [string]$CoverageDirectory = "artifacts/quality/raw/coverage/blocking",
    [switch]$NoRestore,
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "QualityLane.Common.ps1")

Assert-DotNetAvailable

$repoRoot = Get-QualityRepoRoot
$solutionPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $Solution
$runsettingsPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $Runsettings
$resultsPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $ResultsDirectory
$coveragePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $CoverageDirectory
$summaryPath = Join-Path $resultsPath "summary.md"

Write-Host "Running blocking lane..." -ForegroundColor Cyan
Write-Host "Solution: $solutionPath" -ForegroundColor Yellow
Write-Host "Runsettings: $runsettingsPath" -ForegroundColor Yellow
Write-Host "Results: $resultsPath" -ForegroundColor Yellow
Write-Host "Coverage: $coveragePath" -ForegroundColor Yellow

Initialize-ArtifactDirectory -Path $resultsPath -Clean | Out-Null
Initialize-ArtifactDirectory -Path $coveragePath -Clean | Out-Null
Invoke-TestPrerequisites -Solution $solutionPath -Configuration $Configuration -NoRestore:$NoRestore -NoBuild:$NoBuild

$projectName = [System.IO.Path]::GetFileNameWithoutExtension($solutionPath)
$projectCoverageFile = Join-Path $coveragePath "$projectName.coverage.cobertura.xml"
$testArgs = @(
    "test"
    $solutionPath
    "--configuration"
    $Configuration
    "--filter"
    "Category=Blocking"
    "--settings"
    $runsettingsPath
    "--results-directory"
    $resultsPath
    "-p:CollectCoverage=true"
    "-p:CoverletOutputFormat=cobertura"
    "-p:CoverletOutput=$projectCoverageFile"
    "--logger"
    "trx;LogFileName=blocking.trx"
    "--no-build"
    "--no-restore"
)

& dotnet @testArgs
if ($LASTEXITCODE -ne 0) {
    throw "Blocking lane failed with exit code $LASTEXITCODE."
}

Normalize-CoberturaCoverageFiles -RepoRoot $repoRoot -CoverageDirectory $coveragePath

$summary = Write-TrxSummaryMarkdown -Title "Blocking Lane Summary" -ResultsDirectory $resultsPath -SummaryPath $summaryPath -RepoRoot $repoRoot -EmptyMessage "The blocking lane did not produce any TRX files."
Append-GitHubStepSummary -SummaryPath $summary.SummaryPath

if (-not $summary.HasResults) {
    throw "Blocking lane completed without producing TRX results."
}

Write-Host "Blocking lane completed successfully." -ForegroundColor Green
