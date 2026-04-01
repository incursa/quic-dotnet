param(
    [string]$Solution = "Incursa.Quic.slnx",
    [string]$Configuration = "Release",
    [switch]$NoRestore,
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "QualityLane.Common.ps1")

Assert-DotNetAvailable

$repoRoot = Get-QualityRepoRoot
$solutionPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $Solution
$resultsPath = Resolve-RepoPath -RepoRoot $repoRoot -Path "artifacts/quality/raw/test-results"
$coveragePath = Resolve-RepoPath -RepoRoot $repoRoot -Path "artifacts/quality/raw/coverage"
$summaryPath = Join-Path $resultsPath "summary.md"
$testProjects = @(
    Get-ChildItem -Path (Join-Path $repoRoot "tests") -Filter *.csproj -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName
)

Write-Host "Running quality evidence wrapper..." -ForegroundColor Cyan
Write-Host "Solution: $solutionPath" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow
Write-Host "Test projects: $($testProjects.Count)" -ForegroundColor Yellow

if ($testProjects.Count -eq 0) {
    throw "No test projects were found under the repository tests folder."
}

Initialize-ArtifactDirectory -Path $resultsPath -Clean | Out-Null
Initialize-ArtifactDirectory -Path $coveragePath -Clean | Out-Null
Invoke-TestPrerequisites -Solution $solutionPath -Configuration $Configuration -NoRestore:$NoRestore -NoBuild:$NoBuild

foreach ($project in $testProjects) {
    $projectPath = $project.FullName
    $projectName = [System.IO.Path]::GetFileNameWithoutExtension($projectPath)
    $projectResultsPath = Join-Path $resultsPath $projectName
    $projectCoverageFile = Join-Path $coveragePath "$projectName.coverage.cobertura.xml"
    $testArgs = @(
        "test"
        $projectPath
        "--configuration"
        $Configuration
        "--results-directory"
        $projectResultsPath
        "-p:CollectCoverage=true"
        "-p:CoverletOutputFormat=cobertura"
        "-p:CoverletOutput=$projectCoverageFile"
        "--logger"
        "trx;LogFileName=$projectName.trx"
        "--no-build"
        "--no-restore"
    )

    Initialize-ArtifactDirectory -Path $projectResultsPath -Clean | Out-Null

    Write-Host "Testing $projectName..." -ForegroundColor Cyan
    & dotnet @testArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Quality evidence run failed for $projectName with exit code $LASTEXITCODE."
    }
}

Normalize-CoberturaCoverageFiles -RepoRoot $repoRoot -CoverageDirectory $coveragePath

$summary = Write-TrxSummaryMarkdown -Title "Quality Evidence Summary" -ResultsDirectory $resultsPath -SummaryPath $summaryPath -RepoRoot $repoRoot -EmptyMessage "The quality evidence run did not produce any TRX files."
Append-GitHubStepSummary -SummaryPath $summary.SummaryPath

if (-not $summary.HasResults) {
    throw "Quality evidence run completed without producing TRX results."
}

Write-Host "Quality evidence wrapper completed successfully." -ForegroundColor Green
