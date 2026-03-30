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

Write-Host "Running quality evidence wrapper..." -ForegroundColor Cyan
Write-Host "Solution: $solutionPath" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow

Invoke-TestPrerequisites -Solution $solutionPath -Configuration $Configuration -NoRestore:$NoRestore -NoBuild:$NoBuild

$laneArgs = @(
    "-Solution"
    $Solution
    "-Configuration"
    $Configuration
    "-NoRestore"
    "-NoBuild"
)

& pwsh -NoLogo -NoProfile -File (Join-Path $PSScriptRoot "run-smoke-tests.ps1") @laneArgs
if ($LASTEXITCODE -ne 0) {
    throw "Smoke lane failed with exit code $LASTEXITCODE."
}

& pwsh -NoLogo -NoProfile -File (Join-Path $PSScriptRoot "run-blocking-tests.ps1") @laneArgs
if ($LASTEXITCODE -ne 0) {
    throw "Blocking lane failed with exit code $LASTEXITCODE."
}

Write-Host "Quality evidence wrapper completed successfully." -ForegroundColor Green
