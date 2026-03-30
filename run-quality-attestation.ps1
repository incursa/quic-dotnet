[CmdletBinding()]
param(
    [string]$Solution = "Incursa.Quic.slnx",
    [string]$Configuration = "Release",
    [switch]$NoRestore,
    [switch]$NoBuild,
    [switch]$Quick,
    [string]$AttestationOutputDirectory = "artifacts/quality/attestation-run"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$qualityEvidenceScript = Join-Path $repoRoot "scripts/quality/run-quality-evidence.ps1"
$qualityArtifactsRoot = Join-Path $repoRoot "artifacts/quality"
$attestationOutputPath = Join-Path $repoRoot $AttestationOutputDirectory

Write-Host "Running quality evidence and attestation..." -ForegroundColor Cyan
Write-Host "Repository: $repoRoot" -ForegroundColor Yellow
Write-Host "Solution: $Solution" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow
Write-Host ("Mode: {0}" -f ($(if ($Quick) { "quick" } else { "refresh" }))) -ForegroundColor Yellow
Write-Host "Attestation output: $attestationOutputPath" -ForegroundColor Yellow

Push-Location $repoRoot
try {
    if (Test-Path $attestationOutputPath) {
        Remove-Item -LiteralPath $attestationOutputPath -Recurse -Force
    }

    $generatedQualityOutputs = @(
        (Join-Path $qualityArtifactsRoot "testing")
    )

    foreach ($generatedOutput in $generatedQualityOutputs) {
        if (Test-Path $generatedOutput) {
            Remove-Item -LiteralPath $generatedOutput -Recurse -Force
        }
    }

    Get-ChildItem -Path $qualityArtifactsRoot -Directory -Filter "attestation*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

    if (-not $Quick) {
        $rawQualityOutputs = Join-Path $qualityArtifactsRoot "raw"
        if (Test-Path $rawQualityOutputs) {
            Remove-Item -LiteralPath $rawQualityOutputs -Recurse -Force
        }

        & pwsh -NoLogo -NoProfile -File $qualityEvidenceScript -Solution $Solution -Configuration $Configuration -NoRestore:$NoRestore -NoBuild:$NoBuild
        if ($LASTEXITCODE -ne 0) {
            throw "Quality evidence run failed with exit code $LASTEXITCODE."
        }
    }

    & dotnet tool run workbench quality sync --results artifacts/quality/raw/test-results --coverage artifacts/quality/raw/coverage
    if ($LASTEXITCODE -ne 0) {
        throw "Quality sync failed with exit code $LASTEXITCODE."
    }

    & dotnet tool run workbench quality attest --no-exec --emit both --out-dir $attestationOutputPath
    if ($LASTEXITCODE -ne 0) {
        throw "Quality attestation failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

Write-Host "Quality attestation wrapper completed successfully." -ForegroundColor Green
