# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $LocalResultPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [string] $AnalysisId = 'application-send-turn-counterfactual-analysis-v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resultSchemaPath = Join-Path $repoRoot 'schemas\adaptive-runtime-policy-local-result-v1.schema.json'
$outputSchemaPath = Join-Path $repoRoot 'schemas\adaptive-runtime-application-send-turn-counterfactual-analysis-v1.schema.json'
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)

if (Test-Path -LiteralPath $resolvedOutputPath) {
    throw "Counterfactual analysis output already exists: $resolvedOutputPath"
}

$cells = [System.Collections.Generic.List[object]]::new()
foreach ($path in @($LocalResultPath | Sort-Object -Unique)) {
    $resolvedPath = (Resolve-Path -LiteralPath $path).Path
    $rawJson = Get-Content -LiteralPath $resolvedPath -Raw
    if (-not ($rawJson | Test-Json -SchemaFile $resultSchemaPath)) {
        throw "Local result does not validate against the v1 result schema: $resolvedPath"
    }

    $result = $rawJson | ConvertFrom-Json -Depth 100
    if ([string] $result.policyAxis -ne 'application_send_turn_planning' -or
        [string] $result.mode -ne 'forced') {
        throw "Counterfactual input must be a forced application_send_turn_planning result: $resolvedPath"
    }

    $validationPath = Join-Path (Split-Path -Parent $resolvedPath) 'evidence-validation.json'
    $evidenceValid = $false
    if (Test-Path -LiteralPath $validationPath -PathType Leaf) {
        $validation = Get-Content -LiteralPath $validationPath -Raw | ConvertFrom-Json -Depth 30
        $evidenceValid = [bool] $validation.valid
    }

    $axisSettings = $result.policyConfiguration.axisSettings
    $baselineThroughput = [double] $axisSettings.baselineThroughputBytesPerSecond
    $candidateThroughput = [double] $axisSettings.candidateThroughputBytesPerSecond
    $baselineP95 = [double] $axisSettings.baselineLatencyP95Ms
    $candidateP95 = [double] $axisSettings.candidateLatencyP95Ms
    $trafficShape = [string] $result.workload.trafficShape
    $mechanismExposure = if ($trafficShape -in @('download', 'duplex', 'request_response', 'streaming')) {
        'server_application_send_exercised'
    }
    else {
        'server_application_send_not_exercised'
    }
    $correctnessValid =
        [bool] $result.correctnessOutcomes.payloadValidated -and
        [int] $result.correctnessOutcomes.failedOperations -eq 0 -and
        [int] $result.correctnessOutcomes.timedOutOperations -eq 0 -and
        [int] $result.correctnessOutcomes.protocolErrors -eq 0
    $classification = [string] $result.classification
    $analysisEligible =
        $evidenceValid -and
        $correctnessValid -and
        $mechanismExposure -eq 'server_application_send_exercised' -and
        $classification -notin @('invalid_contract', 'invalid_environment', 'failed_correctness', 'stress_only')
    $constructionRowCount = @(
        Get-ChildItem -LiteralPath (Split-Path -Parent $resolvedPath) `
            -Recurse `
            -Filter 'construction-row-*.json' `
            -File
    ).Count

    $assemblies = @($result.binaryProvenance.assemblies)
    $benchmarkHash = [string] (@($assemblies | Where-Object role -eq 'candidate_benchmark') | Select-Object -First 1).sha256
    $runtimeHash = [string] (@($assemblies | Where-Object role -eq 'candidate_runtime') | Select-Object -First 1).sha256

    $cells.Add([ordered]@{
        campaignId = [string] $result.campaignId
        runId = [string] $result.runId
        cellId = [string] $result.cellId
        sourceResultPath = $resolvedPath
        sourceResultSha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        evidenceValidationPath = if (Test-Path -LiteralPath $validationPath -PathType Leaf) {
            [System.IO.Path]::GetFullPath($validationPath)
        } else {
            $null
        }
        evidenceValid = $evidenceValid
        classification = $classification
        correctnessValid = $correctnessValid
        analysisEligible = $analysisEligible
        mechanismExposure = $mechanismExposure
        sequenceProtocol = [string] $result.sequenceProtocol
        workloadAnalysisOnly = [ordered]@{
            scenarioId = [string] $result.workload.scenarioId
            trafficShape = $trafficShape
            payloadBytes = [long] $result.workload.payloadBytes
            effectiveConcurrency = [int] $result.workload.effectiveConcurrency
            warmupSeconds = [int] $result.workload.warmupSeconds
            durationSeconds = [int] $result.workload.durationSeconds
        }
        binaryCohort = [ordered]@{
            benchmarkSha256 = $benchmarkHash
            runtimeSha256 = $runtimeHash
        }
        treatments = [ordered]@{
            baselinePolicy = 'legacy_current'
            candidatePolicy = 'conservative'
        }
        outcomes = [ordered]@{
            baselineThroughputBytesPerSecond = $baselineThroughput
            candidateThroughputBytesPerSecond = $candidateThroughput
            throughputDeltaPercent = if ($baselineThroughput -eq 0) {
                $null
            } else {
                (($candidateThroughput / $baselineThroughput) - 1.0) * 100.0
            }
            baselineLatencyP95Ms = $baselineP95
            candidateLatencyP95Ms = $candidateP95
            latencyP95DeltaPercent = if ($baselineP95 -eq 0) {
                $null
            } else {
                (($candidateP95 / $baselineP95) - 1.0) * 100.0
            }
            maximumWithinTreatmentRelativeRange = [double] $axisSettings.maximumWithinTreatmentRelativeRange
        }
        constructionRowCount = $constructionRowCount
    })
}

$eligibleCells = @($cells | Where-Object analysisEligible)
$constructionRowCountTotal = 0
foreach ($cell in $cells) {
    $constructionRowCountTotal += [int] $cell['constructionRowCount']
}
$report = [ordered]@{
    schemaVersion = 'adaptive-runtime-application-send-turn-counterfactual-analysis-v1'
    analysisId = $AnalysisId
    createdUtc = (Get-Date).ToUniversalTime().ToString('O')
    codeCommit = (& git -C $repoRoot rev-parse HEAD).Trim()
    axisId = 'application_send_turn_planning'
    comparison = [ordered]@{
        baselinePolicy = 'legacy_current'
        candidatePolicy = 'conservative'
        outcomeScope = 'cell_median_not_epoch_independent'
    }
    cells = @($cells)
    summary = [ordered]@{
        cellCount = $cells.Count
        analysisEligibleCellCount = $eligibleCells.Count
        excludedCellCount = $cells.Count - $eligibleCells.Count
        constructionRowCount = $constructionRowCountTotal
        classificationCounts = [ordered]@{}
    }
    recommendation = [ordered]@{
        status = 'continue_evidence_generation'
        activeInternalAuthorized = $false
        reason = 'Local counterfactual cells remain descriptive; independent-host coverage and reviewed holdouts are required before a deterministic rule proposal.'
    }
}
foreach ($classification in @($cells.classification | Sort-Object -Unique)) {
    $report.summary.classificationCounts[$classification] =
        @($cells | Where-Object classification -eq $classification).Count
}

$parent = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$reportJson = $report | ConvertTo-Json -Depth 50
if (-not ($reportJson | Test-Json -SchemaFile $outputSchemaPath)) {
    throw "Generated counterfactual analysis does not validate against $outputSchemaPath"
}
$reportJson | Set-Content -LiteralPath $resolvedOutputPath -Encoding utf8

[ordered]@{
    schemaVersion = 'adaptive-runtime-application-send-turn-counterfactual-analysis-output-v1'
    reportPath = $resolvedOutputPath
    reportSha256 = (Get-FileHash -LiteralPath $resolvedOutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    cellCount = $cells.Count
    analysisEligibleCellCount = $eligibleCells.Count
    excludedCellCount = $cells.Count - $eligibleCells.Count
    constructionRowCount = $report.summary.constructionRowCount
    activeInternalAuthorized = $false
} | ConvertTo-Json -Depth 10
