# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $EvidenceRoot,
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-holdout-campaign-v1.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ExpectedSourceCommit =
        'e8c62e82af8111fe8adb3fd05c2d9c494821f9e0',
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-HoldoutResultCondition([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

$resolvedEvidenceRoot = (Resolve-Path $EvidenceRoot).Path
$manifestPath = Join-Path $resolvedEvidenceRoot 'compiled-manifest.json'
$projectionPath = Join-Path $resolvedEvidenceRoot 'performance-projection.json'
$projectionFirstPath = Join-Path $resolvedEvidenceRoot `
    'performance-projection-first.json'
$analysisPath = Join-Path $resolvedEvidenceRoot 'performance-analysis.json'
$analysisFirstPath = Join-Path $resolvedEvidenceRoot `
    'performance-analysis-first.json'
$rawPaths = @(Get-ChildItem (Join-Path $resolvedEvidenceRoot 'raw') `
    -Filter '*.json' -File | Sort-Object FullName |
    Select-Object -ExpandProperty FullName)

$validation = & (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1') `
    -CampaignPath $CampaignPath `
    -ManifestPath $manifestPath `
    -RawEvidencePath $rawPaths `
    -RepositoryRoot $RepositoryRoot `
    -PassThru
Assert-HoldoutResultCondition (
    $validation.raw_evidence_count -eq 176
) 'performance_holdout_result_run_count_invalid'

$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
$manifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
$projection = Read-AdaptiveRuntimeJsonDocument $projectionPath
$analysis = Read-AdaptiveRuntimeJsonDocument $analysisPath
Assert-HoldoutResultCondition (
    [string]$manifest.source_commit -ceq $ExpectedSourceCommit
) 'performance_holdout_result_source_commit_mismatch'
Assert-HoldoutResultCondition (
    [string]$manifest.campaign_ref.document_id -ceq
        [string]$campaign.document_id -and
    [string]$manifest.campaign_ref.content_sha256 -ceq
        [string]$campaign.content_sha256
) 'performance_holdout_result_campaign_manifest_mismatch'
Assert-HoldoutResultCondition (
    $manifest.active_behavior_authorization -eq $false -and
    $manifest.performance_acceptance_authorization -eq $false -and
    $manifest.production_activation_authorization -eq $false -and
    $analysis.active_behavior_authorization -eq $false -and
    $analysis.production_activation_authorization -eq $false
) 'performance_holdout_result_authorization_invalid'

foreach ($entry in @(
    [pscustomobject]@{
        document = $projection
        schema = 'adaptive-runtime-send-composition-performance-projection-v1.schema.json'
    },
    [pscustomobject]@{
        document = $analysis
        schema = 'adaptive-runtime-send-composition-performance-analysis-v1.schema.json'
    }
)) {
    Assert-HoldoutResultCondition (
        Test-AdaptiveRuntimeJsonSchema $entry.document (
            Join-Path $RepositoryRoot "schemas\$($entry.schema)")
    ) 'performance_holdout_result_schema_invalid'
    Assert-HoldoutResultCondition (
        Test-AdaptiveRuntimeDocumentHash $entry.document
    ) 'performance_holdout_result_hash_invalid'
}
Assert-HoldoutResultCondition (
    (Get-FileHash $projectionPath -Algorithm SHA256).Hash -ceq
        (Get-FileHash $projectionFirstPath -Algorithm SHA256).Hash -and
    (Get-FileHash $analysisPath -Algorithm SHA256).Hash -ceq
        (Get-FileHash $analysisFirstPath -Algorithm SHA256).Hash
) 'performance_holdout_result_rebuild_not_byte_deterministic'

$raw = @($rawPaths | ForEach-Object {
    Read-AdaptiveRuntimeJsonDocument $_
})
$activeHoldoutIds = @(
    'holdout_segment_rich_medium',
    'holdout_many_stream_medium',
    'holdout_copy_pressure_upload'
)
foreach ($workloadId in $activeHoldoutIds) {
    $runs = @($raw | Where-Object {
        [string]$_.split -ceq 'holdout' -and
        [string]$_.workloadId -ceq $workloadId
    })
    Assert-HoldoutResultCondition (
        $runs.Count -eq 16
    ) 'performance_holdout_result_cell_block_incomplete'
    foreach ($cellId in @('A', 'B', 'C', 'D')) {
        Assert-HoldoutResultCondition (
            @($runs | Where-Object cellId -CEQ $cellId).Count -eq 4
        ) 'performance_holdout_result_cell_repetition_invalid'
    }
    Assert-HoldoutResultCondition (
        @($runs | Where-Object {
            [string]$_.cellId -in @('B', 'D') -and
            [long]$_.sample.evidence.batchDistinctOperations -le 0
        }).Count -eq 0
    ) 'performance_holdout_result_batch_activation_missing'
    Assert-HoldoutResultCondition (
        @($runs | Where-Object {
            [string]$_.cellId -ceq 'C' -and
            [long]$_.sample.evidence.bufferDistinctOperations -le 0
        }).Count -eq 0
    ) 'performance_holdout_result_buffer_activation_missing'
    Assert-HoldoutResultCondition (
        @($runs | Where-Object {
            [string]$_.cellId -ceq 'D' -and
            [long]$_.sample.evidence.bufferDistinctOperations -ne 0
        }).Count -eq 0
    ) 'performance_holdout_result_expected_equivalence_broken'
}

$inactiveRuns = @($raw | Where-Object {
    [string]$_.split -ceq 'holdout' -and
    [string]$_.workloadId -ceq 'inactive_control'
})
Assert-HoldoutResultCondition (
    $inactiveRuns.Count -eq 16 -and
    @($inactiveRuns | Where-Object {
        [long]$_.sample.evidence.batchDistinctOperations -ne 0 -or
        [long]$_.sample.evidence.bufferDistinctOperations -ne 0
    }).Count -eq 0
) 'performance_holdout_result_inactive_control_invalid'
Assert-HoldoutResultCondition (
    @($raw | Where-Object {
        $_.correctnessPassed -ne $true -or
        $_.releaseCorrect -ne $true -or
        [long]$_.sample.failures -ne 0
    }).Count -eq 0
) 'performance_holdout_result_correctness_invalid'

$classificationCounts = @{}
foreach ($group in @($validation.classifications |
    Group-Object classification)) {
    $classificationCounts[[string]$group.Name] = [long]$group.Count
}
Assert-HoldoutResultCondition (
    $classificationCounts.performance_eligible -eq 93 -and
    $classificationCounts.expected_equivalent -eq 30 -and
    $classificationCounts.inactive_control -eq 40 -and
    $classificationCounts.activation_missing -eq 13
) 'performance_holdout_result_classification_count_invalid'
$holdoutClassifications = @($validation.classifications |
    Where-Object workload_id -In $activeHoldoutIds)
Assert-HoldoutResultCondition (
    @($holdoutClassifications |
        Where-Object classification -EQ 'activation_missing').Count -eq 0 -and
    @($holdoutClassifications |
        Where-Object classification -EQ 'performance_eligible').Count -eq 36 -and
    @($holdoutClassifications |
        Where-Object classification -EQ 'expected_equivalent').Count -eq 12
) 'performance_holdout_result_active_holdout_classification_invalid'

Assert-HoldoutResultCondition (
    [long]$analysis.run_counts.total -eq 176 -and
    [long]$analysis.run_counts.eligible -eq 93 -and
    [long]$analysis.run_counts.equivalent -eq 30 -and
    [long]$analysis.run_counts.inactive -eq 40 -and
    [long]$analysis.run_counts.excluded -eq 13
) 'performance_holdout_result_analysis_counts_invalid'
Assert-HoldoutResultCondition (
    [string]$analysis.measurement_readiness -ceq
        'measurement_completed_no_stable_rule' -and
    [string]$analysis.selector_assessment.conclusion -ceq
        'no_stable_rule' -and
    $analysis.selector_assessment.shadow_implementation_authorized -eq $false -and
    $null -eq $analysis.selector_assessment.rule_id -and
    $null -eq $analysis.selector_assessment.rule_text -and
    [double]$analysis.selector_assessment.holdout_accuracy -eq (2.0 / 3.0) -and
    [double]$analysis.selector_assessment.holdout_median_regret_percent -eq 0
) 'performance_holdout_result_selector_conclusion_invalid'

$holdoutEffects = @($analysis.effect_estimates |
    Where-Object split -CEQ 'holdout')
Assert-HoldoutResultCondition (
    $holdoutEffects.Count -eq 4 -and
    @($holdoutEffects | Where-Object {
        [string]$_.effect_id -ceq 'expected_equivalence_d_vs_b' -and
        [string]$_.classification -ceq 'expected_equivalent'
    }).Count -eq 1 -and
    @($holdoutEffects | Where-Object {
        [string]$_.effect_id -cne 'expected_equivalence_d_vs_b' -and
        [string]$_.classification -cne 'uncertain'
    }).Count -eq 0
) 'performance_holdout_result_effect_classification_invalid'

$result = [pscustomobject][ordered]@{
    raw_evidence_count = $raw.Count
    performance_eligible_count = $classificationCounts.performance_eligible
    expected_equivalent_count = $classificationCounts.expected_equivalent
    inactive_control_count = $classificationCounts.inactive_control
    activation_missing_count = $classificationCounts.activation_missing
    complete_active_holdout_count = $activeHoldoutIds.Count
    projection_content_sha256 = [string]$projection.content_sha256
    analysis_content_sha256 = [string]$analysis.content_sha256
    measurement_readiness = [string]$analysis.measurement_readiness
    holdout_accuracy = [double]$analysis.selector_assessment.holdout_accuracy
    shadow_implementation_authorized = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
}
if ($PassThru) {
    return $result
}
$result | ConvertTo-Json -Depth 10
