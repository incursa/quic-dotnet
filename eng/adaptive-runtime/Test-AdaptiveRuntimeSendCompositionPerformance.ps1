# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $ManifestPath,
    [string[]] $RawEvidencePath = @(),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-PerformanceCondition(
    [bool] $Condition,
    [string] $Code
) {
    if (-not $Condition) {
        throw $Code
    }
}

function Assert-ExactReference(
    [object] $Reference,
    [object] $Document,
    [string] $Code
) {
    Assert-PerformanceCondition (
        [string]$Reference.document_id -ceq [string]$Document.document_id -and
        [string]$Reference.schema_version -ceq [string]$Document.schema_version -and
        [long]$Reference.document_version -eq [long]$Document.document_version -and
        [string]$Reference.content_sha256 -ceq [string]$Document.content_sha256
    ) $Code
}

$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
$campaignSchema = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-composition-performance-campaign-v1.schema.json'
Assert-PerformanceCondition (
    Test-AdaptiveRuntimeJsonSchema $campaign $campaignSchema
) 'performance_campaign_schema_invalid'
Assert-PerformanceCondition (
    Test-AdaptiveRuntimeDocumentHash $campaign
) 'performance_campaign_hash_mismatch'

$batchReview = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\batch-single-eligible.review.json')
$bufferReview = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\buffer-memory-conservative.review.json')
$correctnessReview = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'tests\fixtures\adaptive-runtime-send-composition-correctness\interaction\interaction-review.json')
$familyCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v2.json')
$behaviorCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')

foreach ($document in @(
    $batchReview,
    $bufferReview,
    $correctnessReview,
    $familyCatalog,
    $behaviorCatalog
)) {
    Assert-PerformanceCondition (
        Test-AdaptiveRuntimeDocumentHash $document
    ) 'performance_prerequisite_hash_mismatch'
}
Assert-ExactReference $campaign.reviewed_proof_refs[0] $batchReview `
    'performance_batch_proof_reference_mismatch'
Assert-ExactReference $campaign.reviewed_proof_refs[1] $bufferReview `
    'performance_buffer_proof_reference_mismatch'
Assert-ExactReference $campaign.correctness_review_ref $correctnessReview `
    'performance_correctness_review_reference_mismatch'
Assert-PerformanceCondition (
    [string]$batchReview.review_outcome -ceq 'passed' -and
    [string]$batchReview.axis_id -ceq 'application_send_batch_formation' -and
    [string]$batchReview.policy_value -ceq 'single_eligible' -and
    [string]$bufferReview.review_outcome -ceq 'passed' -and
    [string]$bufferReview.axis_id -ceq 'buffer_copy_coalescing' -and
    [string]$bufferReview.policy_value -ceq 'memory_conservative' -and
    [string]$correctnessReview.review_outcome -ceq 'passed'
) 'performance_reviewed_prerequisite_missing'

$family = @($familyCatalog.experiment_families |
    Where-Object { [string]$_.family_id -ceq 'send_composition' })
Assert-PerformanceCondition ($family.Count -eq 1) `
    'performance_family_resolution_invalid'
Assert-PerformanceCondition (
    @($family[0].included_axis_ids).Count -eq 2 -and
    @($family[0].included_axis_ids) -contains
        'application_send_batch_formation' -and
    @($family[0].included_axis_ids) -contains
        'buffer_copy_coalescing' -and
    @($family[0].actuation_proof_refs).Count -eq 2
) 'performance_family_membership_invalid'

$expectedCells = [ordered]@{
    A = 'legacy_current|legacy_current|true'
    B = 'single_eligible|legacy_current|true'
    C = 'legacy_current|memory_conservative|true'
    D = 'single_eligible|memory_conservative|false'
}
Assert-PerformanceCondition (@($campaign.cells).Count -eq 4) `
    'performance_cell_count_invalid'
foreach ($entry in $expectedCells.GetEnumerator()) {
    $matches = @($campaign.cells |
        Where-Object { [string]$_.cell_id -ceq [string]$entry.Key })
    Assert-PerformanceCondition ($matches.Count -eq 1) `
        'performance_cell_identity_invalid'
    $cell = $matches[0]
    $actual = '{0}|{1}|{2}' -f
        $cell.batch_value,
        $cell.buffer_value,
        ([bool]$cell.performance_comparable).ToString().ToLowerInvariant()
    Assert-PerformanceCondition ($actual -ceq [string]$entry.Value) `
        'performance_cell_value_invalid'
}
Assert-PerformanceCondition (
    [string]($campaign.cells |
        Where-Object cell_id -EQ 'B').expected_effective_signature -ceq
    [string]($campaign.cells |
        Where-Object cell_id -EQ 'D').expected_effective_signature
) 'performance_expected_equivalence_missing'

foreach ($order in @($campaign.design.orders)) {
    $orderedIds = @($order | Sort-Object -CaseSensitive)
    Assert-PerformanceCondition (
        (ConvertTo-Json $orderedIds -Compress) -ceq '["A","B","C","D"]'
    ) 'performance_order_not_permutation'
}

$manifest = $null
if (-not [string]::IsNullOrWhiteSpace($ManifestPath)) {
    $manifest = Read-AdaptiveRuntimeJsonDocument $ManifestPath
    Assert-PerformanceCondition (
        Test-AdaptiveRuntimeJsonSchema $manifest (
            Join-Path $RepositoryRoot `
                'schemas\adaptive-runtime-send-composition-performance-manifest-v1.schema.json')
    ) 'performance_manifest_schema_invalid'
    Assert-PerformanceCondition (
        Test-AdaptiveRuntimeDocumentHash $manifest
    ) 'performance_manifest_hash_mismatch'
    Assert-ExactReference $manifest.campaign_ref $campaign `
        'performance_manifest_campaign_mismatch'
    Assert-PerformanceCondition (
        $manifest.source_tree_clean -eq $true -and
        $manifest.measurement_authorization -eq $true -and
        $manifest.active_behavior_authorization -eq $false -and
        $manifest.performance_acceptance_authorization -eq $false -and
        $manifest.production_activation_authorization -eq $false
    ) 'performance_manifest_authorization_invalid'
}

$classifications = [Collections.Generic.List[object]]::new()
$rawSchema = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-composition-performance-raw-v1.schema.json'
foreach ($path in @($RawEvidencePath | Sort-Object -Unique)) {
    $raw = Read-AdaptiveRuntimeJsonDocument $path
    Assert-PerformanceCondition (
        Test-AdaptiveRuntimeJsonSchema $raw $rawSchema
    ) 'performance_raw_schema_invalid'
    $cell = @($campaign.cells |
        Where-Object { [string]$_.cell_id -ceq [string]$raw.cellId })
    Assert-PerformanceCondition ($cell.Count -eq 1) `
        'performance_raw_cell_unknown'
    Assert-PerformanceCondition (
        [string]$raw.batchValue -ceq [string]$cell[0].batch_value -and
        [string]$raw.bufferValue -ceq [string]$cell[0].buffer_value
    ) 'performance_raw_cell_value_mismatch'
    if ($null -ne $manifest) {
        Assert-PerformanceCondition (
            [string]$raw.manifestSha256 -ceq
                [string]$manifest.content_sha256 -and
            [string]$raw.sourceCommit -ceq
                [string]$manifest.source_commit -and
            [string]$raw.binarySha256 -ceq
                [string]$manifest.binary_sha256 -and
            [string]$raw.machineFingerprint -ceq
                [string]$manifest.host.fingerprint_sha256
        ) 'performance_raw_manifest_identity_mismatch'
    }

    $evidence = $raw.sample.evidence
    foreach ($event in @($raw.mechanismEventCounts)) {
        $matches = @($behaviorCatalog.effective_behaviors |
            Where-Object {
                [string]$_.axis_id -ceq [string]$event.axisId -and
                @($_.mechanism_event_ids) -ccontains
                    [string]$event.mechanismEventId
            })
        Assert-PerformanceCondition ($matches.Count -eq 1) `
            'performance_behavior_derivation_invalid'
    }
    foreach ($outcome in @($raw.operationResultCounts)) {
        $matches = @($behaviorCatalog.outcome_definitions |
            Where-Object {
                @($_.result_kinds) -ccontains [string]$outcome.resultKind
            })
        Assert-PerformanceCondition ($matches.Count -eq 1) `
            'performance_outcome_derivation_invalid'
    }
    Assert-PerformanceCondition (
        [long]$evidence.batchLegacyOperations +
            [long]$evidence.batchDistinctOperations +
            [long]$evidence.batchNoBehaviorOperations -eq
                [long]$evidence.batchOperations -and
        [long]$evidence.batchUnclassifiableOperations -le
            [long]$evidence.batchNoBehaviorOperations -and
        [long]$evidence.batchInactiveOperations -le
            [long]$evidence.batchOperations -and
        [long]$evidence.batchFallbackOperations -le
            [long]$evidence.batchOperations -and
        [long]$evidence.bufferLegacyOperations +
            [long]$evidence.bufferDistinctOperations +
            [long]$evidence.bufferNoBehaviorOperations -eq
                [long]$evidence.bufferOperations -and
        [long]$evidence.bufferUnclassifiableOperations -le
            [long]$evidence.bufferNoBehaviorOperations -and
        [long]$evidence.bufferInactiveOperations -le
            [long]$evidence.bufferOperations -and
        [long]$evidence.bufferFallbackOperations -le
            [long]$evidence.bufferOperations -and
        [long]$evidence.batchAppliedWrites -le
            [long]$evidence.batchLegalWrites -and
        [long]$evidence.bufferAppliedSegments -le
            [long]$evidence.bufferLegalSegments
    ) 'performance_mechanism_accounting_invalid'
    Assert-PerformanceCondition (
        [long]$evidence.combinedOwnerRents -eq
            [long]$evidence.combinedOwnerReleases -and
        [long]$evidence.invalidReleases -eq 0 -and
        $raw.releaseCorrect -eq $true
    ) 'performance_owner_release_invalid'
    if ([string]$raw.cellId -in @('A', 'C')) {
        Assert-PerformanceCondition (
            [long]$evidence.batchDistinctOperations -eq 0
        ) 'performance_unmanifested_batch_actuation'
    }
    if ([string]$raw.cellId -in @('A', 'B', 'D')) {
        Assert-PerformanceCondition (
            [long]$evidence.bufferDistinctOperations -eq 0
        ) 'performance_unreachable_buffer_actuation_observed'
    }

    $workload = @($campaign.workloads |
        Where-Object { [string]$_.workload_id -ceq [string]$raw.workloadId })
    Assert-PerformanceCondition ($workload.Count -eq 1) `
        'performance_workload_unknown'
    $classification = if (
        $raw.correctnessPassed -ne $true -or [long]$raw.sample.failures -ne 0
    ) {
        'failed_correctness'
    }
    elseif ([string]$workload[0].activation_expectation -ceq
        'inactive_control') {
        'inactive_control'
    }
    elseif ([string]$raw.cellId -in @('B', 'D') -and
        [long]$evidence.batchDistinctOperations -eq 0) {
        'activation_missing'
    }
    elseif ([string]$raw.cellId -ceq 'C' -and
        [long]$evidence.bufferDistinctOperations -eq 0) {
        'activation_missing'
    }
    elseif ([string]$raw.cellId -ceq 'D') {
        'expected_equivalent'
    }
    else {
        'performance_eligible'
    }
    [void]$classifications.Add([pscustomobject][ordered]@{
        path = (Resolve-Path $path).Path
        workload_id = [string]$raw.workloadId
        cell_id = [string]$raw.cellId
        block = [long]$raw.block
        classification = $classification
    })
}

$result = [pscustomobject][ordered]@{
    campaign_schema_valid = $true
    campaign_hash_valid = $true
    prerequisite_reviews_valid = $true
    family_membership_valid = $true
    cell_contract_valid = $true
    manifest_valid = $null -ne $manifest
    raw_evidence_count = @($classifications).Count
    classifications = @($classifications)
}
if ($PassThru) {
    $result
}
else {
    'Adaptive-runtime send-composition performance validation passed.'
    $result | ConvertTo-Json -Depth 8
}
