# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceRoot,
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Read-Input([string] $Name) {
    Read-AdaptiveRuntimeJsonDocument (
        Join-Path $EvidenceRoot "inputs\$Name.json")
}
function Assert-Review([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}
function Get-OperationKey([object] $Value) {
    "$($Value.run_id)|$($Value.connection_key)|$($Value.epoch_sequence)|$($Value.axis_id)|$($Value.decision_instance_id)|$($Value.operation_id)"
}

$capture = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $EvidenceRoot 'mechanism-capture.json')
$proof = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $EvidenceRoot 'interaction-proof.json')
$plan = Read-Input 'experiment_plan'
$validation = Read-Input 'plan_validation'
$manifest = Read-Input 'compiled_execution_manifest'
$run = Read-Input 'experiment_run'
$evidence = Read-Input 'operation_evidence'
$behavior = Read-Input 'behavior_materialization'
$outcome = Read-Input 'outcome_materialization'
$classifications = Read-Input 'classifications'
$inventory = Read-Input 'artifact_inventory'
$metrics = Read-Input 'metric_observations'
$projection = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $EvidenceRoot 'expected\projection.json')
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')
$compatibility = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')

foreach ($document in @(
    $capture,$proof,$plan,$validation,$manifest,$run,$evidence,$behavior,
    $outcome,$classifications,$inventory,$metrics,$projection,$catalog,
    $compatibility)) {
    Assert-Review (Test-AdaptiveRuntimeDocumentHash $document) `
        'interaction_review_hash_invalid'
}
Assert-Review (
    $validation.validation_classification -ceq 'valid_interaction_screen' -and
    $manifest.build_status -ceq 'compiled' -and
    $manifest.correctness_interaction_authorization.execution_purpose -ceq
        'correctness_only' -and
    @($manifest.correctness_interaction_authorization.axis_values).Count -eq 2 -and
    @($manifest.correctness_interaction_authorization.reviewed_proof_refs).Count -eq 2
) 'interaction_review_manifest_unauthorized'
Assert-Review (
    $capture.manifest_content_sha256 -ceq $manifest.content_sha256 -and
    $capture.exact_cell_id -ceq
        $manifest.correctness_interaction_authorization.cell_id -and
    [int]$capture.forced_behavior_distinct_axis_count -eq 2
) 'interaction_review_runtime_cell_mismatch'

$caseMap = @{}
foreach ($record in @($capture.operations)) {
    if (-not $caseMap.ContainsKey([string]$record.interaction_case)) {
        $caseMap[[string]$record.interaction_case] =
            [System.Collections.Generic.List[object]]::new()
    }
    $caseMap[[string]$record.interaction_case].Add($record)
}
$both = @($caseMap.both_distinct)
Assert-Review (
    $both.Count -eq 2 -and
    @($both.axis_id | Sort-Object -Unique).Count -eq 2 -and
    @($both | Where-Object {
        $_.axis_id -eq 'application_send_batch_formation' -and
        $_.evidence.mechanism_event_id -eq
            'mechanism_event.batch_single_eligible' -and
        [long]$_.evidence.legal_work_count -gt 1 -and
        [long]$_.evidence.applied_work_count -eq 1
    }).Count -eq 1 -and
    @($both | Where-Object {
        $_.axis_id -eq 'buffer_copy_coalescing' -and
        $_.evidence.mechanism_event_id -eq
            'mechanism_event.buffer_two_source_cap' -and
        [long]$_.evidence.legal_work_count -gt 2 -and
        [long]$_.evidence.applied_work_count -eq 2
    }).Count -eq 1
) 'interaction_review_both_distinct_missing'
Assert-Review (
    @($caseMap.batch_distinct_buffer_inactive).Count -eq 2 -and
    @($caseMap.batch_inactive_buffer_distinct).Count -eq 2 -and
    @($caseMap.both_inactive | Where-Object {
        $_.evidence.result -eq 'inactive'
    }).Count -eq 2
) 'interaction_review_inactivity_matrix_invalid'
$fallback = @($caseMap.safety_fallback)
$shadow = @($caseMap.shadow_neutrality)
$rollback = @($caseMap.rollback)
Assert-Review (
    $fallback.Count -eq 1 -and
    $fallback[0].evidence.candidate_value -eq 'single_eligible' -and
    $fallback[0].evidence.applied_value -eq 'legacy_current' -and
    $fallback[0].evidence.operation_eligibility_result -eq 'clamped'
) 'interaction_review_fallback_invalid'
Assert-Review (
    $shadow.Count -eq 1 -and
    $null -eq $shadow[0].evidence.forced_value -and
    $shadow[0].evidence.shadow_recommendation -eq 'single_eligible' -and
    $shadow[0].evidence.applied_value -eq 'legacy_current'
) 'interaction_review_shadow_actuated'
Assert-Review (
    $rollback.Count -eq 1 -and
    $null -eq $rollback[0].evidence.forced_value -and
    $rollback[0].evidence.applied_value -eq 'legacy_current'
) 'interaction_review_rollback_invalid'

$operationKeys = @($evidence.operations | ForEach-Object {
    Get-OperationKey $_
})
Assert-Review (
    @($operationKeys | Sort-Object -Unique).Count -eq
        @($evidence.operations).Count
) 'interaction_review_duplicate_operation'
$bufferOperations = @($evidence.operations | Where-Object {
    $_.axis_id -eq 'buffer_copy_coalescing'
})
foreach ($operation in $bufferOperations) {
    $releaseMatches = @($evidence.releases | Where-Object {
        $_.run_id -ceq $operation.run_id -and
        $_.connection_key -ceq $operation.connection_key -and
        $_.axis_id -ceq $operation.axis_id -and
        [long]$_.decision_instance_id -eq
            [long]$operation.decision_instance_id -and
        [long]$_.operation_id -eq [long]$operation.operation_id -and
        [long]$_.operation_epoch_sequence -eq
            [long]$operation.epoch_sequence
    })
    Assert-Review (
        $releaseMatches.Count -eq 1 -and
        [long]$releaseMatches[0].release_count -eq 1 -and
        [long]$releaseMatches[0].release_epoch_sequence -ge
            [long]$operation.epoch_sequence
    ) 'interaction_review_terminal_release_invalid'
}

$evidenceErrors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
    -Evidence $evidence -Catalog $catalog -PlanValidation $validation `
    -ClassificationSet $classifications `
    -CompatibilityCatalog $compatibility -ArtifactInventory $inventory)
Assert-Review ($evidenceErrors.Count -eq 0) (
    "interaction_review_evidence_invalid:$($evidenceErrors -join ',')")
$recomputedBehavior =
    New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$recomputedOutcome =
    New-AdaptiveRuntimeOutcomeMaterializationV2 `
        $evidence $catalog $classifications
Assert-Review (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedBehavior `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior `
        -IncludeRootContentSha256)
) 'interaction_review_behavior_recompute_mismatch'
Assert-Review (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedOutcome `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome `
        -IncludeRootContentSha256)
) 'interaction_review_outcome_recompute_mismatch'

$projectionArgs=@{
    PlanPath=Join-Path $EvidenceRoot 'inputs\experiment_plan.json'
    PlanValidationPath=Join-Path $EvidenceRoot 'inputs\plan_validation.json'
    CompiledManifestPath=Join-Path $EvidenceRoot 'inputs\compiled_execution_manifest.json'
    ExperimentRunPath=Join-Path $EvidenceRoot 'inputs\experiment_run.json'
    HostFingerprintPath=Join-Path $EvidenceRoot 'inputs\host_fingerprint.json'
    BinaryCohortPath=Join-Path $EvidenceRoot 'inputs\binary_cohort.json'
    WorkloadInstancePath=Join-Path $EvidenceRoot 'inputs\workload_instance.json'
    RequestedWorkloadShapePath=Join-Path $EvidenceRoot 'inputs\requested_workload_shape.json'
    EffectiveWorkloadShapePath=Join-Path $EvidenceRoot 'inputs\effective_workload_shape.json'
    OperationEvidencePath=Join-Path $EvidenceRoot 'inputs\operation_evidence.json'
    BehaviorMaterializationPath=Join-Path $EvidenceRoot 'inputs\behavior_materialization.json'
    OutcomeMaterializationPath=Join-Path $EvidenceRoot 'inputs\outcome_materialization.json'
    MetricObservationsPath=Join-Path $EvidenceRoot 'inputs\metric_observations.json'
    ArtifactInventoryPath=Join-Path $EvidenceRoot 'inputs\artifact_inventory.json'
    ClassificationsPath=Join-Path $EvidenceRoot 'inputs\classifications.json'
    BehaviorCatalogPath=Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json'
    ClassificationCompatibilityCatalogPath=Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json'
    PassThru=$true
}
$recomputedProjection=& (Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') @projectionArgs
Assert-Review (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedProjection `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection `
        -IncludeRootContentSha256)
) 'interaction_review_projection_recompute_mismatch'
Assert-Review (
    @($metrics.payload.metric_observations | Where-Object {
        $_.analytical_use -cne 'correctness_only' -or
        -not ([string]$_.metric_id).StartsWith(
            'metric.correctness.', [StringComparison]::Ordinal)
    }).Count -eq 0
) 'interaction_review_performance_metric_prohibited'

$assertions=@(
    'authorization_exact','both_distinct_cell_level',
    'batch_distinct_buffer_inactive','batch_inactive_buffer_distinct',
    'both_inactive','fallback_authoritative','shadow_non_actuating',
    'rollback_clean','composite_operation_accounting',
    'terminal_release_exact','behavior_recomputed','outcome_recomputed',
    'projection_recomputed','correctness_metrics_only')
$review=[pscustomobject][ordered]@{
    schema_version='adaptive-runtime-send-composition-interaction-review-v1'
    document_id='review.send_composition.correctness'
    document_version=1;content_sha256='0'*64
    review_id='review.send_composition.correctness.v1'
    interaction_proof_ref=New-AdaptiveRuntimeDocumentRef $proof
    review_outcome='passed'
    reviewer_tool_version='adaptive_runtime_send_composition_reviewer.v1'
    assertion_ids=@($assertions|Sort-Object -CaseSensitive)
    failure_codes=@()
    recomputed_behavior_sha256=$recomputedBehavior.content_sha256
    recomputed_outcome_sha256=$recomputedOutcome.content_sha256
    recomputed_projection_sha256=$recomputedProjection.content_sha256
    active_behavior_authorization=$false
    performance_acceptance_authorization=$false
    trace_references=[ordered]@{
        requirement_ids=@('REQ-QUIC-CRT-0227')
        architecture_ids=@('ARC-QUIC-CRT-0107')
        work_item_ids=@('WI-QUIC-CRT-0108')
        verification_ids=@('VER-QUIC-CRT-0109')
    }
}
[void](Set-AdaptiveRuntimeDocumentHash $review)
Assert-Review (Test-AdaptiveRuntimeJsonSchema $review (
    Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-composition-interaction-review-v1.schema.json')) `
    'interaction_review_schema_invalid'
Write-AdaptiveRuntimeCanonicalDocument $review $OutputPath
$review
