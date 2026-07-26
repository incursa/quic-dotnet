# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CandidateRoot,
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [Parameter(Mandatory = $true)][string] $ExpectedAxisId,
    [Parameter(Mandatory = $true)][string] $ExpectedPolicyValue,
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [string] $ReviewerToolVersion = 'adaptive_runtime_actuation_proof_reviewer.v1',
    [string] $SchemaRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\schemas')).Path,
    [string] $BehaviorCatalogPath = (Resolve-Path (Join-Path $PSScriptRoot 'experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')).Path,
    [string] $CompatibilityCatalogPath = (Resolve-Path (Join-Path $PSScriptRoot 'experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Read-CandidateDocument([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $CandidateRoot $RelativePath)
}

function Test-ExactReference([object] $Reference, [object] $Document) {
    Test-AdaptiveRuntimeDocumentRef $Reference $Document
}

function Get-OperationKey([object] $Operation) {
    "$($Operation.run_id)|$($Operation.connection_key)|$($Operation.epoch_sequence)|$($Operation.axis_id)|$($Operation.decision_instance_id)|$($Operation.operation_id)"
}

function Add-Assertion(
    [System.Collections.Generic.List[object]] $Assertions,
    [System.Collections.Generic.HashSet[string]] $Failures,
    [string] $AssertionId,
    [bool] $Passed,
    [string] $Evidence,
    [string] $FailureCode,
    [bool] $NotApplicable = $false
) {
    $status = if ($NotApplicable) { 'not_applicable' } elseif ($Passed) { 'passed' } else { 'failed' }
    $Assertions.Add([pscustomobject][ordered]@{
        assertion_id = $AssertionId
        status = $status
        evidence = $Evidence
    })
    if (-not $Passed -and -not $NotApplicable) {
        [void]$Failures.Add($FailureCode)
    }
}

$proof = Read-CandidateDocument 'proof-candidate.json'
$capture = Read-CandidateDocument 'mechanism-capture.json'
$plan = Read-CandidateDocument 'inputs\experiment_plan.json'
$validation = Read-CandidateDocument 'inputs\plan_validation.json'
$manifest = Read-CandidateDocument 'inputs\compiled_execution_manifest.json'
$run = Read-CandidateDocument 'inputs\experiment_run.json'
$hostDocument = Read-CandidateDocument 'inputs\host_fingerprint.json'
$binary = Read-CandidateDocument 'inputs\binary_cohort.json'
$workload = Read-CandidateDocument 'inputs\workload_instance.json'
$requested = Read-CandidateDocument 'inputs\requested_workload_shape.json'
$effective = Read-CandidateDocument 'inputs\effective_workload_shape.json'
$evidence = Read-CandidateDocument 'inputs\operation_evidence.json'
$behavior = Read-CandidateDocument 'inputs\behavior_materialization.json'
$outcome = Read-CandidateDocument 'inputs\outcome_materialization.json'
$metrics = Read-CandidateDocument 'inputs\metric_observations.json'
$inventory = Read-CandidateDocument 'inputs\artifact_inventory.json'
$classifications = Read-CandidateDocument 'inputs\classifications.json'
$projection = Read-CandidateDocument 'expected\projection.json'
$catalog = Read-AdaptiveRuntimeJsonDocument $BehaviorCatalogPath
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument $CompatibilityCatalogPath

$assertions = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$schemaMap = @{
    $proof.schema_version = 'adaptive-runtime-actuation-proof-evidence-v1.schema.json'
    $capture.schema_version = 'adaptive-runtime-actuation-mechanism-capture-v1.schema.json'
    $plan.schema_version = 'adaptive-runtime-experiment-plan-v1.schema.json'
    $validation.schema_version = "adaptive-runtime-experiment-plan-validation-v$($validation.document_version).schema.json"
    $manifest.schema_version = 'adaptive-runtime-compiled-execution-manifest-v1.schema.json'
    $evidence.schema_version = 'adaptive-runtime-operation-evidence-v3.schema.json'
    $behavior.schema_version = 'adaptive-runtime-effective-behavior-materialization-v3.schema.json'
    $outcome.schema_version = 'adaptive-runtime-operation-outcome-materialization-v2.schema.json'
    $projection.schema_version = 'adaptive-runtime-experiment-evidence-projection-v3.schema.json'
    $catalog.schema_version = 'adaptive-runtime-effective-behavior-catalog-v2.schema.json'
    $compatibilityCatalog.schema_version = 'adaptive-runtime-classification-compatibility-catalog-v1.schema.json'
}
$documents = @(
    $proof,$capture,$plan,$validation,$manifest,$run,$hostDocument,$binary,$workload,
    $requested,$effective,$evidence,$behavior,$outcome,$metrics,$inventory,
    $classifications,$projection,$catalog,$compatibilityCatalog
)
$schemaAndHashValid = $true
foreach ($document in $documents) {
    if (-not (Test-AdaptiveRuntimeDocumentHash $document)) {
        $schemaAndHashValid = $false
        continue
    }
    if ($schemaMap.ContainsKey([string]$document.schema_version)) {
        try {
            if (-not (Test-AdaptiveRuntimeJsonSchema $document (
                Join-Path $SchemaRoot $schemaMap[[string]$document.schema_version]))) {
                $schemaAndHashValid = $false
            }
        }
        catch { $schemaAndHashValid = $false }
    }
}

$identityRefsValid =
    (Test-ExactReference $proof.source_plan_ref $plan) -and
    (Test-ExactReference $proof.plan_validation_ref $validation) -and
    (Test-ExactReference $proof.compiled_manifest_ref $manifest) -and
    (Test-ExactReference $proof.experiment_run_ref $run) -and
    (Test-ExactReference $proof.mechanism_capture_ref $capture) -and
    (Test-ExactReference $proof.operation_evidence_ref $evidence) -and
    (Test-ExactReference $proof.behavior_materialization_ref $behavior) -and
    (Test-ExactReference $proof.outcome_materialization_ref $outcome) -and
    (Test-ExactReference $proof.projection_ref $projection) -and
    (Test-ExactReference $proof.binary_cohort_ref $binary) -and
    (Test-ExactReference $proof.host_fingerprint_ref $hostDocument)

$binaryHash = (Get-FileHash (Resolve-Path $BinaryPath).Path -Algorithm SHA256).
    Hash.ToLowerInvariant()
$manifestBinary = @($manifest.binary_provenance | Where-Object role -eq 'test_binary')
$binaryExact = $manifestBinary.Count -eq 1 -and
    [string]$manifestBinary[0].content_sha256 -ceq $binaryHash -and
    [string]$binary.payload.binary_sha256 -ceq $binaryHash
Add-Assertion $assertions $failures 'binary_identity_exact' $binaryExact `
    "binary_sha256=$binaryHash" 'binary_hash_mismatch'

$sourceExact =
    [string]$proof.source_commit -ceq [string]$manifest.source_commit -and
    [string]$proof.source_commit -ceq [string]$binary.payload.source_commit
Add-Assertion $assertions $failures 'source_commit_exact' $sourceExact `
    "source_commit=$($proof.source_commit)" 'source_commit_mismatch'

$singleAxis =
    [int]$capture.forced_behavior_distinct_axis_count -eq 1 -and
    [string]$capture.axis_id -ceq $ExpectedAxisId -and
    [string]$capture.policy_value -ceq $ExpectedPolicyValue
Add-Assertion $assertions $failures 'single_behavior_distinct_axis_forced' $singleAxis `
    "axis=$($capture.axis_id);value=$($capture.policy_value)" `
    'unexpected_forced_axis_count'

$fixedTreatments = @($plan.treatments | Where-Object {
    [string]$_.axis_id -cne $ExpectedAxisId
})
$adjacentLegacy = @($fixedTreatments | Where-Object {
    [string]$_.configured_value -cne 'legacy_current'
}).Count -eq 0
Add-Assertion $assertions $failures 'adjacent_axes_legacy' $adjacentLegacy `
    "fixed_treatment_count=$($fixedTreatments.Count)" 'adjacent_axis_not_legacy'

function Get-CaptureCase([string] $Name) {
    @($capture.operations | Where-Object capture_case -eq $Name)
}
$positive = @(Get-CaptureCase 'positive_actuation')
$fallback = @(Get-CaptureCase 'safety_fallback')
$shadow = @(Get-CaptureCase 'shadow_neutrality')
$rollback = @(Get-CaptureCase 'rollback')
$positiveExact = $positive.Count -eq 1
$activationThreshold = if (
    $ExpectedAxisId -eq 'application_send_batch_formation') { 1 } else { 2 }
$activation = $positiveExact -and
    [long]$positive[0].legal_work_count -gt $activationThreshold
Add-Assertion $assertions $failures 'activation_predicate_reached' $activation `
    "legal_work_count=$(if ($positiveExact) {$positive[0].legal_work_count} else {0})" `
    'activation_predicate_not_reached'
$candidateExact = $positiveExact -and
    [string]$positive[0].forced_value -ceq $ExpectedPolicyValue -and
    [string]$positive[0].candidate_value -ceq $ExpectedPolicyValue
Add-Assertion $assertions $failures 'candidate_value_exact' $candidateExact `
    "candidate=$(if ($positiveExact) {$positive[0].candidate_value} else {'missing'})" `
    'candidate_value_mismatch'
$eligible = $positiveExact -and
    [string]$positive[0].operation_eligibility_result -ceq 'eligible'
Add-Assertion $assertions $failures 'operation_eligible' $eligible `
    "eligibility=$(if ($positiveExact) {$positive[0].operation_eligibility_result} else {'missing'})" `
    'mechanism_evidence_invalid'
$applied = $positiveExact -and
    [string]$positive[0].applied_value -ceq $ExpectedPolicyValue
Add-Assertion $assertions $failures 'policy_value_applied' $applied `
    "applied=$(if ($positiveExact) {$positive[0].applied_value} else {'missing'})" `
    'mechanism_evidence_invalid'
$expectedMechanism = if ($ExpectedAxisId -eq 'application_send_batch_formation') {
    'mechanism_event.batch_single_eligible'
} else { 'mechanism_event.buffer_two_source_cap' }
$mechanism = $positiveExact -and
    [string]$positive[0].mechanism_event_id -ceq $expectedMechanism
Add-Assertion $assertions $failures 'mechanism_event_runtime_derived' $mechanism `
    "mechanism_event=$($positive[0].mechanism_event_id)" 'mechanism_evidence_invalid'

$lowerOnly = $positiveExact -and
    [long]$positive[0].applied_work_count -le [long]$positive[0].legal_work_count
if ($lowerOnly -and $null -ne $positive[0].legal_order_keys) {
    $expectedPrefix = @($positive[0].legal_order_keys)[0..([int]$positive[0].applied_work_count - 1)]
    $lowerOnly = (ConvertTo-Json @($positive[0].applied_order_keys) -Compress) -ceq
        (ConvertTo-Json $expectedPrefix -Compress)
}
Add-Assertion $assertions $failures 'ordering_and_lower_only_authority' $lowerOnly `
    "legal=$($positive[0].legal_work_count);applied=$($positive[0].applied_work_count)" `
    'mechanism_evidence_invalid'

$fallbackValid = $fallback.Count -eq 1 -and
    [string]$fallback[0].candidate_value -ceq $ExpectedPolicyValue -and
    [string]$fallback[0].applied_value -ceq 'legacy_current' -and
    [string]$fallback[0].operation_eligibility_result -in @('clamped','ineligible')
Add-Assertion $assertions $failures 'fallback_authoritative' $fallbackValid `
    "fallback_count=$($fallback.Count)" 'fallback_semantics_invalid'
$shadowValid = $shadow.Count -eq 1 -and
    $null -eq $shadow[0].forced_value -and
    [string]$shadow[0].shadow_recommendation -ceq $ExpectedPolicyValue -and
    [string]$shadow[0].applied_value -ceq 'legacy_current'
Add-Assertion $assertions $failures 'shadow_non_actuating' $shadowValid `
    "shadow_count=$($shadow.Count)" 'shadow_actuated'
$rollbackValid = $rollback.Count -eq 1 -and
    $null -eq $rollback[0].forced_value -and
    $null -eq $rollback[0].shadow_recommendation -and
    [string]$rollback[0].candidate_value -ceq 'legacy_current' -and
    [string]$rollback[0].applied_value -ceq 'legacy_current'
Add-Assertion $assertions $failures 'rollback_restored_legacy' $rollbackValid `
    "rollback_count=$($rollback.Count)" 'rollback_semantics_invalid'

$evidenceKeys = @($evidence.operations | ForEach-Object { Get-OperationKey $_ })
$captureKeys = @($capture.operations | ForEach-Object {
    "$($capture.run_id)|$($_.connection_key)|$($_.epoch_sequence)|$($capture.axis_id)|$($_.decision_instance_id)|$($_.operation_id)"
})
$completeIdentity = $identityRefsValid -and
    @($evidenceKeys | Sort-Object) -join "`n" -ceq
    @($captureKeys | Sort-Object) -join "`n"
Add-Assertion $assertions $failures 'complete_identity_reconciled' $completeIdentity `
    "operation_count=$($evidenceKeys.Count)" 'complete_identity_mismatch'

$recomputedBehavior = New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$behaviorExact = (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedBehavior -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior -IncludeRootContentSha256)
Add-Assertion $assertions $failures 'behavior_catalog_materialization_recomputed' $behaviorExact `
    "hash=$($recomputedBehavior.content_sha256)" 'candidate_reference_mismatch'
$recomputedOutcome = New-AdaptiveRuntimeOutcomeMaterializationV2 $evidence $catalog $classifications
$outcomeExact = (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedOutcome -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome -IncludeRootContentSha256)
Add-Assertion $assertions $failures 'outcome_catalog_materialization_recomputed' $outcomeExact `
    "hash=$($recomputedOutcome.content_sha256)" 'candidate_reference_mismatch'

$projectionScript = Join-Path $PSScriptRoot 'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1'
$projectionArgs = @{
    PlanPath = Join-Path $CandidateRoot 'inputs\experiment_plan.json'
    PlanValidationPath = Join-Path $CandidateRoot 'inputs\plan_validation.json'
    CompiledManifestPath = Join-Path $CandidateRoot 'inputs\compiled_execution_manifest.json'
    ExperimentRunPath = Join-Path $CandidateRoot 'inputs\experiment_run.json'
    HostFingerprintPath = Join-Path $CandidateRoot 'inputs\host_fingerprint.json'
    BinaryCohortPath = Join-Path $CandidateRoot 'inputs\binary_cohort.json'
    WorkloadInstancePath = Join-Path $CandidateRoot 'inputs\workload_instance.json'
    RequestedWorkloadShapePath = Join-Path $CandidateRoot 'inputs\requested_workload_shape.json'
    EffectiveWorkloadShapePath = Join-Path $CandidateRoot 'inputs\effective_workload_shape.json'
    OperationEvidencePath = Join-Path $CandidateRoot 'inputs\operation_evidence.json'
    BehaviorMaterializationPath = Join-Path $CandidateRoot 'inputs\behavior_materialization.json'
    OutcomeMaterializationPath = Join-Path $CandidateRoot 'inputs\outcome_materialization.json'
    MetricObservationsPath = Join-Path $CandidateRoot 'inputs\metric_observations.json'
    ArtifactInventoryPath = Join-Path $CandidateRoot 'inputs\artifact_inventory.json'
    ClassificationsPath = Join-Path $CandidateRoot 'inputs\classifications.json'
    BehaviorCatalogPath = $BehaviorCatalogPath
    ClassificationCompatibilityCatalogPath = $CompatibilityCatalogPath
    PassThru = $true
}
$recomputedProjection = & $projectionScript @projectionArgs
$projectionExact = (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedProjection -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection -IncludeRootContentSha256)
Add-Assertion $assertions $failures 'immutable_projection_chain_valid' `
    ($schemaAndHashValid -and $identityRefsValid -and $projectionExact) `
    "hash=$($recomputedProjection.content_sha256)" 'projection_recompute_mismatch'

$performanceAbsent =
    @($metrics.payload.metric_observations | Where-Object {
        [string]$_.analytical_use -cne 'correctness_only' -or
        -not ([string]$_.metric_id).StartsWith('metric.correctness.', [StringComparison]::Ordinal)
    }).Count -eq 0 -and
    $proof.performance_acceptance_authorization -eq $false -and
    $manifest.performance_acceptance_authorization -eq $false
Add-Assertion $assertions $failures 'no_performance_metric_used' $performanceAbsent `
    "metric_count=$(@($metrics.payload.metric_observations).Count)" 'performance_metric_used'

$terminalValid = $true
$terminalNotApplicable = $ExpectedAxisId -ne 'buffer_copy_coalescing'
if (-not $terminalNotApplicable) {
    $positiveKey = Get-OperationKey $evidence.operations[(
        [array]::IndexOf(@($capture.operations.capture_case), 'positive_actuation'))]
    $matchingRelease = @($evidence.releases | Where-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.operation_epoch_sequence)|$($_.axis_id)|$($_.decision_instance_id)|$($_.operation_id)" -ceq $positiveKey
    })
    $terminalValid = $matchingRelease.Count -eq 1 -and
        [long]$matchingRelease[0].release_count -eq 1 -and
        [long]$matchingRelease[0].release_epoch_sequence -ge
            [long]$matchingRelease[0].operation_epoch_sequence
}
Add-Assertion $assertions $failures 'terminal_release_exact_once' $terminalValid `
    "release_count=$(@($evidence.releases).Count)" 'terminal_release_invalid' `
    $terminalNotApplicable

$outcomeValue = if ($failures.Count -eq 0) { 'passed' } else { 'failed' }
$review = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-actuation-proof-review-v1'
    document_id = "review.$($proof.proof_candidate_id)"
    document_version = 1
    content_sha256 = '0' * 64
    review_id = "review.$($proof.proof_candidate_id).v1"
    candidate_ref = New-AdaptiveRuntimeDocumentRef $proof
    axis_id = $ExpectedAxisId
    policy_value = $ExpectedPolicyValue
    review_outcome = $outcomeValue
    reviewer_tool_version = $ReviewerToolVersion
    source_commit = [string]$proof.source_commit
    binary_sha256 = $binaryHash
    recomputed_behavior_materialization_sha256 = [string]$recomputedBehavior.content_sha256
    recomputed_outcome_materialization_sha256 = [string]$recomputedOutcome.content_sha256
    recomputed_projection_sha256 = [string]$recomputedProjection.content_sha256
    assertion_results = @($assertions | Sort-Object assertion_id)
    failure_codes = @($failures | Sort-Object -CaseSensitive)
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = [ordered]@{
        requirement_ids = @('REQ-QUIC-CRT-0223')
        architecture_ids = @('ARC-QUIC-CRT-0107')
        work_item_ids = @('WI-QUIC-CRT-0108')
        verification_ids = @('VER-QUIC-CRT-0109')
    }
}
[void](Set-AdaptiveRuntimeDocumentHash $review)
if (-not (Test-AdaptiveRuntimeJsonSchema $review (
    Join-Path $SchemaRoot 'adaptive-runtime-actuation-proof-review-v1.schema.json'))) {
    throw 'actuation_proof_review_schema_invalid'
}
Write-AdaptiveRuntimeCanonicalDocument $review $OutputPath
$review
