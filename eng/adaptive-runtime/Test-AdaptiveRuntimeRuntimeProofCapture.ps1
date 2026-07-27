# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-runtime-proof-capture\proofs'
$schemaRoot = Join-Path $RepositoryRoot 'schemas'
$catalogRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control'
$behaviorCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-effective-behavior-catalog-v3.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-classification-compatibility-catalog-v1.json')
$familyCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-experiment-family-catalog-v3.json')

function Copy-JsonObject {
    param([object] $Value)
    $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Assert-Condition {
    param([bool] $Condition, [string] $Code)
    if (-not $Condition) { throw $Code }
}

function Read-ProofFile {
    param([string] $Slug, [string] $RelativePath)
    Read-AdaptiveRuntimeJsonDocument (
        Join-Path (Join-Path $fixtureRoot $Slug) $RelativePath)
}

function Test-DocumentSchemaAndHash {
    param([object] $Document, [string] $Schema)
    Assert-Condition (
        Test-AdaptiveRuntimeJsonSchema $Document (
            Join-Path $schemaRoot $Schema)
    ) "runtime_proof_schema_invalid:$Schema"
    Assert-Condition (
        Test-AdaptiveRuntimeDocumentHash $Document
    ) "runtime_proof_hash_invalid:$($Document.document_id)"
}

function Get-RuntimeCaptureErrors {
    param(
        [object] $Capture,
        [object] $Export,
        [string] $ExportFileHash
    )
    $errors = [Collections.Generic.List[string]]::new()
    function Add-Error([string] $Code) {
        if (-not $errors.Contains($Code)) { $errors.Add($Code) }
    }
    if ([string]$Capture.capture_mode -cne 'runtime_evidence_sink') {
        Add-Error 'expectation_authored_capture_source'
    }
    if ([string]$Capture.runtime_source.export_id -cne
            [string]$Export.export_id -or
        [string]$Capture.runtime_source.file_sha256 -cne $ExportFileHash) {
        Add-Error 'runtime_capture_source_identity_mismatch'
    }
    if ([string]$Capture.runtime_source.source_commit -cne
            [string]$Export.source_commit) {
        Add-Error 'runtime_capture_source_commit_mismatch'
    }
    if ([string]$Capture.runtime_source.binary_sha256 -cne
            [string]$Export.binary_sha256) {
        Add-Error 'runtime_capture_binary_hash_mismatch'
    }
    if ([int]$Capture.forced_behavior_distinct_axis_count -ne 1) {
        Add-Error 'actuation_proof_multi_axis_forcing'
    }
    $caseNames = @(
        'positive_actuation',
        'structurally_inactive',
        'safety_fallback',
        'shadow_neutrality',
        'rollback')
    foreach ($caseName in $caseNames) {
        if (@($Capture.operations |
            Where-Object capture_case -ceq $caseName).Count -ne 1) {
            Add-Error 'runtime_capture_case_missing_or_duplicate'
        }
    }
    foreach ($operation in @($Capture.operations)) {
        $recordIndex = [int]$operation.runtime_source_identity.record_index
        if ($recordIndex -lt 0 -or
            $recordIndex -ge @($Export.records).Count) {
            Add-Error 'runtime_capture_record_missing'
            continue
        }
        $record = $Export.records[$recordIndex]
        if ([long]$record.decision_instance_id -ne
                [long]$operation.decision_instance_id -or
            [long]$record.operation_id -ne
                [long]$operation.operation_id -or
            [string]$record.capture_case -cne
                [string]$operation.capture_case) {
            Add-Error 'runtime_capture_operation_identity_mismatch'
        }
        if ($Capture.axis_id -ceq
            'oversized_write_admission_quantum') {
            $details = $operation.mechanism_details
            if ([long]$record.completion_count -ne 1 -or
                [long]$details.completion_count -ne 1) {
                Add-Error 'logical_write_completion_not_exact_once'
            }
            if ([long]$record.continuation_count -ne
                [long]$details.continuation_count) {
                Add-Error 'continuation_count_mismatch'
            }
            if ([long]$record.continuation_posts -ne
                [long]$details.continuation_posts) {
                Add-Error 'continuation_post_count_mismatch'
            }
        }
        else {
            $details = $operation.mechanism_details
            if ([long]$record.queued_writes_before -ne
                    [long]$details.queued_writes_before -or
                [long]$record.queued_writes_after -ne
                    [long]$details.queued_writes_after) {
                Add-Error 'queued_work_identity_mismatch'
            }
        }
    }
    $positive = @($Capture.operations |
        Where-Object capture_case -ceq 'positive_actuation')[0]
    if ([string]$positive.forced_value -cne
            [string]$Capture.policy_value -or
        [string]$positive.candidate_value -cne
            [string]$Capture.policy_value -or
        [string]$positive.applied_value -cne
            [string]$Capture.policy_value -or
        [long]$positive.legal_work_count -le
            [long]$positive.applied_work_count) {
        Add-Error 'positive_actuation_not_runtime_proven'
    }
    $inactive = @($Capture.operations |
        Where-Object capture_case -ceq 'structurally_inactive')[0]
    if ([string]$inactive.result -cne 'inactive') {
        Add-Error 'inactive_operation_not_retained'
    }
    $fallback = @($Capture.operations |
        Where-Object capture_case -ceq 'safety_fallback')[0]
    if ([string]$fallback.result -notin @('fallback','clamped')) {
        Add-Error 'safety_fallback_not_retained'
    }
    $shadow = @($Capture.operations |
        Where-Object capture_case -ceq 'shadow_neutrality')[0]
    if ($null -ne $shadow.forced_value -or
        [string]$shadow.applied_value -cne 'legacy_current') {
        Add-Error 'shadow_recommendation_actuated'
    }
    if ([string]$shadow.shadow_recommendation -cne
        [string]$Capture.policy_value) {
        Add-Error 'shadow_recommendation_value_mismatch'
    }
    $rollback = @($Capture.operations |
        Where-Object capture_case -ceq 'rollback')[0]
    if ($null -ne $rollback.forced_value -or
        [string]$rollback.candidate_value -cne 'legacy_current' -or
        [string]$rollback.applied_value -cne 'legacy_current') {
        Add-Error 'rollback_retained_policy_state'
    }
    if ($Capture.axis_id -ceq
        'oversized_write_admission_quantum') {
        $expected = if ($Capture.policy_value -ceq 'single_fragment') {
            1
        } else { 2 }
        if ([long]$positive.applied_work_count -ne $expected -or
            [long]$positive.legal_work_count -le $expected) {
            Add-Error 'oversized_activation_predicate_not_reached'
        }
        if ([long]$inactive.legal_work_count -ne 1) {
            Add-Error 'oversized_inactive_case_invalid'
        }
    }
    else {
        if ([long]$positive.legal_work_count -le 1 -or
            [long]$positive.applied_work_count -ne 1 -or
            -not [bool]$positive.mechanism_details.follow_on_wake_required) {
            Add-Error 'queued_activation_or_wake_not_proven'
        }
        if ([long]$inactive.legal_work_count -ne 1) {
            Add-Error 'queued_inactive_legal_budget_invalid'
        }
    }
    return @($errors)
}

function Get-ProjectionParameters {
    param([string] $Slug)
    $root = Join-Path (Join-Path $fixtureRoot $Slug) 'inputs'
    @{
        PlanPath = Join-Path $root 'experiment_plan.json'
        PlanValidationPath = Join-Path $root 'plan_validation.json'
        CompiledManifestPath =
            Join-Path $root 'compiled_execution_manifest.json'
        ExperimentRunPath = Join-Path $root 'experiment_run.json'
        HostFingerprintPath = Join-Path $root 'host_fingerprint.json'
        BinaryCohortPath = Join-Path $root 'binary_cohort.json'
        WorkloadInstancePath = Join-Path $root 'workload_instance.json'
        RequestedWorkloadShapePath =
            Join-Path $root 'requested_workload_shape.json'
        EffectiveWorkloadShapePath =
            Join-Path $root 'effective_workload_shape.json'
        OperationEvidencePath = Join-Path $root 'operation_evidence.json'
        BehaviorMaterializationPath =
            Join-Path $root 'behavior_materialization.json'
        OutcomeMaterializationPath =
            Join-Path $root 'outcome_materialization.json'
        MetricObservationsPath =
            Join-Path $root 'metric_observations.json'
        ArtifactInventoryPath =
            Join-Path $root 'artifact_inventory.json'
        ClassificationsPath = Join-Path $root 'classifications.json'
        BehaviorCatalogPath = Join-Path $catalogRoot `
            'adaptive-runtime-effective-behavior-catalog-v3.json'
        ClassificationCompatibilityCatalogPath = Join-Path $catalogRoot `
            'adaptive-runtime-classification-compatibility-catalog-v1.json'
        SchemaRoot = $schemaRoot
        PassThru = $true
    }
}

$configurations = @(
    [pscustomobject]@{
        Slug = 'oversized-single'
        Axis = 'oversized_write_admission_quantum'
        Value = 'single_fragment'
        ExpectedCaptureErrors = @()
    },
    [pscustomobject]@{
        Slug = 'oversized-bounded'
        Axis = 'oversized_write_admission_quantum'
        Value = 'bounded_multi_fragment'
        ExpectedCaptureErrors = @(
            'shadow_recommendation_value_mismatch')
    },
    [pscustomobject]@{
        Slug = 'queued-single'
        Axis = 'queued_send_burst_budget'
        Value = 'single_datagram'
        ExpectedCaptureErrors = @()
    }
)

$projectionHashes = [ordered]@{}
foreach ($configuration in $configurations) {
    $capture = Read-ProofFile $configuration.Slug 'mechanism-capture.json'
    $proof = Read-ProofFile $configuration.Slug 'proof-candidate.json'
    $promotion = Read-ProofFile $configuration.Slug `
        'promotion-review-input.json'
    Test-DocumentSchemaAndHash $capture `
        'adaptive-runtime-actuation-mechanism-capture-v3.schema.json'
    Test-DocumentSchemaAndHash $proof `
        'adaptive-runtime-actuation-proof-evidence-v3.schema.json'
    Test-DocumentSchemaAndHash $promotion `
        'adaptive-runtime-actuation-proof-promotion-input-v1.schema.json'
    $exportPath = Join-Path (Join-Path $fixtureRoot $configuration.Slug) `
        'runtime-sink-export.json'
    $exportJson = Get-Content -LiteralPath $exportPath -Raw
    Assert-Condition (
        Test-Json -Json $exportJson -SchemaFile (
            Join-Path $schemaRoot `
                'adaptive-runtime-runtime-proof-sink-export-v1.schema.json')
    ) 'runtime_capture_export_schema_invalid'
    $export = $exportJson | ConvertFrom-Json -Depth 100
    $exportHash = (Get-FileHash -LiteralPath $exportPath -Algorithm SHA256).
        Hash.ToLowerInvariant()
    $captureErrors = @(Get-RuntimeCaptureErrors $capture $export $exportHash |
        Sort-Object -CaseSensitive)
    $expectedErrors = @($configuration.ExpectedCaptureErrors |
        Sort-Object -CaseSensitive)
    Assert-Condition (
        (ConvertTo-Json $captureErrors -Compress) -ceq
        (ConvertTo-Json $expectedErrors -Compress)
    ) "runtime_capture_error_set_mismatch:$($configuration.Slug)"
    Assert-Condition (
        [string]$proof.axis_id -ceq $configuration.Axis -and
        [string]$proof.policy_value -ceq $configuration.Value -and
        [string]$proof.review_status -ceq 'candidate' -and
        $null -eq $proof.review_outcome -and
        $proof.active_behavior_authorization -eq $false -and
        $proof.performance_acceptance_authorization -eq $false
    ) "runtime_proof_candidate_state_invalid:$($configuration.Slug)"
    Assert-Condition (
        @($proof.failed_assertions | Sort-Object -CaseSensitive).Count -eq
        $expectedErrors.Count
    ) "runtime_proof_failed_assertion_count:$($configuration.Slug)"
    Assert-Condition (
        [string]$promotion.proof_ref.content_sha256 -ceq
            [string]$proof.content_sha256 -and
        [string]$promotion.reviewed_proof_catalog_base_hash -ceq
            [string]$familyCatalog.content_sha256 -and
        $null -eq $promotion.reviewer_identity -and
        $null -eq $promotion.review_artifact_ref -and
        $null -eq $promotion.independent_outcome -and
        [string]$promotion.promotion_state -ceq 'not_applied'
    ) "runtime_promotion_input_invalid:$($configuration.Slug)"

    $inputs = Join-Path (Join-Path $fixtureRoot $configuration.Slug) 'inputs'
    $evidence = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputs 'operation_evidence.json')
    $classifications = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputs 'classifications.json')
    $expectedBehavior = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputs 'behavior_materialization.json')
    $expectedOutcome = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputs 'outcome_materialization.json')
    $behavior = New-AdaptiveRuntimeBehaviorMaterializationV3 `
        $evidence $behaviorCatalog
    $outcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
        $evidence $behaviorCatalog $classifications
    Assert-Condition (
        [string]$behavior.content_sha256 -ceq
            [string]$expectedBehavior.content_sha256
    ) "runtime_behavior_recompute_mismatch:$($configuration.Slug)"
    Assert-Condition (
        [string]$outcome.content_sha256 -ceq
            [string]$expectedOutcome.content_sha256
    ) "runtime_outcome_recompute_mismatch:$($configuration.Slug)"
    $projectionParameters = Get-ProjectionParameters $configuration.Slug
    $projectionScript = Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1'
    $projection = & $projectionScript @projectionParameters
    $expectedProjection = Read-ProofFile $configuration.Slug `
        'expected\projection.json'
    Assert-Condition (
        [string]$projection.content_sha256 -ceq
            [string]$expectedProjection.content_sha256
    ) "runtime_projection_recompute_mismatch:$($configuration.Slug)"
    $projectionHashes[$configuration.Slug] = $projection.content_sha256
}

$singleCapture = Read-ProofFile 'oversized-single' 'mechanism-capture.json'
$singleExportPath = Join-Path (Join-Path $fixtureRoot 'oversized-single') `
    'runtime-sink-export.json'
$singleExportJson = Get-Content -LiteralPath $singleExportPath -Raw
$singleExport = $singleExportJson | ConvertFrom-Json -Depth 100
$singleExportHash = (Get-FileHash -LiteralPath $singleExportPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$negativeCases = @(
    @('expectation_authored_capture_source', {
        param($value)
        $value.capture_mode = 'focused_correctness_mechanism_harness'
    }),
    @('logical_write_completion_not_exact_once', {
        param($value)
        $value.operations[0].mechanism_details.completion_count = 0
    }),
    @('logical_write_completion_not_exact_once', {
        param($value)
        $value.operations[0].mechanism_details.completion_count = 2
    }),
    @('continuation_count_mismatch', {
        param($value)
        $value.operations[0].mechanism_details.continuation_count++
    }),
    @('oversized_activation_predicate_not_reached', {
        param($value)
        $value.operations[0].legal_work_count = 1
    }),
    @('shadow_recommendation_value_mismatch', {
        param($value)
        (@($value.operations |
            Where-Object capture_case -ceq 'shadow_neutrality')[0]).
            shadow_recommendation = 'legacy_current'
    }),
    @('runtime_capture_operation_identity_mismatch', {
        param($value)
        $value.operations[0].runtime_source_identity.operation_id++
    }),
    @('rollback_retained_policy_state', {
        param($value)
        (@($value.operations |
            Where-Object capture_case -ceq 'rollback')[0]).
            applied_value = 'single_fragment'
    }),
    @('actuation_proof_multi_axis_forcing', {
        param($value)
        $value.forced_behavior_distinct_axis_count = 2
    })
)
$negativeCount = 0
foreach ($negativeCase in $negativeCases) {
    $mutated = Copy-JsonObject $singleCapture
    & $negativeCase[1] $mutated
    $errors = @(Get-RuntimeCaptureErrors `
        $mutated $singleExport $singleExportHash)
    Assert-Condition ($errors -contains [string]$negativeCase[0]) `
        "runtime_negative_case_not_rejected:$($negativeCase[0])"
    $negativeCount++
}

[pscustomobject][ordered]@{
    result = 'passed'
    proof_candidate_count = $configurations.Count
    promotion_ready_count = 2
    promotion_blocked_count = 1
    negative_case_count = $negativeCount
    projection_hashes = $projectionHashes
    active_behavior_authorized = $false
    performance_measurement_ran = $false
}
