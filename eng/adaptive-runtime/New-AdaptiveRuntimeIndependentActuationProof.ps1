# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MechanismCapturePath,
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $ValidationPath,
    [Parameter(Mandatory = $true)][string] $ManifestPath,
    [Parameter(Mandatory = $true)][string] $OutputRoot,
    [string] $CandidateGenerationId,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:FactorProofMode = $false

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

if (-not [string]::IsNullOrWhiteSpace($CandidateGenerationId) -and
    $CandidateGenerationId -notmatch '^[a-z0-9][a-z0-9._-]*$') {
    throw 'CandidateGenerationId must be a stable lower-case identifier.'
}

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)][object] $Value)
    return $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Code
    )
    if (-not $Condition) {
        throw $Code
    }
}

function New-ProofTraceReferences {
    if ($script:FactorProofMode) {
        return [pscustomobject][ordered]@{
            requirement_ids = @(
                'REQ-QUIC-CRT-0235',
                'REQ-QUIC-CRT-0236',
                'REQ-QUIC-CRT-0237',
                'REQ-QUIC-CRT-0238',
                'REQ-QUIC-CRT-0239',
                'REQ-QUIC-CRT-0240'
            )
            architecture_ids = @('ARC-QUIC-CRT-0113')
            work_item_ids = @('WI-QUIC-CRT-0114')
            verification_ids = @('VER-QUIC-CRT-0115')
        }
    }
    return [pscustomobject][ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0218',
            'REQ-QUIC-CRT-0219',
            'REQ-QUIC-CRT-0220',
            'REQ-QUIC-CRT-0221',
            'REQ-QUIC-CRT-0222'
        )
        architecture_ids = @('ARC-QUIC-CRT-0104')
        work_item_ids = @('WI-QUIC-CRT-0105')
        verification_ids = @('VER-QUIC-CRT-0106')
    }
}

function New-InputDocument {
    param(
        [Parameter(Mandatory = $true)][string] $SchemaVersion,
        [Parameter(Mandatory = $true)][string] $DocumentId,
        [Parameter(Mandatory = $true)][object] $Payload
    )
    $document = [pscustomobject][ordered]@{
        schema_version = $SchemaVersion
        document_id = $DocumentId
        document_version = 1
        content_sha256 = '0' * 64
        payload = $Payload
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = New-ProofTraceReferences
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function New-OperationIdentity {
    param(
        [Parameter(Mandatory = $true)][object] $Operation,
        [Parameter(Mandatory = $true)][string] $RunId,
        [Parameter(Mandatory = $true)][string] $AxisId
    )
    return [pscustomobject][ordered]@{
        run_id = $RunId
        connection_key = [string]$Operation.connection_key
        epoch_sequence = [long]$Operation.epoch_sequence
        axis_id = $AxisId
        decision_instance_id = [long]$Operation.decision_instance_id
        operation_id = [long]$Operation.operation_id
    }
}

function New-OperationTarget {
    param(
        [Parameter(Mandatory = $true)][object] $Operation,
        [Parameter(Mandatory = $true)][string] $RunId,
        [Parameter(Mandatory = $true)][string] $AxisId
    )
    $identity = New-OperationIdentity $Operation $RunId $AxisId
    return [pscustomobject][ordered]@{
        target_kind = 'operation'
        run_id = $identity.run_id
        connection_key = $identity.connection_key
        epoch_sequence = $identity.epoch_sequence
        axis_id = $identity.axis_id
        decision_instance_id = $identity.decision_instance_id
        operation_id = $identity.operation_id
    }
}

function New-Classification {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)][object] $Target,
        [Parameter(Mandatory = $true)][string] $Kind
    )
    return [pscustomobject][ordered]@{
        classification_id = $Id
        target = $Target
        kind = $Kind
        reason_code = "reason.$Kind"
        retained = $true
    }
}

function Test-DocumentAgainstSchema {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $SchemaName,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )
    $schemaPath = Join-Path $RepositoryRoot "schemas\$SchemaName"
    $json = $Document | ConvertTo-Json -Depth 100 -Compress
    Assert-Condition (
        $json | Test-Json -SchemaFile $schemaPath -ErrorAction SilentlyContinue
    ) $FailureCode
}

$capture = Read-AdaptiveRuntimeJsonDocument $MechanismCapturePath
[void](Set-AdaptiveRuntimeDocumentHash $capture)
$isFactorProof = [string]$capture.schema_version -ceq
    'adaptive-runtime-actuation-mechanism-capture-v2'
$script:FactorProofMode = $isFactorProof
$captureSchemaName = if ($isFactorProof) {
    'adaptive-runtime-actuation-mechanism-capture-v2.schema.json'
}
else {
    'adaptive-runtime-actuation-mechanism-capture-v1.schema.json'
}
Test-DocumentAgainstSchema $capture `
    $captureSchemaName `
    'actuation_proof_capture_schema_invalid'
$plan = Read-AdaptiveRuntimeJsonDocument $PlanPath
$validation = Read-AdaptiveRuntimeJsonDocument $ValidationPath
$manifest = Read-AdaptiveRuntimeJsonDocument $ManifestPath
$behaviorCatalogFile = if ($isFactorProof) {
    'adaptive-runtime-effective-behavior-catalog-v3.json'
}
else {
    'adaptive-runtime-effective-behavior-catalog-v2.json'
}
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        "eng\adaptive-runtime\experiment-control\$behaviorCatalogFile")
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')

foreach ($document in @(
    $plan,
    $validation,
    $manifest,
    $catalog,
    $compatibilityCatalog
)) {
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $document) `
        'actuation_proof_source_hash_mismatch'
}
Assert-Condition (
    $plan.experiment_type -ceq 'actuation_validation'
) 'actuation_proof_experiment_type_invalid'
Assert-Condition (
    @($plan.varied_axis_ids).Count -eq 1
) 'actuation_proof_multi_axis_forcing'
Assert-Condition (
    [string]$plan.varied_axis_ids[0] -ceq [string]$capture.axis_id
) 'actuation_proof_axis_mismatch'
Assert-Condition (
    [int]$capture.forced_behavior_distinct_axis_count -eq 1
) 'actuation_proof_multi_axis_forcing'
Assert-Condition (
    $manifest.source_commit -match '^[0-9a-f]{40}$'
) 'actuation_proof_source_commit_invalid'
Assert-Condition (
    $manifest.source_plan_ref.content_sha256 -ceq $plan.content_sha256 -and
    $manifest.source_validation_ref.content_sha256 -ceq
        $validation.content_sha256
) 'actuation_proof_stale_manifest'
Assert-Condition (
    $manifest.active_behavior_authorization -eq $false -and
    $manifest.performance_acceptance_authorization -eq $false -and
    $capture.active_behavior_authorization -eq $false -and
    $capture.performance_acceptance_authorization -eq $false
) 'actuation_proof_authorization_invalid'

$axisId = [string]$capture.axis_id
$policyValue = [string]$capture.policy_value
$runId = [string]$capture.run_id
$positive = @($capture.operations |
    Where-Object capture_case -eq 'positive_actuation')
$fallback = @($capture.operations |
    Where-Object capture_case -eq 'safety_fallback')
$shadow = @($capture.operations |
    Where-Object capture_case -eq 'shadow_neutrality')
$rollback = @($capture.operations |
    Where-Object capture_case -eq 'rollback')
$inactive = @($capture.operations |
    Where-Object capture_case -eq 'structurally_inactive')
foreach ($case in @($positive, $fallback, $shadow, $rollback, $inactive)) {
    Assert-Condition ($case.Count -eq 1) `
        'actuation_proof_required_case_missing_or_duplicate'
}
Assert-Condition (
    $positive[0].forced_value -ceq $policyValue -and
    $positive[0].candidate_value -ceq $policyValue -and
    $positive[0].operation_eligibility_result -ceq 'eligible' -and
    $positive[0].operation_eligibility_reason -ceq 'eligible' -and
    $positive[0].applied_value -ceq $policyValue
) 'actuation_proof_positive_operation_invalid'
Assert-Condition (
    $fallback[0].forced_value -ceq $policyValue -and
    $fallback[0].candidate_value -ceq $policyValue -and
    $fallback[0].operation_eligibility_result -in @('clamped','ineligible') -and
    (
        (-not $isFactorProof -and
            $fallback[0].applied_value -ceq 'legacy_current') -or
        ($isFactorProof -and (
            $fallback[0].applied_value -cne $policyValue -or
            [long]$fallback[0].applied_work_count -eq 0))
    )
) 'actuation_proof_safety_fallback_invalid'
Assert-Condition (
    $null -eq $shadow[0].forced_value -and
    $null -ne $shadow[0].shadow_recommendation -and
    ($isFactorProof -or
        $shadow[0].shadow_recommendation -ceq $policyValue) -and
    $shadow[0].applied_value -ceq 'legacy_current'
) 'actuation_proof_shadow_actuated'
Assert-Condition (
    $null -eq $rollback[0].forced_value -and
    $rollback[0].applied_value -ceq 'legacy_current'
) 'actuation_proof_rollback_invalid'

$expectedValueSet = @($catalog.value_behavior_sets | Where-Object {
    [string]$_.axis_id -ceq $axisId -and
    [string]$_.policy_value -ceq $policyValue
})
Assert-Condition ($expectedValueSet.Count -eq 1) `
    'actuation_proof_behavior_set_missing'
$expectedPrimaryIds = @(
    $expectedValueSet[0].primary_expected_behavior_ids |
        Sort-Object -CaseSensitive)
$expectedEvents = @($catalog.effective_behaviors | Where-Object {
    $expectedPrimaryIds -contains [string]$_.effective_behavior_id
} | ForEach-Object mechanism_event_ids | Sort-Object -Unique)
Assert-Condition (
    $expectedEvents -contains [string]$positive[0].mechanism_event_id
) 'actuation_proof_wrong_mechanism_event'
if (-not $isFactorProof -and
    $axisId -ceq 'application_send_batch_formation') {
    Assert-Condition (
        [long]$positive[0].legal_work_count -gt 1 -and
        [long]$positive[0].applied_work_count -eq 1 -and
        [long]$positive[0].applied_work_count -le
            [long]$positive[0].legal_work_count
    ) 'actuation_proof_activation_not_reached'
}
elseif (-not $isFactorProof) {
    Assert-Condition (
        [long]$positive[0].legal_work_count -gt 2 -and
        [long]$positive[0].applied_work_count -eq 2 -and
        [long]$positive[0].applied_work_count -le
            [long]$positive[0].legal_work_count
    ) 'actuation_proof_activation_not_reached'
}
elseif ($axisId -ceq 'oversized_write_admission_quantum') {
    $expectedAppliedCount = if ($policyValue -ceq 'single_fragment') {
        1
    }
    else {
        2
    }
    Assert-Condition (
        [long]$positive[0].legal_work_count -eq 2 -and
        [long]$positive[0].applied_work_count -eq $expectedAppliedCount -and
        [long]$positive[0].applied_work_count -le
            [long]$positive[0].legal_work_count
    ) 'actuation_proof_activation_not_reached'
}
elseif ($axisId -ceq 'queued_send_burst_budget') {
    Assert-Condition (
        [long]$positive[0].legal_work_count -gt 1 -and
        [long]$positive[0].applied_work_count -eq 1 -and
        [long]$positive[0].applied_work_count -lt
            [long]$positive[0].legal_work_count
    ) 'actuation_proof_activation_not_reached'
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$inputRoot = Join-Path $OutputRoot 'inputs'
$expectedRoot = Join-Path $OutputRoot 'expected'
New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $expectedRoot -Force | Out-Null

Write-AdaptiveRuntimeCanonicalDocument $capture (
    Join-Path $OutputRoot 'mechanism-capture.json')

$manifestBinary = @($manifest.binary_provenance |
    Sort-Object role, path | Select-Object -First 1)[0]
Assert-Condition (
    Test-Path -LiteralPath ([string]$manifestBinary.path)
) 'actuation_proof_stale_binary'
$actualBinaryHash = (
    Get-FileHash -LiteralPath ([string]$manifestBinary.path) `
        -Algorithm SHA256).Hash.ToLowerInvariant()
Assert-Condition (
    $actualBinaryHash -ceq [string]$manifestBinary.content_sha256
) 'actuation_proof_stale_binary'
$physicalHostId = if ($null -eq $manifest.host_fingerprint.physical_host_id) {
    $null
}
else {
    ([string]$manifest.host_fingerprint.physical_host_id).ToLowerInvariant()
}
$vmId = if ($null -eq $manifest.host_fingerprint.vm_id) { $null } else {
    ([string]$manifest.host_fingerprint.vm_id).ToLowerInvariant()
}
$hostDocument = New-InputDocument `
    'adaptive-runtime-host-fingerprint-v1' `
    "host_fingerprint.$runId" `
    ([pscustomobject][ordered]@{
        fingerprint_id = [string]$manifest.host_fingerprint.fingerprint_id
        manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        os_platform = [string]$manifest.host_fingerprint.os
        os_architecture =
            [string]$manifest.host_fingerprint.architecture
        physical_host_id = $physicalHostId
        vm_id = $vmId
        resolved_capabilities = @(
            $manifest.host_capabilities.resolved_capabilities.capability_id |
                Sort-Object -CaseSensitive)
    })
$binary = New-InputDocument `
    'adaptive-runtime-binary-cohort-v1' `
    "binary_cohort.$runId" `
    ([pscustomobject][ordered]@{
        binary_cohort_id = [string]$capture.binary_cohort_id
        manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        source_commit = [string]$manifest.source_commit
        binary_path = [string]$manifestBinary.path
        binary_sha256 = [string]$manifestBinary.content_sha256
        runner_version = [string]$manifest.runner_identity.version
        runner_sha256 = [string]$manifest.runner_identity.content_sha256
    })
$run = New-InputDocument `
    'adaptive-runtime-experiment-run-v1' `
    "experiment_run.$runId" `
    ([pscustomobject][ordered]@{
        run_id = $runId
        compiled_manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        host_fingerprint_ref =
            New-AdaptiveRuntimeDocumentRef $hostDocument
        binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
        workload_instance_ids = @("workload.$runId")
    })
$requested = New-InputDocument `
    'adaptive-runtime-workload-shape-v1' `
    "workload_shape.requested.$runId" `
    ([pscustomobject][ordered]@{
        shape_kind = 'requested'
        workload_instance_id = "workload.$runId"
        workload_archetype_id =
            'send_composition_independent_correctness_harness'
        payload_bytes = [long](($capture.operations.legal_bytes |
            Measure-Object -Maximum).Maximum)
        concurrency = 1
        operation_count = @($capture.operations).Count
    })
$effective = New-InputDocument `
    'adaptive-runtime-workload-shape-v1' `
    "workload_shape.effective.$runId" `
    ([pscustomobject][ordered]@{
        shape_kind = 'effective'
        workload_instance_id = "workload.$runId"
        workload_archetype_id =
            'send_composition_independent_correctness_harness'
        payload_bytes = [long](($capture.operations.applied_bytes |
            Measure-Object -Maximum).Maximum)
        concurrency = 1
        operation_count = @($capture.operations).Count
    })
$workload = New-InputDocument `
    'adaptive-runtime-workload-instance-v1' `
    "workload_instance.$runId" `
    ([pscustomobject][ordered]@{
        workload_instance_id = "workload.$runId"
        run_ref = New-AdaptiveRuntimeDocumentRef $run
        requested_shape_ref = New-AdaptiveRuntimeDocumentRef $requested
        effective_shape_ref = New-AdaptiveRuntimeDocumentRef $effective
    })

$operations = @($capture.operations | ForEach-Object {
    [pscustomobject][ordered]@{
        run_id = $runId
        connection_key = [string]$_.connection_key
        epoch_sequence = [long]$_.epoch_sequence
        axis_id = $axisId
        decision_instance_id = [long]$_.decision_instance_id
        operation_id = [long]$_.operation_id
        configured_value = [string]$_.configured_value
        forced_value = $_.forced_value
        shadow_recommendation = $_.shadow_recommendation
        candidate_value = [string]$_.candidate_value
        operation_eligibility_result =
            [string]$_.operation_eligibility_result
        operation_eligibility_reason =
            [string]$_.operation_eligibility_reason
        applied_value = [string]$_.applied_value
        operation_kind = [string]$_.operation_kind
        scope_version = 1
        mechanism_event_id = [string]$_.mechanism_event_id
        legal_work_count = [long]$_.legal_work_count
        applied_work_count = [long]$_.applied_work_count
        legal_bytes = [long]$_.legal_bytes
        applied_bytes = [long]$_.applied_bytes
        result = [string]$_.result
        fallback_or_safety_reason = $_.fallback_or_safety_reason
        terminal_outcome = [string]$_.terminal_outcome
    }
})
$decisions = @($operations | ForEach-Object {
    [pscustomobject][ordered]@{
        run_id = $_.run_id
        connection_key = $_.connection_key
        epoch_sequence = $_.epoch_sequence
        axis_id = $_.axis_id
        decision_instance_id = $_.decision_instance_id
        configured_value = $_.configured_value
        forced_value = $_.forced_value
        shadow_recommendation = $_.shadow_recommendation
        candidate_value = $_.candidate_value
        operation_eligibility_result = $_.operation_eligibility_result
        operation_eligibility_reason = $_.operation_eligibility_reason
        applied_value = $_.applied_value
    }
})
$releases = @($capture.releases | ForEach-Object {
    [pscustomobject][ordered]@{
        run_id = $runId
        connection_key = [string]$_.connection_key
        axis_id = $axisId
        decision_instance_id = [long]$_.decision_instance_id
        operation_id = [long]$_.operation_id
        operation_epoch_sequence = [long]$_.operation_epoch_sequence
        decision_epoch_sequence = [long]$_.decision_epoch_sequence
        release_epoch_sequence = [long]$_.release_epoch_sequence
        release_count = [long]$_.release_count
        terminal_outcome = [string]$_.terminal_outcome
    }
})
$epochKeys = [ordered]@{}
foreach ($operation in $operations) {
    $key = "$($operation.connection_key)|$($operation.epoch_sequence)"
    $epochKeys[$key] = [pscustomobject][ordered]@{
        run_id = $runId
        connection_key = $operation.connection_key
        epoch_sequence = $operation.epoch_sequence
    }
}
foreach ($release in $releases) {
    $key = "$($release.connection_key)|$($release.release_epoch_sequence)"
    $epochKeys[$key] = [pscustomobject][ordered]@{
        run_id = $runId
        connection_key = $release.connection_key
        epoch_sequence = $release.release_epoch_sequence
    }
}
$evidence = [pscustomobject][ordered]@{
    schema_version = if ($isFactorProof) {
        'adaptive-runtime-operation-evidence-v4'
    }
    else {
        'adaptive-runtime-operation-evidence-v3'
    }
    document_id = "operation_evidence.$runId"
    document_version = if ($isFactorProof) { 4 } else { 3 }
    content_sha256 = '0' * 64
    behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $catalog
    plan_validation_ref = New-AdaptiveRuntimeDocumentRef $validation
    experiment_run_ref = New-AdaptiveRuntimeDocumentRef $run
    binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
    run_id = $runId
    binary_cohort_id = [string]$capture.binary_cohort_id
    connection_key = [string]$positive[0].connection_key
    epoch_sequence = [long]$positive[0].epoch_sequence
    result_epoch_sequence = [long]$positive[0].epoch_sequence
    connection_epochs = @($epochKeys.Values |
        Sort-Object connection_key, epoch_sequence)
    decisions = @($decisions | Sort-Object connection_key,
        decision_instance_id)
    operations = @($operations | Sort-Object connection_key,
        decision_instance_id, operation_id)
    releases = @($releases | Sort-Object connection_key,
        decision_instance_id, operation_id, release_epoch_sequence)
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = New-ProofTraceReferences
}
[void](Set-AdaptiveRuntimeDocumentHash $evidence)

$classificationsArray = @($operations | ForEach-Object {
    $kind = switch ([string]$_.result) {
        'inactive' { 'inactive' }
        'fallback' { 'fallback' }
        'clamped' { 'clamped' }
        default { 'analytically_eligible' }
    }
    New-Classification `
        "classification.$axisId.$($_.connection_key).$kind" `
        (New-OperationTarget $_ $runId $axisId) `
        $kind
})
$classificationsArray += @($releases | ForEach-Object {
    New-Classification `
        "classification.$axisId.$($_.connection_key).release" `
        ([pscustomobject][ordered]@{
            target_kind = 'release'
            run_id = $runId
            connection_key = [string]$_.connection_key
            epoch_sequence = [long]$_.operation_epoch_sequence
            axis_id = $axisId
            decision_instance_id = [long]$_.decision_instance_id
            operation_id = [long]$_.operation_id
            release_epoch_sequence = [long]$_.release_epoch_sequence
        }) `
        'diagnostic_context'
})
$classifications = New-InputDocument `
    'adaptive-runtime-classification-set-v1' `
    "classifications.$runId" `
    ([pscustomobject][ordered]@{
        evidence_ref = New-AdaptiveRuntimeDocumentRef $evidence
        compatibility_catalog_ref =
            New-AdaptiveRuntimeDocumentRef $compatibilityCatalog
        classifications = @($classificationsArray |
            Sort-Object classification_id)
    })
$behavior = New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$outcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $catalog $classifications
$metrics = New-InputDocument `
    'adaptive-runtime-metric-observations-v1' `
    "metrics.$runId" `
    ([pscustomobject][ordered]@{
        run_ref = New-AdaptiveRuntimeDocumentRef $run
        metric_observations = @($operations | ForEach-Object {
            [pscustomobject][ordered]@{
                metric_id = 'metric.correctness.operation_count'
                run_id = $runId
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
                analytical_use = 'correctness_only'
                value = 1
            }
        } | Sort-Object connection_key, epoch_sequence)
    })

$inputs = [ordered]@{
    experiment_plan = $plan
    plan_validation = $validation
    compiled_execution_manifest = $manifest
    experiment_run = $run
    host_fingerprint = $hostDocument
    binary_cohort = $binary
    workload_instance = $workload
    requested_workload_shape = $requested
    effective_workload_shape = $effective
    operation_evidence = $evidence
    behavior_materialization = $behavior
    outcome_materialization = $outcome
    metric_observations = $metrics
    classifications = $classifications
}
$inventory = New-InputDocument `
    'adaptive-runtime-artifact-inventory-v1' `
    "artifact_inventory.$runId" `
    ([pscustomobject][ordered]@{
        artifacts = @($inputs.GetEnumerator() | ForEach-Object {
            [pscustomobject][ordered]@{
                role = [string]$_.Key
                document_ref = New-AdaptiveRuntimeDocumentRef $_.Value
            }
        })
    })
$inputs.artifact_inventory = $inventory

foreach ($entry in $inputs.GetEnumerator()) {
    Write-AdaptiveRuntimeCanonicalDocument $entry.Value (
        Join-Path $inputRoot "$($entry.Key).json")
}

$projectionParams = @{
    PlanPath = Join-Path $inputRoot 'experiment_plan.json'
    PlanValidationPath = Join-Path $inputRoot 'plan_validation.json'
    CompiledManifestPath =
        Join-Path $inputRoot 'compiled_execution_manifest.json'
    ExperimentRunPath = Join-Path $inputRoot 'experiment_run.json'
    HostFingerprintPath = Join-Path $inputRoot 'host_fingerprint.json'
    BinaryCohortPath = Join-Path $inputRoot 'binary_cohort.json'
    WorkloadInstancePath = Join-Path $inputRoot 'workload_instance.json'
    RequestedWorkloadShapePath =
        Join-Path $inputRoot 'requested_workload_shape.json'
    EffectiveWorkloadShapePath =
        Join-Path $inputRoot 'effective_workload_shape.json'
    OperationEvidencePath = Join-Path $inputRoot 'operation_evidence.json'
    BehaviorMaterializationPath =
        Join-Path $inputRoot 'behavior_materialization.json'
    OutcomeMaterializationPath =
        Join-Path $inputRoot 'outcome_materialization.json'
    MetricObservationsPath = Join-Path $inputRoot 'metric_observations.json'
    ArtifactInventoryPath = Join-Path $inputRoot 'artifact_inventory.json'
    ClassificationsPath = Join-Path $inputRoot 'classifications.json'
    BehaviorCatalogPath = Join-Path $RepositoryRoot `
        "eng\adaptive-runtime\experiment-control\$behaviorCatalogFile"
    ClassificationCompatibilityCatalogPath = Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json'
    SchemaRoot = Join-Path $RepositoryRoot 'schemas'
    PassThru = $true
}
$projection1 = & (Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') `
    @projectionParams
$projection2 = & (Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') `
    @projectionParams
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection1) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection2)
) 'actuation_proof_projection_not_deterministic'
Write-AdaptiveRuntimeCanonicalDocument $projection1 (
    Join-Path $expectedRoot 'projection.json')

$positiveIdentity = New-OperationIdentity $positive[0] $runId $axisId
$fallbackIdentity = New-OperationIdentity $fallback[0] $runId $axisId
$shadowIdentity = New-OperationIdentity $shadow[0] $runId $axisId
$rollbackIdentity = New-OperationIdentity $rollback[0] $runId $axisId
$positiveDerivation = @($behavior.derivations | Where-Object {
    $_.operation_identity.run_id -ceq $positiveIdentity.run_id -and
    $_.operation_identity.connection_key -ceq
        $positiveIdentity.connection_key -and
    [long]$_.operation_identity.epoch_sequence -eq
        [long]$positiveIdentity.epoch_sequence -and
    $_.operation_identity.axis_id -ceq $positiveIdentity.axis_id -and
    [long]$_.operation_identity.decision_instance_id -eq
        [long]$positiveIdentity.decision_instance_id -and
    [long]$_.operation_identity.operation_id -eq
        [long]$positiveIdentity.operation_id
})
Assert-Condition (
    $positiveDerivation.Count -eq 1 -and
    $positiveDerivation[0].derivation_status -ceq 'matched'
) 'actuation_proof_behavior_derivation_failed'
$expectedPrimary = [string]$expectedPrimaryIds[0]
Assert-Condition (
    @($positiveDerivation[0].effective_behavior_ids) -contains
        $expectedPrimary
) 'actuation_proof_primary_behavior_missing'

$terminalReleaseIdentity = $null
if ($axisId -ceq 'buffer_copy_coalescing') {
    $releaseMatches = @($releases | Where-Object {
        $_.connection_key -ceq $positiveIdentity.connection_key -and
        [long]$_.operation_epoch_sequence -eq
            [long]$positiveIdentity.epoch_sequence -and
        [long]$_.decision_instance_id -eq
            [long]$positiveIdentity.decision_instance_id -and
        [long]$_.operation_id -eq [long]$positiveIdentity.operation_id
    })
    Assert-Condition (
        $releaseMatches.Count -eq 1 -and
        [long]$releaseMatches[0].release_count -eq 1 -and
        [long]$releaseMatches[0].release_epoch_sequence -ge
            [long]$positiveIdentity.epoch_sequence
    ) 'actuation_proof_terminal_release_invalid'
    $terminalReleaseIdentity = [pscustomobject][ordered]@{
        run_id = $runId
        connection_key = $positiveIdentity.connection_key
        operation_epoch_sequence = $positiveIdentity.epoch_sequence
        release_epoch_sequence =
            [long]$releaseMatches[0].release_epoch_sequence
        axis_id = $axisId
        decision_instance_id = $positiveIdentity.decision_instance_id
        operation_id = $positiveIdentity.operation_id
    }
}

$assertions = @(
    'activation_predicate_reached',
    'candidate_is_forced_value',
    'operation_eligibility_independent',
    'behavior_distinct_value_applied',
    'mechanism_event_runtime_derived',
    'primary_behavior_catalog_materialized',
    'safety_fallback_retained',
    'shadow_recommendation_non_actuating',
    'rollback_legacy_restored',
    'deterministic_projection_rebuild',
    'performance_measurement_absent',
    'single_behavior_distinct_axis_forced'
)
if ($axisId -ceq 'application_send_batch_formation') {
    $assertions += @(
        'batch_prefix_shortened_to_one',
        'batch_prefix_not_widened',
        'batch_order_preserved',
        'batch_inactive_operation_retained'
    )
}
elseif ($axisId -ceq 'buffer_copy_coalescing') {
    $assertions += @(
        'buffer_two_source_cap_applied',
        'buffer_prefix_not_widened',
        'buffer_owner_token_correlated',
        'buffer_terminal_release_exact_once'
    )
}
elseif ($axisId -ceq 'oversized_write_admission_quantum') {
    $assertions += @(
        'oversized_logical_write_activation_reached',
        'fragment_quantum_exact',
        'continuation_count_exact',
        'logical_write_completion_exact_once',
        'ownership_and_hard_limits_authoritative',
        'oversized_inactive_operation_retained')
}
elseif ($axisId -ceq 'queued_send_burst_budget') {
    $assertions += @(
        'queued_legal_budget_exceeded_one',
        'queued_follow_on_work_retained',
        'single_datagram_cap_changed_actor_turn',
        'transport_authority_preserved',
        'follow_on_wake_correct',
        'queued_inactive_operation_retained')
}
$activationPredicate = switch ("$axisId=$policyValue") {
    'application_send_batch_formation=single_eligible' {
        'predicate.batch.distinct_only_when_multiple_eligible'
    }
    'buffer_copy_coalescing=memory_conservative' {
        'predicate.buffer.lower_only'
    }
    'oversized_write_admission_quantum=single_fragment' {
        'predicate.oversized_write.single_fragment_distinct'
    }
    'oversized_write_admission_quantum=bounded_multi_fragment' {
        'predicate.oversized_write.bounded_multi_fragment_distinct'
    }
    'queued_send_burst_budget=single_datagram' {
        'predicate.queued_send.legal_budget_gt_one'
    }
    default { throw 'actuation_proof_activation_predicate_missing' }
}
$proofSchemaVersion = if ($isFactorProof) {
    'adaptive-runtime-actuation-proof-evidence-v2'
}
else {
    'adaptive-runtime-actuation-proof-evidence-v1'
}
$proofDocumentVersion = if ($isFactorProof) { 2 } else { 1 }
$proof = [pscustomobject][ordered]@{
    schema_version = $proofSchemaVersion
    document_id = if (
        [string]::IsNullOrWhiteSpace($CandidateGenerationId)) {
        "proof_candidate.$axisId.$policyValue"
    }
    else {
        "proof_candidate.$axisId.$policyValue.$CandidateGenerationId"
    }
    document_version = $proofDocumentVersion
    content_sha256 = '0' * 64
    proof_candidate_id = if (
        [string]::IsNullOrWhiteSpace($CandidateGenerationId)) {
        "proof_candidate.$axisId.$policyValue.v$proofDocumentVersion"
    }
    else {
        "proof_candidate.$axisId.$policyValue.v$proofDocumentVersion.$CandidateGenerationId"
    }
    axis_id = $axisId
    policy_value = $policyValue
    activation_predicate_id = $activationPredicate
    primary_behavior_signature = @($expectedPrimary)
    source_plan_ref = New-AdaptiveRuntimeDocumentRef $plan
    plan_validation_ref = New-AdaptiveRuntimeDocumentRef $validation
    compiled_manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
    experiment_run_ref = New-AdaptiveRuntimeDocumentRef $run
    mechanism_capture_ref = New-AdaptiveRuntimeDocumentRef $capture
    operation_evidence_ref = New-AdaptiveRuntimeDocumentRef $evidence
    behavior_materialization_ref = New-AdaptiveRuntimeDocumentRef $behavior
    outcome_materialization_ref = New-AdaptiveRuntimeDocumentRef $outcome
    projection_ref = New-AdaptiveRuntimeDocumentRef $projection1
    positive_actuation_operation = $positiveIdentity
    safety_fallback_operation = $fallbackIdentity
    shadow_neutrality_operation = $shadowIdentity
    rollback_operation = $rollbackIdentity
    terminal_release_evidence = $terminalReleaseIdentity
    correctness_assertions = @($assertions | Sort-Object -CaseSensitive)
    failed_assertions = @()
    harness_id = [string]$capture.harness_id
    source_commit = [string]$manifest.source_commit
    binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
    host_fingerprint_ref = New-AdaptiveRuntimeDocumentRef $hostDocument
    review_status = 'candidate'
    review_outcome = $null
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = New-ProofTraceReferences
}
[void](Set-AdaptiveRuntimeDocumentHash $proof)
Test-DocumentAgainstSchema $proof `
    (if ($isFactorProof) {
        'adaptive-runtime-actuation-proof-evidence-v2.schema.json'
    }
    else {
        'adaptive-runtime-actuation-proof-evidence-v1.schema.json'
    }) `
    'actuation_proof_schema_invalid'
Write-AdaptiveRuntimeCanonicalDocument $proof (
    Join-Path $OutputRoot 'proof-candidate.json')

$evidenceErrors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
    -Evidence $evidence `
    -Catalog $catalog `
    -PlanValidation $validation `
    -ClassificationSet $classifications `
    -CompatibilityCatalog $compatibilityCatalog `
    -ArtifactInventory $inventory)
Assert-Condition ($evidenceErrors.Count -eq 0) (
    "actuation_proof_evidence_invalid:$($evidenceErrors -join ',')")

$summary = [pscustomobject][ordered]@{
    axis_id = $axisId
    policy_value = $policyValue
    proof_candidate_id = $proof.proof_candidate_id
    candidate_generation_id = if (
        [string]::IsNullOrWhiteSpace($CandidateGenerationId)) {
        $null
    }
    else {
        $CandidateGenerationId
    }
    review_status = 'candidate'
    source_commit = $manifest.source_commit
    binary_sha256 = $manifestBinary.content_sha256
    host_fingerprint_id = $manifest.host_fingerprint.fingerprint_id
    operation_count = $operations.Count
    release_count = $releases.Count
    behavior_aggregate_count = @($behavior.aggregates).Count
    outcome_aggregate_count = @($outcome.aggregates).Count
    authority_chain_inputs = @($projection1.authority_chain).Count
    mechanism_capture_hash = $capture.content_sha256
    operation_evidence_hash = $evidence.content_sha256
    behavior_materialization_hash = $behavior.content_sha256
    outcome_materialization_hash = $outcome.content_sha256
    projection_hash = $projection1.content_sha256
    proof_hash = $proof.content_sha256
    active_behavior_authorized = $false
    performance_acceptance_authorized = $false
}
$summaryJson = ConvertTo-AdaptiveRuntimeCanonicalJson $summary
[System.IO.File]::WriteAllText(
    (Join-Path $OutputRoot 'summary.json'),
    $summaryJson,
    [System.Text.UTF8Encoding]::new($false))
if ($PassThru) {
    $summary
}
