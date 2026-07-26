# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $PlanValidationPath,
    [Parameter(Mandatory = $true)][string] $CompiledManifestPath,
    [Parameter(Mandatory = $true)][string] $ExperimentRunPath,
    [Parameter(Mandatory = $true)][string] $HostFingerprintPath,
    [Parameter(Mandatory = $true)][string] $BinaryCohortPath,
    [Parameter(Mandatory = $true)][string] $WorkloadInstancePath,
    [Parameter(Mandatory = $true)][string] $RequestedWorkloadShapePath,
    [Parameter(Mandatory = $true)][string] $EffectiveWorkloadShapePath,
    [Parameter(Mandatory = $true)][string] $OperationEvidencePath,
    [Parameter(Mandatory = $true)][string] $BehaviorMaterializationPath,
    [Parameter(Mandatory = $true)][string] $OutcomeMaterializationPath,
    [Parameter(Mandatory = $true)][string] $MetricObservationsPath,
    [Parameter(Mandatory = $true)][string] $ArtifactInventoryPath,
    [Parameter(Mandatory = $true)][string] $ClassificationsPath,
    [string] $OutputPath,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1')

function Read-ImmutableDocument {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Role
    )
    $document = Read-AdaptiveRuntimeJsonDocument $Path
    foreach ($property in @(
        'document_id','schema_version','document_version','content_sha256')) {
        if ($null -eq (Get-AdaptiveRuntimeJsonProperty $document $property)) {
            throw "projection_input_missing_identity:${Role}:$property"
        }
    }
    if (-not (Test-AdaptiveRuntimeDocumentHash $document)) {
        throw "projection_input_hash_mismatch:$Role"
    }
    return $document
}

function Assert-Reference {
    param(
        [Parameter(Mandatory = $true)][object] $Reference,
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $ErrorCode
    )
    if (-not (Test-AdaptiveRuntimeDocumentRef $Reference $Document)) {
        throw $ErrorCode
    }
}

function Assert-SameReference {
    param(
        [Parameter(Mandatory = $true)][object] $Left,
        [Parameter(Mandatory = $true)][object] $Right,
        [Parameter(Mandatory = $true)][string] $ErrorCode
    )
    foreach ($property in @(
        'document_id','schema_version','document_version','content_sha256')) {
        if ([string](Get-AdaptiveRuntimeJsonProperty $Left $property) -cne
            [string](Get-AdaptiveRuntimeJsonProperty $Right $property)) {
            throw $ErrorCode
        }
    }
}

function Assert-AuthorizationFrozen {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $Role
    )
    $active = Get-AdaptiveRuntimeJsonProperty $Document `
        'active_behavior_authorization'
    $performance = Get-AdaptiveRuntimeJsonProperty $Document `
        'performance_acceptance_authorization'
    if ($active -eq $true) {
        throw "active_behavior_unauthorized:$Role"
    }
    if ($performance -eq $true) {
        throw "performance_acceptance_unauthorized:$Role"
    }
}

$plan = Read-ImmutableDocument $PlanPath 'plan'
$validation = Read-ImmutableDocument $PlanValidationPath 'plan_validation'
$manifest = Read-ImmutableDocument $CompiledManifestPath 'compiled_manifest'
$experimentRun = Read-ImmutableDocument $ExperimentRunPath 'experiment_run'
$hostFingerprint = Read-ImmutableDocument $HostFingerprintPath 'host_fingerprint'
$binaryCohort = Read-ImmutableDocument $BinaryCohortPath 'binary_cohort'
$workloadInstance = Read-ImmutableDocument $WorkloadInstancePath 'workload_instance'
$requestedWorkload = Read-ImmutableDocument $RequestedWorkloadShapePath `
    'requested_workload_shape'
$effectiveWorkload = Read-ImmutableDocument $EffectiveWorkloadShapePath `
    'effective_workload_shape'
$evidence = Read-ImmutableDocument $OperationEvidencePath 'operation_evidence'
$behavior = Read-ImmutableDocument $BehaviorMaterializationPath `
    'behavior_materialization'
$outcome = Read-ImmutableDocument $OutcomeMaterializationPath `
    'outcome_materialization'
$metrics = Read-ImmutableDocument $MetricObservationsPath 'metric_observations'
$artifacts = Read-ImmutableDocument $ArtifactInventoryPath 'artifact_inventory'
$classifications = Read-ImmutableDocument $ClassificationsPath 'classifications'

foreach ($item in @(
    @($plan, 'plan'),
    @($validation, 'plan_validation'),
    @($manifest, 'compiled_manifest'),
    @($evidence, 'operation_evidence'),
    @($behavior, 'behavior_materialization'),
    @($outcome, 'outcome_materialization')
)) {
    Assert-AuthorizationFrozen $item[0] $item[1]
}

Assert-Reference $validation.validated_plan_ref $plan `
    'projection_plan_validation_reference_mismatch'
Assert-Reference $manifest.source_plan_ref $plan `
    'projection_manifest_plan_reference_mismatch'
Assert-Reference $manifest.source_validation_ref $validation `
    'projection_manifest_validation_reference_mismatch'
Assert-Reference $evidence.plan_validation_ref $validation `
    'projection_evidence_validation_reference_mismatch'

$epochKeys = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($epoch in @($evidence.connection_epochs)) {
    $key = "$($epoch.run_id)|$($epoch.connection_key)|$($epoch.epoch_sequence)"
    if (-not $epochKeys.Add($key)) {
        throw 'projection_duplicate_epoch_identity'
    }
}
foreach ($decision in @($evidence.decisions)) {
    $key = "$($decision.run_id)|$($decision.connection_key)|$($decision.epoch_sequence)"
    if (-not $epochKeys.Contains($key)) {
        throw 'projection_decision_epoch_missing'
    }
}
foreach ($operation in @($evidence.operations)) {
    $key = "$($operation.run_id)|$($operation.connection_key)|$($operation.epoch_sequence)"
    if (-not $epochKeys.Contains($key)) {
        throw 'projection_operation_epoch_missing'
    }
}

$classificationIds = @($classifications.classifications |
    ForEach-Object { [string]$_.classification_id })
if (@($classificationIds | Group-Object |
    Where-Object Count -gt 1).Count -gt 0) {
    throw 'projection_classification_id_duplicate'
}
$operationIds = @($evidence.operations |
    ForEach-Object { [string]$_.operation_id })
$releaseIds = @($evidence.releases |
    ForEach-Object { [string]$_.operation_id })
$artifactIds = @($artifacts.artifacts |
    ForEach-Object { [string]$_.artifact_id })
$epochSequences = @($evidence.connection_epochs |
    ForEach-Object { [string]$_.epoch_sequence })
foreach ($classification in @($classifications.classifications)) {
    $targetId = [string]$classification.target_id
    $exists = switch ([string]$classification.target_kind) {
        'operation' { $operationIds -ccontains $targetId }
        'release' { $releaseIds -ccontains $targetId }
        'artifact' { $artifactIds -ccontains $targetId }
        'epoch' { $epochSequences -ccontains $targetId }
        default { $false }
    }
    if (-not $exists) {
        throw 'projection_classification_target_missing'
    }
}

Assert-Reference $behavior.source_evidence_ref $evidence `
    'projection_behavior_evidence_reference_mismatch'
Assert-Reference $outcome.source_evidence_ref $evidence `
    'projection_outcome_evidence_reference_mismatch'
Assert-SameReference $behavior.behavior_catalog_ref $outcome.behavior_catalog_ref `
    'projection_materialization_catalog_reference_mismatch'

$projection = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-experiment-evidence-projection-v2'
    document_id = "projection.$($experimentRun.document_id)"
    document_version = 2
    content_sha256 = ('0' * 64)
    authority_chain = @(
        New-AdaptiveRuntimeDocumentRef $plan
        New-AdaptiveRuntimeDocumentRef $validation
        New-AdaptiveRuntimeDocumentRef $manifest
        New-AdaptiveRuntimeDocumentRef $evidence
        New-AdaptiveRuntimeDocumentRef $behavior
        New-AdaptiveRuntimeDocumentRef $outcome
    )
    experiment_plan = New-AdaptiveRuntimeDocumentRef $plan
    plan_validation = New-AdaptiveRuntimeDocumentRef $validation
    compiled_execution_manifest = New-AdaptiveRuntimeDocumentRef $manifest
    experiment_run = New-AdaptiveRuntimeDocumentRef $experimentRun
    host_fingerprint = New-AdaptiveRuntimeDocumentRef $hostFingerprint
    binary_cohort = New-AdaptiveRuntimeDocumentRef $binaryCohort
    workload_instance = New-AdaptiveRuntimeDocumentRef $workloadInstance
    requested_workload_shape = New-AdaptiveRuntimeDocumentRef $requestedWorkload
    effective_workload_shape = New-AdaptiveRuntimeDocumentRef $effectiveWorkload
    connection_epochs = @($evidence.connection_epochs | Sort-Object `
        run_id, connection_key, epoch_sequence | ForEach-Object {
            [pscustomobject][ordered]@{
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
            }
        })
    axis_decisions = @($evidence.decisions | Sort-Object `
        run_id, connection_key, epoch_sequence, axis_id, decision_instance_id |
        ForEach-Object {
            [pscustomobject][ordered]@{
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
                axis_id = [string]$_.axis_id
                decision_instance_id = [long]$_.decision_instance_id
            }
        })
    operation_evidence = @($evidence.operations | Sort-Object `
        run_id, connection_key, epoch_sequence, axis_id, operation_id |
        ForEach-Object {
            [pscustomobject][ordered]@{
                operation_id = [long]$_.operation_id
                axis_id = [string]$_.axis_id
                decision_instance_id = [long]$_.decision_instance_id
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
            }
        })
    behavior_materialization = New-AdaptiveRuntimeDocumentRef $behavior
    outcome_materialization = New-AdaptiveRuntimeDocumentRef $outcome
    effective_behavior_aggregates = @($behavior.aggregates | Sort-Object `
        run_id, connection_key, epoch_sequence, axis_id, `
        behavior_catalog_version, effective_behavior_id | ForEach-Object {
            [pscustomobject][ordered]@{
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
                axis_id = [string]$_.axis_id
                behavior_catalog_version = [int]$_.behavior_catalog_version
                effective_behavior_id = [string]$_.effective_behavior_id
            }
        })
    operation_outcome_aggregates = @($outcome.aggregates | Sort-Object `
        run_id, connection_key, epoch_sequence, axis_id, `
        outcome_contract_version, outcome_id | ForEach-Object {
            [pscustomobject][ordered]@{
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
                axis_id = [string]$_.axis_id
                outcome_contract_version = [int]$_.outcome_contract_version
                outcome_id = [string]$_.outcome_id
            }
        })
    metric_observations = @($metrics.metric_observations | Sort-Object `
        metric_id, epoch_sequence)
    artifact_inventory = @($artifacts.artifacts | Sort-Object artifact_id)
    classifications = @($classifications.classifications | Sort-Object `
        classification_id)
    provenance_versions = @(
        @(
            $plan, $validation, $manifest, $experimentRun, $hostFingerprint,
            $binaryCohort, $workloadInstance, $requestedWorkload,
            $effectiveWorkload, $evidence, $behavior, $outcome, $metrics,
            $artifacts, $classifications
        ) | ForEach-Object { [string]$_.schema_version } | Sort-Object -Unique
    )
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $evidence.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $projection)

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-AdaptiveRuntimeCanonicalDocument $projection $OutputPath
}
if ($PassThru -or [string]::IsNullOrWhiteSpace($OutputPath)) {
    return $projection
}
