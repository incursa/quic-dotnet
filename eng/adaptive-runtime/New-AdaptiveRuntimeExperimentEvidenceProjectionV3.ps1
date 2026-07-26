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
    [Parameter(Mandatory = $true)][string] $BehaviorCatalogPath,
    [Parameter(Mandatory = $true)][string] $ClassificationCompatibilityCatalogPath,
    [string] $SchemaRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\schemas')).Path,
    [string] $OutputPath,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $ErrorCode
    )
    if (-not $Condition) { throw $ErrorCode }
}

function Assert-DocumentReference {
    param(
        [Parameter(Mandatory = $true)][object] $Reference,
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $ErrorCode
    )
    Assert-Condition (Test-AdaptiveRuntimeDocumentRef $Reference $Document) $ErrorCode
}

function Get-ProjectionSchemaFile {
    param([Parameter(Mandatory = $true)][string] $SchemaVersion)

    switch ($SchemaVersion) {
        'adaptive-runtime-experiment-plan-v1' {
            'adaptive-runtime-experiment-plan-v1.schema.json'
        }
        'adaptive-runtime-experiment-plan-validation-v2' {
            'adaptive-runtime-experiment-plan-validation-v2.schema.json'
        }
        'adaptive-runtime-experiment-plan-validation-v1' {
            'adaptive-runtime-experiment-plan-validation-v1.schema.json'
        }
        'adaptive-runtime-compiled-execution-manifest-v1' {
            'adaptive-runtime-compiled-execution-manifest-v1.schema.json'
        }
        'adaptive-runtime-operation-evidence-v3' {
            'adaptive-runtime-operation-evidence-v3.schema.json'
        }
        'adaptive-runtime-effective-behavior-materialization-v3' {
            'adaptive-runtime-effective-behavior-materialization-v3.schema.json'
        }
        'adaptive-runtime-operation-outcome-materialization-v2' {
            'adaptive-runtime-operation-outcome-materialization-v2.schema.json'
        }
        'adaptive-runtime-effective-behavior-catalog-v2' {
            'adaptive-runtime-effective-behavior-catalog-v2.schema.json'
        }
        'adaptive-runtime-classification-compatibility-catalog-v1' {
            'adaptive-runtime-classification-compatibility-catalog-v1.schema.json'
        }
        { $_ -in @(
            'adaptive-runtime-experiment-run-v1',
            'adaptive-runtime-host-fingerprint-v1',
            'adaptive-runtime-binary-cohort-v1',
            'adaptive-runtime-workload-instance-v1',
            'adaptive-runtime-workload-shape-v1',
            'adaptive-runtime-metric-observations-v1',
            'adaptive-runtime-artifact-inventory-v1',
            'adaptive-runtime-classification-set-v1'
        ) } {
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        }
        default { $null }
    }
}

function Read-ProjectionDocument {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Role
    )

    $document = Read-AdaptiveRuntimeJsonDocument $Path
    foreach ($property in @(
        'document_id','schema_version','document_version','content_sha256')) {
        if ($null -eq (Get-AdaptiveRuntimeJsonProperty $document $property)) {
            throw "projection_input_schema_invalid:$Role"
        }
    }
    $schemaFile = Get-ProjectionSchemaFile ([string]$document.schema_version)
    if ([string]::IsNullOrWhiteSpace($schemaFile)) {
        throw "projection_input_schema_invalid:$Role"
    }
    try {
        $valid = Test-AdaptiveRuntimeJsonSchema $document (
            Join-Path $SchemaRoot $schemaFile)
    }
    catch {
        throw "projection_input_schema_invalid:$Role"
    }
    if (-not $valid) {
        throw "projection_input_schema_invalid:$Role"
    }
    if (-not (Test-AdaptiveRuntimeDocumentHash $document)) {
        throw "projection_input_hash_mismatch:$Role"
    }
    if ((Get-AdaptiveRuntimeJsonProperty $document `
        'active_behavior_authorization') -eq $true) {
        throw "active_behavior_unauthorized:$Role"
    }
    if ((Get-AdaptiveRuntimeJsonProperty $document `
        'performance_acceptance_authorization') -eq $true) {
        throw "performance_acceptance_unauthorized:$Role"
    }
    return $document
}

$documents = [ordered]@{
    experiment_plan =
        Read-ProjectionDocument $PlanPath 'experiment_plan'
    plan_validation =
        Read-ProjectionDocument $PlanValidationPath 'plan_validation'
    compiled_execution_manifest =
        Read-ProjectionDocument $CompiledManifestPath 'compiled_execution_manifest'
    experiment_run =
        Read-ProjectionDocument $ExperimentRunPath 'experiment_run'
    host_fingerprint =
        Read-ProjectionDocument $HostFingerprintPath 'host_fingerprint'
    binary_cohort =
        Read-ProjectionDocument $BinaryCohortPath 'binary_cohort'
    workload_instance =
        Read-ProjectionDocument $WorkloadInstancePath 'workload_instance'
    requested_workload_shape =
        Read-ProjectionDocument $RequestedWorkloadShapePath 'requested_workload_shape'
    effective_workload_shape =
        Read-ProjectionDocument $EffectiveWorkloadShapePath 'effective_workload_shape'
    operation_evidence =
        Read-ProjectionDocument $OperationEvidencePath 'operation_evidence'
    behavior_materialization =
        Read-ProjectionDocument $BehaviorMaterializationPath 'behavior_materialization'
    outcome_materialization =
        Read-ProjectionDocument $OutcomeMaterializationPath 'outcome_materialization'
    metric_observations =
        Read-ProjectionDocument $MetricObservationsPath 'metric_observations'
    artifact_inventory =
        Read-ProjectionDocument $ArtifactInventoryPath 'artifact_inventory'
    classifications =
        Read-ProjectionDocument $ClassificationsPath 'classifications'
}
$catalog = Read-ProjectionDocument $BehaviorCatalogPath 'behavior_catalog'
$compatibilityCatalog = Read-ProjectionDocument `
    $ClassificationCompatibilityCatalogPath 'classification_compatibility_catalog'

$plan = $documents.experiment_plan
$validation = $documents.plan_validation
$manifest = $documents.compiled_execution_manifest
$run = $documents.experiment_run
$hostDocument = $documents.host_fingerprint
$binary = $documents.binary_cohort
$workload = $documents.workload_instance
$requested = $documents.requested_workload_shape
$effective = $documents.effective_workload_shape
$evidence = $documents.operation_evidence
$behavior = $documents.behavior_materialization
$outcome = $documents.outcome_materialization
$metrics = $documents.metric_observations
$inventory = $documents.artifact_inventory
$classifications = $documents.classifications

Assert-DocumentReference $validation.validated_plan_ref $plan `
    'projection_plan_validation_reference_mismatch'
Assert-DocumentReference $manifest.source_plan_ref $plan `
    'projection_manifest_plan_reference_mismatch'
Assert-DocumentReference $manifest.source_validation_ref $validation `
    'projection_manifest_validation_reference_mismatch'
Assert-DocumentReference $run.payload.compiled_manifest_ref $manifest `
    'projection_run_manifest_mismatch'
Assert-DocumentReference $run.payload.host_fingerprint_ref $hostDocument `
    'projection_host_manifest_mismatch'
Assert-DocumentReference $run.payload.binary_cohort_ref $binary `
    'projection_binary_manifest_mismatch'
Assert-DocumentReference $hostDocument.payload.manifest_ref $manifest `
    'projection_host_manifest_mismatch'
Assert-DocumentReference $binary.payload.manifest_ref $manifest `
    'projection_binary_manifest_mismatch'
Assert-Condition (
    [string]$hostDocument.payload.fingerprint_id -ceq
        [string]$manifest.host_fingerprint.fingerprint_id -and
    [string]$hostDocument.payload.os_architecture -ceq
        [string]$manifest.host_fingerprint.architecture -and
    [string]$hostDocument.payload.os_platform -ceq
        [string]$manifest.host_fingerprint.os
) 'projection_host_manifest_mismatch'
$binarySource = @($manifest.binary_provenance |
    Sort-Object role, path | Select-Object -First 1)
Assert-Condition (
    $binarySource.Count -eq 1 -and
    [string]$binary.payload.source_commit -ceq [string]$manifest.source_commit -and
    [string]$binary.payload.binary_path -ceq [string]$binarySource[0].path -and
    [string]$binary.payload.binary_sha256 -ceq
        [string]$binarySource[0].content_sha256 -and
    [string]$binary.payload.runner_version -ceq
        [string]$manifest.runner_identity.version -and
    [string]$binary.payload.runner_sha256 -ceq
        [string]$manifest.runner_identity.content_sha256
) 'projection_binary_manifest_mismatch'

Assert-DocumentReference $workload.payload.run_ref $run `
    'projection_workload_run_mismatch'
Assert-DocumentReference $workload.payload.requested_shape_ref $requested `
    'projection_workload_shape_mismatch'
Assert-DocumentReference $workload.payload.effective_shape_ref $effective `
    'projection_workload_shape_mismatch'
Assert-Condition (
    @($run.payload.workload_instance_ids) -ccontains
        [string]$workload.payload.workload_instance_id -and
    [string]$requested.payload.shape_kind -ceq 'requested' -and
    [string]$effective.payload.shape_kind -ceq 'effective' -and
    [string]$requested.payload.workload_instance_id -ceq
        [string]$workload.payload.workload_instance_id -and
    [string]$effective.payload.workload_instance_id -ceq
        [string]$workload.payload.workload_instance_id
) 'projection_workload_shape_mismatch'

Assert-DocumentReference $evidence.plan_validation_ref $validation `
    'projection_evidence_validation_reference_mismatch'
Assert-DocumentReference $evidence.experiment_run_ref $run `
    'projection_run_manifest_mismatch'
Assert-DocumentReference $evidence.binary_cohort_ref $binary `
    'projection_binary_manifest_mismatch'
Assert-Condition (
    [string]$evidence.run_id -ceq [string]$run.payload.run_id -and
    [string]$evidence.binary_cohort_id -ceq
        [string]$binary.payload.binary_cohort_id
) 'projection_binary_manifest_mismatch'
Assert-DocumentReference $evidence.behavior_catalog_ref $catalog `
    'projection_materialization_catalog_reference_mismatch'
Assert-DocumentReference $classifications.payload.evidence_ref $evidence `
    'projection_classification_evidence_mismatch'
Assert-DocumentReference `
    $classifications.payload.compatibility_catalog_ref $compatibilityCatalog `
    'projection_classification_evidence_mismatch'

$evidenceErrors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
    -Evidence $evidence `
    -Catalog $catalog `
    -PlanValidation $validation `
    -ClassificationSet $classifications `
    -CompatibilityCatalog $compatibilityCatalog `
    -ArtifactInventory $inventory)
if ($evidenceErrors.Count -gt 0) {
    throw "projection_classification_evidence_mismatch:$($evidenceErrors -join ',')"
}

$recomputedBehavior =
    New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$recomputedOutcome =
    New-AdaptiveRuntimeOutcomeMaterializationV2 `
        $evidence $catalog $classifications
$behaviorBytes = ConvertTo-AdaptiveRuntimeCanonicalJson `
    $behavior -IncludeRootContentSha256
$recomputedBehaviorBytes = ConvertTo-AdaptiveRuntimeCanonicalJson `
    $recomputedBehavior -IncludeRootContentSha256
if ($behaviorBytes -cne $recomputedBehaviorBytes) {
    throw 'projection_behavior_recompute_mismatch'
}
$outcomeBytes = ConvertTo-AdaptiveRuntimeCanonicalJson `
    $outcome -IncludeRootContentSha256
$recomputedOutcomeBytes = ConvertTo-AdaptiveRuntimeCanonicalJson `
    $recomputedOutcome -IncludeRootContentSha256
if ($outcomeBytes -cne $recomputedOutcomeBytes) {
    throw 'projection_outcome_recompute_mismatch'
}

$epochKeys = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($epoch in @($evidence.connection_epochs)) {
    $key = "$($epoch.run_id)|$($epoch.connection_key)|$($epoch.epoch_sequence)"
    if (-not $epochKeys.Add($key)) {
        throw 'projection_duplicate_epoch_identity'
    }
}
foreach ($metric in @($metrics.payload.metric_observations)) {
    $key = "$($metric.run_id)|$($metric.connection_key)|$($metric.epoch_sequence)"
    if ([string]$metric.run_id -cne [string]$run.payload.run_id -or
        -not $epochKeys.Contains($key)) {
        throw 'projection_metric_epoch_missing'
    }
}
Assert-DocumentReference $metrics.payload.run_ref $run `
    'projection_metric_epoch_missing'

$expectedRoles = @($documents.Keys | Where-Object {
    $_ -cne 'artifact_inventory'
} | Sort-Object -CaseSensitive)
$actualEntries = @($inventory.payload.artifacts)
$actualRoles = @($actualEntries.role | Sort-Object -CaseSensitive)
if ((ConvertTo-Json $expectedRoles -Compress) -cne
    (ConvertTo-Json $actualRoles -Compress)) {
    throw 'projection_artifact_inventory_incomplete'
}
foreach ($entry in $actualEntries) {
    Assert-DocumentReference $entry.document_ref $documents[$entry.role] `
        'projection_artifact_inventory_incomplete'
}

foreach ($classification in @($classifications.payload.classifications)) {
    if ([string]$classification.target.target_kind -ceq 'artifact') {
        $artifactMatches = @($actualEntries | Where-Object {
            [string]$_.document_ref.document_id -ceq
                [string]$classification.target.artifact_id
        })
        if ($artifactMatches.Count -ne 1) {
            throw 'projection_classification_evidence_mismatch'
        }
    }
}

$operationIdentities = @($evidence.operations | ForEach-Object {
    New-AdaptiveRuntimeOperationIdentity $_
} | Sort-Object operation_key)
$operationKeys = @($operationIdentities.operation_key)
$aggregateSourceKeys = @()
foreach ($aggregate in @($behavior.aggregates + $outcome.aggregates)) {
    $sourceKeys = @($aggregate.source_operation_identities.operation_key)
    $aggregateSourceKeys += $sourceKeys
    if (@($sourceKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
        @($sourceKeys | Where-Object { $operationKeys -cnotcontains $_ }).Count -gt 0) {
        throw 'projection_aggregate_source_identity_missing'
    }
}
if (@($operationKeys | Where-Object {
    $aggregateSourceKeys -cnotcontains $_
}).Count -gt 0) {
    throw 'projection_aggregate_source_identity_missing'
}

$authorityChain = @($documents.GetEnumerator() | ForEach-Object {
    New-AdaptiveRuntimeDocumentRef $_.Value
})
$projection = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-experiment-evidence-projection-v3'
    document_id = "projection.v3.$($run.document_id)"
    document_version = 3
    content_sha256 = '0' * 64
    authority_chain = $authorityChain
    experiment_plan = New-AdaptiveRuntimeDocumentRef $plan
    plan_validation = New-AdaptiveRuntimeDocumentRef $validation
    compiled_execution_manifest = New-AdaptiveRuntimeDocumentRef $manifest
    experiment_run = New-AdaptiveRuntimeDocumentRef $run
    host_fingerprint = New-AdaptiveRuntimeDocumentRef $hostDocument
    binary_cohort = New-AdaptiveRuntimeDocumentRef $binary
    workload_instance = New-AdaptiveRuntimeDocumentRef $workload
    requested_workload_shape = New-AdaptiveRuntimeDocumentRef $requested
    effective_workload_shape = New-AdaptiveRuntimeDocumentRef $effective
    operation_evidence = New-AdaptiveRuntimeDocumentRef $evidence
    behavior_materialization = New-AdaptiveRuntimeDocumentRef $behavior
    outcome_materialization = New-AdaptiveRuntimeDocumentRef $outcome
    metric_observations = New-AdaptiveRuntimeDocumentRef $metrics
    artifact_inventory = New-AdaptiveRuntimeDocumentRef $inventory
    classifications = New-AdaptiveRuntimeDocumentRef $classifications
    connection_epochs = @($evidence.connection_epochs |
        Sort-Object run_id, connection_key, epoch_sequence)
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
    operation_identities = $operationIdentities
    effective_behavior_aggregates = @($behavior.aggregates |
        Sort-Object run_id, connection_key, epoch_sequence, axis_id,
            effective_behavior_id | ForEach-Object {
            [pscustomobject][ordered]@{
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
                axis_id = [string]$_.axis_id
                behavior_catalog_version = [int]$_.behavior_catalog_version
                effective_behavior_id = [string]$_.effective_behavior_id
                source_operation_keys =
                    @($_.source_operation_identities.operation_key |
                        Sort-Object -CaseSensitive)
            }
        })
    operation_outcome_aggregates = @($outcome.aggregates |
        Sort-Object run_id, connection_key, epoch_sequence, axis_id, outcome_id |
        ForEach-Object {
            [pscustomobject][ordered]@{
                run_id = [string]$_.run_id
                connection_key = [string]$_.connection_key
                epoch_sequence = [long]$_.epoch_sequence
                axis_id = [string]$_.axis_id
                outcome_contract_version = [int]$_.outcome_contract_version
                outcome_id = [string]$_.outcome_id
                source_operation_keys =
                    @($_.source_operation_identities.operation_key |
                        Sort-Object -CaseSensitive)
            }
        })
    provenance_versions = @(
        @($documents.Values) +
        @($catalog, $compatibilityCatalog) |
        ForEach-Object { [string]$_.schema_version } |
        Sort-Object -Unique -CaseSensitive
    )
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $evidence.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $projection)

try {
    $projectionValid = Test-AdaptiveRuntimeJsonSchema $projection (
        Join-Path $SchemaRoot `
            'adaptive-runtime-experiment-evidence-projection-v3.schema.json')
}
catch {
    throw 'projection_output_schema_invalid'
}
if (-not $projectionValid) { throw 'projection_output_schema_invalid' }
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-AdaptiveRuntimeCanonicalDocument $projection $OutputPath
}
if ($PassThru -or [string]::IsNullOrWhiteSpace($OutputPath)) {
    return $projection
}
