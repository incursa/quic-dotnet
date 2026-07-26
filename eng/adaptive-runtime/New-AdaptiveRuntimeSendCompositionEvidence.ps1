# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MechanismCapturePath,
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $ValidationPath,
    [Parameter(Mandatory = $true)][string] $ManifestPath,
    [Parameter(Mandatory = $true)][string] $OutputRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Condition([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}

function New-TraceReferences {
    [pscustomobject][ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0223','REQ-QUIC-CRT-0224','REQ-QUIC-CRT-0225',
            'REQ-QUIC-CRT-0226','REQ-QUIC-CRT-0227','REQ-QUIC-CRT-0228')
        architecture_ids = @('ARC-QUIC-CRT-0107')
        work_item_ids = @('WI-QUIC-CRT-0108')
        verification_ids = @('VER-QUIC-CRT-0109')
    }
}

function New-InputDocument(
    [string] $SchemaVersion,
    [string] $DocumentId,
    [object] $Payload
) {
    $document = [pscustomobject][ordered]@{
        schema_version = $SchemaVersion
        document_id = $DocumentId
        document_version = 1
        content_sha256 = '0' * 64
        payload = $Payload
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = New-TraceReferences
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    $document
}

function New-Classification([object] $Operation) {
    $kind = switch ([string]$Operation.result) {
        'inactive' { 'inactive' }
        'fallback' { 'fallback' }
        'clamped' { 'clamped' }
        default { 'analytically_eligible' }
    }
    [pscustomobject][ordered]@{
        classification_id =
            "classification.$($Operation.axis_id).$($Operation.connection_key).$kind"
        target = [pscustomobject][ordered]@{
            target_kind = 'operation'
            run_id = [string]$Operation.run_id
            connection_key = [string]$Operation.connection_key
            epoch_sequence = [long]$Operation.epoch_sequence
            axis_id = [string]$Operation.axis_id
            decision_instance_id = [long]$Operation.decision_instance_id
            operation_id = [long]$Operation.operation_id
        }
        kind = $kind
        reason_code = "reason.$kind"
        retained = $true
    }
}

$capture = Read-AdaptiveRuntimeJsonDocument $MechanismCapturePath
$plan = Read-AdaptiveRuntimeJsonDocument $PlanPath
$validation = Read-AdaptiveRuntimeJsonDocument $ValidationPath
$manifest = Read-AdaptiveRuntimeJsonDocument $ManifestPath
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')
foreach ($document in @($plan,$validation,$manifest,$catalog,$compatibilityCatalog)) {
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $document) `
        'interaction_source_hash_mismatch'
}
Assert-Condition (
    $plan.experiment_type -ceq 'interaction_screen' -and
    $plan.execution_purpose -ceq 'correctness_only' -and
    @($plan.varied_axis_ids).Count -eq 2 -and
    [int]$capture.forced_behavior_distinct_axis_count -eq 2
) 'interaction_plan_authorization_invalid'
Assert-Condition (
    $capture.manifest_content_sha256 -ceq $manifest.content_sha256 -and
    $manifest.correctness_interaction_authorization.cell_id -ceq
        $capture.exact_cell_id
) 'interaction_manifest_runtime_mismatch'
Assert-Condition (
    $manifest.active_behavior_authorization -eq $false -and
    $manifest.performance_acceptance_authorization -eq $false -and
    $capture.active_behavior_authorization -eq $false -and
    $capture.performance_acceptance_authorization -eq $false
) 'interaction_prohibited_authorization'

$caseIds = @($capture.operations.interaction_case |
    Sort-Object -Unique -CaseSensitive)
$requiredCases = @(
    'batch_distinct_buffer_inactive','batch_inactive_buffer_distinct',
    'both_distinct','both_inactive','rollback','safety_fallback',
    'shadow_neutrality')
Assert-Condition (
    (ConvertTo-Json $caseIds -Compress) -ceq
        (ConvertTo-Json $requiredCases -Compress)
) 'interaction_case_matrix_incomplete'

$runId = [string]$capture.run_id
$manifestBinary = @($manifest.binary_provenance |
    Sort-Object role,path | Select-Object -First 1)[0]
Assert-Condition (
    (Get-FileHash ([string]$manifestBinary.path) -Algorithm SHA256).
        Hash.ToLowerInvariant() -ceq [string]$manifestBinary.content_sha256
) 'interaction_stale_binary'

New-Item -ItemType Directory -Force $OutputRoot | Out-Null
$inputRoot = Join-Path $OutputRoot 'inputs'
$expectedRoot = Join-Path $OutputRoot 'expected'
New-Item -ItemType Directory -Force $inputRoot,$expectedRoot | Out-Null
[void](Set-AdaptiveRuntimeDocumentHash $capture)
Assert-Condition (Test-AdaptiveRuntimeJsonSchema $capture (
    Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-composition-mechanism-capture-v1.schema.json')) `
    'interaction_capture_schema_invalid'
Write-AdaptiveRuntimeCanonicalDocument $capture (
    Join-Path $OutputRoot 'mechanism-capture.json')

$hostDocument = New-InputDocument 'adaptive-runtime-host-fingerprint-v1' `
    "host_fingerprint.$runId" ([pscustomobject][ordered]@{
        fingerprint_id = [string]$manifest.host_fingerprint.fingerprint_id
        manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        os_platform = [string]$manifest.host_fingerprint.os
        os_architecture = [string]$manifest.host_fingerprint.architecture
        physical_host_id = if ($manifest.host_fingerprint.physical_host_id) {
            ([string]$manifest.host_fingerprint.physical_host_id).ToLowerInvariant()
        } else { $null }
        vm_id = if ($manifest.host_fingerprint.vm_id) {
            ([string]$manifest.host_fingerprint.vm_id).ToLowerInvariant()
        } else { $null }
        resolved_capabilities = @(
            $manifest.host_capabilities.resolved_capabilities.capability_id |
            Sort-Object -CaseSensitive)
    })
$binary = New-InputDocument 'adaptive-runtime-binary-cohort-v1' `
    "binary_cohort.$runId" ([pscustomobject][ordered]@{
        binary_cohort_id = [string]$capture.binary_cohort_id
        manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        source_commit = [string]$manifest.source_commit
        binary_path = [string]$manifestBinary.path
        binary_sha256 = [string]$manifestBinary.content_sha256
        runner_version = [string]$manifest.runner_identity.version
        runner_sha256 = [string]$manifest.runner_identity.content_sha256
    })
$run = New-InputDocument 'adaptive-runtime-experiment-run-v1' `
    "experiment_run.$runId" ([pscustomobject][ordered]@{
        run_id = $runId
        compiled_manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        host_fingerprint_ref = New-AdaptiveRuntimeDocumentRef $hostDocument
        binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
        workload_instance_ids = @("workload.$runId")
    })
$requested = New-InputDocument 'adaptive-runtime-workload-shape-v1' `
    "workload_shape.requested.$runId" ([pscustomobject][ordered]@{
        shape_kind = 'requested'
        workload_instance_id = "workload.$runId"
        workload_archetype_id = 'send_composition_correctness_harness'
        payload_bytes = [long](($capture.operations.evidence.legal_bytes |
            Measure-Object -Maximum).Maximum)
        concurrency = 1
        operation_count = @($capture.operations).Count
    })
$effective = New-InputDocument 'adaptive-runtime-workload-shape-v1' `
    "workload_shape.effective.$runId" ([pscustomobject][ordered]@{
        shape_kind = 'effective'
        workload_instance_id = "workload.$runId"
        workload_archetype_id = 'send_composition_correctness_harness'
        payload_bytes = [long](($capture.operations.evidence.applied_bytes |
            Measure-Object -Maximum).Maximum)
        concurrency = 1
        operation_count = @($capture.operations).Count
    })
$workload = New-InputDocument 'adaptive-runtime-workload-instance-v1' `
    "workload_instance.$runId" ([pscustomobject][ordered]@{
        workload_instance_id = "workload.$runId"
        run_ref = New-AdaptiveRuntimeDocumentRef $run
        requested_shape_ref = New-AdaptiveRuntimeDocumentRef $requested
        effective_shape_ref = New-AdaptiveRuntimeDocumentRef $effective
    })

$operations = @($capture.operations | ForEach-Object {
    $source = $_.evidence
    [pscustomobject][ordered]@{
        run_id = $runId
        connection_key = [string]$source.connection_key
        epoch_sequence = [long]$source.epoch_sequence
        axis_id = [string]$_.axis_id
        decision_instance_id = [long]$source.decision_instance_id
        operation_id = [long]$source.operation_id
        configured_value = [string]$source.configured_value
        forced_value = $source.forced_value
        shadow_recommendation = $source.shadow_recommendation
        candidate_value = [string]$source.candidate_value
        operation_eligibility_result =
            [string]$source.operation_eligibility_result
        operation_eligibility_reason =
            [string]$source.operation_eligibility_reason
        applied_value = [string]$source.applied_value
        operation_kind = [string]$source.operation_kind
        scope_version = 1
        mechanism_event_id = [string]$source.mechanism_event_id
        legal_work_count = [long]$source.legal_work_count
        applied_work_count = [long]$source.applied_work_count
        legal_bytes = [long]$source.legal_bytes
        applied_bytes = [long]$source.applied_bytes
        result = [string]$source.result
        fallback_or_safety_reason = $source.fallback_or_safety_reason
        terminal_outcome = [string]$source.terminal_outcome
    }
} | Sort-Object connection_key,axis_id,decision_instance_id,operation_id)
$decisions = @($operations | ForEach-Object {
    [pscustomobject][ordered]@{
        run_id=$_.run_id;connection_key=$_.connection_key
        epoch_sequence=$_.epoch_sequence;axis_id=$_.axis_id
        decision_instance_id=$_.decision_instance_id
        configured_value=$_.configured_value;forced_value=$_.forced_value
        shadow_recommendation=$_.shadow_recommendation
        candidate_value=$_.candidate_value
        operation_eligibility_result=$_.operation_eligibility_result
        operation_eligibility_reason=$_.operation_eligibility_reason
        applied_value=$_.applied_value
    }
})
$releases = @($capture.releases | ForEach-Object {
    $source = $_.evidence
    [pscustomobject][ordered]@{
        run_id=$runId;connection_key=[string]$source.connection_key
        axis_id=[string]$_.axis_id
        decision_instance_id=[long]$source.decision_instance_id
        operation_id=[long]$source.operation_id
        operation_epoch_sequence=[long]$source.operation_epoch_sequence
        decision_epoch_sequence=[long]$source.decision_epoch_sequence
        release_epoch_sequence=[long]$source.release_epoch_sequence
        release_count=[long]$source.release_count
        terminal_outcome=[string]$source.terminal_outcome
    }
} | Sort-Object connection_key,decision_instance_id,operation_id)
$epochs = @($operations | ForEach-Object {
    [pscustomobject][ordered]@{
        run_id=$runId;connection_key=$_.connection_key
        epoch_sequence=$_.epoch_sequence
    }
} | Sort-Object connection_key,epoch_sequence -Unique)
$evidence = [pscustomobject][ordered]@{
    schema_version='adaptive-runtime-operation-evidence-v3'
    document_id="operation_evidence.$runId";document_version=3
    content_sha256='0'*64
    behavior_catalog_ref=New-AdaptiveRuntimeDocumentRef $catalog
    plan_validation_ref=New-AdaptiveRuntimeDocumentRef $validation
    experiment_run_ref=New-AdaptiveRuntimeDocumentRef $run
    binary_cohort_ref=New-AdaptiveRuntimeDocumentRef $binary
    run_id=$runId;binary_cohort_id=[string]$capture.binary_cohort_id
    connection_key=[string]$operations[0].connection_key
    epoch_sequence=1;result_epoch_sequence=1
    connection_epochs=$epochs;decisions=$decisions;operations=$operations
    releases=$releases
    active_behavior_authorization=$false
    performance_acceptance_authorization=$false
    trace_references=New-TraceReferences
}
[void](Set-AdaptiveRuntimeDocumentHash $evidence)
$classificationRows = @($operations | ForEach-Object {
    New-Classification $_
})
$classificationRows += @($releases | ForEach-Object {
    [pscustomobject][ordered]@{
        classification_id =
            "classification.$($_.axis_id).$($_.connection_key).release"
        target=[pscustomobject][ordered]@{
            target_kind='release';run_id=$_.run_id
            connection_key=$_.connection_key
            epoch_sequence=$_.operation_epoch_sequence;axis_id=$_.axis_id
            decision_instance_id=$_.decision_instance_id
            operation_id=$_.operation_id
            release_epoch_sequence=$_.release_epoch_sequence
        }
        kind='diagnostic_context';reason_code='reason.release'
        retained=$true
    }
})
$classifications = New-InputDocument `
    'adaptive-runtime-classification-set-v1' "classifications.$runId" `
    ([pscustomobject][ordered]@{
        evidence_ref=New-AdaptiveRuntimeDocumentRef $evidence
        compatibility_catalog_ref=
            New-AdaptiveRuntimeDocumentRef $compatibilityCatalog
        classifications=@($classificationRows|Sort-Object classification_id)
    })
$behavior = New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$outcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $catalog $classifications
$metrics = New-InputDocument 'adaptive-runtime-metric-observations-v1' `
    "metrics.$runId" ([pscustomobject][ordered]@{
        run_ref=New-AdaptiveRuntimeDocumentRef $run
        metric_observations=@($operations|ForEach-Object {
            [pscustomobject][ordered]@{
                metric_id='metric.correctness.operation_count'
                run_id=$runId;connection_key=$_.connection_key
                epoch_sequence=$_.epoch_sequence
                analytical_use='correctness_only';value=1
            }
        })
    })
$inputs=[ordered]@{
    experiment_plan=$plan;plan_validation=$validation
    compiled_execution_manifest=$manifest;experiment_run=$run
    host_fingerprint=$hostDocument;binary_cohort=$binary
    workload_instance=$workload;requested_workload_shape=$requested
    effective_workload_shape=$effective;operation_evidence=$evidence
    behavior_materialization=$behavior;outcome_materialization=$outcome
    metric_observations=$metrics;classifications=$classifications
}
$inventory=New-InputDocument 'adaptive-runtime-artifact-inventory-v1' `
    "artifact_inventory.$runId" ([pscustomobject][ordered]@{
        artifacts=@($inputs.GetEnumerator()|ForEach-Object {
            [pscustomobject][ordered]@{
                role=[string]$_.Key
                document_ref=New-AdaptiveRuntimeDocumentRef $_.Value
            }
        })
    })
$inputs.artifact_inventory=$inventory
foreach($entry in $inputs.GetEnumerator()){
    Write-AdaptiveRuntimeCanonicalDocument $entry.Value (
        Join-Path $inputRoot "$($entry.Key).json")
}
$projectionArgs=@{
    PlanPath=Join-Path $inputRoot 'experiment_plan.json'
    PlanValidationPath=Join-Path $inputRoot 'plan_validation.json'
    CompiledManifestPath=Join-Path $inputRoot 'compiled_execution_manifest.json'
    ExperimentRunPath=Join-Path $inputRoot 'experiment_run.json'
    HostFingerprintPath=Join-Path $inputRoot 'host_fingerprint.json'
    BinaryCohortPath=Join-Path $inputRoot 'binary_cohort.json'
    WorkloadInstancePath=Join-Path $inputRoot 'workload_instance.json'
    RequestedWorkloadShapePath=Join-Path $inputRoot 'requested_workload_shape.json'
    EffectiveWorkloadShapePath=Join-Path $inputRoot 'effective_workload_shape.json'
    OperationEvidencePath=Join-Path $inputRoot 'operation_evidence.json'
    BehaviorMaterializationPath=Join-Path $inputRoot 'behavior_materialization.json'
    OutcomeMaterializationPath=Join-Path $inputRoot 'outcome_materialization.json'
    MetricObservationsPath=Join-Path $inputRoot 'metric_observations.json'
    ArtifactInventoryPath=Join-Path $inputRoot 'artifact_inventory.json'
    ClassificationsPath=Join-Path $inputRoot 'classifications.json'
    BehaviorCatalogPath=Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json'
    ClassificationCompatibilityCatalogPath=Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json'
    PassThru=$true
}
$projection1=& (Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') @projectionArgs
$projection2=& (Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') @projectionArgs
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection1) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection2)
) 'interaction_projection_not_deterministic'
Write-AdaptiveRuntimeCanonicalDocument $projection1 (
    Join-Path $expectedRoot 'projection.json')
$proof=[pscustomobject][ordered]@{
    schema_version='adaptive-runtime-send-composition-interaction-proof-v1'
    document_id='proof.send_composition.correctness'
    document_version=1;content_sha256='0'*64
    proof_id='proof.send_composition.correctness.v1'
    source_plan_ref=New-AdaptiveRuntimeDocumentRef $plan
    plan_validation_ref=New-AdaptiveRuntimeDocumentRef $validation
    compiled_manifest_ref=New-AdaptiveRuntimeDocumentRef $manifest
    experiment_run_ref=New-AdaptiveRuntimeDocumentRef $run
    operation_evidence_ref=New-AdaptiveRuntimeDocumentRef $evidence
    behavior_materialization_ref=New-AdaptiveRuntimeDocumentRef $behavior
    outcome_materialization_ref=New-AdaptiveRuntimeDocumentRef $outcome
    projection_ref=New-AdaptiveRuntimeDocumentRef $projection1
    interaction_case_ids=$caseIds
    operation_count=$operations.Count;release_count=$releases.Count
    review_status='candidate';review_outcome=$null
    active_behavior_authorization=$false
    performance_acceptance_authorization=$false
    trace_references=New-TraceReferences
}
[void](Set-AdaptiveRuntimeDocumentHash $proof)
Assert-Condition (Test-AdaptiveRuntimeJsonSchema $proof (
    Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-composition-interaction-proof-v1.schema.json')) `
    'interaction_proof_schema_invalid'
Write-AdaptiveRuntimeCanonicalDocument $proof (
    Join-Path $OutputRoot 'interaction-proof.json')
$errors=@(Get-AdaptiveRuntimeEvidenceV3Errors -Evidence $evidence `
    -Catalog $catalog -PlanValidation $validation `
    -ClassificationSet $classifications `
    -CompatibilityCatalog $compatibilityCatalog `
    -ArtifactInventory $inventory)
Assert-Condition ($errors.Count -eq 0) (
    "interaction_evidence_invalid:$($errors -join ',')")
$summary=[pscustomobject][ordered]@{
    operation_count=$operations.Count;release_count=$releases.Count
    behavior_aggregate_count=@($behavior.aggregates).Count
    outcome_aggregate_count=@($outcome.aggregates).Count
    projection_sha256=$projection1.content_sha256
    proof_sha256=$proof.content_sha256
}
if($PassThru){$summary}else{
    $summary|ConvertTo-Json -Depth 10
}
