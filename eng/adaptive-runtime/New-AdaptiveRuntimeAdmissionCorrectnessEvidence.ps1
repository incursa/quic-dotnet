# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CapturePath,
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $ValidationPath,
    [Parameter(Mandatory = $true)][string] $ManifestPath,
    [Parameter(Mandatory = $true)][string] $AuthorizationPath,
    [Parameter(Mandatory = $true)][string] $OutputRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Admission([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}

function New-TraceReferences {
    [pscustomobject][ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0241',
            'REQ-QUIC-CRT-0242',
            'REQ-QUIC-CRT-0243',
            'REQ-QUIC-CRT-0244',
            'REQ-QUIC-CRT-0245',
            'REQ-QUIC-CRT-0246'
        )
        architecture_ids = @('ARC-QUIC-CRT-0116')
        work_item_ids = @('WI-QUIC-CRT-0117')
        verification_ids = @('VER-QUIC-CRT-0118')
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

function New-Assertion([string] $Id, [bool] $Passed) {
    [pscustomobject][ordered]@{
        assertion_id = $Id
        passed = $Passed
    }
}

function Get-AxisValues([object] $Cell) {
    [pscustomobject][ordered]@{
        oversized_write_admission_quantum =
            [string]$Cell.configured_values.oversized_write_admission_quantum
        application_send_batch_formation =
            [string]$Cell.configured_values.application_send_batch_formation
        buffer_copy_coalescing =
            [string]$Cell.configured_values.buffer_copy_coalescing
    }
}

function Get-ExpectedMechanism([string] $AxisId, [string] $Value) {
    switch ("$AxisId|$Value") {
        'oversized_write_admission_quantum|legacy_current' {
            'mechanism_event.oversized_write.bounded_two_fragments_per_turn'
        }
        'oversized_write_admission_quantum|single_fragment' {
            'mechanism_event.oversized_write.one_fragment_per_turn'
        }
        'application_send_batch_formation|legacy_current' {
            'mechanism_event.batch_legal_prefix'
        }
        'application_send_batch_formation|single_eligible' {
            'mechanism_event.batch_single_eligible'
        }
        'buffer_copy_coalescing|legacy_current' {
            'mechanism_event.buffer_legacy_prefix'
        }
        'buffer_copy_coalescing|memory_conservative' {
            'mechanism_event.buffer_two_source_cap'
        }
        default { throw "admission_unknown_axis_value:$AxisId|$Value" }
    }
}

function Convert-CaptureOperation([object] $Cell, [object] $CaptureOperation) {
    $source = $CaptureOperation.evidence
    $axisId = [string]$CaptureOperation.axis_id
    $axisValues = Get-AxisValues $Cell
    $cellValue = [string]$axisValues.$axisId
    if ($axisId -ceq 'oversized_write_admission_quantum') {
        $connectionKey = "$($Cell.connection_state_id).oversized"
        $mechanism = switch ([string]$source.mechanism_event) {
            'BoundedTwoFragmentAdmission' {
                'mechanism_event.oversized_write.bounded_two_fragments_per_turn'
            }
            'SequentialSingleFragmentAdmission' {
                'mechanism_event.oversized_write.one_fragment_per_turn'
            }
            default {
                throw "admission_oversized_mechanism_unknown:$(
                    $source.mechanism_event)"
            }
        }
        $operation = [pscustomobject][ordered]@{
            run_id = [string]$Cell.run_id
            connection_key = $connectionKey
            epoch_sequence = 1
            axis_id = $axisId
            decision_instance_id = [long]$source.decision_instance_id
            operation_id = [long]$source.operation_id
            configured_value = [string]$source.configured_value
            forced_value = [string]$source.forced_value
            shadow_recommendation = $source.shadow_recommendation
            candidate_value = [string]$source.candidate_value
            operation_eligibility_result = 'eligible'
            operation_eligibility_reason = 'legal_fragment_count_gt_one'
            applied_value = [string]$source.applied_value
            operation_kind = 'logical_write'
            scope_version = 1
            mechanism_event_id = $mechanism
            legal_work_count = [long]$source.legal_fragment_count
            applied_work_count = [long]$source.initial_committed_fragments
            legal_bytes = [long]$source.logical_write_bytes
            applied_bytes = [long]$source.initial_committed_bytes
            result = 'applied'
            fallback_or_safety_reason = $null
            terminal_outcome =
                ([string]$source.terminal_outcome).ToLowerInvariant()
        }
    } else {
        $operation = [pscustomobject][ordered]@{
            run_id = [string]$Cell.run_id
            connection_key = [string]$source.connection_key
            epoch_sequence = [long]$source.epoch_sequence
            axis_id = $axisId
            decision_instance_id = [long]$source.decision_instance_id
            operation_id = [long]$source.operation_id
            configured_value = [string]$source.configured_value
            forced_value = [string]$source.forced_value
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
    }
    Assert-Admission (
        [string]$operation.forced_value -ceq $cellValue -and
        [string]$operation.candidate_value -ceq $cellValue -and
        [string]$operation.applied_value -ceq $cellValue
    ) "admission_cell_value_not_actuated:$($Cell.cell_id):$axisId"
    Assert-Admission (
        [string]$operation.mechanism_event_id -ceq
            (Get-ExpectedMechanism $axisId $cellValue)
    ) "admission_mechanism_mismatch:$($Cell.cell_id):$axisId"
    $operation
}

function New-Classification([object] $Operation) {
    [pscustomobject][ordered]@{
        classification_id =
            "classification.$($Operation.axis_id).$(
                $Operation.connection_key).analytically_eligible"
        target = [pscustomobject][ordered]@{
            target_kind = 'operation'
            run_id = [string]$Operation.run_id
            connection_key = [string]$Operation.connection_key
            epoch_sequence = [long]$Operation.epoch_sequence
            axis_id = [string]$Operation.axis_id
            decision_instance_id = [long]$Operation.decision_instance_id
            operation_id = [long]$Operation.operation_id
        }
        kind = 'analytically_eligible'
        reason_code = 'reason.correctness_opportunity'
        retained = $true
    }
}

function Test-Prefix([object[]] $Legal, [object[]] $Applied) {
    if ($Applied.Count -gt $Legal.Count) { return $false }
    for ($index = 0; $index -lt $Applied.Count; $index++) {
        if ([string]$Applied[$index] -cne [string]$Legal[$index]) {
            return $false
        }
    }
    $true
}

$capture = Read-AdaptiveRuntimeJsonDocument $CapturePath
$plan = Read-AdaptiveRuntimeJsonDocument $PlanPath
$validation = Read-AdaptiveRuntimeJsonDocument $ValidationPath
$manifest = Read-AdaptiveRuntimeJsonDocument $ManifestPath
$authorization = Read-AdaptiveRuntimeJsonDocument $AuthorizationPath
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v3.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')

if ([string]$capture.content_sha256 -eq ('0' * 64)) {
    [void](Set-AdaptiveRuntimeDocumentHash $capture)
}
foreach ($document in @(
    $capture, $plan, $validation, $manifest, $authorization, $catalog,
    $compatibilityCatalog
)) {
    Assert-Admission (Test-AdaptiveRuntimeDocumentHash $document) `
        "admission_evidence_source_hash_invalid:$($document.document_id)"
}
Assert-Admission (
    Test-AdaptiveRuntimeJsonSchema $capture (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-runtime-capture-v1.schema.json')
) 'admission_capture_schema_invalid'
Assert-Admission (
    [string]$capture.source_commit -ceq [string]$manifest.source_commit -and
    [string]$capture.binary_sha256 -ceq
        [string]$manifest.binary_provenance.content_sha256 -and
    [string]$capture.manifest_content_sha256 -ceq
        [string]$manifest.content_sha256 -and
    [string]$capture.authorization_content_sha256 -ceq
        [string]$authorization.content_sha256
) 'admission_capture_control_binding_mismatch'
Assert-Admission (
    [string]$authorization.authorization_id -ceq
        'send_admission_composition_correctness_v1' -and
    $capture.active_behavior_authorization -eq $false -and
    $capture.performance_acceptance_authorization -eq $false -and
    $authorization.active_behavior_authorization -eq $false -and
    $authorization.performance_acceptance_authorization -eq $false
) 'admission_prohibited_authorization'
Assert-Admission (
    (Get-FileHash -LiteralPath ([string]$manifest.binary_provenance.path) `
        -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
        [string]$capture.binary_sha256
) 'admission_runtime_binary_stale'
$harnessPath = Join-Path $RepositoryRoot `
    'tests\Incursa.Quic.Tests\bin\Release\net10.0\Incursa.Quic.Tests.dll'
Assert-Admission (
    (Test-Path -LiteralPath $harnessPath -PathType Leaf) -and
    (Get-FileHash -LiteralPath $harnessPath -Algorithm SHA256).
        Hash.ToLowerInvariant() -ceq [string]$capture.harness_binary_sha256
) 'admission_harness_binary_stale'

$cellRefs = @($manifest.compiled_cell_refs | ForEach-Object {
    "$($_.cell_id)|$($_.content_sha256)"
} | Sort-Object -CaseSensitive)
$captureCellRefs = @($capture.cells | ForEach-Object {
    "$($_.cell_id)|$($_.cell_content_sha256)"
} | Sort-Object -CaseSensitive)
Assert-Admission (
    (ConvertTo-Json $cellRefs -Compress) -ceq
    (ConvertTo-Json $captureCellRefs -Compress)
) 'admission_capture_cell_set_mismatch'
Assert-Admission (@($capture.cells).Count -eq 8) `
    'admission_capture_not_exact_eight_cells'
Assert-Admission (
    @($capture.cells.run_id | Sort-Object -Unique).Count -eq 8 -and
    @($capture.cells.connection_state_id | Sort-Object -Unique).Count -eq 8
) 'admission_cross_cell_state_reuse'
$allCaptureIdentities = @($capture.cells.operations.operation_identity)
Assert-Admission (
    @($allCaptureIdentities | Sort-Object -Unique).Count -eq 24
) 'admission_cross_cell_operation_identity_reuse'

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$cellSummaries = @()
foreach ($cell in @($capture.cells | Sort-Object cell_id)) {
    Assert-Admission (
        [string]$cell.configured_values.application_send_turn_planning -ceq
            'legacy_current' -and
        [string]$cell.configured_values.queued_send_burst_budget -ceq
            'legacy_current'
    ) "admission_fourth_axis_not_legacy:$($cell.cell_id)"
    Assert-Admission (
        @($cell.operations).Count -eq 3 -and
        @($cell.releases).Count -eq 1 -and
        @($cell.operations.axis_id | Sort-Object -Unique).Count -eq 3
    ) "admission_cell_sequence_incomplete:$($cell.cell_id)"

    $cellName = ([string]$cell.cell_id).Split('.')[-1]
    $cellRoot = Join-Path $OutputRoot $cellName
    $inputRoot = Join-Path $cellRoot 'inputs'
    $expectedRoot = Join-Path $cellRoot 'expected'
    New-Item -ItemType Directory -Force -Path $inputRoot,$expectedRoot |
        Out-Null
    $runId = [string]$cell.run_id
    $axisValues = Get-AxisValues $cell
    $operations = @($cell.operations | ForEach-Object {
        Convert-CaptureOperation $cell $_
    } | Sort-Object connection_key,axis_id,decision_instance_id,operation_id)
    $operationKeys = @($operations | ForEach-Object {
        (New-AdaptiveRuntimeOperationIdentity $_).operation_key
    })
    Assert-Admission (
        @($operationKeys | Sort-Object -Unique).Count -eq 3
    ) "admission_composite_identity_duplicate:$($cell.cell_id)"

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
            operation_eligibility_result =
                $_.operation_eligibility_result
            operation_eligibility_reason =
                $_.operation_eligibility_reason
            applied_value = $_.applied_value
        }
    })
    $releases = @($cell.releases | ForEach-Object {
        $source = $_.evidence
        [pscustomobject][ordered]@{
            run_id = $runId
            connection_key = [string]$source.connection_key
            axis_id = [string]$_.axis_id
            decision_instance_id = [long]$source.decision_instance_id
            operation_id = [long]$source.operation_id
            operation_epoch_sequence =
                [long]$source.operation_epoch_sequence
            decision_epoch_sequence =
                [long]$source.decision_epoch_sequence
            release_epoch_sequence =
                [long]$source.release_epoch_sequence
            release_count = [long]$source.release_count
            terminal_outcome = [string]$source.terminal_outcome
        }
    })
    $epochs = @($operations | ForEach-Object {
        [pscustomobject][ordered]@{
            run_id = $_.run_id
            connection_key = $_.connection_key
            epoch_sequence = $_.epoch_sequence
        }
    } | Sort-Object connection_key,epoch_sequence -Unique)

    $hostDocument = New-InputDocument `
        'adaptive-runtime-host-fingerprint-v1' `
        "host_fingerprint.$runId" ([pscustomobject][ordered]@{
            fingerprint_id = [string]$capture.host_fingerprint_id
            manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
            os_platform = [string]$capture.os_platform
            os_architecture = [string]$capture.os_architecture
            physical_host_id = [string]$capture.host_fingerprint_id
            vm_id = $null
            resolved_capabilities = @('correctness_only_runtime_capture')
        })
    $binary = New-InputDocument 'adaptive-runtime-binary-cohort-v1' `
        "binary_cohort.$runId" ([pscustomobject][ordered]@{
            binary_cohort_id = "binary_cohort.$runId"
            manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
            source_commit = [string]$capture.source_commit
            binary_path = [string]$manifest.binary_provenance.path
            binary_sha256 = [string]$capture.binary_sha256
            runner_version = 'incursa_quic_tests.release.net10'
            runner_sha256 = [string]$capture.harness_binary_sha256
        })
    $run = New-InputDocument 'adaptive-runtime-experiment-run-v1' `
        "experiment_run.$runId" ([pscustomobject][ordered]@{
            run_id = $runId
            compiled_manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
            authorization_ref = New-AdaptiveRuntimeDocumentRef $authorization
            host_fingerprint_ref =
                New-AdaptiveRuntimeDocumentRef $hostDocument
            binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
            exact_cell_id = [string]$cell.cell_id
            exact_cell_content_sha256 =
                [string]$cell.cell_content_sha256
            workload_instance_ids = @("workload.$runId")
        })
    $requested = New-InputDocument 'adaptive-runtime-workload-shape-v1' `
        "workload_shape.requested.$runId" ([pscustomobject][ordered]@{
            shape_kind = 'requested'
            workload_instance_id = "workload.$runId"
            workload_archetype_id =
                'send_admission_composition_correctness_harness'
            oversized_legal_fragment_count = 5
            batch_eligible_prefix_count = 4
            buffer_source_segment_count = 4
            concurrency = 1
            operation_count = 3
        })
    $effective = New-InputDocument 'adaptive-runtime-workload-shape-v1' `
        "workload_shape.effective.$runId" ([pscustomobject][ordered]@{
            shape_kind = 'effective'
            workload_instance_id = "workload.$runId"
            workload_archetype_id =
                'send_admission_composition_correctness_harness'
            operation_count = 3
            connection_state_id = [string]$cell.connection_state_id
            operation_local_noncoactivation = @(
                $cell.operations | Where-Object operation_local_noncoactivation
            ).Count
        })
    $workload = New-InputDocument 'adaptive-runtime-workload-instance-v1' `
        "workload_instance.$runId" ([pscustomobject][ordered]@{
            workload_instance_id = "workload.$runId"
            run_ref = New-AdaptiveRuntimeDocumentRef $run
            requested_shape_ref = New-AdaptiveRuntimeDocumentRef $requested
            effective_shape_ref = New-AdaptiveRuntimeDocumentRef $effective
        })
    $evidence = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-operation-evidence-v4'
        document_id = "operation_evidence.$runId"
        document_version = 4
        content_sha256 = '0' * 64
        behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $catalog
        plan_validation_ref = New-AdaptiveRuntimeDocumentRef $validation
        experiment_run_ref = New-AdaptiveRuntimeDocumentRef $run
        binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
        run_id = $runId
        binary_cohort_id = "binary_cohort.$runId"
        connection_key = [string]$cell.connection_state_id
        epoch_sequence = 1
        result_epoch_sequence = 1
        connection_epochs = $epochs
        decisions = $decisions
        operations = $operations
        releases = $releases
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = New-TraceReferences
    }
    [void](Set-AdaptiveRuntimeDocumentHash $evidence)
    Assert-Admission (
        Test-AdaptiveRuntimeJsonSchema $evidence (Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-operation-evidence-v4.schema.json')
    ) "admission_operation_evidence_schema_invalid:$($cell.cell_id)"

    $classificationRows = @($operations | ForEach-Object {
        New-Classification $_
    })
    $classificationRows += @($releases | ForEach-Object {
        [pscustomobject][ordered]@{
            classification_id =
                "classification.$($_.axis_id).$(
                    $_.connection_key).release"
            target = [pscustomobject][ordered]@{
                target_kind = 'release'
                run_id = $_.run_id
                connection_key = $_.connection_key
                epoch_sequence = $_.operation_epoch_sequence
                axis_id = $_.axis_id
                decision_instance_id = $_.decision_instance_id
                operation_id = $_.operation_id
                release_epoch_sequence = $_.release_epoch_sequence
            }
            kind = 'diagnostic_context'
            reason_code = 'reason.owner_release'
            retained = $true
        }
    })
    $classifications = New-InputDocument `
        'adaptive-runtime-classification-set-v1' `
        "classifications.$runId" ([pscustomobject][ordered]@{
            evidence_ref = New-AdaptiveRuntimeDocumentRef $evidence
            compatibility_catalog_ref =
                New-AdaptiveRuntimeDocumentRef $compatibilityCatalog
            classifications = @(
                $classificationRows | Sort-Object classification_id)
        })
    $behavior = New-AdaptiveRuntimeBehaviorMaterializationV3 `
        $evidence $catalog
    $outcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
        $evidence $catalog $classifications
    Assert-Admission (
        @($behavior.derivations |
            Where-Object derivation_status -ne 'matched').Count -eq 0
    ) "admission_behavior_derivation_failed:$($cell.cell_id)"
    Assert-Admission (
        @($outcome.derivations |
            Where-Object derivation_status -ne 'behavior_only').Count -eq 0
    ) "admission_outcome_derivation_failed:$($cell.cell_id)"
    Assert-Admission (
        Test-AdaptiveRuntimeJsonSchema $behavior (Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-effective-behavior-materialization-v3.schema.json')
    ) "admission_behavior_schema_invalid:$($cell.cell_id)"
    Assert-Admission (
        Test-AdaptiveRuntimeJsonSchema $outcome (Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-operation-outcome-materialization-v2.schema.json')
    ) "admission_outcome_schema_invalid:$($cell.cell_id)"

    $captureOversized = @($cell.operations |
        Where-Object axis_id -ceq 'oversized_write_admission_quantum')[0].
        evidence
    $captureBatch = @($cell.operations |
        Where-Object axis_id -ceq 'application_send_batch_formation')[0].
        evidence
    $captureBuffer = @($cell.operations |
        Where-Object axis_id -ceq 'buffer_copy_coalescing')[0].evidence
    $captureRelease = @($cell.releases)[0].evidence
    $metricRows = @(
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.activation_opportunity_count'
            axis_id = 'oversized_write_admission_quantum'
            analytical_use = 'correctness_only'
            value = 1
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.fragment_count'
            axis_id = 'oversized_write_admission_quantum'
            analytical_use = 'correctness_only'
            value = [long]$captureOversized.legal_fragment_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.continuation_count'
            axis_id = 'oversized_write_admission_quantum'
            analytical_use = 'correctness_only'
            value = [long]$captureOversized.continuation_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.completion_count'
            axis_id = 'oversized_write_admission_quantum'
            analytical_use = 'correctness_only'
            value = [long]$captureOversized.completion_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.eligible_prefix_count'
            axis_id = 'application_send_batch_formation'
            analytical_use = 'correctness_only'
            value = [long]$captureBatch.legal_work_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.applied_prefix_count'
            axis_id = 'application_send_batch_formation'
            analytical_use = 'correctness_only'
            value = [long]$captureBatch.applied_work_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.source_segment_count'
            axis_id = 'buffer_copy_coalescing'
            analytical_use = 'correctness_only'
            value = [long]$captureBuffer.legal_work_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.applied_source_segment_count'
            axis_id = 'buffer_copy_coalescing'
            analytical_use = 'correctness_only'
            value = [long]$captureBuffer.applied_work_count
        },
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.owner_release_count'
            axis_id = 'buffer_copy_coalescing'
            analytical_use = 'correctness_only'
            value = [long]$captureRelease.release_count
        }
    )
    $metrics = New-InputDocument `
        'adaptive-runtime-metric-observations-v1' "metrics.$runId" `
        ([pscustomobject][ordered]@{
            run_ref = New-AdaptiveRuntimeDocumentRef $run
            metric_observations = $metricRows
        })

    $inputs = [ordered]@{
        experiment_plan = $plan
        plan_validation = $validation
        compiled_execution_manifest = $manifest
        correctness_authorization = $authorization
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
        "artifact_inventory.$runId" ([pscustomobject][ordered]@{
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

    $appliedValues = [pscustomobject][ordered]@{}
    foreach ($axisId in @(
        'oversized_write_admission_quantum',
        'application_send_batch_formation',
        'buffer_copy_coalescing'
    )) {
        $appliedValues | Add-Member -NotePropertyName $axisId `
            -NotePropertyValue ([string]@($operations |
                Where-Object axis_id -ceq $axisId)[0].applied_value)
    }
    $projection = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-send-admission-projection-v1'
        document_id = "projection.send_admission.$cellName"
        document_version = 1
        content_sha256 = '0' * 64
        cell_id = [string]$cell.cell_id
        source_refs = @($inputs.GetEnumerator() | ForEach-Object {
            New-AdaptiveRuntimeDocumentRef $_.Value
        })
        operation_count = 3
        release_count = 1
        configured_values = $axisValues
        applied_values = $appliedValues
        mechanism_event_ids = @(
            $operations.mechanism_event_id | Sort-Object -CaseSensitive)
        behavior_materialization_sha256 = [string]$behavior.content_sha256
        outcome_materialization_sha256 = [string]$outcome.content_sha256
        performance_metric_count = @($metricRows |
            Where-Object analytical_use -ne 'correctness_only').Count
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = New-TraceReferences
    }
    [void](Set-AdaptiveRuntimeDocumentHash $projection)
    Assert-Admission (
        Test-AdaptiveRuntimeJsonSchema $projection (Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-send-admission-projection-v1.schema.json')
    ) "admission_projection_schema_invalid:$($cell.cell_id)"

    $guardrails = @(
        New-Assertion 'exact_configured_forced_candidate_applied_values' (
            (ConvertTo-AdaptiveRuntimeCanonicalJson $axisValues) -ceq
            (ConvertTo-AdaptiveRuntimeCanonicalJson $appliedValues))
        New-Assertion 'oversized_more_than_one_legal_fragment' (
            [long]$captureOversized.legal_fragment_count -gt 1)
        New-Assertion 'oversized_exact_initial_fragment_quantum' (
            [long]$captureOversized.initial_committed_fragments -eq
                $(if (
                    [string]$axisValues.oversized_write_admission_quantum -ceq
                        'single_fragment') { 1 } else { 2 }))
        New-Assertion 'oversized_all_continuations_accounted' (
            [long]$captureOversized.committed_fragments -eq
                [long]$captureOversized.legal_fragment_count -and
            [long]$captureOversized.committed_bytes -eq
                [long]$captureOversized.logical_write_bytes)
        New-Assertion 'oversized_exactly_once_terminal_completion' (
            [long]$captureOversized.completion_count -eq 1)
        New-Assertion 'batch_more_than_one_eligible_write' (
            [long]$captureBatch.legal_work_count -gt 1)
        New-Assertion 'batch_lower_only_cap' (
            [long]$captureBatch.applied_work_count -le
                [long]$captureBatch.legal_work_count)
        New-Assertion 'batch_priority_sequence_prefix_preserved' (
            Test-Prefix @($captureBatch.legal_order_keys) `
                @($captureBatch.applied_order_keys))
        New-Assertion 'buffer_more_than_two_source_segments' (
            [long]$captureBuffer.legal_work_count -gt 2)
        New-Assertion 'buffer_lower_only_cap' (
            [long]$captureBuffer.applied_work_count -le
                [long]$captureBuffer.legal_work_count)
        New-Assertion 'buffer_exact_owner_release' (
            [long]$captureRelease.release_count -eq 1 -and
            [string]$captureRelease.terminal_outcome -ceq 'released')
        New-Assertion 'all_source_operations_accounted' (
            @($operations).Count -eq 3)
        New-Assertion 'behavior_materialization_recomputed' (
            @($behavior.derivations |
                Where-Object derivation_status -eq 'matched').Count -eq 3)
        New-Assertion 'outcome_materialization_recomputed' (
            @($outcome.derivations |
                Where-Object derivation_status -eq 'behavior_only').Count -eq
                3)
        New-Assertion 'performance_result_absent' (
            @($metricRows |
                Where-Object analytical_use -ne 'correctness_only').Count -eq
                0)
    )
    $crossAxis = @(
        New-Assertion 'fresh_cell_run_and_connection_state' (
            @($cell.operations.operation_identity |
                Sort-Object -Unique).Count -eq 3)
        New-Assertion 'operation_local_noncoactivation_not_cell_inactivity' (
            @($cell.operations |
                Where-Object operation_local_noncoactivation).Count -eq 1 -and
            @($operations | Where-Object result -eq 'applied').Count -eq 3)
        New-Assertion 'oversized_continuation_preserves_downstream_operations' (
            [long]$captureOversized.completion_count -eq 1 -and
            [string]$captureBatch.result -ceq 'applied' -and
            [string]$captureBuffer.result -ceq 'applied')
        New-Assertion 'oversized_completion_ownership_not_merged' (
            [long]$captureOversized.completion_count -eq 1 -and
            [long]$captureRelease.release_count -eq 1)
        New-Assertion 'batch_shortening_preserves_buffer_ownership' (
            [string]$captureBuffer.terminal_outcome -ceq 'released' -and
            [long]$captureRelease.release_count -eq 1)
        New-Assertion 'buffer_coalescing_preserves_legal_stage1_prefix' (
            Test-Prefix @($captureBuffer.legal_order_keys) `
                @($captureBuffer.applied_order_keys))
        New-Assertion 'separate_downstream_operations_actuate' (
            @($operations |
                Where-Object applied_value -cne 'legacy_current').Count -eq
            @($axisValues.psobject.Properties |
                Where-Object Value -cne 'legacy_current').Count)
        New-Assertion 'no_undeclared_fourth_axis_authority' (
            [string]$cell.configured_values.application_send_turn_planning `
                -ceq 'legacy_current' -and
            [string]$cell.configured_values.queued_send_burst_budget `
                -ceq 'legacy_current')
        New-Assertion 'relationship_graph_authority_preserved' (
            @($operations.mechanism_event_id | Sort-Object -Unique).Count -eq
                3)
        New-Assertion 'no_cross_cell_identity_leakage' (
            @($allCaptureIdentities |
                Where-Object { $_ -like "$runId|*" }).Count -eq 3)
    )
    $failed = @($guardrails + $crossAxis |
        Where-Object passed -eq $false |
        ForEach-Object assertion_id |
        Sort-Object -CaseSensitive)
    $activationCounts = [pscustomobject][ordered]@{
        oversized_write_admission_quantum = 1
        application_send_batch_formation = 1
        buffer_copy_coalescing = 1
    }
    $actuationCounts = [pscustomobject][ordered]@{
        oversized_write_admission_quantum =
            $(if (
                [string]$axisValues.oversized_write_admission_quantum -cne
                    'legacy_current') { 1 } else { 0 })
        application_send_batch_formation =
            $(if (
                [string]$axisValues.application_send_batch_formation -cne
                    'legacy_current') { 1 } else { 0 })
        buffer_copy_coalescing =
            $(if (
                [string]$axisValues.buffer_copy_coalescing -cne
                    'legacy_current') { 1 } else { 0 })
    }
    $result = if ($failed.Count -gt 0) {
        'correctness_failed'
    } elseif (@($axisValues.psobject.Properties |
        Where-Object Value -cne 'legacy_current' |
        Where-Object { [long]$actuationCounts.$($_.Name) -ne 1 }).Count -gt 0) {
        'activation_incomplete'
    } else {
        'correctness_passed'
    }
    $cellResult = [pscustomobject][ordered]@{
        schema_version =
            'adaptive-runtime-send-admission-cell-result-v1'
        document_id = "cell_result.send_admission.$cellName"
        document_version = 1
        content_sha256 = '0' * 64
        cell_id = [string]$cell.cell_id
        cell_content_sha256 = [string]$cell.cell_content_sha256
        axis_values = $axisValues
        activation_opportunities = $activationCounts
        behavior_distinct_actuations = $actuationCounts
        inactive_operation_count =
            @($operations | Where-Object result -eq 'inactive').Count
        fallback_operation_count =
            @($operations | Where-Object result -eq 'fallback').Count
        guardrail_assertions = $guardrails
        cross_axis_assertions = $crossAxis
        failed_assertions = $failed
        result = $result
        evidence_ref = New-AdaptiveRuntimeDocumentRef $evidence
        projection_ref = New-AdaptiveRuntimeDocumentRef $projection
        authorization_ref = New-AdaptiveRuntimeDocumentRef $authorization
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = New-TraceReferences
    }
    [void](Set-AdaptiveRuntimeDocumentHash $cellResult)
    Assert-Admission (
        Test-AdaptiveRuntimeJsonSchema $cellResult (
            Join-Path $RepositoryRoot `
                'schemas\adaptive-runtime-send-admission-cell-result-v1.schema.json')
    ) "admission_cell_result_schema_invalid:$($cell.cell_id)"
    Write-AdaptiveRuntimeCanonicalDocument $projection (
        Join-Path $expectedRoot 'analytical_projection.json')
    Write-AdaptiveRuntimeCanonicalDocument $cellResult (
        Join-Path $expectedRoot 'cell_correctness_result.json')
    Assert-Admission (
        @(Get-ChildItem -LiteralPath $cellRoot -File -Recurse).Count -eq 18
    ) "admission_cell_evidence_chain_not_exact:$($cell.cell_id)"
    $cellSummaries += [pscustomobject][ordered]@{
        cell_id = [string]$cell.cell_id
        result = $result
        operation_count = 3
        release_count = 1
        evidence_content_sha256 = [string]$evidence.content_sha256
        projection_content_sha256 = [string]$projection.content_sha256
        cell_result_content_sha256 = [string]$cellResult.content_sha256
    }
}

Write-AdaptiveRuntimeCanonicalDocument $capture $CapturePath
$summary = [pscustomobject][ordered]@{
    capture_content_sha256 = [string]$capture.content_sha256
    cell_count = @($cellSummaries).Count
    correctness_passed_count =
        @($cellSummaries | Where-Object result -eq 'correctness_passed').Count
    activation_incomplete_count =
        @($cellSummaries | Where-Object result -eq 'activation_incomplete').
            Count
    correctness_failed_count =
        @($cellSummaries | Where-Object result -eq 'correctness_failed').Count
    execution_blocked_count =
        @($cellSummaries | Where-Object result -eq 'execution_blocked').Count
    cells = $cellSummaries
}
if ($PassThru) {
    $summary
} else {
    $summary | ConvertTo-Json -Depth 10
}
