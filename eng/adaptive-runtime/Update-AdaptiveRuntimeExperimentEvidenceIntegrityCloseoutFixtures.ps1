# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-exp-evidence-closeout'
$catalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
$hardeningRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-experiment-hardening'
$planPath = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-exp-plan\valid\interaction.plan.json'
$validationPath = Join-Path $hardeningRoot `
    'linked\interaction.validation.v2.json'
$manifestPath = Join-Path $hardeningRoot `
    'projection-inputs\compiled-manifest.json'

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)][object] $Value)
    return $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Write-Fixture {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $RelativePath
    )
    $path = Join-Path $fixtureRoot $RelativePath
    Write-AdaptiveRuntimeCanonicalDocument $Document $path
    return $path
}

function New-CloseoutTraceReferences {
    return [ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0214',
            'REQ-QUIC-CRT-0215',
            'REQ-QUIC-CRT-0216',
            'REQ-QUIC-CRT-0217'
        )
        architecture_ids = @('ARC-QUIC-CRT-0101')
        work_item_ids = @('WI-QUIC-CRT-0102')
        verification_ids = @('VER-QUIC-CRT-0103')
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
        trace_references = New-CloseoutTraceReferences
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function New-OperationTarget {
    param([Parameter(Mandatory = $true)][object] $Operation)
    return [pscustomobject][ordered]@{
        target_kind = 'operation'
        run_id = [string]$Operation.run_id
        connection_key = [string]$Operation.connection_key
        epoch_sequence = [long]$Operation.epoch_sequence
        axis_id = [string]$Operation.axis_id
        decision_instance_id = [long]$Operation.decision_instance_id
        operation_id = [long]$Operation.operation_id
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

$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v2.json')
$plan = Read-AdaptiveRuntimeJsonDocument $planPath
$validation = Read-AdaptiveRuntimeJsonDocument $validationPath
$manifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
$outcomeMappingCases = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-outcome-mapping-fixture-v1'
    document_id = 'outcome_mapping_cases.closeout.fixture'
    document_version = 1
    content_sha256 = '0' * 64
    behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $catalog
    cases = @($catalog.outcome_definitions | Sort-Object outcome_id |
        ForEach-Object {
            $definition = $_
            @($definition.result_kinds | Sort-Object -CaseSensitive |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        result_kind = [string]$_
                        expected_outcome_id =
                            [string]$definition.outcome_id
                        requires_retained_classification =
                            [bool]$definition.requires_retained_classification
                    }
                })
        })
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = New-CloseoutTraceReferences
}
[void](Write-Fixture $outcomeMappingCases `
    'valid\outcome-mapping-cases.json')

$classificationKinds = @(
    'analytically_eligible',
    'inactive',
    'fallback',
    'clamped',
    'invalid',
    'negative',
    'excluded',
    'unclassifiable',
    'error',
    'terminal_release_failure',
    'diagnostic'
)
$outcomeByKind = @{
    inactive = 'outcome.inactive'
    fallback = 'outcome.fallback'
    clamped = 'outcome.clamped'
    invalid = 'outcome.invalid'
    negative = 'outcome.negative'
    unclassifiable = 'outcome.unclassifiable'
    error = 'outcome.error'
    terminal_release_failure = 'outcome.terminal_release_failure'
    diagnostic = 'outcome.diagnostic'
}
$classificationDefinitions = @($classificationKinds | ForEach-Object {
    $outcomeIds = [System.Collections.Generic.List[string]]::new()
    if ($outcomeByKind.ContainsKey($_)) {
        $outcomeIds.Add([string]$outcomeByKind[$_])
    }
    [pscustomobject][ordered]@{
        classification_kind = $_
        role = 'primary'
        outcome_ids = $outcomeIds
        reviewed_version = 1
    }
})
$classificationDefinitions += [pscustomobject][ordered]@{
    classification_kind = 'diagnostic_context'
    role = 'supplemental'
    outcome_ids = [System.Collections.Generic.List[string]]::new()
    reviewed_version = 1
}
$compatiblePairs = @($classificationKinds | ForEach-Object {
    $parts = @($_, 'diagnostic_context') | Sort-Object -CaseSensitive
    [pscustomobject][ordered]@{
        pair_id = "pair.$($parts[0]).$($parts[1])"
        left_kind = $parts[0]
        right_kind = $parts[1]
        reviewed_version = 1
    }
})
$compatibilityCatalog = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-classification-compatibility-catalog-v1'
    document_id =
        'adaptive_runtime_classification_compatibility_catalog_v1'
    document_version = 1
    content_sha256 = '0' * 64
    classification_definitions =
        @($classificationDefinitions | Sort-Object classification_kind)
    compatible_pairs = @($compatiblePairs | Sort-Object pair_id)
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = New-CloseoutTraceReferences
}
Write-AdaptiveRuntimeCanonicalDocument $compatibilityCatalog (
    Join-Path $catalogRoot `
        'adaptive-runtime-classification-compatibility-catalog-v1.json')

$hostDocument = New-InputDocument `
    'adaptive-runtime-host-fingerprint-v1' `
    'host_fingerprint.closeout.fixture' `
    ([pscustomobject][ordered]@{
        fingerprint_id = [string]$manifest.host_fingerprint.fingerprint_id
        manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        os_platform = [string]$manifest.host_fingerprint.os
        os_architecture = [string]$manifest.host_fingerprint.architecture
        physical_host_id = 'physical_host.fixture'
        vm_id = $null
        resolved_capabilities = @(
            $manifest.host_capabilities.resolved_capabilities.capability_id |
                Sort-Object -CaseSensitive)
    })
$binarySource = @($manifest.binary_provenance |
    Sort-Object role, path | Select-Object -First 1)[0]
$binary = New-InputDocument `
    'adaptive-runtime-binary-cohort-v1' `
    'binary_cohort.closeout.fixture' `
    ([pscustomobject][ordered]@{
        binary_cohort_id = 'binary.closeout.fixture'
        manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        source_commit = [string]$manifest.source_commit
        binary_path = [string]$binarySource.path
        binary_sha256 = [string]$binarySource.content_sha256
        runner_version = [string]$manifest.runner_identity.version
        runner_sha256 = [string]$manifest.runner_identity.content_sha256
    })
$run = New-InputDocument `
    'adaptive-runtime-experiment-run-v1' `
    'experiment_run.closeout.fixture' `
    ([pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        compiled_manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
        host_fingerprint_ref = New-AdaptiveRuntimeDocumentRef $hostDocument
        binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
        workload_instance_ids = @('workload.closeout.fixture')
    })
$requested = New-InputDocument `
    'adaptive-runtime-workload-shape-v1' `
    'workload_shape.requested.closeout.fixture' `
    ([pscustomobject][ordered]@{
        shape_kind = 'requested'
        workload_instance_id = 'workload.closeout.fixture'
        workload_archetype_id = 'send_composition_correctness'
        payload_bytes = 512
        concurrency = 1
        operation_count = 4
    })
$effective = New-InputDocument `
    'adaptive-runtime-workload-shape-v1' `
    'workload_shape.effective.closeout.fixture' `
    ([pscustomobject][ordered]@{
        shape_kind = 'effective'
        workload_instance_id = 'workload.closeout.fixture'
        workload_archetype_id = 'send_composition_correctness'
        payload_bytes = 512
        concurrency = 1
        operation_count = 4
    })
$workload = New-InputDocument `
    'adaptive-runtime-workload-instance-v1' `
    'workload_instance.closeout.fixture' `
    ([pscustomobject][ordered]@{
        workload_instance_id = 'workload.closeout.fixture'
        run_ref = New-AdaptiveRuntimeDocumentRef $run
        requested_shape_ref = New-AdaptiveRuntimeDocumentRef $requested
        effective_shape_ref = New-AdaptiveRuntimeDocumentRef $effective
    })

$decisions = @(
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.a'
        epoch_sequence = 1
        axis_id = 'application_send_batch_formation'
        decision_instance_id = 101
        configured_value = 'legacy_current'
        forced_value = 'single_eligible'
        shadow_recommendation = $null
        candidate_value = 'single_eligible'
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = 'eligible'
        applied_value = 'single_eligible'
    },
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.a'
        epoch_sequence = 1
        axis_id = 'buffer_copy_coalescing'
        decision_instance_id = 201
        configured_value = 'legacy_current'
        forced_value = 'memory_conservative'
        shadow_recommendation = $null
        candidate_value = 'memory_conservative'
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = 'eligible'
        applied_value = 'memory_conservative'
    },
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.a'
        epoch_sequence = 1
        axis_id = 'application_send_batch_formation'
        decision_instance_id = 102
        configured_value = 'legacy_current'
        forced_value = 'single_eligible'
        shadow_recommendation = $null
        candidate_value = 'single_eligible'
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = 'structurally_inactive'
        applied_value = 'legacy_current'
    },
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.b'
        epoch_sequence = 1
        axis_id = 'application_send_batch_formation'
        decision_instance_id = 301
        configured_value = 'legacy_current'
        forced_value = 'single_eligible'
        shadow_recommendation = $null
        candidate_value = 'single_eligible'
        operation_eligibility_result = 'ineligible'
        operation_eligibility_reason = 'safety_guard'
        applied_value = 'legacy_current'
    }
)
$operations = @(
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.a'
        epoch_sequence = 1
        axis_id = 'application_send_batch_formation'
        decision_instance_id = 101
        operation_id = 1
        configured_value = 'legacy_current'
        forced_value = 'single_eligible'
        shadow_recommendation = $null
        candidate_value = 'single_eligible'
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = 'eligible'
        applied_value = 'single_eligible'
        operation_kind = 'packet_plan'
        scope_version = 1
        mechanism_event_id = 'mechanism_event.batch_single_eligible'
        legal_work_count = 3
        applied_work_count = 1
        legal_bytes = 300
        applied_bytes = 100
        result = 'applied'
        fallback_or_safety_reason = $null
        terminal_outcome = 'packet_plan_committed'
    },
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.a'
        epoch_sequence = 1
        axis_id = 'buffer_copy_coalescing'
        decision_instance_id = 201
        operation_id = 1
        configured_value = 'legacy_current'
        forced_value = 'memory_conservative'
        shadow_recommendation = $null
        candidate_value = 'memory_conservative'
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = 'eligible'
        applied_value = 'memory_conservative'
        operation_kind = 'combined_send'
        scope_version = 1
        mechanism_event_id = 'mechanism_event.buffer_two_source_cap'
        legal_work_count = 4
        applied_work_count = 2
        legal_bytes = 400
        applied_bytes = 200
        result = 'applied'
        fallback_or_safety_reason = $null
        terminal_outcome = 'released'
    },
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.a'
        epoch_sequence = 1
        axis_id = 'application_send_batch_formation'
        decision_instance_id = 102
        operation_id = 2
        configured_value = 'legacy_current'
        forced_value = 'single_eligible'
        shadow_recommendation = $null
        candidate_value = 'single_eligible'
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = 'structurally_inactive'
        applied_value = 'legacy_current'
        operation_kind = 'packet_plan'
        scope_version = 1
        mechanism_event_id = 'mechanism_event.batch_legal_prefix'
        legal_work_count = 1
        applied_work_count = 1
        legal_bytes = 80
        applied_bytes = 80
        result = 'inactive'
        fallback_or_safety_reason = 'eligible_count_one'
        terminal_outcome = 'packet_plan_committed'
    },
    [pscustomobject][ordered]@{
        run_id = 'run.closeout.fixture'
        connection_key = 'connection.b'
        epoch_sequence = 1
        axis_id = 'application_send_batch_formation'
        decision_instance_id = 301
        operation_id = 1
        configured_value = 'legacy_current'
        forced_value = 'single_eligible'
        shadow_recommendation = $null
        candidate_value = 'single_eligible'
        operation_eligibility_result = 'ineligible'
        operation_eligibility_reason = 'safety_guard'
        applied_value = 'legacy_current'
        operation_kind = 'packet_plan'
        scope_version = 1
        mechanism_event_id = 'mechanism_event.batch_legal_prefix'
        legal_work_count = 2
        applied_work_count = 2
        legal_bytes = 132
        applied_bytes = 132
        result = 'fallback'
        fallback_or_safety_reason = 'safety_guard'
        terminal_outcome = 'packet_plan_committed'
    }
)
$evidence = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-operation-evidence-v3'
    document_id = 'operation_evidence.closeout.fixture'
    document_version = 3
    content_sha256 = '0' * 64
    behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $catalog
    plan_validation_ref = New-AdaptiveRuntimeDocumentRef $validation
    experiment_run_ref = New-AdaptiveRuntimeDocumentRef $run
    binary_cohort_ref = New-AdaptiveRuntimeDocumentRef $binary
    run_id = 'run.closeout.fixture'
    binary_cohort_id = 'binary.closeout.fixture'
    connection_key = 'connection.a'
    epoch_sequence = 1
    result_epoch_sequence = 1
    connection_epochs = @(
        [pscustomobject][ordered]@{
            run_id = 'run.closeout.fixture'
            connection_key = 'connection.a'
            epoch_sequence = 1
        },
        [pscustomobject][ordered]@{
            run_id = 'run.closeout.fixture'
            connection_key = 'connection.a'
            epoch_sequence = 2
        },
        [pscustomobject][ordered]@{
            run_id = 'run.closeout.fixture'
            connection_key = 'connection.b'
            epoch_sequence = 1
        }
    )
    decisions = $decisions
    operations = $operations
    releases = @(
        [pscustomobject][ordered]@{
            run_id = 'run.closeout.fixture'
            connection_key = 'connection.a'
            axis_id = 'buffer_copy_coalescing'
            decision_instance_id = 201
            operation_id = 1
            operation_epoch_sequence = 1
            decision_epoch_sequence = 1
            release_epoch_sequence = 2
            release_count = 1
            terminal_outcome = 'released'
        }
    )
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = New-CloseoutTraceReferences
}
[void](Set-AdaptiveRuntimeDocumentHash $evidence)

$classificationsArray = @(
    New-Classification 'classification.batch.applied' `
        (New-OperationTarget $operations[0]) 'analytically_eligible'
    New-Classification 'classification.buffer.applied' `
        (New-OperationTarget $operations[1]) 'analytically_eligible'
    New-Classification 'classification.batch.inactive' `
        (New-OperationTarget $operations[2]) 'inactive'
    New-Classification 'classification.batch.inactive.context' `
        (New-OperationTarget $operations[2]) 'diagnostic_context'
    New-Classification 'classification.batch.fallback' `
        (New-OperationTarget $operations[3]) 'fallback'
    New-Classification 'classification.release.context' `
        ([pscustomobject][ordered]@{
            target_kind = 'release'
            run_id = 'run.closeout.fixture'
            connection_key = 'connection.a'
            epoch_sequence = 1
            axis_id = 'buffer_copy_coalescing'
            decision_instance_id = 201
            operation_id = 1
            release_epoch_sequence = 2
        }) 'diagnostic_context'
    New-Classification 'classification.epoch.context' `
        ([pscustomobject][ordered]@{
            target_kind = 'epoch'
            run_id = 'run.closeout.fixture'
            connection_key = 'connection.b'
            epoch_sequence = 1
        }) 'diagnostic_context'
    New-Classification 'classification.artifact.context' `
        ([pscustomobject][ordered]@{
            target_kind = 'artifact'
            artifact_id =
                'adaptive_runtime_experiment_plan_send_composition_interaction_v1'
        }) 'diagnostic_context'
)
$classifications = New-InputDocument `
    'adaptive-runtime-classification-set-v1' `
    'classifications.closeout.fixture' `
    ([pscustomobject][ordered]@{
        evidence_ref = New-AdaptiveRuntimeDocumentRef $evidence
        compatibility_catalog_ref =
            New-AdaptiveRuntimeDocumentRef $compatibilityCatalog
        classifications = $classificationsArray
    })
$behavior = New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$outcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $catalog $classifications
$metrics = New-InputDocument `
    'adaptive-runtime-metric-observations-v1' `
    'metrics.closeout.fixture' `
    ([pscustomobject][ordered]@{
        run_ref = New-AdaptiveRuntimeDocumentRef $run
        metric_observations = @(
            [pscustomobject][ordered]@{
                metric_id = 'metric.correctness.operation_count'
                run_id = 'run.closeout.fixture'
                connection_key = 'connection.a'
                epoch_sequence = 1
                analytical_use = 'correctness_only'
                value = 3
            },
            [pscustomobject][ordered]@{
                metric_id = 'metric.correctness.operation_count'
                run_id = 'run.closeout.fixture'
                connection_key = 'connection.b'
                epoch_sequence = 1
                analytical_use = 'correctness_only'
                value = 1
            }
        )
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
    'artifact_inventory.closeout.fixture' `
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
    [void](Write-Fixture $entry.Value "valid\inputs\$($entry.Key).json")
}

$projectionParams = @{
    PlanPath = Join-Path $fixtureRoot 'valid\inputs\experiment_plan.json'
    PlanValidationPath = Join-Path $fixtureRoot 'valid\inputs\plan_validation.json'
    CompiledManifestPath =
        Join-Path $fixtureRoot 'valid\inputs\compiled_execution_manifest.json'
    ExperimentRunPath = Join-Path $fixtureRoot 'valid\inputs\experiment_run.json'
    HostFingerprintPath = Join-Path $fixtureRoot 'valid\inputs\host_fingerprint.json'
    BinaryCohortPath = Join-Path $fixtureRoot 'valid\inputs\binary_cohort.json'
    WorkloadInstancePath = Join-Path $fixtureRoot 'valid\inputs\workload_instance.json'
    RequestedWorkloadShapePath =
        Join-Path $fixtureRoot 'valid\inputs\requested_workload_shape.json'
    EffectiveWorkloadShapePath =
        Join-Path $fixtureRoot 'valid\inputs\effective_workload_shape.json'
    OperationEvidencePath =
        Join-Path $fixtureRoot 'valid\inputs\operation_evidence.json'
    BehaviorMaterializationPath =
        Join-Path $fixtureRoot 'valid\inputs\behavior_materialization.json'
    OutcomeMaterializationPath =
        Join-Path $fixtureRoot 'valid\inputs\outcome_materialization.json'
    MetricObservationsPath =
        Join-Path $fixtureRoot 'valid\inputs\metric_observations.json'
    ArtifactInventoryPath =
        Join-Path $fixtureRoot 'valid\inputs\artifact_inventory.json'
    ClassificationsPath =
        Join-Path $fixtureRoot 'valid\inputs\classifications.json'
    BehaviorCatalogPath =
        Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v2.json'
    ClassificationCompatibilityCatalogPath =
        Join-Path $catalogRoot `
            'adaptive-runtime-classification-compatibility-catalog-v1.json'
    SchemaRoot = Join-Path $RepositoryRoot 'schemas'
    PassThru = $true
}
$projection = & (Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') @projectionParams
[void](Write-Fixture $projection 'valid\expected\projection.json')

$completeReleaseIdentity = Copy-JsonObject $evidence
$reusedDecision = Copy-JsonObject $completeReleaseIdentity.decisions[1]
$reusedDecision.decision_instance_id = 202
$completeReleaseIdentity.decisions += $reusedDecision
$reusedOperation = Copy-JsonObject $completeReleaseIdentity.operations[1]
$reusedOperation.decision_instance_id = 202
$completeReleaseIdentity.operations += $reusedOperation
$reusedRelease = Copy-JsonObject $completeReleaseIdentity.releases[0]
$reusedRelease.decision_instance_id = 202
$completeReleaseIdentity.releases += $reusedRelease
[void](Write-Fixture $completeReleaseIdentity `
    'valid\release-complete-identity-reuse.json')

$changedCatalog = Copy-JsonObject $catalog
$inactiveDefinition = @($changedCatalog.outcome_definitions |
    Where-Object outcome_id -eq 'outcome.inactive')[0]
$fallbackDefinition = @($changedCatalog.outcome_definitions |
    Where-Object outcome_id -eq 'outcome.fallback')[0]
$inactiveDefinition.result_kinds = @('fallback')
$fallbackDefinition.result_kinds = @('inactive')
[void](Write-Fixture $changedCatalog 'valid\catalog-mapping-changed.json')
$ambiguousCatalog = Copy-JsonObject $catalog
(@($ambiguousCatalog.outcome_definitions |
    Where-Object outcome_id -eq 'outcome.fallback')[0]).result_kinds =
    @('fallback','inactive')
[void](Write-Fixture $ambiguousCatalog 'invalid\catalog-outcome-ambiguous.json')

$invalidEvidence = Copy-JsonObject $evidence
$invalidEvidence.operations[2].result = 'unknown_result_kind'
[void](Write-Fixture $invalidEvidence 'invalid\outcome-no-match.json')
$forgedRelease = Copy-JsonObject $evidence
$forgedRelease.releases[0].decision_epoch_sequence = 2
[void](Write-Fixture $forgedRelease 'invalid\release-forged-decision-epoch.json')
$releaseOperationMismatch = Copy-JsonObject $evidence
$releaseOperationMismatch.releases[0].operation_id = 999
[void](Write-Fixture $releaseOperationMismatch `
    'invalid\release-operation-identity-mismatch.json')
$releaseDecisionMismatch = Copy-JsonObject $evidence
$releaseDecisionMismatch.releases[0].decision_instance_id = 999
[void](Write-Fixture $releaseDecisionMismatch `
    'invalid\release-operation-decision-mismatch.json')
$releaseLinkedDecisionMissing = Copy-JsonObject $evidence
$releaseLinkedDecisionMissing.operations[1].decision_instance_id = 999
$releaseLinkedDecisionMissing.releases[0].decision_instance_id = 999
[void](Write-Fixture $releaseLinkedDecisionMissing `
    'invalid\release-decision-identity-mismatch.json')
$releaseEpochMissing = Copy-JsonObject $evidence
$releaseEpochMissing.releases[0].release_epoch_sequence = 999
[void](Write-Fixture $releaseEpochMissing `
    'invalid\release-epoch-missing.json')
$releasePrecedesDecision = Copy-JsonObject $evidence
$releasePrecedesDecision.decisions[1].epoch_sequence = 2
$releasePrecedesDecision.operations[1].epoch_sequence = 2
$releasePrecedesDecision.releases[0].operation_epoch_sequence = 2
$releasePrecedesDecision.releases[0].decision_epoch_sequence = 2
$releasePrecedesDecision.releases[0].release_epoch_sequence = 1
[void](Write-Fixture $releasePrecedesDecision `
    'invalid\release-precedes-decision.json')
$duplicateRelease = Copy-JsonObject $evidence
$duplicateRelease.releases = @(
    $duplicateRelease.releases[0],
    (Copy-JsonObject $duplicateRelease.releases[0]))
[void](Write-Fixture $duplicateRelease 'invalid\duplicate-owner-release.json')
$missingRelease = Copy-JsonObject $evidence
$missingRelease.releases = @()
[void](Write-Fixture $missingRelease 'invalid\missing-terminal-release.json')
$ambiguousOperationTarget = Copy-JsonObject $evidence
$ambiguousOperationTarget.operations +=
    Copy-JsonObject $ambiguousOperationTarget.operations[0]
[void](Write-Fixture $ambiguousOperationTarget `
    'invalid\classification-target-ambiguous.json')

foreach ($case in @(
    @('wrong-run', 'run_id', 'run.wrong'),
    @('wrong-connection', 'connection_key', 'connection.wrong'),
    @('wrong-axis', 'axis_id', 'buffer_copy_coalescing'),
    @('wrong-decision', 'decision_instance_id', 999),
    @('wrong-operation', 'operation_id', 999)
)) {
    $invalidClassifications = Copy-JsonObject $classifications
    $invalidClassifications.payload.classifications[0].target.($case[1]) =
        $case[2]
    [void](Write-Fixture $invalidClassifications `
        "invalid\classification-$($case[0]).json")
}
$missingRequired = Copy-JsonObject $classifications
$missingRequired.payload.classifications = @(
    $missingRequired.payload.classifications |
        Where-Object classification_id -ne 'classification.batch.inactive')
[void](Write-Fixture $missingRequired `
    'invalid\classification-required-primary-missing.json')
$contradiction = Copy-JsonObject $classifications
$contradiction.payload.classifications +=
    New-Classification 'classification.batch.inactive.fallback' `
        (New-OperationTarget $operations[2]) 'fallback'
[void](Write-Fixture $contradiction `
    'invalid\classification-contradiction.json')
$legacyTarget = Copy-JsonObject $classifications
$legacyClassification = $legacyTarget.payload.classifications[0]
$legacyClassification.PSObject.Properties.Remove('target')
$legacyClassification | Add-Member -NotePropertyName target_kind `
    -NotePropertyValue 'operation'
$legacyClassification | Add-Member -NotePropertyName target_id `
    -NotePropertyValue 1
[void](Write-Fixture $legacyTarget `
    'invalid\classification-ambiguous-legacy-target.json')

$invalidProjectionDocuments = [ordered]@{}
$wrongHost = Copy-JsonObject $hostDocument
$wrongHost.payload.fingerprint_id = 'host.wrong'
[void](Set-AdaptiveRuntimeDocumentHash $wrongHost)
$invalidProjectionDocuments['host-unrelated.json'] = $wrongHost
$wrongBinary = Copy-JsonObject $binary
$wrongBinary.payload.binary_sha256 = 'd' * 64
[void](Set-AdaptiveRuntimeDocumentHash $wrongBinary)
$invalidProjectionDocuments['binary-unrelated.json'] = $wrongBinary
$wrongWorkload = Copy-JsonObject $workload
$wrongWorkload.payload.run_ref.document_id = 'run.unrelated'
[void](Set-AdaptiveRuntimeDocumentHash $wrongWorkload)
$invalidProjectionDocuments['workload-unrelated.json'] = $wrongWorkload
$wrongMetrics = Copy-JsonObject $metrics
$wrongMetrics.payload.metric_observations[0].epoch_sequence = 999
[void](Set-AdaptiveRuntimeDocumentHash $wrongMetrics)
$invalidProjectionDocuments['metrics-unrelated.json'] = $wrongMetrics
$wrongBehavior = Copy-JsonObject $behavior
$wrongBehavior.aggregates[0].byte_count += 1
[void](Set-AdaptiveRuntimeDocumentHash $wrongBehavior)
$invalidProjectionDocuments['behavior-recompute-mismatch.json'] = $wrongBehavior
$wrongOutcome = Copy-JsonObject $outcome
$wrongOutcome.aggregates[0].byte_count += 1
[void](Set-AdaptiveRuntimeDocumentHash $wrongOutcome)
$invalidProjectionDocuments['outcome-recompute-mismatch.json'] = $wrongOutcome
$wrongInventory = Copy-JsonObject $inventory
$wrongInventory.payload.artifacts =
    @($wrongInventory.payload.artifacts | Select-Object -Skip 1)
[void](Set-AdaptiveRuntimeDocumentHash $wrongInventory)
$invalidProjectionDocuments['artifact-inventory-incomplete.json'] = $wrongInventory
foreach ($entry in $invalidProjectionDocuments.GetEnumerator()) {
    [void](Write-Fixture $entry.Value "invalid\projection\$($entry.Key)")
}

$expectations = [pscustomobject][ordered]@{
    evidence_invalid = [ordered]@{
        'outcome-no-match.json' = 'outcome_derivation_no_match'
        'release-forged-decision-epoch.json' =
            'release_decision_epoch_mismatch'
        'release-operation-identity-mismatch.json' =
            'release_operation_identity_mismatch'
        'release-operation-decision-mismatch.json' =
            'release_operation_identity_mismatch'
        'release-decision-identity-mismatch.json' =
            'release_decision_identity_mismatch'
        'release-epoch-missing.json' = 'release_epoch_missing'
        'release-precedes-decision.json' = 'release_precedes_decision'
        'duplicate-owner-release.json' = 'duplicate_owner_release'
        'missing-terminal-release.json' = 'missing_terminal_release_evidence'
        'classification-target-ambiguous.json' =
            'classification_target_ambiguous'
    }
    classification_invalid = [ordered]@{
        'classification-wrong-run.json' = 'classification_target_missing'
        'classification-wrong-connection.json' =
            'classification_target_missing'
        'classification-wrong-axis.json' = 'classification_target_missing'
        'classification-wrong-decision.json' =
            'classification_target_missing'
        'classification-wrong-operation.json' =
            'classification_target_missing'
        'classification-required-primary-missing.json' =
            'required_retained_classification_missing'
        'classification-contradiction.json' =
            'classification_contradiction'
        'classification-ambiguous-legacy-target.json' =
            'projection_input_schema_invalid'
    }
    projection_invalid = [ordered]@{
        'host-unrelated.json' = 'projection_host_manifest_mismatch'
        'binary-unrelated.json' = 'projection_binary_manifest_mismatch'
        'workload-unrelated.json' = 'projection_workload_run_mismatch'
        'metrics-unrelated.json' = 'projection_metric_epoch_missing'
        'behavior-recompute-mismatch.json' =
            'projection_behavior_recompute_mismatch'
        'outcome-recompute-mismatch.json' =
            'projection_outcome_recompute_mismatch'
        'artifact-inventory-incomplete.json' =
            'projection_input_schema_invalid'
    }
}
$expectationsPath = Join-Path $fixtureRoot 'expectations.json'
$expectationsParent = Split-Path -Parent $expectationsPath
if (-not (Test-Path -LiteralPath $expectationsParent)) {
    [void](New-Item -ItemType Directory -Path $expectationsParent)
}
[System.IO.File]::WriteAllText(
    $expectationsPath,
    (ConvertTo-AdaptiveRuntimeCanonicalJson $expectations),
    [System.Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    fixture_root = $fixtureRoot
    valid_inputs = $inputs.Count
    evidence_invalid = $expectations.evidence_invalid.Count
    classification_invalid = $expectations.classification_invalid.Count
    projection_invalid = $expectations.projection_invalid.Count
    catalog_hash = $catalog.content_sha256
    classification_catalog_hash = $compatibilityCatalog.content_sha256
    projection_hash = $projection.content_sha256
}
