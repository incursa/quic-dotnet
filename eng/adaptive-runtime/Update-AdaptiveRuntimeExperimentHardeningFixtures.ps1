# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param([string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

$root = Join-Path $RepositoryRoot 'tests\fixtures\adaptive-runtime-experiment-hardening'
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')
$interactionPlanPath = Join-Path $RepositoryRoot (
    'tests\fixtures\adaptive-runtime-experiment-plan-compiler\valid\interaction.plan.json')
$verificationSourcePlanPath = Join-Path $RepositoryRoot (
    'tests\fixtures\adaptive-runtime-experiment-plan-compiler\warning\send-verification.plan.json')
New-Item -ItemType Directory -Path (Join-Path $root 'linked') -Force | Out-Null
$verificationPlan = Read-AdaptiveRuntimeJsonDocument $verificationSourcePlanPath
$verificationPlan.family_id = 'send_planning_verification'
[void](Set-AdaptiveRuntimeDocumentHash $verificationPlan)
$verificationPlanPath = Join-Path $root 'linked\send-verification.plan.v2-input.json'
Write-AdaptiveRuntimeCanonicalDocument $verificationPlan $verificationPlanPath
$interactionValidation = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
    -PlanPath $interactionPlanPath -RepositoryRoot $RepositoryRoot `
    -CatalogContractVersion v2 -PassThru
$verificationValidation = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
    -PlanPath $verificationPlanPath -RepositoryRoot $RepositoryRoot `
    -CatalogContractVersion v2 -PassThru

$trace = [ordered]@{
    requirement_ids = @('REQ-QUIC-CRT-0210','REQ-QUIC-CRT-0211','REQ-QUIC-CRT-0212','REQ-QUIC-CRT-0213')
    architecture_ids = @('ARC-QUIC-CRT-0098')
    work_item_ids = @('WI-QUIC-CRT-0099')
    verification_ids = @('VER-QUIC-CRT-0100')
}

function Copy-Value([object] $Value) {
    return $Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
}

function New-Decision {
    param(
        [string] $Axis,
        [long] $Id,
        [string] $Configured,
        [AllowNull()][object] $Forced,
        [AllowNull()][object] $Shadow,
        [string] $Candidate,
        [string] $Applied
    )
    return [ordered]@{
        run_id = 'run.hardening.fixture'
        connection_key = 'connection.hardening.1'
        axis_id = $Axis
        decision_instance_id = $Id
        epoch_sequence = 1
        configured_value = $Configured
        forced_value = $Forced
        shadow_recommendation = $Shadow
        candidate_value = $Candidate
        applied_value = $Applied
    }
}

function New-Operation {
    param(
        [string] $Axis,
        [long] $DecisionId,
        [long] $OperationId,
        [string] $Configured,
        [AllowNull()][object] $Forced,
        [AllowNull()][object] $Shadow,
        [string] $Candidate,
        [string] $Eligibility,
        [string] $Reason,
        [string] $Applied,
        [string] $OperationKind,
        [string] $MechanismEventId,
        [long] $LegalWork,
        [long] $AppliedWork,
        [long] $LegalBytes,
        [long] $AppliedBytes,
        [string] $Result,
        [AllowNull()][object] $Fallback,
        [AllowNull()][object] $Terminal
    )
    return [ordered]@{
        run_id = 'run.hardening.fixture'
        connection_key = 'connection.hardening.1'
        configured_value = $Configured
        forced_value = $Forced
        shadow_recommendation = $Shadow
        operation_kind = $OperationKind
        scope_version = 1
        axis_id = $Axis
        decision_instance_id = $DecisionId
        operation_id = $OperationId
        epoch_sequence = 1
        candidate_value = $Candidate
        operation_eligibility_result = $Eligibility
        operation_eligibility_reason = $Reason
        applied_value = $Applied
        mechanism_event_id = $MechanismEventId
        source_event_kind = 'axis_specific_mechanism'
        legal_work_count = $LegalWork
        applied_work_count = $AppliedWork
        legal_bytes = $LegalBytes
        applied_bytes = $AppliedBytes
        result = $Result
        fallback_or_safety_reason = $Fallback
        terminal_outcome = $Terminal
    }
}

function New-Classification {
    param([long] $OperationId, [string] $Kind)
    return [ordered]@{
        classification_id = "classification.$OperationId.$Kind"
        target_kind = 'operation'
        target_id = $OperationId
        kind = $Kind
        reason_code = "reason.$Kind"
        provenance_ref = New-AdaptiveRuntimeDocumentRef $interactionValidation
        retained = $true
    }
}

function New-BaseEvidence([string] $Id) {
    $batchDecision = New-Decision `
        'application_send_batch_formation' 101 'legacy_current' `
        'single_eligible' $null 'single_eligible' 'single_eligible'
    $batchOperation = New-Operation `
        'application_send_batch_formation' 101 1001 'legacy_current' `
        'single_eligible' $null 'single_eligible' 'eligible' 'eligible' `
        'single_eligible' 'packet_plan' `
        'mechanism_event.batch_single_eligible' 3 1 300 100 `
        'succeeded' $null 'packet_plan_committed'
    return [ordered]@{
        schema_version = 'adaptive-runtime-operation-evidence-v2'
        document_id = $Id
        document_version = 2
        content_sha256 = '0' * 64
        behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $catalog
        plan_validation_ref = New-AdaptiveRuntimeDocumentRef $interactionValidation
        run_id = 'run.hardening.fixture'
        binary_cohort_id = 'binary.hardening.fixture'
        connection_key = 'connection.hardening.1'
        epoch_sequence = 1
        result_epoch_sequence = 1
        connection_epochs = @(
            [ordered]@{
                run_id = 'run.hardening.fixture'
                connection_key = 'connection.hardening.1'
                epoch_sequence = 1
            },
            [ordered]@{
                run_id = 'run.hardening.fixture'
                connection_key = 'connection.hardening.1'
                epoch_sequence = 2
            }
        )
        decisions = @($batchDecision)
        operations = @($batchOperation)
        releases = @()
        artifact_inventory = @(
            [ordered]@{
                artifact_id = 'artifact.hardening.source'
                content_sha256 = '1' * 64
            }
        )
        classifications = @(
            New-Classification 1001 'analytically_eligible'
        )
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = Copy-Value $trace
    }
}

function Add-BufferScenario {
    param(
        [object] $Document,
        [string] $Configured,
        [AllowNull()][object] $Forced,
        [string] $Candidate,
        [string] $Applied,
        [string] $Mechanism,
        [long] $LegalWork,
        [long] $AppliedWork,
        [string] $Result,
        [string] $ClassificationKind
    )
    $decision = New-Decision 'buffer_copy_coalescing' 201 $Configured `
        $Forced $null $Candidate $Applied
    $operation = New-Operation 'buffer_copy_coalescing' 201 2001 `
        $Configured $Forced $null $Candidate 'eligible' `
        $(if ($Result -eq 'inactive') { 'structurally_inactive' } else { 'eligible' }) `
        $Applied 'combined_send' $Mechanism $LegalWork $AppliedWork `
        ($LegalWork * 100) ($AppliedWork * 100) $Result $null 'released'
    $Document.decisions += $decision
    $Document.operations += $operation
    $Document.releases += [ordered]@{
        run_id = 'run.hardening.fixture'
        connection_key = 'connection.hardening.1'
        axis_id = 'buffer_copy_coalescing'
        operation_id = 2001
        decision_instance_id = 201
        decision_epoch_sequence = 1
        release_epoch_sequence = 2
        release_count = 1
        terminal_outcome = 'released'
    }
    $Document.classifications += New-Classification 2001 $ClassificationKind
}

function Set-SingleBatchScenario {
    param(
        [object] $Document,
        [string] $Configured,
        [AllowNull()][object] $Forced,
        [AllowNull()][object] $Shadow,
        [string] $Candidate,
        [string] $Eligibility,
        [string] $Reason,
        [string] $Applied,
        [string] $Mechanism,
        [string] $Result,
        [string] $Kind
    )
    $Document.decisions = @(
        New-Decision 'application_send_batch_formation' 101 $Configured `
            $Forced $Shadow $Candidate $Applied
    )
    $Document.operations = @(
        New-Operation 'application_send_batch_formation' 101 1001 `
            $Configured $Forced $Shadow $Candidate $Eligibility $Reason `
            $Applied 'packet_plan' $Mechanism 3 `
            $(if ($Result -in @('fallback','invalid','unclassifiable')) { 0 } else { 1 }) `
            300 $(if ($Result -in @('fallback','invalid','unclassifiable')) { 0 } else { 100 }) `
            $Result $(if ($Result -in @('fallback','clamped')) { 'safety_guard' } else { $null }) `
            $(if ($Result -eq 'succeeded') { 'packet_plan_committed' } else { 'packet_plan_abandoned' })
    )
    $Document.releases = @()
    $Document.classifications = @(
        New-Classification 1001 $Kind
    )
}

function Write-Document([string] $Group, [string] $Name, [object] $Document) {
    $Document.document_id = ($Name -replace '\.json$','' -replace '[^a-z0-9._-]','_')
    Write-AdaptiveRuntimeCanonicalDocument $Document (Join-Path $root "$Group\$Name")
}

Write-AdaptiveRuntimeCanonicalDocument $interactionValidation (
    Join-Path $root 'linked\interaction.validation.v2.json')
Write-AdaptiveRuntimeCanonicalDocument $verificationValidation (
    Join-Path $root 'linked\send-verification.validation.v2.json')

$valid = [ordered]@{}
$valid['catalog.batch-single.json'] = New-BaseEvidence 'fixture.catalog.batch_single'
$legacy = New-BaseEvidence 'fixture.catalog.batch_legacy'
Set-SingleBatchScenario $legacy 'legacy_current' $null $null 'legacy_current' `
    'eligible' 'eligible' 'legacy_current' `
    'mechanism_event.batch_legal_prefix' 'succeeded' 'analytically_eligible'
$valid['catalog.batch-legacy.json'] = $legacy
$bufferLegacy = New-BaseEvidence 'fixture.catalog.buffer_legacy'
$bufferLegacy.decisions=@();$bufferLegacy.operations=@();$bufferLegacy.classifications=@()
Add-BufferScenario $bufferLegacy 'legacy_current' $null 'legacy_current' `
    'legacy_current' 'mechanism_event.buffer_legacy_prefix' 4 4 `
    'succeeded' 'analytically_eligible'
$valid['catalog.buffer-legacy.json'] = $bufferLegacy
$bufferConservative = New-BaseEvidence 'fixture.catalog.buffer_conservative'
$bufferConservative.decisions=@();$bufferConservative.operations=@();$bufferConservative.classifications=@()
Add-BufferScenario $bufferConservative 'legacy_current' 'memory_conservative' `
    'memory_conservative' 'memory_conservative' `
    'mechanism_event.buffer_two_source_cap' 4 2 'succeeded' 'analytically_eligible'
$valid['catalog.buffer-conservative.json'] = $bufferConservative
$multi = New-BaseEvidence 'fixture.multiple_behaviors'
Set-SingleBatchScenario $multi 'legacy_current' $null $null 'legacy_current' `
    'eligible' 'eligible' 'legacy_current' `
    'mechanism_event.batch_legal_prefix' 'succeeded' 'analytically_eligible'
$secondDecision = New-Decision 'application_send_batch_formation' 102 `
    'legacy_current' 'single_eligible' $null 'single_eligible' 'single_eligible'
$secondOperation = New-Operation 'application_send_batch_formation' 102 1002 `
    'legacy_current' 'single_eligible' $null 'single_eligible' 'eligible' `
    'eligible' 'single_eligible' 'packet_plan' `
    'mechanism_event.batch_single_eligible' 3 1 300 100 `
    'succeeded' $null 'packet_plan_committed'
$multi.decisions += $secondDecision
$multi.operations += $secondOperation
$multi.classifications += New-Classification 1002 'analytically_eligible'
$valid['multiple-behaviors.json'] = $multi
$inactive = New-BaseEvidence 'fixture.inactive'
Set-SingleBatchScenario $inactive 'legacy_current' 'single_eligible' $null `
    'single_eligible' 'eligible' 'structurally_inactive' 'single_eligible' `
    'mechanism_event.batch_legal_prefix' 'inactive' 'inactive'
$valid['inactive-retained.json'] = $inactive
$fallback = New-BaseEvidence 'fixture.fallback'
Set-SingleBatchScenario $fallback 'legacy_current' 'single_eligible' $null `
    'single_eligible' 'ineligible' 'resource_guard' 'legacy_current' `
    'mechanism_event.batch_legal_prefix' 'fallback' 'fallback'
$valid['safe-fallback.json'] = $fallback
$unclassifiable = New-BaseEvidence 'fixture.unclassifiable'
Set-SingleBatchScenario $unclassifiable 'legacy_current' 'single_eligible' $null `
    'single_eligible' 'ineligible' 'unclassifiable_evidence' 'legacy_current' `
    'mechanism_event.batch_unknown' 'unclassifiable' 'unclassifiable'
$valid['unclassifiable-retained.json'] = $unclassifiable
$both = Copy-Value $multi
Add-BufferScenario $both 'legacy_current' 'memory_conservative' `
    'memory_conservative' 'memory_conservative' `
    'mechanism_event.buffer_two_source_cap' 4 2 'succeeded' 'analytically_eligible'
$valid['both-axes-distinct.json'] = $both
foreach ($entry in $valid.GetEnumerator()) {
    Write-Document 'valid' $entry.Key (Copy-Value $entry.Value)
}

$warning = [ordered]@{
    'multiple-derived-from-content.json' = $multi
    'inactive-derived-from-content.json' = $inactive
    'renamed-inactive-content-copy.json' = $inactive
    'fallback-derived-from-content.json' = $fallback
    'fallback-name-without-content.json' = $legacy
}
$verificationEvidence = Copy-Value $legacy
$verificationEvidence.plan_validation_ref =
    New-AdaptiveRuntimeDocumentRef $verificationValidation
$warning['verification-only-linked-validation.json'] = $verificationEvidence
foreach ($entry in $warning.GetEnumerator()) {
    Write-Document 'warning' $entry.Key (Copy-Value $entry.Value)
}

$invalidBuilders = [ordered]@{
    'candidate-mismatch.json' = { param($d) $d.operations[0].candidate_value='legacy_current' }
    'applied-mismatch.json' = { param($d) $d.operations[0].applied_value='legacy_current' }
    'configured-mismatch.json' = { param($d) $d.operations[0].configured_value='single_eligible' }
    'forced-mismatch.json' = { param($d) $d.operations[0].forced_value=$null }
    'shadow-mismatch.json' = { param($d) $d.operations[0].shadow_recommendation='single_eligible' }
    'eligibility-reason-mismatch.json' = { param($d) $d.operations[0].operation_eligibility_reason='resource_guard' }
    'wrong-run.json' = { param($d) $d.operations[0].run_id='run.other' }
    'wrong-connection.json' = { param($d) $d.operations[0].connection_key='connection.other' }
    'missing-top-epoch.json' = { param($d) $d.connection_epochs[0].epoch_sequence=3 }
    'duplicate-top-epoch.json' = { param($d) $d.connection_epochs+=Copy-Value $d.connection_epochs[0] }
    'missing-decision-epoch.json' = { param($d) $d.decisions[0].epoch_sequence=3 }
    'missing-operation-epoch.json' = { param($d) $d.operations[0].epoch_sequence=3 }
    'unknown-mechanism-event.json' = { param($d) $d.operations[0].mechanism_event_id='mechanism_event.unknown' }
    'stale-catalog.json' = { param($d) $d.behavior_catalog_ref.content_sha256='2'*64 }
    'classification-target-missing.json' = { param($d) $d.classifications[0].target_id=9999 }
    'classification-id-duplicate.json' = {
        param($d) $copy=Copy-Value $d.classifications[0];$copy.kind='diagnostic';$d.classifications+=$copy
    }
    'classification-contradiction.json' = {
        param($d) $copy=Copy-Value $d.classifications[0];$copy.classification_id='classification.1001.invalid';$copy.kind='invalid';$d.classifications+=$copy
    }
    'unrelated-retention.json' = {
        param($d)
        Set-SingleBatchScenario $d 'legacy_current' 'single_eligible' $null `
            'single_eligible' 'eligible' 'structurally_inactive' 'single_eligible' `
            'mechanism_event.batch_legal_prefix' 'inactive' 'inactive'
        $d.classifications[0].target_id=9999
    }
}
$bufferRelease = Copy-Value $bufferConservative
$invalidBuilders['release-before-decision.json'] = {
    param($d) $script:d = $d
}
$invalidExpectations = [ordered]@{
    'candidate-mismatch.json' = 'candidate_value_mismatch'
    'applied-mismatch.json' = 'applied_value_mismatch'
    'configured-mismatch.json' = 'configured_value_mismatch'
    'forced-mismatch.json' = 'forced_value_mismatch'
    'shadow-mismatch.json' = 'shadow_recommendation_mismatch'
    'eligibility-reason-mismatch.json' = 'eligibility_reason_mismatch'
    'wrong-run.json' = 'run_correlation_mismatch'
    'wrong-connection.json' = 'connection_correlation_mismatch'
    'missing-top-epoch.json' = 'top_epoch_missing'
    'duplicate-top-epoch.json' = 'top_epoch_not_unique'
    'missing-decision-epoch.json' = 'decision_epoch_missing'
    'missing-operation-epoch.json' = 'operation_epoch_missing'
    'unknown-mechanism-event.json' = 'behavior_derivation_no_match'
    'stale-catalog.json' = 'stale_behavior_catalog_version'
    'classification-target-missing.json' = 'classification_target_missing'
    'classification-id-duplicate.json' = 'classification_id_duplicate'
    'classification-contradiction.json' = 'classification_contradiction'
    'unrelated-retention.json' = 'required_retained_classification_missing'
}
foreach ($entry in $invalidBuilders.GetEnumerator()) {
    if ($entry.Key -eq 'release-before-decision.json') { continue }
    $document = New-BaseEvidence "fixture.invalid.$($entry.Key)"
    & $entry.Value $document
    Write-Document 'invalid' $entry.Key $document
}
$releaseBefore = Copy-Value $bufferRelease
$releaseBefore.connection_epochs += [ordered]@{
    run_id='run.hardening.fixture';connection_key='connection.hardening.1';epoch_sequence=2
}
$releaseBefore.epoch_sequence=2
$releaseBefore.result_epoch_sequence=2
$releaseBefore.decisions[0].epoch_sequence=2
$releaseBefore.operations[0].epoch_sequence=2
$releaseBefore.releases[0].decision_epoch_sequence=2
$releaseBefore.releases[0].release_epoch_sequence=1
Write-Document 'invalid' 'release-before-decision.json' $releaseBefore
$invalidExpectations['release-before-decision.json']='release_precedes_decision'
$releaseMissing = Copy-Value $bufferRelease
$releaseMissing.releases[0].release_epoch_sequence=3
Write-Document 'invalid' 'release-epoch-missing.json' $releaseMissing
$invalidExpectations['release-epoch-missing.json']='release_epoch_missing'

$warningExpectations = [ordered]@{
    'multiple-derived-from-content.json' = @('measurement_freeze_active','multiple_effective_behaviors_in_epoch')
    'inactive-derived-from-content.json' = @('inactive_operation_retained','measurement_freeze_active')
    'renamed-inactive-content-copy.json' = @('inactive_operation_retained','measurement_freeze_active')
    'fallback-derived-from-content.json' = @('fallback_operation_retained','measurement_freeze_active')
    'fallback-name-without-content.json' = @('measurement_freeze_active')
    'verification-only-linked-validation.json' = @('measurement_freeze_active','verification_only_equivalent_cell_retained')
}

function New-ProjectionInput {
    param(
        [string] $DocumentId,
        [string] $SchemaVersion,
        [string] $PayloadProperty,
        [object] $Payload
    )
    $document = [pscustomobject][ordered]@{
        schema_version = $SchemaVersion
        document_id = $DocumentId
        document_version = 1
        content_sha256 = ('0' * 64)
    }
    $document | Add-Member -NotePropertyName $PayloadProperty `
        -NotePropertyValue $Payload
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

$projectionInputRoot = Join-Path $root 'projection-inputs'
$projectionExpectedRoot = Join-Path $root 'expected'
$interactionPlan = Read-AdaptiveRuntimeJsonDocument $interactionPlanPath
$projectionEvidence = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $root 'valid\both-axes-distinct.json')
$behaviorMaterialization = New-AdaptiveRuntimeBehaviorMaterializationV2 `
    -Evidence $projectionEvidence -Catalog $catalog
$outcomeMaterialization = New-AdaptiveRuntimeOutcomeMaterializationV1 `
    -Evidence $projectionEvidence -Catalog $catalog
$manifest = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot (
        'tests\fixtures\adaptive-runtime-experiment-plan-compiler\valid\compiled-manifest.fixture.json'))
$manifest.document_id = 'manifest.fixture.hardening_projection'
$manifest.compiled_execution_manifest_id =
    'manifest.fixture.hardening_projection.v1'
$manifest.source_plan_ref = New-AdaptiveRuntimeDocumentRef $interactionPlan
$manifest.source_validation_ref =
    New-AdaptiveRuntimeDocumentRef $interactionValidation
$manifest.post_build_refs = @(
    New-AdaptiveRuntimeDocumentRef $interactionPlan
    New-AdaptiveRuntimeDocumentRef $interactionValidation
)
$manifest.notes = @(
    'Correctness-only immutable projection fixture; no execution occurred.')
[void](Set-AdaptiveRuntimeDocumentHash $manifest)

$experimentRun = New-ProjectionInput 'run.document.hardening_fixture' `
    'adaptive-runtime-experiment-run-fixture-v1' 'run_id' `
    'run.hardening.fixture'
$hostFingerprint = New-ProjectionInput 'host.document.hardening_fixture' `
    'adaptive-runtime-host-fingerprint-fixture-v1' 'host_id' `
    'host.hardening.fixture'
$binaryCohort = New-ProjectionInput 'binary.document.hardening_fixture' `
    'adaptive-runtime-binary-cohort-fixture-v1' 'binary_cohort_id' `
    'binary.hardening.fixture'
$workloadInstance = New-ProjectionInput 'workload.document.hardening_fixture' `
    'adaptive-runtime-workload-instance-fixture-v1' 'workload_instance_id' `
    'workload.hardening.fixture'
$requestedWorkload = New-ProjectionInput `
    'requested_workload.document.hardening_fixture' `
    'adaptive-runtime-requested-workload-shape-fixture-v1' `
    'requested_shape_id' 'shape.requested.hardening.fixture'
$effectiveWorkload = New-ProjectionInput `
    'effective_workload.document.hardening_fixture' `
    'adaptive-runtime-effective-workload-shape-fixture-v1' `
    'effective_shape_id' 'shape.effective.hardening.fixture'
$metrics = New-ProjectionInput 'metrics.document.hardening_fixture' `
    'adaptive-runtime-metric-observations-fixture-v1' `
    'metric_observations' @(
        [pscustomobject][ordered]@{
            metric_id = 'metric.correctness.mechanism_attribution'
            epoch_sequence = 1
            analytical_use = 'correctness_only'
        })
$artifacts = New-ProjectionInput 'artifacts.document.hardening_fixture' `
    'adaptive-runtime-artifact-inventory-fixture-v1' 'artifacts' `
    @($projectionEvidence.artifact_inventory)
$classifications = New-ProjectionInput `
    'classifications.document.hardening_fixture' `
    'adaptive-runtime-classifications-fixture-v1' 'classifications' `
    @($projectionEvidence.classifications)

$projectionFiles = [ordered]@{
    plan = $interactionPlanPath
    validation = Join-Path $root 'linked\interaction.validation.v2.json'
    manifest = Join-Path $projectionInputRoot 'compiled-manifest.json'
    experiment_run = Join-Path $projectionInputRoot 'experiment-run.json'
    host = Join-Path $projectionInputRoot 'host-fingerprint.json'
    binary = Join-Path $projectionInputRoot 'binary-cohort.json'
    workload = Join-Path $projectionInputRoot 'workload-instance.json'
    requested = Join-Path $projectionInputRoot 'requested-workload-shape.json'
    effective = Join-Path $projectionInputRoot 'effective-workload-shape.json'
    evidence = Join-Path $root 'valid\both-axes-distinct.json'
    behavior = Join-Path $projectionExpectedRoot 'behavior-materialization.json'
    outcome = Join-Path $projectionExpectedRoot 'outcome-materialization.json'
    metrics = Join-Path $projectionInputRoot 'metric-observations.json'
    artifacts = Join-Path $projectionInputRoot 'artifact-inventory.json'
    classifications = Join-Path $projectionInputRoot 'classifications.json'
    projection = Join-Path $projectionExpectedRoot 'projection.json'
}
foreach ($entry in @(
    @($manifest, $projectionFiles.manifest),
    @($experimentRun, $projectionFiles.experiment_run),
    @($hostFingerprint, $projectionFiles.host),
    @($binaryCohort, $projectionFiles.binary),
    @($workloadInstance, $projectionFiles.workload),
    @($requestedWorkload, $projectionFiles.requested),
    @($effectiveWorkload, $projectionFiles.effective),
    @($behaviorMaterialization, $projectionFiles.behavior),
    @($outcomeMaterialization, $projectionFiles.outcome),
    @($metrics, $projectionFiles.metrics),
    @($artifacts, $projectionFiles.artifacts),
    @($classifications, $projectionFiles.classifications)
)) {
    Write-AdaptiveRuntimeCanonicalDocument $entry[0] $entry[1]
}

$projectionInvalidRoot = Join-Path $root 'projection-invalid'
$missingHash = Copy-Value $experimentRun
$missingHash.PSObject.Properties.Remove('content_sha256')
[IO.Directory]::CreateDirectory($projectionInvalidRoot) | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $projectionInvalidRoot 'experiment-run-missing-hash.json'),
    ($missingHash | ConvertTo-Json -Depth 20 -Compress),
    [Text.UTF8Encoding]::new($false))
$wrongBehaviorSource = Copy-Value $behaviorMaterialization
$wrongBehaviorSource.source_evidence_ref.content_sha256 = ('e' * 64)
[void](Set-AdaptiveRuntimeDocumentHash $wrongBehaviorSource)
Write-AdaptiveRuntimeCanonicalDocument $wrongBehaviorSource (
    Join-Path $projectionInvalidRoot 'behavior-wrong-source-ref.json')
$manifestMismatch = Copy-Value $manifest
$manifestMismatch.source_plan_ref.content_sha256 = ('e' * 64)
[void](Set-AdaptiveRuntimeDocumentHash $manifestMismatch)
Write-AdaptiveRuntimeCanonicalDocument $manifestMismatch (
    Join-Path $projectionInvalidRoot 'manifest-plan-mismatch.json')
$duplicateEpochEvidence = Copy-Value $projectionEvidence
$duplicateEpochEvidence.connection_epochs +=
    Copy-Value $duplicateEpochEvidence.connection_epochs[0]
[void](Set-AdaptiveRuntimeDocumentHash $duplicateEpochEvidence)
Write-AdaptiveRuntimeCanonicalDocument $duplicateEpochEvidence (
    Join-Path $projectionInvalidRoot 'evidence-duplicate-epoch.json')
$missingTargetClassifications = Copy-Value $classifications
$missingTargetClassifications.classifications[0].target_id = 9999
[void](Set-AdaptiveRuntimeDocumentHash $missingTargetClassifications)
Write-AdaptiveRuntimeCanonicalDocument $missingTargetClassifications (
    Join-Path $projectionInvalidRoot 'classifications-target-missing.json')
$projectionInvalidExpectations = [ordered]@{
    'experiment-run-missing-hash.json' =
        'projection_input_missing_identity:experiment_run:content_sha256'
    'behavior-wrong-source-ref.json' =
        'projection_behavior_evidence_reference_mismatch'
    'manifest-plan-mismatch.json' =
        'projection_manifest_plan_reference_mismatch'
    'evidence-duplicate-epoch.json' =
        'projection_duplicate_epoch_identity'
    'classifications-target-missing.json' =
        'projection_classification_target_missing'
}

& (Join-Path $PSScriptRoot 'New-AdaptiveRuntimeExperimentEvidenceProjection.ps1') `
    -PlanPath $projectionFiles.plan `
    -PlanValidationPath $projectionFiles.validation `
    -CompiledManifestPath $projectionFiles.manifest `
    -ExperimentRunPath $projectionFiles.experiment_run `
    -HostFingerprintPath $projectionFiles.host `
    -BinaryCohortPath $projectionFiles.binary `
    -WorkloadInstancePath $projectionFiles.workload `
    -RequestedWorkloadShapePath $projectionFiles.requested `
    -EffectiveWorkloadShapePath $projectionFiles.effective `
    -OperationEvidencePath $projectionFiles.evidence `
    -BehaviorMaterializationPath $projectionFiles.behavior `
    -OutcomeMaterializationPath $projectionFiles.outcome `
    -MetricObservationsPath $projectionFiles.metrics `
    -ArtifactInventoryPath $projectionFiles.artifacts `
    -ClassificationsPath $projectionFiles.classifications `
    -OutputPath $projectionFiles.projection

$expectations = [ordered]@{
    valid = @($valid.Keys)
    warning = $warningExpectations
    invalid = $invalidExpectations
    projection_invalid = $projectionInvalidExpectations
}
[IO.Directory]::CreateDirectory($root) | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $root 'expectations.json'),
    ($expectations | ConvertTo-Json -Depth 30),
    [Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    valid = $valid.Count
    warning = $warning.Count
    invalid = $invalidExpectations.Count
    root = $root
} | ConvertTo-Json
