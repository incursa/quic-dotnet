# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$fixtureRoot = Join-Path $RepoRoot 'tests\fixtures\adaptive-runtime-experiment-runtime-evidence'
$catalogPath = Join-Path $RepoRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v1.json'
$catalog = Read-AdaptiveRuntimeJsonDocument -Path $catalogPath
$zeroHash = '0' * 64
$trace = [ordered]@{
    requirement_ids = @('REQ-QUIC-CRT-0206','REQ-QUIC-CRT-0207','REQ-QUIC-CRT-0208','REQ-QUIC-CRT-0209')
    architecture_ids = @('ARC-QUIC-CRT-0095')
    work_item_ids = @('WI-QUIC-CRT-0096')
    verification_ids = @('VER-QUIC-CRT-0097')
}
$catalogRef = [ordered]@{
    document_id = $catalog.document_id
    schema_version = $catalog.schema_version
    document_version = $catalog.document_version
    content_sha256 = $catalog.content_sha256
}

function Copy-Document {
    param([Parameter(Mandatory = $true)][object] $Document)
    return ($Document | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
}

function New-Decision {
    param(
        [string] $Axis,
        [int] $Id,
        [string] $Configured,
        [AllowNull()][object] $Forced,
        [AllowNull()][object] $Shadow,
        [string] $Candidate,
        [string] $Applied
    )
    return [ordered]@{
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
        [int] $DecisionId,
        [int] $OperationId,
        [string] $Candidate,
        [string] $Eligibility,
        [string] $Reason,
        [string] $Applied,
        [string] $Mechanism,
        [int] $LegalWork,
        [int] $AppliedWork,
        [int] $LegalBytes,
        [int] $AppliedBytes,
        [string] $Result,
        [AllowNull()][object] $FallbackReason,
        [AllowNull()][object] $TerminalOutcome,
        [AllowNull()][object] $Behavior
    )
    return [ordered]@{
        axis_id = $Axis
        decision_instance_id = $DecisionId
        operation_id = $OperationId
        epoch_sequence = 1
        candidate_value = $Candidate
        operation_eligibility_result = $Eligibility
        operation_eligibility_reason = $Reason
        applied_value = $Applied
        mechanism_event = $Mechanism
        source_event_kind = 'axis_specific_mechanism'
        legal_work_count = $LegalWork
        applied_work_count = $AppliedWork
        legal_bytes = $LegalBytes
        applied_bytes = $AppliedBytes
        result = $Result
        fallback_or_safety_reason = $FallbackReason
        terminal_outcome = $TerminalOutcome
        effective_behavior_id = $Behavior
    }
}

function New-Classification {
    param([int] $OperationId, [string] $Kind)
    return [ordered]@{
        classification_id = "classification.$OperationId.$Kind"
        operation_id = $OperationId
        kind = $Kind
        retained = $true
    }
}

function Update-DeclaredAggregates {
    param([Parameter(Mandatory = $true)][object] $Document)
    $groups = @($Document.operations |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.effective_behavior_id) } |
        Group-Object { "$($_.axis_id)|$($_.effective_behavior_id)" })
    $Document.declared_aggregates = @($groups | ForEach-Object {
        $parts = $_.Name -split '\|', 2
        [long]$workCount = 0
        [long]$byteCount = 0
        foreach ($operation in $_.Group) {
            $workCount += [long]$operation.applied_work_count
            $byteCount += [long]$operation.applied_bytes
        }
        [ordered]@{
            axis_id = $parts[0]
            effective_behavior_id = $parts[1]
            operation_count = @($_.Group).Count
            work_count = $workCount
            byte_count = $byteCount
        }
    })
}

function New-BaseDocument {
    param([string] $Id)
    $batchDecision = New-Decision `
        -Axis 'application_send_batch_formation' `
        -Id 101 `
        -Configured 'legacy_current' `
        -Forced 'single_eligible' `
        -Shadow $null `
        -Candidate 'single_eligible' `
        -Applied 'single_eligible'
    $batchOperation = New-Operation `
        -Axis 'application_send_batch_formation' `
        -DecisionId 101 `
        -OperationId 1001 `
        -Candidate 'single_eligible' `
        -Eligibility 'eligible' `
        -Reason 'eligible' `
        -Applied 'single_eligible' `
        -Mechanism 'batch_single_eligible' `
        -LegalWork 3 `
        -AppliedWork 1 `
        -LegalBytes 300 `
        -AppliedBytes 100 `
        -Result 'succeeded' `
        -FallbackReason $null `
        -TerminalOutcome 'packet_plan_committed' `
        -Behavior 'behavior.application_send_batch_formation.single_eligible.prefix'
    $document = [ordered]@{
        schema_version = 'adaptive-runtime-operation-evidence-v1'
        document_id = $Id
        document_version = 1
        content_sha256 = $zeroHash
        behavior_catalog_ref = Copy-Document $catalogRef
        run_id = 'run.correctness.fixture'
        binary_cohort_id = 'binary.cohort.fixture'
        connection_key = 'connection.fixture.1'
        epoch_sequence = 1
        result_epoch_sequence = 1
        connection_epochs = @(
            [ordered]@{
                run_id = 'run.correctness.fixture'
                connection_key = 'connection.fixture.1'
                epoch_sequence = 1
            }
        )
        decisions = @($batchDecision)
        operations = @($batchOperation)
        releases = @()
        declared_aggregates = @()
        artifact_inventory = @(
            [ordered]@{
                artifact_id = 'artifact.source.fixture'
                content_sha256 = '1' * 64
            }
        )
        classifications = @(New-Classification -OperationId 1001 -Kind 'analytically_eligible')
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = Copy-Document $trace
    }
    Update-DeclaredAggregates $document
    return $document
}

function Set-SingleScenario {
    param([object] $Document, [object] $Decision, [object] $Operation, [string] $Kind)
    $Document.decisions = @($Decision)
    $Document.operations = @($Operation)
    $Document.releases = @()
    if ($Operation.axis_id -eq 'buffer_copy_coalescing' -and
        $Operation.mechanism_event -notin @('buffer_no_owner','broad_endpoint','unclassifiable')) {
        $Document.releases = @(
            [ordered]@{
                axis_id = 'buffer_copy_coalescing'
                operation_id = $Operation.operation_id
                decision_instance_id = $Operation.decision_instance_id
                decision_epoch_sequence = 1
                release_epoch_sequence = 1
                release_count = 1
                terminal_outcome = 'released'
            }
        )
    }
    $Document.classifications = @(New-Classification -OperationId $Operation.operation_id -Kind $Kind)
    Update-DeclaredAggregates $Document
}

function Write-Fixture {
    param([string] $Group, [string] $Name, [object] $Document)
    $Document.document_id = ($Name -replace '\.fixture\.json$','' -replace '[^a-z0-9._-]','_')
    Write-AdaptiveRuntimeCanonicalDocument `
        -Document $Document `
        -Path (Join-Path $fixtureRoot "$Group\$Name")
}

$batchDistinctDecision = New-Decision 'application_send_batch_formation' 101 'legacy_current' 'single_eligible' $null 'single_eligible' 'single_eligible'
$batchDistinct = New-Operation 'application_send_batch_formation' 101 1001 'single_eligible' 'eligible' 'eligible' 'single_eligible' 'batch_single_eligible' 3 1 300 100 'succeeded' $null 'packet_plan_committed' 'behavior.application_send_batch_formation.single_eligible.prefix'
$batchInactiveDecision = New-Decision 'application_send_batch_formation' 102 'legacy_current' 'single_eligible' $null 'single_eligible' 'single_eligible'
$batchInactive = New-Operation 'application_send_batch_formation' 102 1002 'single_eligible' 'eligible' 'structurally_inactive' 'single_eligible' 'batch_legal_prefix' 1 1 100 100 'inactive' $null 'packet_plan_committed' 'behavior.application_send_batch_formation.legacy_current.prefix'
$batchFallbackDecision = New-Decision 'application_send_batch_formation' 103 'legacy_current' 'single_eligible' $null 'single_eligible' 'legacy_current'
$batchFallback = New-Operation 'application_send_batch_formation' 103 1003 'single_eligible' 'clamped' 'resource_guard' 'legacy_current' 'batch_no_packet_plan' 0 0 0 0 'fallback' 'congestion_guard' 'packet_plan_abandoned' $null
$bufferDistinctDecision = New-Decision 'buffer_copy_coalescing' 201 'legacy_current' 'memory_conservative' $null 'memory_conservative' 'memory_conservative'
$bufferDistinct = New-Operation 'buffer_copy_coalescing' 201 2001 'memory_conservative' 'eligible' 'eligible' 'memory_conservative' 'buffer_two_source_cap' 4 2 400 200 'succeeded' $null 'released' 'behavior.buffer_copy_coalescing.memory_conservative.two_source_cap'
$bufferInactiveDecision = New-Decision 'buffer_copy_coalescing' 202 'legacy_current' 'memory_conservative' $null 'memory_conservative' 'memory_conservative'
$bufferInactive = New-Operation 'buffer_copy_coalescing' 202 2002 'memory_conservative' 'eligible' 'structurally_inactive' 'memory_conservative' 'buffer_legacy_prefix' 2 2 200 200 'inactive' $null 'released' 'behavior.buffer_copy_coalescing.legacy_current.exact_prefix'
$bufferFallbackDecision = New-Decision 'buffer_copy_coalescing' 203 'legacy_current' 'memory_conservative' $null 'memory_conservative' 'legacy_current'
$bufferFallback = New-Operation 'buffer_copy_coalescing' 203 2003 'memory_conservative' 'clamped' 'lifecycle_guard' 'legacy_current' 'buffer_legacy_prefix' 4 4 400 400 'clamped' 'lifecycle_guard' 'released' 'behavior.buffer_copy_coalescing.legacy_current.exact_prefix'

$validScenarios = [ordered]@{
    'batch.distinct.fixture.json' = @($batchDistinctDecision,$batchDistinct,'analytically_eligible')
    'batch.inactive.fixture.json' = @($batchInactiveDecision,$batchInactive,'inactive')
    'batch.fallback.fixture.json' = @($batchFallbackDecision,$batchFallback,'fallback')
    'buffer.distinct.fixture.json' = @($bufferDistinctDecision,$bufferDistinct,'analytically_eligible')
    'buffer.inactive.fixture.json' = @($bufferInactiveDecision,$bufferInactive,'inactive')
    'buffer.fallback.fixture.json' = @($bufferFallbackDecision,$bufferFallback,'clamped')
    'join.decision_operation.fixture.json' = @($batchDistinctDecision,$batchDistinct,'analytically_eligible')
    'join.operation_epoch.fixture.json' = @($bufferDistinctDecision,$bufferDistinct,'analytically_eligible')
    'aggregate.recompute.fixture.json' = @($batchDistinctDecision,$batchDistinct,'analytically_eligible')
    'projection.rebuild.fixture.json' = @($bufferDistinctDecision,$bufferDistinct,'analytically_eligible')
}
foreach ($entry in $validScenarios.GetEnumerator()) {
    $doc = New-BaseDocument "fixture.$($entry.Key)"
    Set-SingleScenario $doc (Copy-Document $entry.Value[0]) (Copy-Document $entry.Value[1]) $entry.Value[2]
    Write-Fixture 'valid' $entry.Key $doc
}

function Write-InteractionFixture {
    param(
        [string] $Name,
        [object] $BatchDecision,
        [object] $BatchOperation,
        [string] $BatchKind,
        [object] $BufferDecision,
        [object] $BufferOperation,
        [string] $BufferKind
    )
    $doc = New-BaseDocument "fixture.$Name"
    $doc.decisions = @(Copy-Document $BatchDecision; Copy-Document $BufferDecision)
    $doc.operations = @(Copy-Document $BatchOperation; Copy-Document $BufferOperation)
    $doc.releases = @(
        [ordered]@{
            axis_id = 'buffer_copy_coalescing'
            operation_id = $BufferOperation.operation_id
            decision_instance_id = $BufferOperation.decision_instance_id
            decision_epoch_sequence = 1
            release_epoch_sequence = 1
            release_count = 1
            terminal_outcome = 'released'
        }
    )
    $doc.classifications = @(
        New-Classification $BatchOperation.operation_id $BatchKind
        New-Classification $BufferOperation.operation_id $BufferKind
    )
    Update-DeclaredAggregates $doc
    Write-Fixture 'valid' $Name $doc
}

Write-InteractionFixture 'interaction.both_distinct.fixture.json' $batchDistinctDecision $batchDistinct 'analytically_eligible' $bufferDistinctDecision $bufferDistinct 'analytically_eligible'
Write-InteractionFixture 'interaction.batch_distinct_buffer_inactive.fixture.json' $batchDistinctDecision $batchDistinct 'analytically_eligible' $bufferInactiveDecision $bufferInactive 'inactive'
Write-InteractionFixture 'interaction.batch_inactive_buffer_distinct.fixture.json' $batchInactiveDecision $batchInactive 'inactive' $bufferDistinctDecision $bufferDistinct 'analytically_eligible'
Write-InteractionFixture 'interaction.both_inactive.fixture.json' $batchInactiveDecision $batchInactive 'inactive' $bufferInactiveDecision $bufferInactive 'inactive'

$multi = New-BaseDocument 'fixture.epoch.multiple_behaviors'
$multi.decisions = @(Copy-Document $batchDistinctDecision; Copy-Document $batchInactiveDecision)
$multi.operations = @(Copy-Document $batchDistinct; Copy-Document $batchInactive)
$multi.classifications = @(
    New-Classification 1001 'analytically_eligible'
    New-Classification 1002 'inactive'
)
Update-DeclaredAggregates $multi
Write-Fixture 'valid' 'epoch.multiple_behaviors.fixture.json' $multi

$negative = New-BaseDocument 'fixture.negative.retained'
$negativeOperation = Copy-Document $batchFallback
$negativeOperation.result = 'negative'
$negativeOperation.fallback_or_safety_reason = 'retained_negative'
Set-SingleScenario $negative (Copy-Document $batchFallbackDecision) $negativeOperation 'negative'
Write-Fixture 'valid' 'negative.retained_classification.fixture.json' $negative

$warningFiles = [ordered]@{
    'multiple_behaviors_same_epoch.warning.fixture.json' = $multi
    'inactive_operation_retained.warning.fixture.json' = (Read-AdaptiveRuntimeJsonDocument (Join-Path $fixtureRoot 'valid\batch.inactive.fixture.json'))
    'retained_inactive_content_stable_copy.warning.fixture.json' = (Read-AdaptiveRuntimeJsonDocument (Join-Path $fixtureRoot 'valid\batch.inactive.fixture.json'))
    'fallback_operation_retained.warning.fixture.json' = (Read-AdaptiveRuntimeJsonDocument (Join-Path $fixtureRoot 'valid\batch.fallback.fixture.json'))
    'verification_only_equivalent_cell_retained.warning.fixture.json' = $negative
}
foreach ($entry in $warningFiles.GetEnumerator()) {
    Write-Fixture 'warning' $entry.Key (Copy-Document $entry.Value)
}

$invalidBuilders = [ordered]@{
    'missing_decision_correlation.fixture.json' = {
        param($d) $d.operations[0].decision_instance_id = 999
    }
    'duplicate_decision_instance.fixture.json' = {
        param($d) $d.decisions = @($d.decisions[0], (Copy-Document $d.decisions[0]))
    }
    'candidate_value_mismatch.fixture.json' = {
        param($d) $d.operations[0].candidate_value = 'legacy_current'
    }
    'wrong_axis_attribution.fixture.json' = {
        param($d) $d.operations[0].axis_id = 'buffer_copy_coalescing'
    }
    'wrong_epoch_attribution.fixture.json' = {
        param($d) $d.operations[0].epoch_sequence = 2
    }
    'broad_endpoint_event_relabel.fixture.json' = {
        param($d)
        $d.operations[0].source_event_kind = 'broad_endpoint'
        $d.operations[0].mechanism_event = 'broad_endpoint'
    }
    'mutually_exclusive_behavior_collision.fixture.json' = {
        param($d)
        $copy = Copy-Document $d.operations[0]
        $copy.effective_behavior_id = 'behavior.application_send_batch_formation.legacy_current.prefix'
        $d.operations = @($d.operations[0], $copy)
    }
    'duplicate_operation_correlation.fixture.json' = {
        param($d)
        $d.operations = @($d.operations[0], (Copy-Document $d.operations[0]))
    }
    'unsupported_behavior_id.fixture.json' = {
        param($d) $d.operations[0].effective_behavior_id = 'behavior.unsupported'
    }
    'stale_behavior_catalog_version.fixture.json' = {
        param($d) $d.behavior_catalog_ref.content_sha256 = '2' * 64
    }
    'aggregate_operation_count_mismatch.fixture.json' = {
        param($d) $d.declared_aggregates[0].operation_count = 2
    }
    'aggregate_byte_mismatch.fixture.json' = {
        param($d) $d.declared_aggregates[0].byte_count = 999
    }
    'missing_checksum.fixture.json' = {
        param($d) $d.artifact_inventory = @()
    }
    'invalid_result_to_epoch_join.fixture.json' = {
        param($d) $d.result_epoch_sequence = 2
    }
    'duplicate_epoch_identity.fixture.json' = {
        param($d) $d.connection_epochs = @($d.connection_epochs[0], (Copy-Document $d.connection_epochs[0]))
    }
    'top_epoch_missing.fixture.json' = {
        param($d) $d.connection_epochs[0].epoch_sequence = 2
    }
    'classification_id_duplicate.fixture.json' = {
        param($d)
        $copy = Copy-Document $d.classifications[0]
        $copy.kind = 'diagnostic'
        $d.classifications = @($d.classifications[0], $copy)
    }
    'shadow_recommendation_changing_applied_behavior.fixture.json' = {
        param($d)
        $d.decisions[0].forced_value = $null
        $d.decisions[0].shadow_recommendation = 'single_eligible'
        $d.decisions[0].candidate_value = 'single_eligible'
        $d.decisions[0].applied_value = 'single_eligible'
    }
    'forced_candidate_bypassing_operation_eligibility.fixture.json' = {
        param($d)
        $d.operations[0].operation_eligibility_result = 'ineligible'
        $d.operations[0].operation_eligibility_reason = 'resource_guard'
        $d.operations[0].applied_value = 'single_eligible'
    }
    'missing_terminal_release_evidence.fixture.json' = {
        param($d)
        Set-SingleScenario $d (Copy-Document $bufferDistinctDecision) (Copy-Document $bufferDistinct) 'analytically_eligible'
        $d.releases = @()
    }
    'duplicate_owner_release.fixture.json' = {
        param($d)
        Set-SingleScenario $d (Copy-Document $bufferDistinctDecision) (Copy-Document $bufferDistinct) 'analytically_eligible'
        $d.releases[0].release_count = 2
    }
    'missing_retained_classification.fixture.json' = {
        param($d) $d.classifications = @()
    }
    'unclassifiable_mechanism_silently_assigned_behavior.fixture.json' = {
        param($d)
        $d.operations[0].mechanism_event = 'unclassifiable'
        $d.operations[0].operation_eligibility_reason = 'unclassifiable_evidence'
    }
    'unknown_field.fixture.json' = {
        param($d) $d['unknown_field'] = $true
    }
}
$expectations = [ordered]@{
    valid = @{}
    warning = [ordered]@{
        'multiple_behaviors_same_epoch.warning.fixture.json' = @('multiple_effective_behaviors_in_epoch')
        'inactive_operation_retained.warning.fixture.json' = @('inactive_operation_retained')
        'retained_inactive_content_stable_copy.warning.fixture.json' = @('inactive_operation_retained')
        'fallback_operation_retained.warning.fixture.json' = @('fallback_operation_retained')
        'verification_only_equivalent_cell_retained.warning.fixture.json' = @('verification_only_equivalent_cell_retained')
    }
    invalid = [ordered]@{
        'missing_decision_correlation.fixture.json' = 'missing_decision_correlation'
        'duplicate_decision_instance.fixture.json' = 'duplicate_decision_instance'
        'candidate_value_mismatch.fixture.json' = 'candidate_value_mismatch'
        'wrong_axis_attribution.fixture.json' = 'wrong_axis_attribution'
        'wrong_epoch_attribution.fixture.json' = 'wrong_epoch_attribution'
        'broad_endpoint_event_relabel.fixture.json' = 'broad_endpoint_not_axis_mechanism'
        'mutually_exclusive_behavior_collision.fixture.json' = 'mutually_exclusive_behavior_collision'
        'duplicate_operation_correlation.fixture.json' = 'duplicate_operation_correlation'
        'unsupported_behavior_id.fixture.json' = 'unsupported_behavior_id'
        'stale_behavior_catalog_version.fixture.json' = 'stale_behavior_catalog_version'
        'aggregate_operation_count_mismatch.fixture.json' = 'aggregate_operation_count_mismatch'
        'aggregate_byte_mismatch.fixture.json' = 'aggregate_byte_mismatch'
        'missing_checksum.fixture.json' = 'missing_checksum'
        'invalid_result_to_epoch_join.fixture.json' = 'invalid_result_to_epoch_join'
        'duplicate_epoch_identity.fixture.json' = 'duplicate_epoch_identity'
        'top_epoch_missing.fixture.json' = 'top_epoch_missing'
        'classification_id_duplicate.fixture.json' = 'classification_id_duplicate'
        'shadow_recommendation_changing_applied_behavior.fixture.json' = 'shadow_recommendation_changed_applied_behavior'
        'forced_candidate_bypassing_operation_eligibility.fixture.json' = 'forced_candidate_bypassed_operation_eligibility'
        'missing_terminal_release_evidence.fixture.json' = 'missing_terminal_release_evidence'
        'duplicate_owner_release.fixture.json' = 'duplicate_owner_release'
        'missing_retained_classification.fixture.json' = 'missing_retained_classification'
        'unclassifiable_mechanism_silently_assigned_behavior.fixture.json' = 'unclassifiable_mechanism_assigned_behavior'
        'unknown_field.fixture.json' = 'unknown_field'
    }
}
foreach ($entry in $invalidBuilders.GetEnumerator()) {
    $doc = New-BaseDocument "fixture.invalid.$($entry.Key)"
    & $entry.Value $doc
    Write-Fixture 'invalid' $entry.Key $doc
}

$expectationPath = Join-Path $fixtureRoot 'expectations.json'
$expectationText = $expectations | ConvertTo-Json -Depth 20
[System.IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
[System.IO.File]::WriteAllText(
    $expectationPath,
    $expectationText,
    [System.Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    valid = @(Get-ChildItem (Join-Path $fixtureRoot 'valid') -File).Count
    warning = @(Get-ChildItem (Join-Path $fixtureRoot 'warning') -File).Count
    invalid = @(Get-ChildItem (Join-Path $fixtureRoot 'invalid') -File).Count
    fixture_root = $fixtureRoot
} | ConvertTo-Json
