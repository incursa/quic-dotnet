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

$controlRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control'
$schemaRoot = Join-Path $RepositoryRoot 'schemas'

function New-DocumentRef([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function New-Trace {
    [pscustomobject][ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0247',
            'REQ-QUIC-CRT-0248',
            'REQ-QUIC-CRT-0249',
            'REQ-QUIC-CRT-0250',
            'REQ-QUIC-CRT-0251',
            'REQ-QUIC-CRT-0252'
        )
        architecture_ids = @('ARC-QUIC-CRT-0119')
        work_item_ids = @('WI-QUIC-CRT-0120')
        verification_ids = @('VER-QUIC-CRT-0121')
    }
}

function Write-Utf8NoBom([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText(
        $Path,
        $Text.TrimEnd() + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

function Read-Control([string] $Name) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $controlRoot $Name)
}

function Assert-Current([object] $Document, [string] $Code) {
    if (-not (Test-AdaptiveRuntimeDocumentHash $Document)) {
        throw $Code
    }
}

$family = Read-Control `
    'adaptive-runtime-experiment-family-catalog-v5.json'
$relationship = Read-Control `
    'adaptive-runtime-policy-relationship-graph-v3.json'
$constraint = Read-Control `
    'adaptive-runtime-combination-constraint-catalog-v2.json'
$retainedCellSpace = Read-Control `
    'adaptive-runtime-factor-cell-space-v2.json'
$correctnessPlan = Read-Control `
    'adaptive-runtime-send-admission-correctness-plan-v1.json'
$batchReview = Read-Control `
    'reviewed-proofs\batch-single-eligible.review.json'
$bufferReview = Read-Control `
    'reviewed-proofs\buffer-memory-conservative.review.json'
$oversizedReview = Read-Control `
    'reviewed-proofs\oversized-single-fragment.review.json'

foreach ($entry in ([ordered]@{
    family = $family
    relationship = $relationship
    constraint = $constraint
    retained_cell_space = $retainedCellSpace
    correctness_plan = $correctnessPlan
    batch_review = $batchReview
    buffer_review = $bufferReview
    oversized_review = $oversizedReview
}).GetEnumerator()) {
    Assert-Current $entry.Value "admission_performance_source_hash_invalid:$($entry.Key)"
}

$schemaV2Path = Join-Path $schemaRoot `
    'adaptive-runtime-factor-cell-space-v2.schema.json'
$schemaV3Path = Join-Path $schemaRoot `
    'adaptive-runtime-factor-cell-space-v3.schema.json'
$schemaText = Get-Content -LiteralPath $schemaV2Path -Raw
$schemaText = $schemaText.Replace("`r`n", "`n")
$schemaText = $schemaText.Replace(
    'adaptive-runtime-factor-cell-space-v2',
    'adaptive-runtime-factor-cell-space-v3')
$schemaText = $schemaText.Replace(
    '"document_version": { "const": 2 }',
    '"document_version": { "const": 3 }')
$classificationV2 = @'
        "classification": {
          "enum": [
            "correctness_single_axis_candidate",
            "capability_pending",
            "cell_structurally_inactive",
            "rejected"
          ]
        },
'@
$classificationV3 = @'
        "classification": {
          "enum": [
            "correctness_single_axis_candidate",
            "capability_pending",
            "reviewed_exact_exhaustive",
            "review_blocked",
            "cell_structurally_inactive",
            "rejected"
          ]
        },
'@
$schemaText = $schemaText.Replace($classificationV2, $classificationV3)
if (-not $schemaText.Contains('"reviewed_exact_exhaustive"')) {
    throw 'admission_performance_factor_schema_variant_failed'
}
Write-Utf8NoBom $schemaV3Path $schemaText

$trace = New-Trace
$catalogRefs = @($retainedCellSpace.catalog_refs | ForEach-Object {
    if ([string]$_.document_id -ceq
        'adaptive_runtime_experiment_family_catalog_v3') {
        New-DocumentRef $family
    }
    else {
        $_
    }
})

$reviewedCells = [Collections.Generic.List[object]]::new()
foreach ($cell in @($correctnessPlan.planned_cells)) {
    $annotations = [Collections.Generic.List[string]]::new()
    $suffix = ([string]$cell.cell_id).Split('.')[-1]
    if ($suffix -ceq 'a0') {
        [void]$annotations.Add('verification_only')
    }
    $operationLocal =
        [string]$cell.oversized_write_admission_quantum -ceq
            'single_fragment' -and
        (
            [string]$cell.application_send_batch_formation -cne
                'legacy_current' -or
            [string]$cell.buffer_copy_coalescing -cne 'legacy_current'
        )
    if ($operationLocal) {
        [void]$annotations.Add('operation_local_noncoactivation')
    }
    $reasonCodes = [Collections.Generic.List[string]]::new()
    if ($operationLocal) {
        [void]$reasonCodes.Add('operation_local_noncoactivation')
    }
    [void]$reviewedCells.Add([pscustomobject][ordered]@{
        cell_id = [string]$cell.cell_id
        cell_order = [int]$suffix.Substring(1)
        axis_values = @(
            [pscustomobject][ordered]@{
                axis_id = 'application_send_batch_formation'
                policy_value =
                    [string]$cell.application_send_batch_formation
            },
            [pscustomobject][ordered]@{
                axis_id = 'buffer_copy_coalescing'
                policy_value = [string]$cell.buffer_copy_coalescing
            },
            [pscustomobject][ordered]@{
                axis_id = 'oversized_write_admission_quantum'
                policy_value =
                    [string]$cell.oversized_write_admission_quantum
            }
        )
        classification = 'reviewed_exact_exhaustive'
        annotations = @($annotations | Sort-Object)
        reason_codes = $reasonCodes.ToArray()
        measurement_authorized = $false
        active_behavior_authorization = $false
    })
}

$retainedAdmission = @($retainedCellSpace.family_spaces |
    Where-Object family_id -ceq 'send_admission_composition')
$boundedCells = @($retainedAdmission[0].planned_cells | Where-Object {
    @($_.axis_values | Where-Object {
        $_.axis_id -ceq 'oversized_write_admission_quantum' -and
        $_.policy_value -ceq 'bounded_multi_fragment'
    }).Count -eq 1
} | Sort-Object cell_order)
$blockedCells = [Collections.Generic.List[object]]::new()
foreach ($cell in $boundedCells) {
    $operationLocal =
        @($cell.annotations) -contains 'operation_local_noncoactivation'
    $annotations = @('measurement_blocked')
    if ($operationLocal) {
        $annotations += 'operation_local_noncoactivation'
    }
    $reasonCodes = [Collections.Generic.List[string]]::new()
    [void]$reasonCodes.Add('shadow_recommendation_value_mismatch')
    if ($operationLocal) {
        [void]$reasonCodes.Add('operation_local_noncoactivation')
    }
    [void]$blockedCells.Add([pscustomobject][ordered]@{
        cell_id = [string]$cell.cell_id
        cell_order = [int]$cell.cell_order
        axis_values = @($cell.axis_values)
        classification = 'review_blocked'
        annotations = @($annotations | Sort-Object)
        reason_codes = @($reasonCodes | Sort-Object)
        measurement_authorized = $false
        active_behavior_authorization = $false
    })
}

$queuedSpace = @($retainedCellSpace.family_spaces |
    Where-Object family_id -ceq 'queued_send_burst_correctness')[0]
$cellSpace = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-factor-cell-space-v3'
    document_id = 'adaptive_runtime_factor_cell_space_v3'
    document_version = 3
    content_sha256 = '0' * 64
    catalog_refs = $catalogRefs
    generation_mode = 'exhaustive_explicit'
    covering_array_generator_implemented = $false
    covering_array_trigger_effective_cell_count = 65
    family_spaces = @(
        [pscustomobject][ordered]@{
            family_id = 'send_admission_composition'
            raw_configured_cell_count = 12
            after_illegal_removal_count = 12
            after_capability_filter_count = 8
            expected_equivalence_group_count = 0
            distinct_effective_cell_count_including_baseline = 8
            nonlegacy_behavior_distinct_treatment_value_count = 3
            partition_counts = [pscustomobject][ordered]@{
                correctness_executable = 8
                capability_pending = 0
                cell_structurally_inactive = 0
                rejected = 4
            }
            annotation_counts = [pscustomobject][ordered]@{
                measurement_blocked = 4
                verification_only = 1
                operation_local_noncoactivation = 6
                safety_clamped = 0
            }
            annotation_counts_overlap_partitions = $true
            planned_cells = @($reviewedCells) + @($blockedCells)
        },
        $queuedSpace
    )
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $cellSpace)
Write-AdaptiveRuntimeCanonicalDocument $cellSpace (Join-Path $controlRoot `
    'adaptive-runtime-factor-cell-space-v3.json')

$campaign = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-performance-campaign-v1'
    document_id =
        'adaptive_runtime_send_admission_performance_campaign_v1'
    document_version = 1
    content_sha256 = '0' * 64
    authorization_id = 'send_admission_composition_performance_v1'
    campaign_id = 'campaign.send_admission_composition.performance.v1'
    family_id = 'send_admission_composition'
    execution_purpose = 'offline_performance'
    generation_mode = 'exhaustive_explicit'
    covering_array_generator_implemented = $false
    covering_array_trigger_effective_cell_count = 65
    source_document_refs = @(
        $family,
        $cellSpace,
        $correctnessPlan,
        $relationship,
        $constraint,
        $batchReview,
        $bufferReview,
        $oversizedReview
    ) | ForEach-Object { New-DocumentRef $_ }
    planned_cells = @($correctnessPlan.planned_cells)
    dry_run_workloads = @(
        [pscustomobject][ordered]@{
            workload_id = 'exact_admission_opportunity_dry_run'
            purpose = 'authorization_dry_run'
            timing_eligible = $false
            opportunity_sets = @(
                'oversized_write',
                'batch_formation',
                'buffer_coalescing'
            )
        }
    )
    design = [pscustomobject][ordered]@{
        seed = 20260728
        serial_execution = $true
        dry_run_repetitions = 1
        proposed_pilot_cells = @('a0', 'a3', 'a4', 'a7')
        full_pilot_cells = @('a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7')
        timing_execution_scope = 'decision_required'
    }
    environment = [pscustomobject][ordered]@{
        host_selection_state = 'decision_required'
        workload_selection_state = 'decision_required'
        clean_source_required_for_timing = $true
        binary_hash_required_for_timing = $true
        host_fingerprint_required_for_timing = $true
        evidence_destination_required_for_timing = $true
    }
    metrics = [pscustomobject][ordered]@{
        primary = @(
            'useful_bytes_per_second',
            'operations_per_second'
        )
        guardrails = @(
            'latency_p95_milliseconds',
            'cpu_microseconds_per_operation',
            'allocated_bytes_per_operation',
            'jain_fairness'
        )
        mechanisms = @(
            'oversized_admission_activation_rate',
            'fragments_per_logical_write',
            'batch_activation_rate',
            'buffer_activation_rate',
            'logical_write_completion_count',
            'owner_release_count',
            'fallback_count',
            'inactive_count'
        )
    }
    correctness_gates = @(
        'payload_exact',
        'logical_write_completion_exact',
        'terminal_release_exact',
        'manifest_identity_exact',
        'runtime_cell_exact',
        'mechanism_accounting_exact',
        'active_behavior_unauthorized',
        'production_activation_unauthorized'
    )
    measurement_capability_authorized = $true
    timing_execution_authorized = $false
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    production_activation_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $campaign)
Write-AdaptiveRuntimeCanonicalDocument $campaign (Join-Path $controlRoot `
    'adaptive-runtime-send-admission-performance-campaign-v1.json')

[pscustomobject][ordered]@{
    factor_cell_space_path = Join-Path $controlRoot `
        'adaptive-runtime-factor-cell-space-v3.json'
    factor_cell_space_sha256 = $cellSpace.content_sha256
    campaign_path = Join-Path $controlRoot `
        'adaptive-runtime-send-admission-performance-campaign-v1.json'
    campaign_sha256 = $campaign.content_sha256
    reviewed_cell_count = $reviewedCells.Count
    blocked_cell_count = $blockedCells.Count
    covering_array_generator_implemented = $false
    timing_execution_authorized = $false
} | ConvertTo-Json -Depth 8
