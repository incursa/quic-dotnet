# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ControlPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-balanced-campaign-v1.json'),
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Compile([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Read-Repo([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function New-DocumentReference([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Get-ReferenceKey([object] $Reference) {
    '{0}|{1}|{2}|{3}' -f
        [string]$Reference.document_id,
        [string]$Reference.schema_version,
        [int]$Reference.document_version,
        [string]$Reference.content_sha256
}

function Get-AxisValue([object] $Cell, [string] $AxisId) {
    $value = @(
        $Cell.axis_values |
            Where-Object axis_id -CEQ $AxisId
    )
    Assert-Compile ($value.Count -eq 1) "axis_value_missing:$AxisId"
    [string]$value[0].policy_value
}

function Assert-BalancedSequence([string[]] $Sequence) {
    Assert-Compile ($Sequence.Count -eq 64) `
        'execution_sequence_count_invalid'
    for ($position = 0; $position -lt 8; $position++) {
        $positionCells = @(
            for ($block = 0; $block -lt 8; $block++) {
                $Sequence[($block * 8) + $position]
            }
        )
        Assert-Compile (
            @($positionCells | Sort-Object -Unique).Count -eq 8
        ) "execution_position_balance_invalid:$position"
    }
    $orderedPairs = @(
        for ($block = 0; $block -lt 8; $block++) {
            for ($position = 0; $position -lt 7; $position++) {
                '{0}>{1}' -f
                    $Sequence[($block * 8) + $position],
                    $Sequence[($block * 8) + $position + 1]
            }
        }
    )
    Assert-Compile (
        $orderedPairs.Count -eq 56 -and
        @($orderedPairs | Sort-Object -Unique).Count -eq 56
    ) 'execution_first_order_carryover_balance_invalid'
}

$control = Read-AdaptiveRuntimeJsonDocument $ControlPath
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $control) `
    'balanced_campaign_hash_invalid'
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $control (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-balanced-campaign-v1.schema.json')
) 'balanced_campaign_schema_invalid'

$campaign = Read-Repo `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'
$factor = Read-Repo `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-factor-cell-space-v3.json'
$pilotResult = Read-Repo `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-pilot-result-v1.json'
foreach ($document in @($campaign, $factor, $pilotResult)) {
    Assert-Compile (Test-AdaptiveRuntimeDocumentHash $document) `
        "source_hash_invalid:$($document.document_id)"
}
Assert-Compile (
    (Get-ReferenceKey $control.campaign_ref) -ceq
        (Get-ReferenceKey (New-DocumentReference $campaign)) -and
    (Get-ReferenceKey $control.factor_space_ref) -ceq
        (Get-ReferenceKey (New-DocumentReference $factor)) -and
    (Get-ReferenceKey $control.pilot_result_ref) -ceq
        (Get-ReferenceKey (New-DocumentReference $pilotResult))
) 'balanced_campaign_source_binding_invalid'

Assert-Compile (
    [string]::Join('|', @($control.selected_cells)) -ceq
        'a0|a1|a2|a3|a4|a5|a6|a7'
) 'balanced_campaign_selected_cells_invalid'
Assert-BalancedSequence @($control.execution_sequence)

$familySpace = @(
    $factor.family_spaces |
        Where-Object family_id -CEQ 'send_admission_composition'
)
Assert-Compile ($familySpace.Count -eq 1) 'admission_family_space_missing'
$reviewed = @(
    $familySpace[0].planned_cells |
        Where-Object classification -CEQ 'reviewed_exact_exhaustive' |
        Sort-Object cell_order
)
Assert-Compile ($reviewed.Count -eq 8) 'reviewed_cell_count_invalid'
$bindingById = @{}
foreach ($binding in @($control.cell_bindings)) {
    Assert-Compile (-not $bindingById.ContainsKey([string]$binding.cell_id)) `
        "duplicate_cell_binding:$($binding.cell_id)"
    $bindingById[[string]$binding.cell_id] = $binding
}
foreach ($cell in $reviewed) {
    $cellId = ([string]$cell.cell_id).Split('.')[-1]
    Assert-Compile ($bindingById.ContainsKey($cellId)) `
        "cell_binding_missing:$cellId"
    $binding = $bindingById[$cellId]
    Assert-Compile (
        [string]$binding.oversized_write_admission_quantum -ceq
            (Get-AxisValue $cell 'oversized_write_admission_quantum') -and
        [string]$binding.application_send_batch_formation -ceq
            (Get-AxisValue $cell 'application_send_batch_formation') -and
        [string]$binding.buffer_copy_coalescing -ceq
            (Get-AxisValue $cell 'buffer_copy_coalescing') -and
        (Test-AdaptiveRuntimeDocumentHash $binding)
    ) "cell_binding_invalid:$cellId"
}

Assert-Compile (
    [string]$control.controller_uri -ceq
        'http://10.10.99.176:5088' -and
    [string]$control.host_selection.placement_policy -ceq
        'isolated-pair' -and
    [string]$control.host_selection.worker_selection_owner -ceq
        'controller-owned' -and
    [int]$control.design.block_count -eq 8 -and
    [int]$control.design.repetitions_per_cell -eq 8 -and
    [int]$control.design.repetitions_per_job -eq 1 -and
    [int]$control.design.total_job_count -eq 64 -and
    $control.resource_metrics.target_runtime_counters_requested -eq
        $false -and
    $control.resource_metrics.load_process_metrics_required -eq
        $true -and
    [int]$control.resource_metrics.bounded_server_stdout_max_bytes -eq
        65536 -and
    $control.covering_array_generator_implemented -eq $false -and
    $control.covering_array_required -eq $false -and
    $control.measurement_capability_authorized -eq $true -and
    $control.timing_execution_authorized -eq $true -and
    $control.performance_acceptance_authorization -eq $false -and
    $control.adaptive_rule_derivation_authorization -eq $false -and
    $control.active_behavior_authorization -eq $false -and
    $control.production_activation_authorization -eq $false
) 'balanced_campaign_controls_invalid'
Assert-Compile (
    @($control.excluded_values.oversized_write_admission_quantum) `
        -contains 'bounded_multi_fragment'
) 'bounded_multi_fragment_exclusion_missing'

$plannedRuns = @(
    for ($index = 0; $index -lt 64; $index++) {
        $cellId = [string]$control.execution_sequence[$index]
        $binding = $bindingById[$cellId]
        [pscustomobject][ordered]@{
            execution_index = $index + 1
            block_index = [math]::Floor($index / 8) + 1
            position_index = ($index % 8) + 1
            cell_id = $cellId
            cell_repetition = [math]::Floor($index / 8) + 1
            repetitions = 1
            state = 'planned'
            job_id = $null
            package_ref = $null
            run_id = $null
            topology = $null
            outcome = $null
            controller_artifact_index_path = $null
            controller_artifact_downloads = @()
            policy_controls = [pscustomobject][ordered]@{
                oversized_write_admission_quantum =
                    [string]$binding.oversized_write_admission_quantum
                application_send_batch_formation =
                    [string]$binding.application_send_batch_formation
                buffer_copy_coalescing =
                    [string]$binding.buffer_copy_coalescing
            }
        }
    }
)

$manifest = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-performance-balanced-manifest-v1'
    document_id =
        'manifest.send_admission_composition.performance.balanced.v1'
    document_version = 1
    content_sha256 = '0' * 64
    control_ref = New-DocumentReference $control
    campaign_ref = New-DocumentReference $campaign
    factor_space_ref = New-DocumentReference $factor
    pilot_result_ref = New-DocumentReference $pilotResult
    controller_uri = [string]$control.controller_uri
    host_selection = $control.host_selection
    package_selection = $control.package_selection
    design = $control.design
    selected_cells = @($control.selected_cells)
    execution_sequence = @($control.execution_sequence)
    cell_bindings = @($control.cell_bindings)
    resource_metrics = $control.resource_metrics
    excluded_values = $control.excluded_values
    planned_runs = $plannedRuns
    measurement_capability_authorized = $true
    timing_execution_authorized = $true
    no_measurements = $true
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = $control.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-performance-balanced-manifest-v1.schema.json'
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $manifest $schemaPath
) 'balanced_manifest_schema_invalid'
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $manifest) `
    'balanced_manifest_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $manifest $OutputPath

if ($PassThru) {
    $manifest
}
else {
    [pscustomobject][ordered]@{
        output_path = [IO.Path]::GetFullPath($OutputPath)
        manifest_sha256 = [string]$manifest.content_sha256
        cell_count = @($manifest.selected_cells).Count
        block_count = [int]$manifest.design.block_count
        planned_run_count = @($manifest.planned_runs).Count
        repetitions_per_cell =
            [int]$manifest.design.repetitions_per_cell
        timing_execution_authorized = $true
        actual_measurements_run = 0
    } | ConvertTo-Json -Depth 8
}
