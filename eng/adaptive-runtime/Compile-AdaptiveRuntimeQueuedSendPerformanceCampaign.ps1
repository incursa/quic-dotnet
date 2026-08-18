# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ControlPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-queued-send-performance-campaign-v1.json'),
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

function Normalize-QueuedSendCellId([string] $CellId) {
    switch -Regex ($CellId) {
        '^q0$' { return 'q0' }
        '^q1$' { return 'q1' }
        '^(?:cell\.queued_send_burst_budget\.performance\.)?q0$' { return 'q0' }
        '^(?:cell\.queued_send_burst_budget\.performance\.)?q1$' { return 'q1' }
        '^(?:cell\.queued_send\.)00$' { return 'q0' }
        '^(?:cell\.queued_send\.)01$' { return 'q1' }
        default { throw "queued_cell_id_invalid:$CellId" }
    }
}

function New-DocumentReference([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

$control = Read-AdaptiveRuntimeJsonDocument $ControlPath
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $control) `
    'queued_control_hash_invalid'
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $control (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-queued-send-performance-campaign-v1.schema.json')
) 'queued_control_schema_invalid'

$selectedCellIds = @($control.selected_cells | ForEach-Object {
    Normalize-QueuedSendCellId ([string]$_)
})
Assert-Compile ([string]::Join('|', $selectedCellIds) -ceq 'q0|q1') `
    'queued_control_selected_cells_invalid'

$bindingCellIds = @($control.cell_bindings | ForEach-Object {
    Normalize-QueuedSendCellId ([string]$_.cell_id)
})
Assert-Compile (
    [string]::Join('|', $bindingCellIds) -ceq 'q0|q1' -and
    [string]$control.cell_bindings[0].queued_send_burst_budget -ceq 'legacy_current' -and
    [string]$control.cell_bindings[1].queued_send_burst_budget -ceq 'single_datagram'
) 'queued_control_cell_bindings_invalid'

Assert-Compile (
    [int]$control.design.block_count -eq 8 -and
    [int]$control.design.positions_per_block -eq 2 -and
    [int]$control.design.repetitions_per_cell -eq 8 -and
    [int]$control.design.repetitions_per_job -eq 1 -and
    [int]$control.design.total_job_count -eq 16 -and
    [bool]$control.design.deterministic -eq $true -and
    [string]$control.activation_gate.predicate_id -ceq
        'predicate.queued_send.legal_budget_gt_one' -and
    [string]$control.activation_gate.required_cell_id -ceq
        'cell.queued_send_burst_budget.performance.q1'
) 'queued_control_design_invalid'

$expectedExecutionSequence = [System.Collections.Generic.List[string]]::new()
$plannedRuns = [System.Collections.Generic.List[object]]::new()
for ($block = 1; $block -le 8; $block++) {
    $order = if (($block % 2) -eq 1) { @('q0', 'q1') } else { @('q1', 'q0') }
    for ($position = 1; $position -le 2; $position++) {
        $executionIndex = (($block - 1) * 2) + $position
        $cellId = $order[$position - 1]
        $fullCellId = if ($cellId -ceq 'q0') {
            'cell.queued_send_burst_budget.performance.q0'
        }
        else {
            'cell.queued_send_burst_budget.performance.q1'
        }
        [void]$expectedExecutionSequence.Add($fullCellId)
        $binding = if ($cellId -ceq 'q0') {
            $control.cell_bindings[0]
        }
        else {
            $control.cell_bindings[1]
        }
        [void]$plannedRuns.Add([pscustomobject][ordered]@{
            execution_index = $executionIndex
            block_index = [math]::Floor(($executionIndex - 1) / 2) + 1
            position_index = $position
            cell_id = $fullCellId
            cell_repetition = $block
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
                queued_send_burst_budget =
                    [string]$binding.queued_send_burst_budget
                adjacent_axes = $binding.adjacent_axes
            }
        })
    }
}

Assert-Compile (
    [string]::Join('|', @($control.execution_sequence)) -ceq
        [string]::Join('|', $expectedExecutionSequence)
) 'queued_control_execution_sequence_invalid'

$manifest = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-queued-send-performance-manifest-v1'
    document_id = 'manifest.queued_send_burst_budget.performance.v1'
    document_version = 1
    content_sha256 = '0' * 64
    control_ref = New-DocumentReference $control
    catalog_bindings = $control.catalog_bindings
    planned_runs = @($plannedRuns)
    no_measurements = $true
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = $control.trace_references
    campaign_id = [string]$control.campaign_id
    family_id = [string]$control.family_id
    controller_uri = [string]$control.controller_uri
    host_selection = $control.host_selection
    package_selection = $control.package_selection
    design = $control.design
    selected_cells = @($control.selected_cells)
    execution_sequence = @($control.execution_sequence)
    cell_bindings = @($control.cell_bindings)
    activation_gate = $control.activation_gate
    resource_metrics = $control.resource_metrics
    covering_array_generator_implemented =
        [bool]$control.covering_array_generator_implemented
    covering_array_required = [bool]$control.covering_array_required
    measurement_capability_authorized =
        [bool]$control.measurement_capability_authorized
    timing_execution_authorized = [bool]$control.timing_execution_authorized
}

[void](Set-AdaptiveRuntimeDocumentHash $manifest)
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $manifest (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-queued-send-performance-manifest-v1.schema.json')
) 'queued_manifest_schema_invalid'
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $manifest) `
    'queued_manifest_hash_invalid'

Write-AdaptiveRuntimeCanonicalDocument $manifest $OutputPath

if ($PassThru) {
    $manifest
}
else {
    [pscustomobject][ordered]@{
        output_path = [IO.Path]::GetFullPath($OutputPath)
        manifest_sha256 = [string]$manifest.content_sha256
        planned_run_count = @($manifest.planned_runs).Count
        selected_cell_count = @($manifest.selected_cells).Count
        no_measurements = [bool]$manifest.no_measurements
    } | ConvertTo-Json -Depth 8
}
