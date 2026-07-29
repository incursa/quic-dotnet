# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $OutputPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-balanced-campaign-v1.json'),
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Fixture([bool] $Condition, [string] $Code) {
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

function Get-AxisValue([object] $Cell, [string] $AxisId) {
    $value = @(
        $Cell.axis_values |
            Where-Object axis_id -CEQ $AxisId
    )
    Assert-Fixture ($value.Count -eq 1) "axis_value_missing:$AxisId"
    [string]$value[0].policy_value
}

$campaign = Read-Repo `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'
$factor = Read-Repo `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-factor-cell-space-v3.json'
$pilotResult = Read-Repo `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-pilot-result-v1.json'

foreach ($document in @($campaign, $factor, $pilotResult)) {
    Assert-Fixture (Test-AdaptiveRuntimeDocumentHash $document) `
        "source_hash_invalid:$($document.document_id)"
}

$familySpace = @(
    $factor.family_spaces |
        Where-Object family_id -CEQ 'send_admission_composition'
)
Assert-Fixture ($familySpace.Count -eq 1) 'admission_family_space_missing'
$reviewedCells = @(
    $familySpace[0].planned_cells |
        Where-Object classification -CEQ 'reviewed_exact_exhaustive' |
        Sort-Object cell_order
)
Assert-Fixture ($reviewedCells.Count -eq 8) `
    'reviewed_cell_count_invalid'

$cellBindings = @(
    foreach ($cell in $reviewedCells) {
        $cellId = ([string]$cell.cell_id).Split('.')[-1]
        $binding = [pscustomobject][ordered]@{
            cell_id = $cellId
            content_sha256 = '0' * 64
            oversized_write_admission_quantum =
                Get-AxisValue $cell 'oversized_write_admission_quantum'
            application_send_batch_formation =
                Get-AxisValue $cell 'application_send_batch_formation'
            buffer_copy_coalescing =
                Get-AxisValue $cell 'buffer_copy_coalescing'
        }
        [void](Set-AdaptiveRuntimeDocumentHash $binding)
        $binding
    }
)
Assert-Fixture (
    [string]::Join('|', @($cellBindings.cell_id)) -ceq
        'a0|a1|a2|a3|a4|a5|a6|a7'
) 'reviewed_cell_identity_invalid'

# This is the even-order Williams balanced Latin-square sequence. Across eight
# blocks every cell occupies every position once and every ordered
# first-order predecessor/successor pair occurs once.
$baseOrder = @(0, 1, 7, 2, 6, 3, 5, 4)
$executionSequence = @(
    for ($block = 0; $block -lt 8; $block++) {
        foreach ($value in $baseOrder) {
            'a{0}' -f (($value + $block) % 8)
        }
    }
)
Assert-Fixture ($executionSequence.Count -eq 64) `
    'execution_sequence_count_invalid'
for ($position = 0; $position -lt 8; $position++) {
    $positionCells = @(
        for ($block = 0; $block -lt 8; $block++) {
            $executionSequence[($block * 8) + $position]
        }
    )
    Assert-Fixture (
        @($positionCells | Sort-Object -Unique).Count -eq 8
    ) "position_balance_invalid:$position"
}
$orderedPairs = @(
    for ($block = 0; $block -lt 8; $block++) {
        for ($position = 0; $position -lt 7; $position++) {
            '{0}>{1}' -f
                $executionSequence[($block * 8) + $position],
                $executionSequence[($block * 8) + $position + 1]
        }
    }
)
Assert-Fixture (
    $orderedPairs.Count -eq 56 -and
    @($orderedPairs | Sort-Object -Unique).Count -eq 56
) 'first_order_carryover_balance_invalid'

$control = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-performance-balanced-campaign-v1'
    document_id =
        'adaptive_runtime_send_admission_performance_balanced_campaign_v1'
    document_version = 1
    content_sha256 = '0' * 64
    campaign_ref = New-DocumentReference $campaign
    factor_space_ref = New-DocumentReference $factor
    pilot_result_ref = New-DocumentReference $pilotResult
    controller_uri = 'http://10.10.99.176:5088'
    host_selection = [pscustomobject][ordered]@{
        placement_policy = 'isolated-pair'
        worker_selection_owner = 'controller-owned'
        required_capabilities = @(
            'evidenceTier=offline-ml-two-host-vm'
        )
    }
    package_selection = [pscustomobject][ordered]@{
        component_package_references = @(
            [pscustomobject][ordered]@{
                package_id =
                    'org.protocol-lab.components.scenario.raw-quic-transport'
                package_version = '0.1.20'
                sha256 =
                    'b9ab49d83404b7dd4d377fb6ed04dd0594869f69c01c05082a28bbb5cb4a3bd2'
            },
            [pscustomobject][ordered]@{
                package_id =
                    'org.protocol-lab.components.executor.quic-go-raw-load'
                package_version = '0.1.17'
                sha256 =
                    'e5a8c03cebd67a9722d47d080728fbb2c52d4dcdd34474880e179972d0df5167'
            }
        )
        package_target = 'RawQuic'
        implementation_id = 'quic-dotnet-raw-dev'
        suite_id = 'quic-transport-v1-comparison'
        scenario_id = 'quic.transport.multiplex.100x64kb'
        protocol = 'quic'
        test_executor_id = 'quic-go-raw-load'
        load_profile_id = 'raw-quic-peer-confidence'
        package_backed_execution = $true
    }
    design = [pscustomobject][ordered]@{
        kind = 'williams_balanced_latin_square'
        deterministic = $true
        cell_count = 8
        block_count = 8
        repetitions_per_cell = 8
        repetitions_per_job = 1
        total_job_count = 64
        position_balanced = $true
        first_order_carryover_balanced = $true
    }
    selected_cells = @($cellBindings.cell_id)
    execution_sequence = $executionSequence
    cell_bindings = $cellBindings
    resource_metrics = [pscustomobject][ordered]@{
        target_runtime_counters_requested = $false
        load_process_metrics_required = $true
        bounded_server_stdout_max_bytes = 65536
    }
    excluded_values = [pscustomobject][ordered]@{
        oversized_write_admission_quantum = @(
            'bounded_multi_fragment'
        )
    }
    covering_array_generator_implemented = $false
    covering_array_required = $false
    covering_array_trigger_effective_cell_count = 65
    measurement_capability_authorized = $true
    timing_execution_authorized = $true
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = [pscustomobject][ordered]@{
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
[void](Set-AdaptiveRuntimeDocumentHash $control)
$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-performance-balanced-campaign-v1.schema.json'
Assert-Fixture (
    Test-AdaptiveRuntimeJsonSchema $control $schemaPath
) 'balanced_campaign_schema_invalid'
Assert-Fixture (Test-AdaptiveRuntimeDocumentHash $control) `
    'balanced_campaign_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $control $OutputPath

if ($PassThru) {
    $control
}
else {
    [pscustomobject][ordered]@{
        output_path = [IO.Path]::GetFullPath($OutputPath)
        content_sha256 = [string]$control.content_sha256
        cell_count = @($control.selected_cells).Count
        block_count = [int]$control.design.block_count
        total_job_count = [int]$control.design.total_job_count
        actual_measurements_run = 0
    } | ConvertTo-Json -Depth 8
}
