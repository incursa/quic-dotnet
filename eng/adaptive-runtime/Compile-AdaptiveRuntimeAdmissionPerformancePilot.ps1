# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $PilotPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json'),
    [Parameter(Mandatory = $true)][string] $OutputPath,
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

function Read-Control([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function New-DocumentRef([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Get-RefKey([object] $Reference) {
    "$($Reference.document_id)|$($Reference.schema_version)|$($Reference.document_version)|$($Reference.content_sha256)"
}

function Join-Values([object[]] $Values) {
    [string]::Join('|', @($Values | ForEach-Object { [string]$_ }))
}

function Get-CellBinding([object] $Cell) {
    [pscustomobject][ordered]@{
        cell_id = [string]$Cell.cell_id
        content_sha256 = [string]$Cell.content_sha256
        oversized_write_admission_quantum =
            [string]$Cell.oversized_write_admission_quantum
        application_send_batch_formation =
            [string]$Cell.application_send_batch_formation
        buffer_copy_coalescing = [string]$Cell.buffer_copy_coalescing
    }
}

function Get-ReviewedCellAxisValue([object] $Cell, [string] $AxisId) {
    $axisValue = @($Cell.axis_values | Where-Object axis_id -ceq $AxisId)[0]
    Assert-Compile ($null -ne $axisValue) "admission_pilot_axis_missing:$AxisId"
    [string]$axisValue.policy_value
}

$pilot = Read-AdaptiveRuntimeJsonDocument $PilotPath
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $pilot) `
    'admission_pilot_hash_invalid'
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $pilot (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-pilot-v1.schema.json')
) 'admission_pilot_schema_invalid'

$campaign = Read-Control `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'
$family = Read-Control `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v5.json'
$factor = Read-Control `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-factor-cell-space-v3.json'
$constraint = Read-Control `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-combination-constraint-catalog-v2.json'
$relationship = Read-Control `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-policy-relationship-graph-v3.json'

foreach ($document in @($campaign, $family, $factor, $constraint, $relationship)) {
    Assert-Compile (Test-AdaptiveRuntimeDocumentHash $document) `
        "admission_pilot_source_hash_invalid:$($document.document_id)"
}

$selected = @($pilot.selected_cells)
Assert-Compile (
    (Join-Values ($selected | Sort-Object)) -ceq
    (Join-Values @('a0','a3','a4','a7'))
) 'admission_pilot_selected_cells_invalid'
Assert-Compile (
    (Join-Values @($pilot.execution_sequence)) -ceq
    (Join-Values @('a0','a4','a3','a7'))
) 'admission_pilot_execution_sequence_invalid'
Assert-Compile (
    [string]$pilot.controller_uri -ceq 'http://10.10.99.176:5088' -and
    [string]$pilot.host_selection.placement_policy -ceq 'isolated-pair' -and
    [string]$pilot.host_selection.worker_selection_owner -ceq 'controller-owned' -and
    [string]$pilot.package_selection.package_target -ceq 'RawQuic' -and
    [string]$pilot.package_selection.implementation_id -ceq 'quic-dotnet-raw-dev' -and
    [string]$pilot.package_selection.suite_id -ceq 'quic-transport-v1-comparison' -and
    [string]$pilot.package_selection.scenario_id -ceq 'quic.transport.multiplex.100x64kb' -and
    [string]$pilot.package_selection.protocol -ceq 'quic' -and
    [string]$pilot.package_selection.test_executor_id -ceq 'quic-go-raw-load' -and
    [string]$pilot.package_selection.load_profile_id -ceq 'raw-quic-peer-confidence' -and
    [int]$pilot.package_selection.repetitions_per_cell -eq 2 -and
    $pilot.package_selection.package_backed_execution -eq $true -and
    $pilot.covering_array_generator_implemented -eq $false -and
    [int]$pilot.covering_array_trigger_effective_cell_count -eq 65 -and
    $pilot.measurement_capability_authorized -eq $true -and
    $pilot.timing_execution_authorized -eq $true -and
    $pilot.active_behavior_authorization -eq $false -and
    $pilot.performance_acceptance_authorization -eq $false -and
    $pilot.production_activation_authorization -eq $false
) 'admission_pilot_controls_invalid'

$componentPackageReferenceKeys = @(
    $pilot.package_selection.component_package_references |
        ForEach-Object {
            "{0}|{1}|{2}" -f
                [string]$_.package_id,
                [string]$_.package_version,
                [string]$_.sha256
        }
)
Assert-Compile (
    (Join-Values $componentPackageReferenceKeys) -ceq
    (Join-Values @(
        'org.protocol-lab.components.scenario.raw-quic-transport|0.1.20|b9ab49d83404b7dd4d377fb6ed04dd0594869f69c01c05082a28bbb5cb4a3bd2',
        'org.protocol-lab.components.executor.quic-go-raw-load|0.1.17|e5a8c03cebd67a9722d47d080728fbb2c52d4dcdd34474880e179972d0df5167'
    ))
) 'admission_pilot_component_package_references_invalid'

$admissionSpace = @($factor.family_spaces | Where-Object family_id -ceq 'send_admission_composition')
Assert-Compile ($admissionSpace.Count -eq 1) 'admission_pilot_factor_space_missing'
$reviewed = @($admissionSpace[0].planned_cells |
    Where-Object classification -ceq 'reviewed_exact_exhaustive' |
    Sort-Object cell_order)
$selectedReviewed = @($reviewed | Where-Object {
    ([string]$_.cell_id).Split('.')[-1] -in @($pilot.selected_cells)
} | Sort-Object cell_order)
Assert-Compile ($selectedReviewed.Count -eq 4) `
    'admission_pilot_selected_reviewed_cells_invalid'
Assert-Compile (
    (Join-Values @($selectedReviewed.cell_id | ForEach-Object {
        ([string]$_).Split('.')[-1]
    })) -ceq (Join-Values @('a0','a3','a4','a7'))
) 'admission_pilot_selected_reviewed_identity_invalid'
$reviewedById = @{}
foreach ($cell in $reviewed) {
    $reviewedById[[string]$cell.cell_id] = $cell
}

$expectedCells = @(
    [pscustomobject][ordered]@{
        cell_id = 'a0'
        oversized_write_admission_quantum = 'legacy_current'
        application_send_batch_formation = 'legacy_current'
        buffer_copy_coalescing = 'legacy_current'
    },
    [pscustomobject][ordered]@{
        cell_id = 'a3'
        oversized_write_admission_quantum = 'legacy_current'
        application_send_batch_formation = 'single_eligible'
        buffer_copy_coalescing = 'memory_conservative'
    },
    [pscustomobject][ordered]@{
        cell_id = 'a4'
        oversized_write_admission_quantum = 'single_fragment'
        application_send_batch_formation = 'legacy_current'
        buffer_copy_coalescing = 'legacy_current'
    },
    [pscustomobject][ordered]@{
        cell_id = 'a7'
        oversized_write_admission_quantum = 'single_fragment'
        application_send_batch_formation = 'single_eligible'
        buffer_copy_coalescing = 'memory_conservative'
    }
)

foreach ($expected in $expectedCells) {
    $cellId = "cell.send_admission_composition.correctness.$($expected.cell_id)"
    Assert-Compile ($reviewedById.ContainsKey($cellId)) `
        "admission_pilot_cell_missing:$($expected.cell_id)"
    $actual = $reviewedById[$cellId]
    Assert-Compile (
        (Get-ReviewedCellAxisValue $actual 'oversized_write_admission_quantum') -ceq
            $expected.oversized_write_admission_quantum -and
        (Get-ReviewedCellAxisValue $actual 'application_send_batch_formation') -ceq
            $expected.application_send_batch_formation -and
        (Get-ReviewedCellAxisValue $actual 'buffer_copy_coalescing') -ceq
            $expected.buffer_copy_coalescing
    ) "admission_pilot_cell_control_invalid:$($expected.cell_id)"
}

$declaredCellBindings = @($pilot.cell_bindings | ForEach-Object { Get-CellBinding $_ })
$declaredCellBindingById = @{}
foreach ($binding in $declaredCellBindings) {
    $declaredCellBindingById[[string]$binding.cell_id] = $binding
}
$expectedCellBindings = @($expectedCells | ForEach-Object {
    $cellId = "cell.send_admission_composition.correctness.$($_.cell_id)"
    $declaredBinding = $declaredCellBindingById[$_.cell_id]
    [pscustomobject][ordered]@{
        cell_id = $_.cell_id
        content_sha256 = [string]$declaredBinding.content_sha256
        oversized_write_admission_quantum = $_.oversized_write_admission_quantum
        application_send_batch_formation = $_.application_send_batch_formation
        buffer_copy_coalescing = $_.buffer_copy_coalescing
    }
})
Assert-Compile (
    (ConvertTo-Json $declaredCellBindings -Compress) -ceq
    (ConvertTo-Json $expectedCellBindings -Compress)
) 'admission_pilot_cell_binding_invalid'

$selectedRefKeys = @($pilot.campaign_ref | ForEach-Object { Get-RefKey $_ })
Assert-Compile (
    (ConvertTo-Json $selectedRefKeys -Compress) -ceq
    (ConvertTo-Json @(
        'adaptive_runtime_send_admission_performance_campaign_v1|adaptive-runtime-send-admission-performance-campaign-v1|1|51fb749232512381152acf0a7bbae4c2f137f017796a27e295983774e025c327'
    ) -Compress)
) 'admission_pilot_campaign_binding_invalid'
Assert-Compile (
    @($pilot.excluded_values.oversized_write_admission_quantum) -contains
        'bounded_multi_fragment'
) 'admission_pilot_bounded_exclusion_invalid'

$manifest = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-send-admission-performance-pilot-manifest-v1'
    document_id = 'manifest.send_admission_composition.performance.pilot.v1'
    document_version = 1
    content_sha256 = '0' * 64
    pilot_ref = New-DocumentRef $pilot
    campaign_ref = New-DocumentRef $campaign
    controller_uri = [string]$pilot.controller_uri
    host_selection = $pilot.host_selection
    package_selection = $pilot.package_selection
    selected_cells = @($pilot.selected_cells)
    execution_sequence = @($pilot.execution_sequence)
    cell_bindings = @($declaredCellBindings)
    excluded_values = $pilot.excluded_values
    planned_runs = @(
        for ($i = 0; $i -lt $pilot.execution_sequence.Count; $i++) {
            $cellId = [string]$pilot.execution_sequence[$i]
            $binding = @($declaredCellBindings | Where-Object cell_id -eq $cellId)[0]
            [pscustomobject][ordered]@{
                cell_id = $cellId
                execution_order_index = $i + 1
                repetitions = 2
                state = 'planned'
                job_id = $null
                package_ref = $null
                run_id = $null
                topology = $null
                outcome = $null
                controller_artifact_index_path = $null
                controller_artifact_downloads = @()
                policy_controls = [pscustomobject][ordered]@{
                    oversized_write_admission_quantum = [string]$binding.oversized_write_admission_quantum
                    application_send_batch_formation = [string]$binding.application_send_batch_formation
                    buffer_copy_coalescing = [string]$binding.buffer_copy_coalescing
                }
            }
        }
    )
    measurement_capability_authorized = $true
    timing_execution_authorized = $true
    no_measurements = $true
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    production_activation_authorization = $false
    trace_references = $pilot.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $manifest (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-pilot-manifest-v1.schema.json')
) 'admission_pilot_manifest_schema_invalid'
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $manifest) `
    'admission_pilot_manifest_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $manifest $OutputPath

if ($PassThru) {
    $manifest
}
else {
    [pscustomobject][ordered]@{
        output_path = [IO.Path]::GetFullPath($OutputPath)
        manifest_sha256 = [string]$manifest.content_sha256
        selected_cell_count = @($manifest.selected_cells).Count
        execution_sequence = @($manifest.execution_sequence)
        repetitions_per_cell = 2
        timing_execution_authorized = $true
        actual_measurements_run = 0
    } | ConvertTo-Json -Depth 8
}
