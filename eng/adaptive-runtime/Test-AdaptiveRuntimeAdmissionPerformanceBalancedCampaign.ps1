# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\admission-performance-balanced-tests'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$assertionCount = 0
function Assert-Ready([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
    $script:assertionCount++
}

function Copy-Document([object] $Document) {
    $Document | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Assert-CompileRejects(
    [object] $Control,
    [string] $Name,
    [string] $ExpectedCode
) {
    [void](Set-AdaptiveRuntimeDocumentHash $Control)
    $controlPath = Join-Path $TemporaryRoot "$Name.control.json"
    $manifestPath = Join-Path $TemporaryRoot "$Name.manifest.json"
    Write-AdaptiveRuntimeCanonicalDocument $Control $controlPath
    try {
        & (Join-Path $PSScriptRoot `
            'Compile-AdaptiveRuntimeAdmissionPerformanceBalancedCampaign.ps1') `
            -RepositoryRoot $RepositoryRoot `
            -ControlPath $controlPath `
            -OutputPath $manifestPath | Out-Null
        throw "expected_rejection_missing:$Name"
    }
    catch {
        Assert-Ready (
            $_.Exception.Message -like "*$ExpectedCode*"
        ) "unexpected_rejection:${Name}:$($_.Exception.Message)"
    }
}

[void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)
$controlPath = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-balanced-campaign-v1.json'
$controlSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-performance-balanced-campaign-v1.schema.json'
$manifestSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-performance-balanced-manifest-v1.schema.json'
$control = Read-AdaptiveRuntimeJsonDocument $controlPath

Assert-Ready (Test-AdaptiveRuntimeDocumentHash $control) `
    'balanced_control_hash_invalid'
Assert-Ready (
    Test-AdaptiveRuntimeJsonSchema $control $controlSchemaPath
) 'balanced_control_schema_invalid'
Assert-Ready (
    [string]::Join('|', @($control.selected_cells)) -ceq
        'a0|a1|a2|a3|a4|a5|a6|a7' -and
    @($control.cell_bindings).Count -eq 8
) 'balanced_control_cells_invalid'
Assert-Ready (
    [string]$control.design.kind -ceq
        'williams_balanced_latin_square' -and
    [int]$control.design.block_count -eq 8 -and
    [int]$control.design.repetitions_per_cell -eq 8 -and
    [int]$control.design.repetitions_per_job -eq 1 -and
    [int]$control.design.total_job_count -eq 64
) 'balanced_control_design_invalid'
Assert-Ready (
    $control.resource_metrics.target_runtime_counters_requested -eq
        $true -and
    $control.resource_metrics.load_process_metrics_required -eq
        $true -and
    [int]$control.resource_metrics.bounded_server_stdout_max_bytes -eq
        65536
) 'balanced_control_resource_metrics_invalid'
Assert-Ready (
    $control.covering_array_generator_implemented -eq $false -and
    $control.covering_array_required -eq $false -and
    $control.performance_acceptance_authorization -eq $false -and
    $control.adaptive_rule_derivation_authorization -eq $false -and
    $control.active_behavior_authorization -eq $false -and
    $control.production_activation_authorization -eq $false
) 'balanced_control_authorization_invalid'

$sequence = @($control.execution_sequence)
Assert-Ready ($sequence.Count -eq 64) `
    'balanced_execution_sequence_count_invalid'
for ($position = 0; $position -lt 8; $position++) {
    $positionCells = @(
        for ($block = 0; $block -lt 8; $block++) {
            $sequence[($block * 8) + $position]
        }
    )
    Assert-Ready (
        @($positionCells | Sort-Object -Unique).Count -eq 8
    ) "balanced_position_invalid:$position"
}
$orderedPairs = @(
    for ($block = 0; $block -lt 8; $block++) {
        for ($position = 0; $position -lt 7; $position++) {
            '{0}>{1}' -f
                $sequence[($block * 8) + $position],
                $sequence[($block * 8) + $position + 1]
        }
    }
)
Assert-Ready (
    $orderedPairs.Count -eq 56 -and
    @($orderedPairs | Sort-Object -Unique).Count -eq 56
) 'balanced_first_order_carryover_invalid'

$generatedControlOne = Join-Path $TemporaryRoot 'control-one.json'
$generatedControlTwo = Join-Path $TemporaryRoot 'control-two.json'
& (Join-Path $PSScriptRoot `
    'Update-AdaptiveRuntimeAdmissionPerformanceBalancedCampaignFixtures.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -OutputPath $generatedControlOne | Out-Null
& (Join-Path $PSScriptRoot `
    'Update-AdaptiveRuntimeAdmissionPerformanceBalancedCampaignFixtures.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -OutputPath $generatedControlTwo | Out-Null
Assert-Ready (
    [IO.File]::ReadAllText($generatedControlOne) -ceq
        [IO.File]::ReadAllText($generatedControlTwo) -and
    [IO.File]::ReadAllText($generatedControlOne) -ceq
        [IO.File]::ReadAllText($controlPath)
) 'balanced_control_replay_mismatch'

$manifestOnePath = Join-Path $TemporaryRoot 'manifest-one.json'
$manifestTwoPath = Join-Path $TemporaryRoot 'manifest-two.json'
& (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeAdmissionPerformanceBalancedCampaign.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -ControlPath $controlPath `
    -OutputPath $manifestOnePath | Out-Null
& (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeAdmissionPerformanceBalancedCampaign.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -ControlPath $controlPath `
    -OutputPath $manifestTwoPath | Out-Null
$manifest = Read-AdaptiveRuntimeJsonDocument $manifestOnePath
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $manifest) `
    'balanced_manifest_hash_invalid'
Assert-Ready (
    Test-AdaptiveRuntimeJsonSchema $manifest $manifestSchemaPath
) 'balanced_manifest_schema_invalid'
Assert-Ready (
    [IO.File]::ReadAllText($manifestOnePath) -ceq
        [IO.File]::ReadAllText($manifestTwoPath)
) 'balanced_manifest_replay_mismatch'
Assert-Ready (
    @($manifest.planned_runs).Count -eq 64 -and
    @($manifest.planned_runs.cell_id |
        Group-Object |
        Where-Object Count -eq 8).Count -eq 8 -and
    @($manifest.planned_runs.block_index |
        Group-Object |
        Where-Object Count -eq 8).Count -eq 8 -and
    @($manifest.planned_runs.position_index |
        Group-Object |
        Where-Object Count -eq 8).Count -eq 8
) 'balanced_manifest_run_shape_invalid'
Assert-Ready (
    $manifest.no_measurements -eq $true -and
    $manifest.timing_execution_authorized -eq $true -and
    $manifest.performance_acceptance_authorization -eq $false -and
    $manifest.adaptive_rule_derivation_authorization -eq $false -and
    $manifest.active_behavior_authorization -eq $false -and
    $manifest.production_activation_authorization -eq $false
) 'balanced_manifest_authorization_invalid'

$sequenceMutation = Copy-Document $control
$sequenceMutation.execution_sequence[1] =
    $sequenceMutation.execution_sequence[0]
Assert-CompileRejects $sequenceMutation 'unbalanced-sequence' `
    'execution_position_balance_invalid'

$acceptanceMutation = Copy-Document $control
$acceptanceMutation.performance_acceptance_authorization = $true
Assert-CompileRejects $acceptanceMutation 'performance-acceptance' `
    'JSON is not valid with the schema'

$coveringMutation = Copy-Document $control
$coveringMutation.covering_array_generator_implemented = $true
Assert-CompileRejects $coveringMutation 'covering-array' `
    'JSON is not valid with the schema'

$blockedMutation = Copy-Document $control
$blockedMutation.cell_bindings[0].
    oversized_write_admission_quantum = 'bounded_multi_fragment'
Assert-CompileRejects $blockedMutation 'blocked-value' `
    'JSON is not valid with the schema'

$driverPath = Join-Path $PSScriptRoot `
    'Invoke-AdaptiveRuntimeAdmissionPerformanceBalancedCampaign.ps1'
$driverText = Get-Content -LiteralPath $driverPath -Raw
Assert-Ready (
    $driverText.Contains('[switch] $Resume') -and
    $driverText.Contains(
        '[int] $StopAfterCompletedRunCount = 64') -and
    $driverText.Contains(
        'AdaptiveRuntimeAdmissionPerformanceManifestContentSha256') -and
    $driverText.Contains('Write-CampaignState') -and
    $driverText.Contains('CaptureCounters = $true') -and
    $driverText.Contains(
        'load-tool-process-metrics-summary\.json') -and
    $driverText.Contains(
        'bounded_server_stdout_max_bytes') -and
    $driverText.Contains(
        'independent_physical_hosts') -and
    $driverText.Contains(
        'adaptive_rule_derivation_authorization = $false')
) 'balanced_driver_safety_controls_missing'
Assert-Ready (
    -not $driverText.Contains('CaptureTrace = $true')
) 'balanced_driver_trace_capture_enabled'

$planRoot = Join-Path $TemporaryRoot 'plan-only'
$plan = & $driverPath `
    -RepositoryRoot $RepositoryRoot `
    -ControlPath $controlPath `
    -OutputRoot $planRoot |
        ConvertFrom-Json
Assert-Ready (
    [string]$plan.mode -ceq 'plan_only' -and
    [int]$plan.planned_run_count -eq 64 -and
    [int]$plan.actual_measurements_run -eq 0
) 'balanced_driver_plan_only_invalid'

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    control_sha256 = [string]$control.content_sha256
    manifest_sha256 = [string]$manifest.content_sha256
    cell_count = 8
    block_count = 8
    planned_run_count = 64
    actual_measurements_run = 0
} | ConvertTo-Json -Depth 8
