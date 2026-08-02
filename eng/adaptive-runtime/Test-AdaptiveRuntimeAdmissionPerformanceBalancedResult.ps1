# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ResultPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-balanced-result-v1.json'),
    [string] $ExecutionRoot,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\admission-performance-balanced-result-tests'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$assertionCount = 0
function Assert-Result([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
    $script:assertionCount++
}

function Copy-Document([object] $Document) {
    $Document | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Assert-SchemaRejects(
    [object] $Document,
    [string] $SchemaPath,
    [string] $Code
) {
    $rejected = $false
    try {
        $rejected = -not (
            Test-AdaptiveRuntimeJsonSchema $Document $SchemaPath)
    }
    catch {
        $rejected = $true
    }
    Assert-Result $rejected $Code
}

$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-performance-balanced-result-v1.schema.json'
$result = Read-AdaptiveRuntimeJsonDocument $ResultPath

Assert-Result (Test-AdaptiveRuntimeDocumentHash $result) `
    'balanced_result_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeJsonSchema $result $schemaPath) `
    'balanced_result_schema_invalid'
Assert-Result (
    [string]$result.conclusion -ceq
        'balanced_campaign_completed_characterization_only_no_rule' -and
    [string]$result.source_dirty_state -ceq 'clean'
) 'balanced_result_conclusion_invalid'
Assert-Result (
    [int]$result.run_counts.planned_runs -eq 64 -and
    [int]$result.run_counts.completed_runs -eq 64 -and
    [int]$result.run_counts.actual_measurements_run -eq 64 -and
    [int]$result.run_counts.failed_attempts -eq 2 -and
    [long]$result.run_counts.failed_requests -eq 0 -and
    [long]$result.run_counts.timeout_requests -eq 0 -and
    [int]$result.run_counts.saturated_runs -eq 0
) 'balanced_result_run_counts_invalid'
Assert-Result (
    @($result.runs).Count -eq 64 -and
    @($result.runs.execution_index | Sort-Object -Unique).Count -eq 64 -and
    [string]::Join('|', @($result.runs.execution_index | Sort-Object)) -ceq
        [string]::Join('|', @(1..64)) -and
    @($result.runs.job_id | Sort-Object -Unique).Count -eq 64 -and
    @($result.runs.run_id | Sort-Object -Unique).Count -eq 64
) 'balanced_result_run_identity_invalid'
Assert-Result (
    [string]::Join('|', @($result.cells.cell_id | Sort-Object)) -ceq
        'a0|a1|a2|a3|a4|a5|a6|a7' -and
    @($result.packages).Count -eq 8 -and
    @($result.packages.cell_id | Sort-Object -Unique).Count -eq 8
) 'balanced_result_cell_or_package_identity_invalid'
foreach ($cellId in @('a0','a1','a2','a3','a4','a5','a6','a7')) {
    $runs = @($result.runs | Where-Object cell_id -CEQ $cellId)
    Assert-Result (
        $runs.Count -eq 8 -and
        @($runs.block_index | Sort-Object -Unique).Count -eq 8 -and
        @($runs.position_index | Sort-Object -Unique).Count -eq 8
    ) "balanced_result_cell_balance_invalid:$cellId"
}
Assert-Result (
    @($result.runs | Where-Object {
        [long]$_.total_requests -eq [long]$_.successful_requests -and
        [long]$_.failed_requests -eq 0 -and
        [long]$_.timeout_requests -eq 0 -and
        [long]$_.bytes_sent -eq [long]$_.bytes_received -and
        [string]$_.load_generator_saturation_status -ceq
            'load-generator-saturation-not-detected' -and
        [long]$_.bounded_aggregate.stdout_bytes -gt 0 -and
        [long]$_.bounded_aggregate.stdout_bytes -le 65536 -and
        $_.bounded_aggregate.arithmetic_saturated -eq $false -and
        [int]$_.load_process.sample_count -gt 0 -and
        [string]$_.target_runtime_counter_status -ceq 'unavailable'
    }).Count -eq 64
) 'balanced_result_run_invariants_invalid'
Assert-Result (
    @($result.failed_attempts).Count -eq 2 -and
    @($result.failed_attempts | Where-Object {
        [int]$_.execution_index -eq 45 -and
        [string]$_.cell_id -ceq 'a3' -and
        $_.measurement_recorded -eq $false -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$_.failure_reason_code)
    }).Count -eq 2
) 'balanced_result_failed_attempts_invalid'

$expectedTerms = @(
    'oversized',
    'batch',
    'buffer',
    'oversized_x_batch',
    'oversized_x_buffer',
    'batch_x_buffer',
    'oversized_x_batch_x_buffer'
)
Assert-Result (
    @($result.factorial_contrasts).Count -eq 7 -and
    [string]::Join('|', @(
        $result.factorial_contrasts.term | Sort-Object)) -ceq
        [string]::Join('|', @($expectedTerms | Sort-Object)) -and
    @($result.factorial_contrasts | Where-Object {
        [string]$_.classification -ceq
            'descriptive_characterization_only' -and
        @($_.effects).Count -eq 4 -and
        @($_.effects | Where-Object {
            [int]$_.block_effects.n -eq 8
        }).Count -eq 4
    }).Count -eq 7
) 'balanced_result_factorial_contrasts_invalid'
Assert-Result (
    @($result.block_summaries).Count -eq 8 -and
    @($result.block_summaries.index | Sort-Object -Unique).Count -eq 8 -and
    @($result.position_summaries).Count -eq 8 -and
    @($result.position_summaries.index | Sort-Object -Unique).Count -eq 8
) 'balanced_result_block_or_position_summary_invalid'
Assert-Result (
    $result.resource_telemetry.load_process_samples_present -eq $true -and
    @($result.resource_telemetry.load_process_warnings_retained).Count -gt 0 -and
    [string]$result.resource_telemetry.target_runtime_counter_status -ceq
        'unavailable' -and
    [double]$result.resource_telemetry.server_stdout_bytes.maximum -le
        [double]$result.resource_telemetry.bounded_server_stdout_max_bytes
) 'balanced_result_resource_telemetry_invalid'
Assert-Result (
    [string]$result.analysis_boundary.classification -ceq
        'descriptive_characterization_only' -and
    $result.analysis_boundary.predeclared_practical_thresholds_available -eq
        $false -and
    $result.analysis_boundary.held_out_validation_available -eq $false -and
    [string]$result.analysis_boundary.threshold_consequence -ceq
        'blocks_performance_acceptance_and_rule_derivation'
) 'balanced_result_analysis_boundary_invalid'
Assert-Result (
    $result.covering_array.generator_implemented -eq $false -and
    $result.covering_array.required_for_current_eight_cell_family -eq
        $false -and
    [int]$result.covering_array.trigger_effective_cell_count -eq 65
) 'balanced_result_covering_array_scope_invalid'
Assert-Result (
    $result.performance_acceptance_authorization -eq $false -and
    $result.adaptive_rule_derivation_authorization -eq $false -and
    $result.active_behavior_authorization -eq $false -and
    $result.production_activation_authorization -eq $false
) 'balanced_result_authorization_invalid'

$acceptanceMutation = Copy-Document $result
$acceptanceMutation.performance_acceptance_authorization = $true
Assert-SchemaRejects $acceptanceMutation $schemaPath `
    'balanced_result_schema_accepted_performance_authorization'

$ruleMutation = Copy-Document $result
$ruleMutation.adaptive_rule_derivation_authorization = $true
Assert-SchemaRejects $ruleMutation $schemaPath `
    'balanced_result_schema_accepted_rule_authorization'

$coveringArrayMutation = Copy-Document $result
$coveringArrayMutation.covering_array.generator_implemented = $true
Assert-SchemaRejects $coveringArrayMutation $schemaPath `
    'balanced_result_schema_accepted_covering_array_generator'

$countMutation = Copy-Document $result
$countMutation.run_counts.completed_runs = 63
Assert-SchemaRejects $countMutation $schemaPath `
    'balanced_result_schema_accepted_incomplete_campaign'

$thresholdMutation = Copy-Document $result
$thresholdMutation.analysis_boundary.
    predeclared_practical_thresholds_available = $true
Assert-SchemaRejects $thresholdMutation $schemaPath `
    'balanced_result_schema_accepted_retroactive_thresholds'

$replayVerified = $false
if (-not [string]::IsNullOrWhiteSpace($ExecutionRoot)) {
    [void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)
    $replayPath = Join-Path $TemporaryRoot 'replayed-balanced-result.json'
    & (Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeAdmissionPerformanceBalancedResult.ps1') `
        -RepositoryRoot $RepositoryRoot `
        -ExecutionRoot $ExecutionRoot `
        -OutputPath $replayPath | Out-Null
    $expectedBytes = [IO.File]::ReadAllBytes(
        [IO.Path]::GetFullPath($ResultPath))
    $replayedBytes = [IO.File]::ReadAllBytes(
        [IO.Path]::GetFullPath($replayPath))
    Assert-Result (
        [Convert]::ToBase64String($expectedBytes) -ceq
            [Convert]::ToBase64String($replayedBytes)
    ) 'balanced_result_replay_bytes_mismatch'
    $replayVerified = $true
}

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    result_sha256 = [string]$result.content_sha256
    completed_run_count = [int]$result.run_counts.completed_runs
    failed_attempt_count = [int]$result.run_counts.failed_attempts
    contrast_count = @($result.factorial_contrasts).Count
    replay_verified = $replayVerified
    actual_measurements_run = 0
} | ConvertTo-Json -Depth 8
