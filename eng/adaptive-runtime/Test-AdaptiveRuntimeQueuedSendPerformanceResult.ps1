# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ResultPath,
    [string] $ExecutionRoot,
    [string] $ControlPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-queued-send-performance-campaign-v1.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\queued-send-performance-result-replay'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$assertionCount = 0
function Assert-Result([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
    $script:assertionCount++
}

$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-queued-send-performance-result-v1.schema.json'
$result = Read-AdaptiveRuntimeJsonDocument $ResultPath
Assert-Result (Test-AdaptiveRuntimeDocumentHash $result) 'queued_result_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeJsonSchema $result $schemaPath) `
    'queued_result_schema_invalid'
Assert-Result ([string]$result.conclusion -ceq
    'queued_send_campaign_completed_characterization_only_no_rule' -and
    [string]$result.analysis_boundary.classification -ceq
        'descriptive_characterization_only' -and
    $result.analysis_boundary.threshold_available -eq $false -and
    $result.analysis_boundary.winner_selection_authorized -eq $false) `
    'queued_result_boundary_invalid'
Assert-Result ([int]$result.run_counts.planned_runs -eq 16 -and
    [int]$result.run_counts.completed_runs -eq 16 -and
    [int]$result.run_counts.actual_measurements_run -eq 16 -and
    [int]$result.run_counts.activation_preflight_runs -eq 1 -and
    [long]$result.run_counts.failed_requests -eq 0 -and
    [long]$result.run_counts.timeout_requests -eq 0 -and
    [int]$result.run_counts.saturated_runs -eq 0) 'queued_result_counts_invalid'
Assert-Result (@($result.runs).Count -eq 16 -and
    @($result.runs.execution_index | Sort-Object -Unique).Count -eq 16 -and
    @($result.runs.job_id | Sort-Object -Unique).Count -eq 16 -and
    @($result.runs.run_id | Sort-Object -Unique).Count -eq 16) `
    'queued_result_run_identity_invalid'
foreach ($cellId in @(
    'cell.queued_send_burst_budget.performance.q0',
    'cell.queued_send_burst_budget.performance.q1')) {
    $cellRuns = @($result.runs | Where-Object cell_id -CEQ $cellId)
    Assert-Result ($cellRuns.Count -eq 8 -and
        @($cellRuns.block_index | Sort-Object -Unique).Count -eq 8 -and
        @($cellRuns.position_index | Sort-Object -Unique).Count -eq 2 -and
        @($cellRuns | Group-Object position_index |
            Where-Object Count -eq 4).Count -eq 2) `
        "queued_result_cell_balance_invalid:$cellId"
}
Assert-Result (@($result.block_summaries).Count -eq 8 -and
    @($result.block_summaries.order -CEQ 'q0_then_q1').Count -eq 4 -and
    @($result.block_summaries.order -CEQ 'q1_then_q0').Count -eq 4 -and
    @($result.order_summaries).Count -eq 2) 'queued_result_order_invalid'
Assert-Result ([string]$result.activation_preflight.predicate_id -ceq
    'predicate.queued_send.legal_budget_gt_one' -and
    $result.activation_preflight.activation_observed -eq $true -and
    $result.activation_preflight.accepted_timed_row -eq $false) `
    'queued_result_preflight_invalid'
Assert-Result (@($result.runs | Where-Object {
    [long]$_.total_requests -eq [long]$_.successful_requests -and
    [long]$_.failed_requests -eq 0 -and [long]$_.timeout_requests -eq 0 -and
    [long]$_.bytes_sent -eq [long]$_.bytes_received -and
    [string]$_.load_generator_saturation_status -ceq
        'load-generator-saturation-not-detected' -and
    [long]$_.bounded_aggregate.stdout_bytes -le 65536 -and
    [long]$_.bounded_aggregate.queued_send_burst_evidence_count -gt 0 -and
    $_.bounded_aggregate.arithmetic_saturated -eq $false -and
    [int]$_.load_process.sample_count -gt 0
}).Count -eq 16) 'queued_result_run_invariants_invalid'
Assert-Result ($result.performance_acceptance_authorization -eq $false -and
    $result.adaptive_rule_derivation_authorization -eq $false -and
    $result.active_behavior_authorization -eq $false -and
    $result.production_activation_authorization -eq $false -and
    $result.covering_array.generator_implemented -eq $false -and
    $result.covering_array.required_for_current_two_cell_family -eq $false) `
    'queued_result_authorization_invalid'

$replayVerified = $false
if (-not [string]::IsNullOrWhiteSpace($ExecutionRoot)) {
    [void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)
    $replayPath = Join-Path $TemporaryRoot 'queued-send-result.replayed.json'
    & (Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeQueuedSendPerformanceResult.ps1') `
        -RepositoryRoot $RepositoryRoot -ControlPath $ControlPath `
        -ExecutionRoot $ExecutionRoot -OutputPath $replayPath | Out-Null
    Assert-Result ([Convert]::ToBase64String([IO.File]::ReadAllBytes(
        [IO.Path]::GetFullPath($ResultPath))) -ceq
        [Convert]::ToBase64String([IO.File]::ReadAllBytes(
            [IO.Path]::GetFullPath($replayPath)))) `
        'queued_result_replay_bytes_mismatch'
    $replayVerified = $true
}

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    result_sha256 = [string]$result.content_sha256
    completed_run_count = 16
    failed_attempt_count = @($result.failed_attempts).Count
    replay_verified = $replayVerified
    actual_measurements_run = 0
} | ConvertTo-Json -Depth 8
