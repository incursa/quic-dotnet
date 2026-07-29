# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ResultPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-pilot-result-v1.json'),
    [string] $ExecutionRoot,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\admission-performance-pilot-result-tests'
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
    'schemas\adaptive-runtime-send-admission-performance-pilot-result-v1.schema.json'
$result = Read-AdaptiveRuntimeJsonDocument $ResultPath

Assert-Result (Test-AdaptiveRuntimeDocumentHash $result) `
    'pilot_result_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeJsonSchema $result $schemaPath) `
    'pilot_result_schema_invalid'
Assert-Result (
    [string]$result.conclusion -ceq 'pilot_completed_directional_only' -and
    [string]$result.source_dirty_state -ceq 'clean'
) 'pilot_result_conclusion_invalid'
Assert-Result (
    [int]$result.run_counts.cells -eq 4 -and
    [int]$result.run_counts.repetitions -eq 8 -and
    [int]$result.run_counts.successful_repetitions -eq 8 -and
    [int]$result.run_counts.failed_repetitions -eq 0 -and
    [long]$result.run_counts.timeout_requests -eq 0
) 'pilot_result_run_counts_invalid'
Assert-Result (
    [string]::Join('|', @($result.execution_sequence)) -ceq
        'a0|a4|a3|a7'
) 'pilot_result_execution_sequence_invalid'
Assert-Result (
    [string]::Join('|', @($result.cells.cell_id | Sort-Object)) -ceq
        'a0|a3|a4|a7'
) 'pilot_result_cells_invalid'
Assert-Result (
    @($result.cells.job_id | Sort-Object -Unique).Count -eq 4 -and
    @($result.cells.run_id | Sort-Object -Unique).Count -eq 4
) 'pilot_result_run_identity_not_unique'
Assert-Result (
    @($result.cells |
        Where-Object {
            [string]$_.topology.classification -ceq
                'independent_physical_hosts' -and
            [string]$_.topology.sut_node_id -ceq
                'plab-worker-x64-02' -and
            [string]$_.topology.load_node_id -ceq
                'plab-worker-x64-03' -and
            [string]$_.topology.sut_physical_host_id -cne
                [string]$_.topology.load_physical_host_id
        }).Count -eq 4
) 'pilot_result_topology_invalid'
Assert-Result (
    @($result.cells |
        Where-Object {
            [int]$_.bounded_aggregate.epoch_count -gt 0 -and
            [long]$_.bounded_aggregate.stdout_bytes -gt 0 -and
            [long]$_.bounded_aggregate.stdout_bytes -le 65536 -and
            [long]$_.bounded_aggregate.application_send_batch_evidence_count -gt 0 -and
            [long]$_.bounded_aggregate.oversized_write_evidence_count -gt 0 -and
            [long]$_.bounded_aggregate.buffer_copy_operation_count -gt 0 -and
            [long]$_.bounded_aggregate.owner_release_count -gt 0 -and
            $_.bounded_aggregate.arithmetic_saturated -eq $false
        }).Count -eq 4
) 'pilot_result_bounded_aggregate_invalid'
Assert-Result (
    @($result.cells.repetitions |
        Where-Object {
            [long]$_.total_requests -eq [long]$_.successful_requests -and
            [long]$_.failed_requests -eq 0 -and
            [long]$_.timeout_requests -eq 0 -and
            [long]$_.bytes_sent -eq [long]$_.bytes_received -and
            [string]$_.load_generator_saturation_status -ceq
                'load-generator-saturation-not-detected'
        }).Count -eq 8
) 'pilot_result_repetition_invariant_invalid'
Assert-Result (
    @($result.directional_comparisons).Count -eq 3 -and
    @($result.directional_comparisons |
        Where-Object {
            [string]$_.versus_cell_id -ceq 'a0' -and
            [string]$_.classification -ceq 'directional_only'
        }).Count -eq 3
) 'pilot_result_directional_comparisons_invalid'
Assert-Result (
    $result.covering_array.generator_implemented -eq $false -and
    $result.covering_array.required_for_current_eight_cell_family -eq
        $false -and
    [int]$result.covering_array.trigger_effective_cell_count -eq 65
) 'pilot_result_covering_array_scope_invalid'
Assert-Result (
    $result.performance_acceptance_authorization -eq $false -and
    $result.adaptive_rule_derivation_authorization -eq $false -and
    $result.active_behavior_authorization -eq $false -and
    $result.production_activation_authorization -eq $false
) 'pilot_result_authorization_invalid'

$acceptanceMutation = Copy-Document $result
$acceptanceMutation.performance_acceptance_authorization = $true
Assert-SchemaRejects $acceptanceMutation $schemaPath `
    'pilot_result_schema_accepted_performance_authorization'

$coveringArrayMutation = Copy-Document $result
$coveringArrayMutation.covering_array.generator_implemented = $true
Assert-SchemaRejects $coveringArrayMutation $schemaPath `
    'pilot_result_schema_accepted_covering_array_generator'

$failureMutation = Copy-Document $result
$failureMutation.run_counts.failed_repetitions = 1
Assert-SchemaRejects $failureMutation $schemaPath `
    'pilot_result_schema_accepted_failed_repetition'

$replayVerified = $false
if (-not [string]::IsNullOrWhiteSpace($ExecutionRoot)) {
    [void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)
    $replayPath = Join-Path $TemporaryRoot 'replayed-result.json'
    & (Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeAdmissionPerformancePilotResult.ps1') `
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
    ) 'pilot_result_replay_bytes_mismatch'
    $replayVerified = $true
}

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    result_sha256 = [string]$result.content_sha256
    cell_count = @($result.cells).Count
    repetition_count = @($result.cells.repetitions).Count
    replay_verified = $replayVerified
    actual_measurements_run = 0
} | ConvertTo-Json -Depth 8
