# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExecutionRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ControlPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-queued-send-performance-campaign-v1.json'),
    [string] $OutputPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-queued-send-performance-result-v1.json'),
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Result([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}

function New-DocumentReference([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Get-Median([double[]] $Values) {
    $ordered = @($Values | Sort-Object)
    Assert-Result ($ordered.Count -gt 0) 'median_input_empty'
    if (($ordered.Count % 2) -eq 1) {
        return [double]$ordered[[int][math]::Floor($ordered.Count / 2)]
    }
    ([double]$ordered[($ordered.Count / 2) - 1] +
        [double]$ordered[$ordered.Count / 2]) / 2.0
}

function Get-Statistics([double[]] $Values) {
    Assert-Result ($Values.Count -gt 0) 'statistics_input_empty'
    $mean = [double](($Values | Measure-Object -Average).Average)
    $squares = 0.0
    foreach ($value in $Values) {
        $squares += [math]::Pow(([double]$value - $mean), 2)
    }
    $standardDeviation = if ($Values.Count -gt 1) {
        [math]::Sqrt($squares / ($Values.Count - 1))
    } else { 0.0 }
    [pscustomobject][ordered]@{
        n = $Values.Count; mean = $mean; median = Get-Median $Values
        sample_standard_deviation = $standardDeviation
        coefficient_of_variation_percent = if ($mean -ne 0.0) {
            100.0 * $standardDeviation / [math]::Abs($mean)
        } else { 0.0 }
        minimum = [double](($Values | Measure-Object -Minimum).Minimum)
        maximum = [double](($Values | Measure-Object -Maximum).Maximum)
    }
}

function Get-MeasureSum([object[]] $Rows, [string] $Property) {
    $segments = @($Property -split '\.')
    $sum = [long]0
    foreach ($row in $Rows) {
        $value = $row
        foreach ($segment in $segments) {
            $value = $value.PSObject.Properties[$segment].Value
        }
        $sum += [long]$value
    }
    $sum
}

function Convert-PackageReference([object] $Reference) {
    [pscustomobject][ordered]@{
        package_id = [string]$Reference.packageId
        package_version = [string]$Reference.packageVersion
        sha256 = [string]$Reference.sha256
    }
}

function Get-CellLabel([string] $CellId) {
    switch ($CellId) {
        'cell.queued_send_burst_budget.performance.q0' { 'q0'; break }
        'cell.queued_send_burst_budget.performance.q1' { 'q1'; break }
        default { throw "queued_cell_id_unknown:$CellId" }
    }
}

$executionRootFull = [IO.Path]::GetFullPath($ExecutionRoot)
$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-queued-send-performance-result-v1.schema.json'
$control = Read-AdaptiveRuntimeJsonDocument $ControlPath
$compiled = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $executionRootFull 'compiled-manifest.json')
$state = Get-Content -LiteralPath (
    Join-Path $executionRootFull 'campaign-state.json') -Raw |
    ConvertFrom-Json -Depth 100
$nodes = @(Get-Content -LiteralPath (
    Join-Path $executionRootFull 'controller-nodes.json') -Raw |
    ConvertFrom-Json -Depth 100)
$packageIdentities = @(Get-Content -LiteralPath (
    Join-Path $executionRootFull 'package-identities.json') -Raw |
    ConvertFrom-Json -Depth 100)
$preflight = Get-Content -LiteralPath (
    Join-Path $executionRootFull 'activation-preflight.json') -Raw |
    ConvertFrom-Json -Depth 100

Assert-Result (Test-AdaptiveRuntimeDocumentHash $control) 'queued_control_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $compiled) 'queued_manifest_hash_invalid'
Assert-Result ([string]$compiled.control_ref.content_sha256 -ceq
    [string]$control.content_sha256) 'queued_manifest_control_binding_invalid'
Assert-Result ([string]$state.control_sha256 -ceq [string]$control.content_sha256 -and
    [string]$state.manifest_sha256 -ceq [string]$compiled.content_sha256 -and
    [string]$state.source_commit -match '^[0-9a-f]{40}$' -and
    [string]$state.source_dirty_state -ceq 'clean' -and
    [int]$state.planned_run_count -eq 16 -and
    [int]$state.completed_run_count -eq 16) 'queued_state_identity_or_count_invalid'
Assert-Result ($state.performance_acceptance_authorization -eq $false -and
    $state.adaptive_rule_derivation_authorization -eq $false -and
    $state.active_behavior_authorization -eq $false -and
    $state.production_activation_authorization -eq $false) `
    'queued_state_authorization_invalid'
Assert-Result (@($compiled.planned_runs).Count -eq 16 -and
    $packageIdentities.Count -eq 2) 'queued_manifest_or_package_count_invalid'
Assert-Result ([string]$preflight.predicate_id -ceq
    'predicate.queued_send.legal_budget_gt_one' -and
    [string]$preflight.cell_id -ceq
        'cell.queued_send_burst_budget.performance.q1' -and
    $preflight.activation_observed -eq $true -and
    $preflight.accepted_timed_row -eq $false -and
    [string]$preflight.topology.classification -ceq 'independent_physical_hosts' -and
    [string]$preflight.topology.sutNodeId -ceq 'plab-worker-x64-02' -and
    [string]$preflight.topology.loadNodeId -ceq 'plab-worker-x64-03' -and
    $preflight.performance_acceptance_authorization -eq $false -and
    $preflight.adaptive_rule_derivation_authorization -eq $false -and
    $preflight.active_behavior_authorization -eq $false -and
    $preflight.production_activation_authorization -eq $false) `
    'queued_activation_preflight_invalid'

$bindingByCell = @{}
foreach ($binding in @($control.cell_bindings)) {
    $cellId = [string]$binding.cell_id
    Assert-Result ($cellId -cin @(
        'cell.queued_send_burst_budget.performance.q0',
        'cell.queued_send_burst_budget.performance.q1') -and
        -not $bindingByCell.ContainsKey($cellId)) "queued_binding_invalid:$cellId"
    $bindingByCell[$cellId] = $binding
}
Assert-Result ($bindingByCell.Count -eq 2 -and
    [string]$bindingByCell[
        'cell.queued_send_burst_budget.performance.q0'].
            queued_send_burst_budget -ceq 'legacy_current' -and
    [string]$bindingByCell[
        'cell.queued_send_burst_budget.performance.q1'].
            queued_send_burst_budget -ceq 'single_datagram') `
    'queued_bindings_not_exact'

$packageByCell = @{}
$packages = @(
    foreach ($identity in @($packageIdentities | Sort-Object cell_id)) {
        $cellId = [string]$identity.cell_id
        Assert-Result ($bindingByCell.ContainsKey($cellId) -and
            -not $packageByCell.ContainsKey($cellId)) "queued_package_cell_invalid:$cellId"
        $packageByCell[$cellId] = $identity.package_ref
        [pscustomobject][ordered]@{
            cell_id = $cellId
            package_ref = Convert-PackageReference $identity.package_ref
        }
    }
)
Assert-Result ($packageByCell.Count -eq 2) 'queued_package_identity_not_unique'

$completedAttempts = @($state.attempts | Where-Object outcome -CEQ 'Completed' |
    Sort-Object execution_index)
$failedAttemptsSource = @($state.attempts | Where-Object outcome -CNE 'Completed' |
    Sort-Object execution_index,attempt_index)
$failedPreflightAttemptsSource = @($preflight.attempts |
    Where-Object outcome -CNE 'Completed' | Sort-Object attempt_index)
Assert-Result ($completedAttempts.Count -eq 16 -and
    @($completedAttempts.execution_index | Sort-Object -Unique).Count -eq 16 -and
    [string]::Join('|', @($completedAttempts.execution_index)) -ceq
        [string]::Join('|', @(1..16)) -and
    [int]$state.failed_attempt_count -eq $failedAttemptsSource.Count) `
    'queued_attempt_reconciliation_invalid'
$failedCampaignAttempts = @(
    foreach ($attempt in $failedAttemptsSource) {
        Assert-Result ([string]::IsNullOrWhiteSpace(
            [string]$attempt.measurement_summary_path)) `
            "queued_failed_attempt_has_measurement:$($attempt.job_id)"
        [pscustomobject][ordered]@{
            phase = 'timed_campaign'
            execution_index = [int]$attempt.execution_index
            attempt_index = [int]$attempt.attempt_index
            cell_id = [string]$attempt.cell_id
            job_id = [string]$attempt.job_id
            run_id = [string]$attempt.run_id
            outcome = [string]$attempt.outcome
            package_ref = Convert-PackageReference $attempt.package_ref
            failure_reason_code = [string]$attempt.failure_reason_code
            measurement_recorded = $false
        }
    }
)
$failedPreflightAttempts = @(
    foreach ($attempt in $failedPreflightAttemptsSource) {
        Assert-Result ([string]::IsNullOrWhiteSpace(
            [string]$attempt.measurement_summary_path)) `
            "queued_failed_preflight_has_measurement:$($attempt.job_id)"
        [pscustomobject][ordered]@{
            phase = 'activation_preflight'
            execution_index = 0
            attempt_index = [int]$attempt.attempt_index
            cell_id = [string]$attempt.cell_id
            job_id = [string]$attempt.job_id
            run_id = [string]$attempt.run_id
            outcome = [string]$attempt.outcome
            package_ref = Convert-PackageReference $attempt.package_ref
            failure_reason_code = [string]$attempt.failure_reason_code
            measurement_recorded = $false
        }
    }
)
$failedAttempts = @($failedPreflightAttempts) + @($failedCampaignAttempts)

$rows = [Collections.Generic.List[object]]::new()
foreach ($attempt in $completedAttempts) {
    $executionIndex = [int]$attempt.execution_index
    $planned = @($compiled.planned_runs | Where-Object {
        [int]$_.execution_index -eq $executionIndex })
    Assert-Result ($planned.Count -eq 1 -and
        [string]$planned[0].cell_id -ceq [string]$attempt.cell_id -and
        [int]$planned[0].block_index -eq [int]$attempt.block_index -and
        [int]$planned[0].position_index -eq [int]$attempt.position_index) `
        "queued_planned_run_identity_mismatch:$executionIndex"
    $cellId = [string]$attempt.cell_id
    $expectedPackage = $packageByCell[$cellId]
    Assert-Result ([string]$attempt.package_ref.packageId -ceq
        [string]$expectedPackage.packageId -and
        [string]$attempt.package_ref.packageVersion -ceq
            [string]$expectedPackage.packageVersion -and
        [string]$attempt.package_ref.sha256 -ceq [string]$expectedPackage.sha256) `
        "queued_package_identity_mismatch:$executionIndex"
    Assert-Result ([string]$attempt.topology.classification -ceq
        'independent_physical_hosts' -and
        [string]$attempt.topology.sutNodeId -ceq 'plab-worker-x64-02' -and
        [string]$attempt.topology.loadNodeId -ceq 'plab-worker-x64-03' -and
        [string]$attempt.topology.sutPhysicalHostId -cne
            [string]$attempt.topology.loadPhysicalHostId) `
        "queued_topology_invariant_failed:$executionIndex"
    $summary = Get-Content -LiteralPath ([string]$attempt.measurement_summary_path) -Raw |
        ConvertFrom-Json -Depth 100
    $benchmark = $summary.benchmark
    $bounded = $summary.bounded_aggregate
    $load = $summary.load_process_metrics
    Assert-Result ([string]$summary.schema_version -ceq
        'adaptive-runtime-queued-send-performance-measurement-summary-v1' -and
        [int]$summary.execution_index -eq $executionIndex -and
        [string]$summary.cell_id -ceq $cellId -and
        [string]$summary.job_id -ceq [string]$attempt.job_id -and
        $summary.accepted_timed_row -eq $true) `
        "queued_measurement_identity_invalid:$executionIndex"
    Assert-Result ([long]$benchmark.total_requests -gt 0 -and
        [long]$benchmark.total_requests -eq [long]$benchmark.successful_requests -and
        [long]$benchmark.failed_requests -eq 0 -and [long]$benchmark.timeout_requests -eq 0 -and
        [long]$benchmark.bytes_sent -eq 0 -and
        [long]$benchmark.bytes_received -eq
            ([long]$benchmark.total_requests * 1MB) -and
        [string]$benchmark.load_generator_saturation_status -ceq
            'load-generator-saturation-not-detected') `
        "queued_benchmark_invariant_failed:$executionIndex"
    Assert-Result ([long]$bounded.stdout_bytes -gt 0 -and
        [long]$bounded.stdout_bytes -le
            [long]$control.resource_metrics.bounded_server_stdout_max_bytes -and
        [long]$bounded.epoch_count -gt 0 -and
        [long]$bounded.queued_send_burst_evidence_count -gt 0 -and
        [long]$bounded.legal_budget_gt_one_count -ge 0 -and
        $bounded.arithmetic_saturated -eq $false) `
        "queued_bounded_aggregate_invalid:$executionIndex"
    Assert-Result ([int]$load.sample_count -gt 0 -and
        [double]$load.normalized_cpu_percent_mean -ge 0 -and
        [double]$load.normalized_cpu_percent_peak_interval -ge 0 -and
        [long]$load.memory_max_bytes -gt 0) `
        "queued_resource_telemetry_invalid:$executionIndex"
    Assert-Result ($summary.performance_acceptance_authorized -eq $false -and
        $summary.adaptive_rule_derivation_authorized -eq $false -and
        $summary.active_behavior_authorized -eq $false -and
        $summary.production_activation_authorized -eq $false) `
        "queued_measurement_authorization_invalid:$executionIndex"
    [void]$rows.Add([pscustomobject][ordered]@{
        execution_index = $executionIndex; block_index = [int]$attempt.block_index
        position_index = [int]$attempt.position_index; cell_id = $cellId
        job_id = [string]$attempt.job_id; run_id = [string]$attempt.run_id
        package_ref = Convert-PackageReference $attempt.package_ref
        metrics = [pscustomobject][ordered]@{
            requests_per_second = [double]$benchmark.requests_per_second
            useful_bytes_per_second = [double]$benchmark.throughput_bytes_per_second
            latency_p50_ms = [double]$benchmark.latency_p50_ms
            latency_p95_ms = [double]$benchmark.latency_p95_ms
        }
        total_requests = [long]$benchmark.total_requests
        successful_requests = [long]$benchmark.successful_requests
        failed_requests = [long]$benchmark.failed_requests
        timeout_requests = [long]$benchmark.timeout_requests
        bytes_sent = [long]$benchmark.bytes_sent; bytes_received = [long]$benchmark.bytes_received
        load_generator_saturation_status = [string]$benchmark.load_generator_saturation_status
        bounded_aggregate = [pscustomobject][ordered]@{
            epoch_count = [long]$bounded.epoch_count; stdout_bytes = [long]$bounded.stdout_bytes
            queued_send_burst_evidence_count =
                [long]$bounded.queued_send_burst_evidence_count
            legal_budget_gt_one_count = [long]$bounded.legal_budget_gt_one_count
            arithmetic_saturated = [bool]$bounded.arithmetic_saturated
        }
        load_process = [pscustomobject][ordered]@{
            sample_count = [int]$load.sample_count
            normalized_cpu_percent_mean = [double]$load.normalized_cpu_percent_mean
            normalized_cpu_percent_peak_interval =
                [double]$load.normalized_cpu_percent_peak_interval
            memory_max_bytes = [long]$load.memory_max_bytes
            warnings = @($load.warnings | ForEach-Object { [string]$_ })
        }
        target_runtime_counter_status =
            [string]$summary.target_process_metrics.runtime_counter_status
    })
}

Assert-Result (@($rows.job_id | Sort-Object -Unique).Count -eq 16 -and
    @($rows.run_id | Sort-Object -Unique).Count -eq 16 -and
    @($rows | Group-Object cell_id | Where-Object Count -eq 8).Count -eq 2 -and
    @($rows | Group-Object block_index | Where-Object Count -eq 2).Count -eq 8 -and
    @($rows | Group-Object position_index | Where-Object Count -eq 8).Count -eq 2) `
    'queued_run_shape_invalid'
foreach ($cellId in @(
    'cell.queued_send_burst_budget.performance.q0',
    'cell.queued_send_burst_budget.performance.q1')) {
    $cellRows = @($rows | Where-Object cell_id -CEQ $cellId)
    Assert-Result (@($cellRows.block_index | Sort-Object -Unique).Count -eq 8 -and
        @($cellRows.position_index | Sort-Object -Unique).Count -eq 2 -and
        @($cellRows | Group-Object position_index | Where-Object Count -eq 4).Count -eq 2) `
        "queued_cell_balance_invalid:$cellId"
}

$runs = @($rows | ForEach-Object {
    [pscustomobject][ordered]@{
        execution_index = [int]$_.execution_index; block_index = [int]$_.block_index
        position_index = [int]$_.position_index; cell_id = [string]$_.cell_id
        job_id = [string]$_.job_id; run_id = [string]$_.run_id; package_ref = $_.package_ref
        metrics = $_.metrics; total_requests = [long]$_.total_requests
        successful_requests = [long]$_.successful_requests
        failed_requests = [long]$_.failed_requests; timeout_requests = [long]$_.timeout_requests
        bytes_sent = [long]$_.bytes_sent; bytes_received = [long]$_.bytes_received
        load_generator_saturation_status = [string]$_.load_generator_saturation_status
        bounded_aggregate = $_.bounded_aggregate; load_process = $_.load_process
        target_runtime_counter_status = [string]$_.target_runtime_counter_status
    }
})

$cells = @(
    foreach ($cellId in @(
        'cell.queued_send_burst_budget.performance.q0',
        'cell.queued_send_burst_budget.performance.q1')) {
        $cellRows = @($rows | Where-Object cell_id -CEQ $cellId)
        [pscustomobject][ordered]@{
            cell_id = $cellId
            queued_send_burst_budget =
                [string]$bindingByCell[$cellId].queued_send_burst_budget
            package_ref = Convert-PackageReference $packageByCell[$cellId]
            requests_per_second = Get-Statistics @($cellRows.metrics.requests_per_second)
            useful_bytes_per_second = Get-Statistics @($cellRows.metrics.useful_bytes_per_second)
            latency_p50_ms = Get-Statistics @($cellRows.metrics.latency_p50_ms)
            latency_p95_ms = Get-Statistics @($cellRows.metrics.latency_p95_ms)
            bounded_evidence_totals = [pscustomobject][ordered]@{
                epoch_count = Get-MeasureSum $cellRows 'bounded_aggregate.epoch_count'
                stdout_bytes = Get-MeasureSum $cellRows 'bounded_aggregate.stdout_bytes'
                queued_send_burst_evidence_count =
                    Get-MeasureSum $cellRows 'bounded_aggregate.queued_send_burst_evidence_count'
                legal_budget_gt_one_count =
                    Get-MeasureSum $cellRows 'bounded_aggregate.legal_budget_gt_one_count'
                arithmetic_saturated = $false
            }
        }
    }
)

$metricIds = @('requests_per_second','useful_bytes_per_second',
    'latency_p50_ms','latency_p95_ms')
$blockSummaries = @(
    foreach ($block in 1..8) {
        $blockRows = @($rows | Where-Object { [int]$_.block_index -eq $block } |
            Sort-Object position_index)
        Assert-Result ($blockRows.Count -eq 2 -and
            @($blockRows.cell_id | Sort-Object -Unique).Count -eq 2) `
            "queued_block_invalid:$block"
        $q0 = @($blockRows | Where-Object {
            [string]$_.cell_id -ceq
                'cell.queued_send_burst_budget.performance.q0' })[0]
        $q1 = @($blockRows | Where-Object {
            [string]$_.cell_id -ceq
                'cell.queued_send_burst_budget.performance.q1' })[0]
        [pscustomobject][ordered]@{
            block_index = $block
            order = [string]::Join('_then_', @($blockRows | ForEach-Object {
                Get-CellLabel ([string]$_.cell_id) }))
            directional_differences_q1_minus_q0 = [pscustomobject][ordered]@{
                requests_per_second = [double]$q1.metrics.requests_per_second -
                    [double]$q0.metrics.requests_per_second
                useful_bytes_per_second = [double]$q1.metrics.useful_bytes_per_second -
                    [double]$q0.metrics.useful_bytes_per_second
                latency_p50_ms = [double]$q1.metrics.latency_p50_ms -
                    [double]$q0.metrics.latency_p50_ms
                latency_p95_ms = [double]$q1.metrics.latency_p95_ms -
                    [double]$q0.metrics.latency_p95_ms
            }
        }
    }
)

$orderSummaries = @(
    foreach ($order in @('q0_then_q1','q1_then_q0')) {
        $blocks = @($blockSummaries | Where-Object order -CEQ $order)
        Assert-Result ($blocks.Count -eq 4) "queued_order_balance_invalid:$order"
        [pscustomobject][ordered]@{
            order = $order; block_count = 4
            directional_differences_q1_minus_q0 = [pscustomobject][ordered]@{
                requests_per_second = Get-Statistics @(
                    $blocks.directional_differences_q1_minus_q0.requests_per_second)
                useful_bytes_per_second = Get-Statistics @(
                    $blocks.directional_differences_q1_minus_q0.useful_bytes_per_second)
                latency_p50_ms = Get-Statistics @(
                    $blocks.directional_differences_q1_minus_q0.latency_p50_ms)
                latency_p95_ms = Get-Statistics @(
                    $blocks.directional_differences_q1_minus_q0.latency_p95_ms)
            }
        }
    }
)

$overallDirectional = [pscustomobject][ordered]@{}
foreach ($metricId in $metricIds) {
    $overallDirectional | Add-Member -NotePropertyName $metricId -NotePropertyValue (
        Get-Statistics @($blockSummaries.directional_differences_q1_minus_q0.$metricId))
}

$nodeById = @{}
foreach ($node in $nodes) { $nodeById[[string]$node.nodeId] = $node }
Assert-Result ($nodeById.ContainsKey('plab-worker-x64-02') -and
    $nodeById.ContainsKey('plab-worker-x64-03')) 'queued_worker_snapshot_missing'
$warningCodes = @($rows.load_process.warnings | ForEach-Object { [string]$_ } |
    Sort-Object -Unique)

$result = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-queued-send-performance-result-v1'
    document_id = 'adaptive_runtime_queued_send_performance_result_v1'
    document_version = 1; content_sha256 = '0' * 64
    control_ref = New-DocumentReference $control
    compiled_manifest_ref = New-DocumentReference $compiled
    source_commit = [string]$state.source_commit; source_dirty_state = 'clean'
    controller_uri = [string]$state.controller_uri
    worker_pair = [pscustomobject][ordered]@{
        topology_classification = 'independent_physical_hosts'
        sut_node_id = 'plab-worker-x64-02'
        sut_physical_host_id =
            [string]$nodeById['plab-worker-x64-02'].capabilities.labels.physicalHostId
        load_node_id = 'plab-worker-x64-03'
        load_physical_host_id =
            [string]$nodeById['plab-worker-x64-03'].capabilities.labels.physicalHostId
    }
    workload = [pscustomobject][ordered]@{
        suite_id = [string]$control.package_selection.suite_id
        scenario_id = [string]$control.package_selection.scenario_id
        protocol = [string]$control.package_selection.protocol
        test_executor_id = [string]$control.package_selection.test_executor_id
        load_profile_id = [string]$control.package_selection.load_profile_id
        repetitions_per_cell = 8; block_count = 8
    }
    activation_preflight = [pscustomobject][ordered]@{
        predicate_id = [string]$preflight.predicate_id
        cell_id = 'cell.queued_send_burst_budget.performance.q1'
        job_id = [string]$preflight.job_id; run_id = [string]$preflight.run_id
        activation_observed = $true; accepted_timed_row = $false
        attempt_count = @($preflight.attempts).Count
        failed_attempt_count = $failedPreflightAttempts.Count
    }
    run_counts = [pscustomobject][ordered]@{
        planned_runs = 16; completed_runs = 16; actual_measurements_run = 16
        activation_preflight_runs = 1; failed_attempts = $failedAttempts.Count
        failed_requests = Get-MeasureSum $rows 'failed_requests'
        timeout_requests = Get-MeasureSum $rows 'timeout_requests'
        saturated_runs = @($rows | Where-Object {
            [string]$_.load_generator_saturation_status -cne
                'load-generator-saturation-not-detected' }).Count
    }
    packages = $packages; failed_attempts = $failedAttempts; runs = $runs; cells = $cells
    block_summaries = $blockSummaries; order_summaries = $orderSummaries
    overall_directional_differences_q1_minus_q0 = $overallDirectional
    resource_telemetry = [pscustomobject][ordered]@{
        load_process_samples_present = $true
        load_process_warnings_retained = $warningCodes
        target_runtime_counter_status = if (@($rows |
            Where-Object target_runtime_counter_status -CEQ 'captured').Count -gt 0) {
                'partially_or_fully_captured' } else { 'unavailable' }
        load_cpu_percent = Get-Statistics @($rows.load_process.normalized_cpu_percent_mean)
        load_cpu_peak_interval_max = [double](($rows.load_process.
            normalized_cpu_percent_peak_interval | Measure-Object -Maximum).Maximum)
        load_memory_max_bytes = [long](($rows.load_process.memory_max_bytes |
            Measure-Object -Maximum).Maximum)
        server_stdout_bytes = Get-Statistics @($rows.bounded_aggregate.stdout_bytes)
        bounded_server_stdout_max_bytes =
            [long]$control.resource_metrics.bounded_server_stdout_max_bytes
    }
    analysis_boundary = [pscustomobject][ordered]@{
        classification = 'descriptive_characterization_only'
        directional_difference_definition =
            'single_datagram_minus_legacy_current_within_each_counterbalanced_block'
        threshold_available = $false; winner_selection_authorized = $false
        performance_acceptance_authorized = $false
        adaptive_rule_derivation_authorized = $false
        active_behavior_authorized = $false
        production_activation_authorized = $false
    }
    covering_array = [pscustomobject][ordered]@{
        generator_implemented = $false
        required_for_current_two_cell_family = $false
    }
    limitations = @('one_worker_pair_only','one_workload_only',
        'no_predeclared_practical_threshold','no_winner_or_rule_derivation',
        'characterization_only')
    conclusion = 'queued_send_campaign_completed_characterization_only_no_rule'
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = $control.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $result)
Assert-Result (Test-AdaptiveRuntimeJsonSchema $result $schemaPath) `
    'queued_result_schema_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $result) 'queued_result_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $result $OutputPath

if ($PassThru) { $result } else {
    [pscustomobject][ordered]@{
        result_path = [IO.Path]::GetFullPath($OutputPath)
        result_sha256 = [string]$result.content_sha256
        completed_run_count = 16; failed_attempt_count = $failedAttempts.Count
        block_summary_count = 8; order_summary_count = 2
        conclusion = [string]$result.conclusion
    } | ConvertTo-Json -Depth 8
}
