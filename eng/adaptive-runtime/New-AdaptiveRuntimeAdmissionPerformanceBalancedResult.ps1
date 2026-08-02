# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExecutionRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $OutputPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-balanced-result-v1.json'),
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Result([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
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

function Get-Median([double[]] $Values) {
    $ordered = @($Values | Sort-Object)
    Assert-Result ($ordered.Count -gt 0) 'median_input_empty'
    if (($ordered.Count % 2) -eq 1) {
        return [double]$ordered[[int][math]::Floor($ordered.Count / 2)]
    }
    return (
        [double]$ordered[($ordered.Count / 2) - 1] +
        [double]$ordered[$ordered.Count / 2]
    ) / 2.0
}

function Get-Statistics([double[]] $Values) {
    Assert-Result ($Values.Count -gt 0) 'statistics_input_empty'
    $mean = [double](($Values | Measure-Object -Average).Average)
    $sumOfSquares = 0.0
    foreach ($value in $Values) {
        $sumOfSquares += [math]::Pow(([double]$value - $mean), 2)
    }
    $standardDeviation = if ($Values.Count -gt 1) {
        [math]::Sqrt($sumOfSquares / ($Values.Count - 1))
    }
    else {
        0.0
    }
    [pscustomobject][ordered]@{
        n = $Values.Count
        mean = $mean
        median = Get-Median $Values
        sample_standard_deviation = $standardDeviation
        coefficient_of_variation_percent = if ($mean -ne 0.0) {
            100.0 * $standardDeviation / [math]::Abs($mean)
        }
        else {
            0.0
        }
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

$executionRootFull = [IO.Path]::GetFullPath($ExecutionRoot)
$controlPath = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-balanced-campaign-v1.json'
$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-performance-balanced-result-v1.schema.json'
$control = Read-AdaptiveRuntimeJsonDocument $controlPath
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

Assert-Result (Test-AdaptiveRuntimeDocumentHash $control) `
    'balanced_control_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $compiled) `
    'balanced_manifest_hash_invalid'
Assert-Result (
    [string]$state.control_sha256 -ceq [string]$control.content_sha256 -and
    [string]$state.manifest_sha256 -ceq [string]$compiled.content_sha256 -and
    [string]$state.source_commit -match '^[0-9a-f]{40}$' -and
    [string]$state.source_dirty_state -ceq 'clean' -and
    [int]$state.planned_run_count -eq 64 -and
    [int]$state.completed_run_count -eq 64 -and
    [int]$state.failed_attempt_count -eq 2
) 'campaign_state_identity_or_count_invalid'
Assert-Result (
    $state.performance_acceptance_authorization -eq $false -and
    $state.adaptive_rule_derivation_authorization -eq $false -and
    $state.active_behavior_authorization -eq $false -and
    $state.production_activation_authorization -eq $false
) 'campaign_state_authorization_invalid'
Assert-Result (
    @($compiled.planned_runs).Count -eq 64 -and
    @($packageIdentities).Count -eq 8
) 'manifest_or_package_count_invalid'

$bindingByCell = @{}
foreach ($binding in @($control.cell_bindings)) {
    $bindingByCell[[string]$binding.cell_id] = $binding
}
$packageByCell = @{}
$packages = @(
    foreach ($identity in @($packageIdentities | Sort-Object cell_id)) {
        $cellId = [string]$identity.cell_id
        Assert-Result ($bindingByCell.ContainsKey($cellId)) `
            "package_cell_unknown:$cellId"
        $packageByCell[$cellId] = $identity.package_ref
        [pscustomobject][ordered]@{
            cell_id = $cellId
            package_ref = Convert-PackageReference $identity.package_ref
        }
    }
)
Assert-Result (@($packageByCell.Keys | Sort-Object -Unique).Count -eq 8) `
    'package_cell_identity_not_unique'

$completedAttempts = @(
    $state.attempts |
        Where-Object outcome -CEQ 'Completed' |
        Sort-Object execution_index
)
$failedAttemptsSource = @(
    $state.attempts |
        Where-Object outcome -CNE 'Completed' |
        Sort-Object execution_index, attempt_index
)
Assert-Result (
    $completedAttempts.Count -eq 64 -and
    $failedAttemptsSource.Count -eq 2 -and
    @($completedAttempts.execution_index | Sort-Object -Unique).Count -eq 64 -and
    [string]::Join('|', @($completedAttempts.execution_index)) -ceq
        [string]::Join('|', @(1..64))
) 'attempt_reconciliation_invalid'

$failedAttempts = @(
    foreach ($attempt in $failedAttemptsSource) {
        Assert-Result (
            [string]::IsNullOrWhiteSpace(
                [string]$attempt.measurement_summary_path)
        ) "failed_attempt_has_measurement:$($attempt.job_id)"
        [pscustomobject][ordered]@{
            execution_index = [int]$attempt.execution_index
            attempt_index = [int]$attempt.attempt_index
            cell_id = [string]$attempt.cell_id
            job_id = [string]$attempt.job_id
            failure_reason_code = [string]$attempt.failure_reason_code
            measurement_recorded = $false
        }
    }
)

$rows = [System.Collections.Generic.List[object]]::new()
foreach ($attempt in $completedAttempts) {
    $executionIndex = [int]$attempt.execution_index
    $planned = @($compiled.planned_runs | Where-Object {
        [int]$_.execution_index -eq $executionIndex
    })
    Assert-Result ($planned.Count -eq 1) `
        "planned_run_missing:$executionIndex"
    Assert-Result (
        [string]$planned[0].cell_id -ceq [string]$attempt.cell_id -and
        [int]$planned[0].block_index -eq [int]$attempt.block_index -and
        [int]$planned[0].position_index -eq [int]$attempt.position_index
    ) "planned_run_identity_mismatch:$executionIndex"

    $cellId = [string]$attempt.cell_id
    $expectedPackage = $packageByCell[$cellId]
    Assert-Result (
        [string]$attempt.package_ref.packageId -ceq
            [string]$expectedPackage.packageId -and
        [string]$attempt.package_ref.packageVersion -ceq
            [string]$expectedPackage.packageVersion -and
        [string]$attempt.package_ref.sha256 -ceq
            [string]$expectedPackage.sha256
    ) "package_identity_mismatch:$executionIndex"
    Assert-Result (
        [string]$attempt.topology.classification -ceq
            'independent_physical_hosts' -and
        [string]$attempt.topology.sutNodeId -ceq
            'plab-worker-x64-02' -and
        [string]$attempt.topology.loadNodeId -ceq
            'plab-worker-x64-03' -and
        [string]$attempt.topology.sutPhysicalHostId -cne
            [string]$attempt.topology.loadPhysicalHostId
    ) "topology_invariant_failed:$executionIndex"

    $summary = Get-Content -LiteralPath (
        [string]$attempt.measurement_summary_path) -Raw |
        ConvertFrom-Json -Depth 100
    $benchmark = $summary.benchmark
    $bounded = $summary.bounded_aggregate
    $epoch = $bounded.final_epoch
    $load = $summary.load_process_metrics
    Assert-Result (
        [string]$summary.schema_version -ceq
            'adaptive-runtime-admission-performance-balanced-measurement-summary-v1' -and
        [int]$summary.execution_index -eq $executionIndex -and
        [string]$summary.cell_id -ceq $cellId -and
        [string]$summary.job_id -ceq [string]$attempt.job_id
    ) "measurement_identity_mismatch:$executionIndex"
    Assert-Result (
        [long]$benchmark.total_requests -gt 0 -and
        [long]$benchmark.successful_requests -eq
            [long]$benchmark.total_requests -and
        [long]$benchmark.failed_requests -eq 0 -and
        [long]$benchmark.timeout_requests -eq 0 -and
        [long]$benchmark.bytes_sent -gt 0 -and
        [long]$benchmark.bytes_sent -eq [long]$benchmark.bytes_received -and
        [string]$benchmark.load_generator_saturation_status -ceq
            'load-generator-saturation-not-detected'
    ) "measurement_invariant_failed:$executionIndex"
    Assert-Result (
        [int]$bounded.epoch_count -gt 0 -and
        [long]$bounded.stdout_bytes -gt 0 -and
        [long]$bounded.stdout_bytes -le
            [long]$control.resource_metrics.bounded_server_stdout_max_bytes -and
        [string]$epoch.schemaVersion -ceq
            'adaptive-runtime-bounded-aggregate-epoch-v1' -and
        [long]$epoch.applicationSendBatchEvidenceCount -gt 0 -and
        [long]$epoch.applicationSendBatchAppliedWriteCount -gt 0 -and
        [long]$epoch.oversizedWriteEvidenceCount -gt 0 -and
        [long]$epoch.oversizedCommittedFragments -gt 0 -and
        [long]$epoch.oversizedCommittedBytes -gt 0 -and
        [long]$epoch.bufferCopyOperationCount -gt 0 -and
        [long]$epoch.ownerReleaseCount -gt 0 -and
        $epoch.arithmeticSaturated -eq $false
    ) "bounded_aggregate_invariant_failed:$executionIndex"
    Assert-Result (
        [int]$load.sample_count -gt 0 -and
        [double]$load.normalized_cpu_percent_mean -ge 0 -and
        [double]$load.normalized_cpu_percent_peak_interval -ge 0 -and
        [long]$load.memory_max_bytes -gt 0 -and
        [string]$summary.target_process_metrics.runtime_counter_status -ceq
            'unavailable'
    ) "resource_telemetry_invariant_failed:$executionIndex"
    Assert-Result (
        $summary.performance_acceptance_authorized -eq $false -and
        $summary.adaptive_rule_derivation_authorized -eq $false -and
        $summary.active_behavior_authorized -eq $false -and
        $summary.production_activation_authorized -eq $false
    ) "measurement_authorization_invalid:$executionIndex"

    $binding = $bindingByCell[$cellId]
    $oversizedCode = if (
        [string]$binding.oversized_write_admission_quantum -ceq
            'single_fragment') { 1 } else { -1 }
    $batchCode = if (
        [string]$binding.application_send_batch_formation -ceq
            'single_eligible') { 1 } else { -1 }
    $bufferCode = if (
        [string]$binding.buffer_copy_coalescing -ceq
            'memory_conservative') { 1 } else { -1 }
    [void]$rows.Add([pscustomobject][ordered]@{
        execution_index = $executionIndex
        block_index = [int]$attempt.block_index
        position_index = [int]$attempt.position_index
        cell_id = $cellId
        job_id = [string]$attempt.job_id
        run_id = [string]$attempt.run_id
        package_ref = Convert-PackageReference $attempt.package_ref
        oversized_code = $oversizedCode
        batch_code = $batchCode
        buffer_code = $bufferCode
        metrics = [pscustomobject][ordered]@{
            requests_per_second = [double]$benchmark.requests_per_second
            useful_bytes_per_second =
                [double]$benchmark.throughput_bytes_per_second
            latency_p50_ms = [double]$benchmark.latency_p50_ms
            latency_p95_ms = [double]$benchmark.latency_p95_ms
        }
        total_requests = [long]$benchmark.total_requests
        successful_requests = [long]$benchmark.successful_requests
        failed_requests = [long]$benchmark.failed_requests
        timeout_requests = [long]$benchmark.timeout_requests
        bytes_sent = [long]$benchmark.bytes_sent
        bytes_received = [long]$benchmark.bytes_received
        load_generator_saturation_status =
            [string]$benchmark.load_generator_saturation_status
        bounded_aggregate = [pscustomobject][ordered]@{
            epoch_count = [long]$bounded.epoch_count
            stdout_bytes = [long]$bounded.stdout_bytes
            application_send_batch_evidence_count =
                [long]$epoch.applicationSendBatchEvidenceCount
            application_send_batch_applied_write_count =
                [long]$epoch.applicationSendBatchAppliedWriteCount
            oversized_write_evidence_count =
                [long]$epoch.oversizedWriteEvidenceCount
            oversized_committed_fragments =
                [long]$epoch.oversizedCommittedFragments
            oversized_committed_bytes =
                [long]$epoch.oversizedCommittedBytes
            buffer_copy_operation_count =
                [long]$epoch.bufferCopyOperationCount
            owner_release_count = [long]$epoch.ownerReleaseCount
            arithmetic_saturated = [bool]$epoch.arithmeticSaturated
        }
        load_process = [pscustomobject][ordered]@{
            sample_count = [int]$load.sample_count
            normalized_cpu_percent_mean =
                [double]$load.normalized_cpu_percent_mean
            normalized_cpu_percent_peak_interval =
                [double]$load.normalized_cpu_percent_peak_interval
            memory_max_bytes = [long]$load.memory_max_bytes
            warnings = @($load.warnings | ForEach-Object { [string]$_ })
        }
        target_runtime_counter_status =
            [string]$summary.target_process_metrics.runtime_counter_status
    })
}

Assert-Result (
    @($rows.job_id | Sort-Object -Unique).Count -eq 64 -and
    @($rows.run_id | Sort-Object -Unique).Count -eq 64 -and
    @($rows | Group-Object cell_id | Where-Object Count -eq 8).Count -eq 8 -and
    @($rows | Group-Object block_index | Where-Object Count -eq 8).Count -eq 8 -and
    @($rows | Group-Object position_index | Where-Object Count -eq 8).Count -eq 8
) 'balanced_run_shape_invalid'
foreach ($cellId in @('a0','a1','a2','a3','a4','a5','a6','a7')) {
    $cellRows = @($rows | Where-Object cell_id -CEQ $cellId)
    Assert-Result (
        @($cellRows.block_index | Sort-Object -Unique).Count -eq 8 -and
        @($cellRows.position_index | Sort-Object -Unique).Count -eq 8
    ) "cell_balance_invalid:$cellId"
}

$runs = @(
    foreach ($row in $rows) {
        [pscustomobject][ordered]@{
            execution_index = [int]$row.execution_index
            block_index = [int]$row.block_index
            position_index = [int]$row.position_index
            cell_id = [string]$row.cell_id
            job_id = [string]$row.job_id
            run_id = [string]$row.run_id
            package_ref = $row.package_ref
            metrics = $row.metrics
            total_requests = [long]$row.total_requests
            successful_requests = [long]$row.successful_requests
            failed_requests = [long]$row.failed_requests
            timeout_requests = [long]$row.timeout_requests
            bytes_sent = [long]$row.bytes_sent
            bytes_received = [long]$row.bytes_received
            load_generator_saturation_status =
                [string]$row.load_generator_saturation_status
            bounded_aggregate = $row.bounded_aggregate
            load_process = $row.load_process
            target_runtime_counter_status =
                [string]$row.target_runtime_counter_status
        }
    }
)

$metricIds = @(
    'requests_per_second',
    'useful_bytes_per_second',
    'latency_p50_ms',
    'latency_p95_ms'
)
$cells = @(
    foreach ($cellId in @('a0','a1','a2','a3','a4','a5','a6','a7')) {
        $cellRows = @($rows | Where-Object cell_id -CEQ $cellId)
        $binding = $bindingByCell[$cellId]
        [pscustomobject][ordered]@{
            cell_id = $cellId
            policy_values = [pscustomobject][ordered]@{
                oversized_write_admission_quantum =
                    [string]$binding.oversized_write_admission_quantum
                application_send_batch_formation =
                    [string]$binding.application_send_batch_formation
                buffer_copy_coalescing =
                    [string]$binding.buffer_copy_coalescing
            }
            package_ref = Convert-PackageReference $packageByCell[$cellId]
            requests_per_second = Get-Statistics @(
                $cellRows.metrics.requests_per_second)
            useful_bytes_per_second = Get-Statistics @(
                $cellRows.metrics.useful_bytes_per_second)
            latency_p50_ms = Get-Statistics @(
                $cellRows.metrics.latency_p50_ms)
            latency_p95_ms = Get-Statistics @(
                $cellRows.metrics.latency_p95_ms)
            activation_totals = [pscustomobject][ordered]@{
                epoch_count = Get-MeasureSum $cellRows `
                    'bounded_aggregate.epoch_count'
                stdout_bytes = Get-MeasureSum $cellRows `
                    'bounded_aggregate.stdout_bytes'
                application_send_batch_evidence_count =
                    Get-MeasureSum $cellRows `
                        'bounded_aggregate.application_send_batch_evidence_count'
                application_send_batch_applied_write_count =
                    Get-MeasureSum $cellRows `
                        'bounded_aggregate.application_send_batch_applied_write_count'
                oversized_write_evidence_count =
                    Get-MeasureSum $cellRows `
                        'bounded_aggregate.oversized_write_evidence_count'
                oversized_committed_fragments =
                    Get-MeasureSum $cellRows `
                        'bounded_aggregate.oversized_committed_fragments'
                oversized_committed_bytes =
                    Get-MeasureSum $cellRows `
                        'bounded_aggregate.oversized_committed_bytes'
                buffer_copy_operation_count =
                    Get-MeasureSum $cellRows `
                        'bounded_aggregate.buffer_copy_operation_count'
                owner_release_count = Get-MeasureSum $cellRows `
                    'bounded_aggregate.owner_release_count'
                arithmetic_saturated = $false
            }
        }
    }
)

function New-IndexSummaries([string] $Property) {
    @(
        foreach ($group in @($rows | Group-Object $Property |
            Sort-Object { [int]$_.Name })) {
            [pscustomobject][ordered]@{
                index = [int]$group.Name
                requests_per_second = Get-Statistics @(
                    $group.Group.metrics.requests_per_second)
                latency_p95_ms = Get-Statistics @(
                    $group.Group.metrics.latency_p95_ms)
            }
        }
    )
}

$contrastDefinitions = @(
    [pscustomobject]@{ term = 'oversized'; factors = @('oversized_write_admission_quantum'); code = { param($row) $row.oversized_code } },
    [pscustomobject]@{ term = 'batch'; factors = @('application_send_batch_formation'); code = { param($row) $row.batch_code } },
    [pscustomobject]@{ term = 'buffer'; factors = @('buffer_copy_coalescing'); code = { param($row) $row.buffer_code } },
    [pscustomobject]@{ term = 'oversized_x_batch'; factors = @('oversized_write_admission_quantum','application_send_batch_formation'); code = { param($row) $row.oversized_code * $row.batch_code } },
    [pscustomobject]@{ term = 'oversized_x_buffer'; factors = @('oversized_write_admission_quantum','buffer_copy_coalescing'); code = { param($row) $row.oversized_code * $row.buffer_code } },
    [pscustomobject]@{ term = 'batch_x_buffer'; factors = @('application_send_batch_formation','buffer_copy_coalescing'); code = { param($row) $row.batch_code * $row.buffer_code } },
    [pscustomobject]@{ term = 'oversized_x_batch_x_buffer'; factors = @('oversized_write_admission_quantum','application_send_batch_formation','buffer_copy_coalescing'); code = { param($row) $row.oversized_code * $row.batch_code * $row.buffer_code } }
)
$contrasts = @(
    foreach ($definition in $contrastDefinitions) {
        $code = $definition.code
        $positive = @($rows | Where-Object { (& $code $_) -eq 1 })
        $negative = @($rows | Where-Object { (& $code $_) -eq -1 })
        Assert-Result (
            $positive.Count -eq 32 -and $negative.Count -eq 32
        ) "contrast_balance_invalid:$($definition.term)"
        $effects = @(
            foreach ($metricId in $metricIds) {
                $positiveValues = @($positive | ForEach-Object {
                    [double]$_.metrics.$metricId
                })
                $negativeValues = @($negative | ForEach-Object {
                    [double]$_.metrics.$metricId
                })
                $allValues = @($rows | ForEach-Object {
                    [double]$_.metrics.$metricId
                })
                $positiveMean = [double](
                    ($positiveValues | Measure-Object -Average).Average)
                $negativeMean = [double](
                    ($negativeValues | Measure-Object -Average).Average)
                $grandMean = [double](
                    ($allValues | Measure-Object -Average).Average)
                $effect = $positiveMean - $negativeMean
                $blockEffects = @(
                    foreach ($block in 1..8) {
                        $blockRows = @($rows | Where-Object {
                            [int]$_.block_index -eq $block
                        })
                        $blockPositive = @($blockRows | Where-Object {
                            (& $code $_) -eq 1
                        } | ForEach-Object {
                            [double]$_.metrics.$metricId
                        })
                        $blockNegative = @($blockRows | Where-Object {
                            (& $code $_) -eq -1
                        } | ForEach-Object {
                            [double]$_.metrics.$metricId
                        })
                        [double](
                            ($blockPositive | Measure-Object -Average).Average -
                            ($blockNegative | Measure-Object -Average).Average)
                    }
                )
                [pscustomobject][ordered]@{
                    metric_id = $metricId
                    grand_mean = $grandMean
                    negative_mean = $negativeMean
                    positive_mean = $positiveMean
                    effect = $effect
                    effect_percent_of_grand_mean = if ($grandMean -ne 0.0) {
                        100.0 * $effect / [math]::Abs($grandMean)
                    }
                    else { 0.0 }
                    block_effects = Get-Statistics $blockEffects
                }
            }
        )
        [pscustomobject][ordered]@{
            term = [string]$definition.term
            factors = @($definition.factors)
            classification = 'descriptive_characterization_only'
            effects = $effects
        }
    }
)

$nodeById = @{}
foreach ($node in $nodes) {
    $nodeById[[string]$node.nodeId] = $node
}
$sutNode = $nodeById['plab-worker-x64-02']
Assert-Result ($null -ne $sutNode -and
    $nodeById.ContainsKey('plab-worker-x64-03')) `
    'selected_worker_snapshot_missing'

$warningCodes = @($rows.load_process.warnings |
    ForEach-Object { [string]$_ } | Sort-Object -Unique)
$limitations = [System.Collections.Generic.List[string]]::new()
foreach ($limitation in @(
    'one_worker_pair_only',
    'one_workload_only',
    'same_pair_and_workload_not_held_out_validation',
    'target_runtime_counters_unavailable',
    'load_process_warnings_retained',
    'predeclared_practical_thresholds_unavailable',
    'performance_acceptance_and_rule_derivation_blocked'
)) {
    $limitations.Add($limitation)
}
$a5 = @($cells | Where-Object cell_id -CEQ 'a5')[0]
if ([double]$a5.requests_per_second.coefficient_of_variation_percent -gt 5.0) {
    $limitations.Add('a5_high_variability_requires_independent_validation')
}

$result = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-performance-balanced-result-v1'
    document_id =
        'adaptive_runtime_send_admission_performance_balanced_result_v1'
    document_version = 1
    content_sha256 = '0' * 64
    control_ref = New-DocumentReference $control
    compiled_manifest_ref = New-DocumentReference $compiled
    source_commit = [string]$state.source_commit
    source_dirty_state = [string]$state.source_dirty_state
    controller_uri = [string]$state.controller_uri
    worker_pair = [pscustomobject][ordered]@{
        topology_classification = 'independent_physical_hosts'
        evidence_tier =
            [string]$sutNode.capabilities.labels.evidenceTier
        identity_caveat =
            [string]$sutNode.capabilities.labels.identityCaveat
        sut_node_id = 'plab-worker-x64-02'
        sut_physical_host_id =
            [string]$sutNode.capabilities.labels.physicalHostId
        load_node_id = 'plab-worker-x64-03'
        load_physical_host_id =
            [string]$nodeById['plab-worker-x64-03'].capabilities.labels.physicalHostId
    }
    workload = [pscustomobject][ordered]@{
        suite_id = [string]$control.package_selection.suite_id
        scenario_id = [string]$control.package_selection.scenario_id
        protocol = [string]$control.package_selection.protocol
        test_executor_id =
            [string]$control.package_selection.test_executor_id
        load_profile_id =
            [string]$control.package_selection.load_profile_id
        repetitions_per_cell = [int]$control.design.repetitions_per_cell
        block_count = [int]$control.design.block_count
    }
    run_counts = [pscustomobject][ordered]@{
        planned_runs = 64
        completed_runs = 64
        actual_measurements_run = 64
        failed_attempts = $failedAttempts.Count
        failed_requests = Get-MeasureSum $rows 'failed_requests'
        timeout_requests = Get-MeasureSum $rows 'timeout_requests'
        saturated_runs = @($rows | Where-Object {
            [string]$_.load_generator_saturation_status -cne
                'load-generator-saturation-not-detected'
        }).Count
    }
    packages = $packages
    failed_attempts = $failedAttempts
    runs = $runs
    cells = $cells
    block_summaries = New-IndexSummaries 'block_index'
    position_summaries = New-IndexSummaries 'position_index'
    factorial_contrasts = $contrasts
    resource_telemetry = [pscustomobject][ordered]@{
        load_process_samples_present = $true
        load_process_warnings_retained = $warningCodes
        target_runtime_counter_status = 'unavailable'
        load_cpu_percent = Get-Statistics @(
            $rows.load_process.normalized_cpu_percent_mean)
        load_cpu_peak_interval_max = [double](
            ($rows.load_process.normalized_cpu_percent_peak_interval |
                Measure-Object -Maximum).Maximum)
        load_memory_max_bytes = [long](
            ($rows.load_process.memory_max_bytes |
                Measure-Object -Maximum).Maximum)
        server_stdout_bytes = Get-Statistics @(
            $rows.bounded_aggregate.stdout_bytes)
        bounded_server_stdout_max_bytes =
            [long]$control.resource_metrics.bounded_server_stdout_max_bytes
    }
    analysis_boundary = [pscustomobject][ordered]@{
        classification = 'descriptive_characterization_only'
        contrast_definition =
            'mean_at_positive_coding_minus_mean_at_negative_coding'
        block_effect_definition =
            'same_contrast_recomputed_once_per_balanced_block'
        predeclared_practical_thresholds_available = $false
        threshold_consequence =
            'blocks_performance_acceptance_and_rule_derivation'
        held_out_validation_available = $false
    }
    covering_array = [pscustomobject][ordered]@{
        generator_implemented = $false
        required_for_current_eight_cell_family = $false
        trigger_effective_cell_count =
            [int]$control.covering_array_trigger_effective_cell_count
    }
    limitations = @($limitations)
    conclusion =
        'balanced_campaign_completed_characterization_only_no_rule'
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = $control.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $result)
Assert-Result (
    Test-AdaptiveRuntimeJsonSchema $result $schemaPath
) 'balanced_result_schema_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $result) `
    'balanced_result_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $result $OutputPath

if ($PassThru) {
    $result
}
else {
    [pscustomobject][ordered]@{
        result_path = [IO.Path]::GetFullPath($OutputPath)
        result_sha256 = [string]$result.content_sha256
        completed_run_count = $rows.Count
        failed_attempt_count = $failedAttempts.Count
        contrast_count = $contrasts.Count
        conclusion = [string]$result.conclusion
    } | ConvertTo-Json -Depth 6
}
