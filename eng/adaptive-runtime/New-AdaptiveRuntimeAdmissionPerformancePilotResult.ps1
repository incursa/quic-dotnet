# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExecutionRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $OutputPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-pilot-result-v1.json'),
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

function Get-DescriptiveMidpoint([object[]] $Repetitions, [string] $Property) {
    Assert-Result ($Repetitions.Count -eq 2) `
        "descriptive_midpoint_repetition_count_invalid:$Property"
    (
        [double]$Repetitions[0].$Property +
        [double]$Repetitions[1].$Property
    ) / 2.0
}

$executionRootFull = [IO.Path]::GetFullPath($ExecutionRoot)
$pilotPath = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json'
$pilot = Read-AdaptiveRuntimeJsonDocument $pilotPath
$compiled = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $executionRootFull 'compiled-manifest.json')
$execution = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $executionRootFull 'execution-manifest.json')
$nodes = @(
    Get-Content -LiteralPath (
        Join-Path $executionRootFull 'controller-nodes.json') -Raw |
        ConvertFrom-Json
)

Assert-Result (Test-AdaptiveRuntimeDocumentHash $pilot) 'pilot_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $compiled) `
    'compiled_manifest_hash_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $execution) `
    'execution_manifest_hash_invalid'
Assert-Result (
    @($execution.planned_runs).Count -eq 4 -and
    @($execution.planned_runs |
        Where-Object {
            [string]$_.state -ceq 'completed' -and
            [string]$_.outcome -ceq 'Completed' -and
            [string]$_.topology.classification -ceq
                'independent_physical_hosts'
        }).Count -eq 4
) 'execution_manifest_not_complete'

$cellOrder = @('a0', 'a4', 'a3', 'a7')
$cellResults = [System.Collections.Generic.List[object]]::new()
$sourceCommit = $null
$allRepetitions = [System.Collections.Generic.List[object]]::new()
foreach ($cellId in $cellOrder) {
    $run = @(
        $execution.planned_runs |
            Where-Object cell_id -CEQ $cellId
    )
    Assert-Result ($run.Count -eq 1) "execution_cell_missing:$cellId"
    $jobPath = Join-Path $executionRootFull "cells\$cellId\job-result.json"
    $summaryPath = Join-Path $executionRootFull `
        "cells\$cellId\downloads\measurement-summary.json"
    $stdoutPath = Join-Path $executionRootFull `
        "cells\$cellId\downloads\server.stdout.txt"
    $job = Get-Content -LiteralPath $jobPath -Raw | ConvertFrom-Json
    $summary = Get-Content -LiteralPath $summaryPath -Raw |
        ConvertFrom-Json
    $implementationPackage = @(
        $job.result.packages |
            Where-Object packageId -CEQ 'quic-dotnet-raw-dev'
    )
    Assert-Result ($implementationPackage.Count -eq 1) `
        "implementation_package_missing:$cellId"
    if ($null -eq $sourceCommit) {
        $sourceCommit =
            [string]$implementationPackage[0].sourceCommitSha
    }
    Assert-Result (
        [string]$implementationPackage[0].sourceCommitSha -ceq
            $sourceCommit -and
        [string]$implementationPackage[0].sourceDirtyState -ceq 'clean'
    ) "source_identity_mismatch:$cellId"

    $repetitions = @(
        $summary.repetitions |
            Sort-Object repetition |
            ForEach-Object {
                Assert-Result (
                    [int]$_.repetition -in @(1, 2) -and
                    [long]$_.total_requests -gt 0 -and
                    [long]$_.successful_requests -eq
                        [long]$_.total_requests -and
                    [long]$_.failed_requests -eq 0 -and
                    [long]$_.timeout_requests -eq 0 -and
                    [long]$_.bytes_sent -gt 0 -and
                    [long]$_.bytes_sent -eq [long]$_.bytes_received -and
                    [string]$_.load_generator_saturation_status -ceq
                        'load-generator-saturation-not-detected'
                ) "measurement_invariant_failed:$cellId:r$($_.repetition)"
                $repetition = [pscustomobject][ordered]@{
                    repetition = [int]$_.repetition
                    requests_per_second =
                        [double]$_.requests_per_second
                    useful_bytes_per_second =
                        [double]$_.throughput_bytes_per_second
                    latency_p50_ms = [double]$_.latency_p50_ms
                    latency_p95_ms = [double]$_.latency_p95_ms
                    total_requests = [long]$_.total_requests
                    successful_requests =
                        [long]$_.successful_requests
                    failed_requests = [long]$_.failed_requests
                    timeout_requests = [long]$_.timeout_requests
                    bytes_sent = [long]$_.bytes_sent
                    bytes_received = [long]$_.bytes_received
                    load_generator_saturation_status =
                        [string]$_.load_generator_saturation_status
                }
                [void]$allRepetitions.Add($repetition)
                $repetition
            }
    )
    Assert-Result ($repetitions.Count -eq 2) `
        "measurement_repetition_count_invalid:$cellId"

    $bounded = $summary.final_bounded_aggregate
    Assert-Result (
        [int]$summary.bounded_aggregate_epoch_count -gt 0 -and
        [string]$bounded.SchemaVersion -ceq
            'adaptive-runtime-bounded-aggregate-epoch-v1' -and
        $bounded.ArithmeticSaturated -eq $false -and
        [long]$bounded.ApplicationSendBatchEvidenceCount -gt 0 -and
        [long]$bounded.OversizedWriteEvidenceCount -gt 0 -and
        [long]$bounded.OversizedCommittedBytes -gt 0 -and
        [long]$bounded.BufferCopyOperationCount -gt 0 -and
        [long]$bounded.OwnerReleaseCount -gt 0
    ) "bounded_aggregate_invariant_failed:$cellId"

    $binding = @(
        $pilot.cell_bindings |
            Where-Object cell_id -CEQ $cellId
    )
    Assert-Result ($binding.Count -eq 1) "pilot_binding_missing:$cellId"
    [void]$cellResults.Add([pscustomobject][ordered]@{
        cell_id = $cellId
        cell_content_sha256 = [string]$binding[0].content_sha256
        policy_values = [pscustomobject][ordered]@{
            oversized_write_admission_quantum =
                [string]$binding[0].oversized_write_admission_quantum
            application_send_batch_formation =
                [string]$binding[0].application_send_batch_formation
            buffer_copy_coalescing =
                [string]$binding[0].buffer_copy_coalescing
        }
        job_id = [string]$job.jobId
        run_id = [string]$job.result.runId
        implementation_package = [pscustomobject][ordered]@{
            package_id =
                [string]$implementationPackage[0].packageId
            package_version =
                [string]$implementationPackage[0].packageVersion
            sha256 = [string]@($job.request.packages |
                Where-Object packageId -CEQ 'quic-dotnet-raw-dev')[0].sha256
        }
        topology = [pscustomobject][ordered]@{
            classification =
                [string]$run[0].topology.classification
            sut_node_id = [string]$run[0].topology.sutNodeId
            sut_physical_host_id =
                [string]$run[0].topology.sutPhysicalHostId
            load_node_id = [string]$run[0].topology.loadNodeId
            load_physical_host_id =
                [string]$run[0].topology.loadPhysicalHostId
        }
        repetitions = $repetitions
        descriptive_midpoint = [pscustomobject][ordered]@{
            requests_per_second =
                Get-DescriptiveMidpoint $repetitions `
                    'requests_per_second'
            useful_bytes_per_second =
                Get-DescriptiveMidpoint $repetitions `
                    'useful_bytes_per_second'
            latency_p50_ms =
                Get-DescriptiveMidpoint $repetitions 'latency_p50_ms'
            latency_p95_ms =
                Get-DescriptiveMidpoint $repetitions 'latency_p95_ms'
        }
        bounded_aggregate = [pscustomobject][ordered]@{
            epoch_count =
                [int]$summary.bounded_aggregate_epoch_count
            stdout_bytes = (Get-Item -LiteralPath $stdoutPath).Length
            connection_count = [long]$bounded.ConnectionCount
            application_send_batch_evidence_count =
                [long]$bounded.ApplicationSendBatchEvidenceCount
            oversized_write_evidence_count =
                [long]$bounded.OversizedWriteEvidenceCount
            oversized_committed_bytes =
                [long]$bounded.OversizedCommittedBytes
            buffer_copy_operation_count =
                [long]$bounded.BufferCopyOperationCount
            owner_release_count =
                [long]$bounded.OwnerReleaseCount
            arithmetic_saturated =
                [bool]$bounded.ArithmeticSaturated
        }
    })
}

Assert-Result (
    @($cellResults.job_id | Sort-Object -Unique).Count -eq 4 -and
    @($cellResults.run_id | Sort-Object -Unique).Count -eq 4
) 'run_identity_not_unique'

$nodeById = @{}
foreach ($node in $nodes) {
    $nodeById[[string]$node.nodeId] = $node
}
$sutNode = $nodeById['plab-worker-x64-02']
$loadNode = $nodeById['plab-worker-x64-03']
Assert-Result ($null -ne $sutNode -and $null -ne $loadNode) `
    'selected_worker_snapshot_missing'

$baseline = @($cellResults | Where-Object cell_id -CEQ 'a0')[0]
$comparisons = @(
    foreach ($cellId in @('a4', 'a3', 'a7')) {
        $cell = @(
            $cellResults | Where-Object cell_id -CEQ $cellId
        )[0]
        $baselineRps =
            [double]$baseline.descriptive_midpoint.requests_per_second
        $baselineP95 =
            [double]$baseline.descriptive_midpoint.latency_p95_ms
        [pscustomobject][ordered]@{
            cell_id = $cellId
            versus_cell_id = 'a0'
            requests_per_second_difference_percent =
                100.0 * (
                    [double]$cell.descriptive_midpoint.requests_per_second -
                    $baselineRps
                ) / $baselineRps
            latency_p95_difference_percent =
                100.0 * (
                    [double]$cell.descriptive_midpoint.latency_p95_ms -
                    $baselineP95
                ) / $baselineP95
            classification = 'directional_only'
        }
    }
)

$result = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-performance-pilot-result-v1'
    document_id =
        'adaptive_runtime_send_admission_performance_pilot_result_v1'
    document_version = 1
    content_sha256 = '0' * 64
    pilot_ref = New-DocumentReference $pilot
    compiled_manifest_ref = New-DocumentReference $compiled
    execution_manifest_ref = New-DocumentReference $execution
    source_commit = $sourceCommit
    source_dirty_state = 'clean'
    controller_uri = [string]$pilot.controller_uri
    execution_sequence = $cellOrder
    worker_pair = [pscustomobject][ordered]@{
        topology_classification = 'independent_physical_hosts'
        evidence_tier = 'offline-ml-two-host-vm'
        identity_caveat =
            [string]$sutNode.capabilities.labels.identityCaveat
        sut = [pscustomobject][ordered]@{
            node_id = [string]$sutNode.nodeId
            physical_host_id =
                [string]$sutNode.capabilities.labels.physicalHostId
            logical_processor_count =
                [int]$sutNode.capabilities.logicalProcessorCount
            total_memory_bytes =
                [long]$sutNode.capabilities.totalMemoryBytes
        }
        load = [pscustomobject][ordered]@{
            node_id = [string]$loadNode.nodeId
            physical_host_id =
                [string]$loadNode.capabilities.labels.physicalHostId
            logical_processor_count =
                [int]$loadNode.capabilities.logicalProcessorCount
            total_memory_bytes =
                [long]$loadNode.capabilities.totalMemoryBytes
        }
    }
    workload = [pscustomobject][ordered]@{
        suite_id = [string]$pilot.package_selection.suite_id
        scenario_id = [string]$pilot.package_selection.scenario_id
        protocol = [string]$pilot.package_selection.protocol
        test_executor_id =
            [string]$pilot.package_selection.test_executor_id
        load_profile_id =
            [string]$pilot.package_selection.load_profile_id
        repetitions_per_cell =
            [int]$pilot.package_selection.repetitions_per_cell
    }
    run_counts = [pscustomobject][ordered]@{
        cells = $cellResults.Count
        repetitions = $allRepetitions.Count
        successful_repetitions = @($allRepetitions |
            Where-Object failed_requests -EQ 0).Count
        failed_repetitions = @($allRepetitions |
            Where-Object failed_requests -NE 0).Count
        timeout_requests = [long]((
            $allRepetitions |
                Measure-Object timeout_requests -Sum).Sum)
    }
    cells = @($cellResults)
    directional_comparisons = $comparisons
    conclusion = 'pilot_completed_directional_only'
    covering_array = [pscustomobject][ordered]@{
        generator_implemented = $false
        required_for_current_eight_cell_family = $false
        trigger_effective_cell_count =
            [int]$pilot.covering_array_trigger_effective_cell_count
    }
    limitations = @(
        'two_repetitions_per_cell',
        'serial_nonrandomized_cell_order',
        'sut_load_worker_cpu_asymmetry',
        'duplicate_machine_id_user_attested_physical_separation',
        'target_process_metrics_unavailable',
        'load_generator_cpu_unknown',
        'selected_pilot_cannot_separate_batch_and_buffer_effects'
    )
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = $pilot.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $result)
Assert-Result (
    Test-AdaptiveRuntimeJsonSchema $result (
        Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-send-admission-performance-pilot-result-v1.schema.json')
) 'pilot_result_schema_invalid'
Assert-Result (Test-AdaptiveRuntimeDocumentHash $result) `
    'pilot_result_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $result $OutputPath

if ($PassThru) {
    $result
}
else {
    [pscustomobject][ordered]@{
        result_path = [IO.Path]::GetFullPath($OutputPath)
        result_sha256 = [string]$result.content_sha256
        cell_count = $cellResults.Count
        repetition_count = $allRepetitions.Count
        conclusion = [string]$result.conclusion
    } | ConvertTo-Json -Depth 6
}
