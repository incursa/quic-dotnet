# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\queued-send-performance-result-generator-tests'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$assertionCount = 0
function Assert-Test([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
    $script:assertionCount++
}
function Write-Json([string] $Path, [object] $Value) {
    $parent = Split-Path -Parent $Path
    [void](New-Item -ItemType Directory -Force -Path $parent)
    $Value | ConvertTo-Json -Depth 100 | Set-Content $Path -Encoding utf8
}

[void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)
$executionRoot = Join-Path $TemporaryRoot 'execution'
[void](New-Item -ItemType Directory -Force -Path $executionRoot)
$controlPath = Join-Path $TemporaryRoot 'control.json'
$resultOnePath = Join-Path $TemporaryRoot 'result-one.json'
$resultTwoPath = Join-Path $TemporaryRoot 'result-two.json'
$sha = '1' * 64
$q0Id = 'cell.queued_send_burst_budget.performance.q0'
$q1Id = 'cell.queued_send_burst_budget.performance.q1'
$control = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-queued-send-performance-campaign-v1'
    document_id = 'test_queued_send_performance_campaign'
    document_version = 1; content_sha256 = '0' * 64
    controller_uri = 'http://10.10.99.176:5088'
    package_selection = [pscustomobject][ordered]@{
        suite_id = 'raw-quic-local-v1'
        scenario_id = 'quic.transport.stream-download.1mb'
        protocol = 'quic'; test_executor_id = 'quic-go-raw-load'
        load_profile_id = 'raw-quic-peer-confidence'
    }
    design = [pscustomobject][ordered]@{
        repetitions_per_cell = 8; block_count = 8; total_job_count = 16
    }
    resource_metrics = [pscustomobject][ordered]@{
        bounded_server_stdout_max_bytes = 65536
    }
    cell_bindings = @(
        [pscustomobject][ordered]@{ cell_id=$q0Id; queued_send_burst_budget='legacy_current' },
        [pscustomobject][ordered]@{ cell_id=$q1Id; queued_send_burst_budget='single_datagram' }
    )
    trace_references = [pscustomobject][ordered]@{
        requirement_ids = @('REQ-QUIC-CRT-0253')
    }
}
[void](Set-AdaptiveRuntimeDocumentHash $control)
Write-AdaptiveRuntimeCanonicalDocument $control $controlPath

$plannedRuns = [Collections.Generic.List[object]]::new()
$attempts = [Collections.Generic.List[object]]::new()
for ($block = 1; $block -le 8; $block++) {
    $order = if (($block % 2) -eq 1) { @($q0Id,$q1Id) } else { @($q1Id,$q0Id) }
    for ($position = 1; $position -le 2; $position++) {
        $executionIndex = (($block - 1) * 2) + $position
        $cellId = $order[$position - 1]
        [void]$plannedRuns.Add([pscustomobject][ordered]@{
            execution_index=$executionIndex; block_index=$block; position_index=$position
            cell_id=$cellId
            policy_controls=[pscustomobject][ordered]@{
                queued_send_burst_budget=if($cellId -ceq $q0Id){'legacy_current'}else{'single_datagram'}
            }
        })
        $summaryPath = Join-Path $executionRoot "runs\$executionIndex\measurement-summary.json"
        $value = 1000.0 + ($executionIndex * 10.0) +
            $(if ($cellId -ceq $q1Id) { 5.0 } else { 0.0 })
        $summary = [pscustomobject][ordered]@{
            schema_version='adaptive-runtime-queued-send-performance-measurement-summary-v1'
            execution_index=$executionIndex; cell_id=$cellId
            job_id="job-$executionIndex"; accepted_timed_row=$true
            activation_predicate=[pscustomobject][ordered]@{
                predicate_id='predicate.queued_send.legal_budget_gt_one'
                observed=$true; observation_count=10
            }
            benchmark=[pscustomobject][ordered]@{
                requests_per_second=$value; throughput_bytes_per_second=$value*1048576
                latency_p50_ms=2.0; latency_p95_ms=4.0
                total_requests=100; successful_requests=100; failed_requests=0
                timeout_requests=0; bytes_sent=0; bytes_received=104857600
                load_generator_saturation_status='load-generator-saturation-not-detected'
            }
            bounded_aggregate=[pscustomobject][ordered]@{
                epoch_count=2; stdout_bytes=2048
                queued_send_burst_evidence_count=20
                legal_budget_gt_one_count=10
                arithmetic_saturated=$false
                last_epoch_sequence=2
                last_epoch_observed_at_utc='2026-08-02T00:00:02Z'
                benchmark_completed_at_utc='2026-08-02T00:00:03Z'
                emitted_epoch_count=2
            }
            load_process_metrics=[pscustomobject][ordered]@{
                sample_count=3; normalized_cpu_percent_mean=20.0
                normalized_cpu_percent_peak_interval=30.0; memory_max_bytes=1048576
                warnings=@('synthetic_fixture')
            }
            target_process_metrics=[pscustomobject][ordered]@{
                runtime_counter_status='unavailable'
            }
            performance_acceptance_authorized=$false
            adaptive_rule_derivation_authorized=$false
            active_behavior_authorized=$false
            production_activation_authorized=$false
        }
        Write-Json $summaryPath $summary
        [void]$attempts.Add([pscustomobject][ordered]@{
            execution_index=$executionIndex; block_index=$block; position_index=$position
            cell_id=$cellId; attempt_index=1
            package_ref=[pscustomobject][ordered]@{
                packageId="package-$($cellId.Split('.')[-1])"; packageVersion='test-v1'; sha256=$sha
            }
            job_id="job-$executionIndex"; run_id="run-$executionIndex"
            topology=[pscustomobject][ordered]@{
                sutNodeId='plab-worker-x64-02'; loadNodeId='plab-worker-x64-03'
                sutPhysicalHostId='physical-x64-02'; loadPhysicalHostId='physical-x64-03'
                classification='independent_physical_hosts'
            }
            outcome='Completed'; failure_reason_code=$null
            measurement_summary_path=$summaryPath
        })
    }
}
$manifest = [pscustomobject][ordered]@{
    schema_version='adaptive-runtime-queued-send-performance-manifest-v1'
    document_id='test_queued_send_performance_manifest'; document_version=1
    content_sha256='0'*64
    control_ref=[pscustomobject][ordered]@{
        document_id=[string]$control.document_id
        schema_version=[string]$control.schema_version
        document_version=[int]$control.document_version
        content_sha256=[string]$control.content_sha256
    }
    planned_runs=@($plannedRuns)
}
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
Write-AdaptiveRuntimeCanonicalDocument $manifest (
    Join-Path $executionRoot 'compiled-manifest.json')
$failedAttempt = [pscustomobject][ordered]@{
    execution_index=3; block_index=2; position_index=1; cell_id=$q1Id; attempt_index=1
    package_ref=[pscustomobject][ordered]@{
        packageId='package-q1'; packageVersion='test-v1'; sha256=$sha
    }
    job_id='failed-job'; run_id=''; topology=$null; outcome='failed'
    failure_reason_code='synthetic_infrastructure_failure'; measurement_summary_path=$null
}
$allAttempts = @($failedAttempt) + @($attempts)
Write-Json (Join-Path $executionRoot 'campaign-state.json') ([pscustomobject][ordered]@{
    control_sha256=[string]$control.content_sha256
    manifest_sha256=[string]$manifest.content_sha256
    source_commit='a'*40; source_dirty_state='clean'
    controller_uri='http://10.10.99.176:5088'; planned_run_count=16
    completed_run_count=16; failed_attempt_count=1; attempts=$allAttempts
    performance_acceptance_authorization=$false
    adaptive_rule_derivation_authorization=$false
    active_behavior_authorization=$false
    production_activation_authorization=$false
})
Write-Json (Join-Path $executionRoot 'controller-nodes.json') @(
    [pscustomobject]@{ nodeId='plab-worker-x64-02'; capabilities=[pscustomobject]@{
        labels=[pscustomobject]@{ physicalHostId='physical-x64-02' } } },
    [pscustomobject]@{ nodeId='plab-worker-x64-03'; capabilities=[pscustomobject]@{
        labels=[pscustomobject]@{ physicalHostId='physical-x64-03' } } }
)
Write-Json (Join-Path $executionRoot 'package-identities.json') @(
    [pscustomobject]@{ cell_id=$q0Id; package_ref=[pscustomobject]@{
        packageId='package-q0'; packageVersion='test-v1'; sha256=$sha } },
    [pscustomobject]@{ cell_id=$q1Id; package_ref=[pscustomobject]@{
        packageId='package-q1'; packageVersion='test-v1'; sha256=$sha } }
)
Write-Json (Join-Path $executionRoot 'activation-preflight.json') ([pscustomobject][ordered]@{
    predicate_id='predicate.queued_send.legal_budget_gt_one'; cell_id=$q1Id
    job_id='preflight-job'; run_id='preflight-run'; activation_observed=$true
    accepted_timed_row=$false
    topology=[pscustomobject]@{
        classification='independent_physical_hosts'; sutNodeId='plab-worker-x64-02'
        loadNodeId='plab-worker-x64-03'
    }
    attempts=@(
        [pscustomobject]@{
            attempt_index=1; cell_id=$q1Id; job_id='failed-preflight-job'
            run_id='failed-preflight-run'; package_ref=[pscustomobject]@{
                packageId='package-q1'; packageVersion='test-v1'; sha256=$sha }
            outcome='failed'; failure_reason_code='synthetic_preflight_failure'
            measurement_summary_path=$null
        },
        [pscustomobject]@{
            attempt_index=2; cell_id=$q1Id; job_id='preflight-job'
            run_id='preflight-run'; package_ref=[pscustomobject]@{
                packageId='package-q1'; packageVersion='test-v1'; sha256=$sha }
            outcome='Completed'; failure_reason_code=$null
            measurement_summary_path='synthetic-preflight-summary.json'
        }
    )
    performance_acceptance_authorization=$false
    adaptive_rule_derivation_authorization=$false
    active_behavior_authorization=$false
    production_activation_authorization=$false
})

$generator = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeQueuedSendPerformanceResult.ps1'
& $generator -RepositoryRoot $RepositoryRoot -ControlPath $controlPath `
    -ExecutionRoot $executionRoot -OutputPath $resultOnePath | Out-Null
& $generator -RepositoryRoot $RepositoryRoot -ControlPath $controlPath `
    -ExecutionRoot $executionRoot -OutputPath $resultTwoPath | Out-Null
Assert-Test ([IO.File]::ReadAllText($resultOnePath) -ceq
    [IO.File]::ReadAllText($resultTwoPath)) 'queued_result_generation_not_deterministic'
$result = Read-AdaptiveRuntimeJsonDocument $resultOnePath
Assert-Test (@($result.runs).Count -eq 16 -and @($result.failed_attempts).Count -eq 2 -and
    @($result.failed_attempts | Where-Object {
        [string]$_.phase -ceq 'activation_preflight' }).Count -eq 1) `
    'queued_result_fixture_reconciliation_invalid'
Assert-Test (@($result.block_summaries).Count -eq 8 -and
    @($result.order_summaries).Count -eq 2) 'queued_result_fixture_summary_invalid'
Assert-Test ($result.performance_acceptance_authorization -eq $false -and
    $result.adaptive_rule_derivation_authorization -eq $false -and
    $result.active_behavior_authorization -eq $false -and
    $result.production_activation_authorization -eq $false) `
    'queued_result_fixture_authorization_invalid'
$replay = & (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeQueuedSendPerformanceResult.ps1') `
    -RepositoryRoot $RepositoryRoot -ControlPath $controlPath `
    -ResultPath $resultOnePath -ExecutionRoot $executionRoot `
    -TemporaryRoot (Join-Path $TemporaryRoot 'replay') | ConvertFrom-Json
Assert-Test ($replay.replay_verified -eq $true -and
    [int]$replay.completed_run_count -eq 16) 'queued_result_fixture_replay_invalid'

$mutated = $result | ConvertTo-Json -Depth 100 -Compress |
    ConvertFrom-Json -Depth 100
$mutated.performance_acceptance_authorization = $true
$rejected = $false
try {
    $rejected = -not (Test-AdaptiveRuntimeJsonSchema $mutated (
        Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-queued-send-performance-result-v1.schema.json'))
} catch { $rejected = $true }
Assert-Test $rejected 'queued_result_schema_accepted_performance_authorization'

[pscustomobject][ordered]@{
    assertion_count=$assertionCount
    result_sha256=[string]$result.content_sha256
    completed_run_count=16; failed_attempt_count=2
    replay_verified=$true; actual_measurements_run=0
} | ConvertTo-Json -Depth 8
