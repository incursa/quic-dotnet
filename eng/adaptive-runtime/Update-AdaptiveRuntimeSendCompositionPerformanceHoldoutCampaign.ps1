# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $BaseCampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $OutputPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-holdout-campaign-v1.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$campaign = Read-AdaptiveRuntimeJsonDocument $BaseCampaignPath
$campaign.document_id =
    'adaptive_runtime_send_composition_performance_holdout_campaign_v1'
$campaign.content_sha256 = '0' * 64
$campaign.design.seed = 20260727

$replacementHoldouts = @(
    [pscustomobject][ordered]@{
        workload_id = 'holdout_segment_rich_medium'
        family = 'segment_rich_writes'
        split = 'holdout'
        scenario = 'upload'
        payload_bytes = 12288
        response_payload_bytes = 1
        concurrency = 10
        receive_window_bytes = 0
        activation_expectation = 'batch_and_upstream_buffer_reachable'
    },
    [pscustomobject][ordered]@{
        workload_id = 'holdout_many_stream_medium'
        family = 'many_stream_saturation'
        split = 'holdout'
        scenario = 'upload'
        payload_bytes = 32768
        response_payload_bytes = 1
        concurrency = 12
        receive_window_bytes = 0
        activation_expectation = 'batch_and_upstream_buffer_reachable'
    },
    [pscustomobject][ordered]@{
        workload_id = 'holdout_copy_pressure_upload'
        family = 'copy_memory_pressure'
        split = 'holdout'
        scenario = 'upload'
        payload_bytes = 49152
        response_payload_bytes = 1
        concurrency = 20
        receive_window_bytes = 0
        activation_expectation = 'batch_and_upstream_buffer_reachable'
    }
)

$retainedWorkloads = @($campaign.workloads | Where-Object {
    [string]$_.split -cne 'holdout' -or
    [string]$_.workload_id -ceq 'inactive_control'
})
$campaign.workloads = @($retainedWorkloads + $replacementHoldouts)

[void](Set-AdaptiveRuntimeDocumentHash -Document $campaign)
$json = $campaign | ConvertTo-Json -Depth 100
[IO.File]::WriteAllText(
    $OutputPath,
    "$json`n",
    [Text.UTF8Encoding]::new($false))

$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-composition-performance-campaign-v1.schema.json'
if (-not (Test-AdaptiveRuntimeJsonSchema $campaign $schemaPath)) {
    throw 'performance_holdout_campaign_schema_invalid'
}
if (-not (Test-AdaptiveRuntimeDocumentHash $campaign)) {
    throw 'performance_holdout_campaign_hash_invalid'
}

[pscustomobject][ordered]@{
    output_path = $OutputPath
    content_sha256 = [string]$campaign.content_sha256
    workload_count = @($campaign.workloads).Count
    holdout_workload_count =
        @($campaign.workloads | Where-Object split -CEQ 'holdout').Count
    deterministic_seed = [long]$campaign.design.seed
}
