# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $BaseCampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $HoldoutCampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-holdout-campaign-v1.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-HoldoutCondition([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Get-WorkloadShape([object] $Workload) {
    return '{0}|{1}|{2}|{3}|{4}' -f
        [string]$Workload.scenario,
        [long]$Workload.payload_bytes,
        [long]$Workload.response_payload_bytes,
        [long]$Workload.concurrency,
        [long]$Workload.receive_window_bytes
}

$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-composition-performance-campaign-v1.schema.json'
$base = Read-AdaptiveRuntimeJsonDocument $BaseCampaignPath
$holdout = Read-AdaptiveRuntimeJsonDocument $HoldoutCampaignPath

foreach ($campaign in @($base, $holdout)) {
    Assert-HoldoutCondition (
        Test-AdaptiveRuntimeJsonSchema $campaign $schemaPath
    ) 'performance_holdout_campaign_schema_invalid'
    Assert-HoldoutCondition (
        Test-AdaptiveRuntimeDocumentHash $campaign
    ) 'performance_holdout_campaign_hash_invalid'
}

Assert-HoldoutCondition (
    [string]$base.content_sha256 -cne [string]$holdout.content_sha256 -and
    [string]$base.document_id -cne [string]$holdout.document_id
) 'performance_holdout_campaign_identity_not_distinct'
Assert-HoldoutCondition (
    (ConvertTo-Json @($base.cells) -Depth 20 -Compress) -ceq
    (ConvertTo-Json @($holdout.cells) -Depth 20 -Compress)
) 'performance_holdout_cells_changed'
Assert-HoldoutCondition (
    (ConvertTo-Json @($base.reviewed_proof_refs) -Depth 20 -Compress) -ceq
    (ConvertTo-Json @($holdout.reviewed_proof_refs) -Depth 20 -Compress) -and
    (ConvertTo-Json $base.correctness_review_ref -Depth 20 -Compress) -ceq
    (ConvertTo-Json $holdout.correctness_review_ref -Depth 20 -Compress)
) 'performance_holdout_review_authority_changed'
Assert-HoldoutCondition (
    $holdout.measurement_authorization -eq $true -and
    $holdout.active_behavior_authorization -eq $false -and
    $holdout.performance_acceptance_authorization -eq $false -and
    $holdout.production_activation_authorization -eq $false
) 'performance_holdout_authorization_invalid'

$holdouts = @($holdout.workloads | Where-Object split -CEQ 'holdout')
$activeHoldouts = @($holdouts | Where-Object {
    [string]$_.activation_expectation -ceq
        'batch_and_upstream_buffer_reachable'
})
$inactiveHoldouts = @($holdouts | Where-Object {
    [string]$_.activation_expectation -ceq 'inactive_control'
})
Assert-HoldoutCondition (
    $holdouts.Count -eq 4 -and
    $activeHoldouts.Count -eq 3 -and
    $inactiveHoldouts.Count -eq 1
) 'performance_holdout_shape_count_invalid'
Assert-HoldoutCondition (
    @($activeHoldouts | Where-Object scenario -CNE 'upload').Count -eq 0 -and
    @($activeHoldouts | Where-Object concurrency -LT 2).Count -eq 0
) 'performance_holdout_activation_shape_invalid'

$trainingShapes = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($workload in @($holdout.workloads | Where-Object split -CEQ 'train')) {
    [void]$trainingShapes.Add((Get-WorkloadShape $workload))
}
Assert-HoldoutCondition (
    @($activeHoldouts | Where-Object {
        $trainingShapes.Contains((Get-WorkloadShape $_))
    }).Count -eq 0
) 'performance_holdout_duplicates_training_point'

$temporaryPath = Join-Path ([IO.Path]::GetTempPath()) (
    'adaptive-runtime-holdout-campaign-{0}.json' -f
    [Guid]::NewGuid().ToString('N'))
try {
    & (Join-Path $PSScriptRoot `
        'Update-AdaptiveRuntimeSendCompositionPerformanceHoldoutCampaign.ps1') `
        -BaseCampaignPath $BaseCampaignPath `
        -OutputPath $temporaryPath `
        -RepositoryRoot $RepositoryRoot | Out-Null
    Assert-HoldoutCondition (
        (Get-FileHash $temporaryPath -Algorithm SHA256).Hash -ceq
        (Get-FileHash $HoldoutCampaignPath -Algorithm SHA256).Hash
    ) 'performance_holdout_generation_not_byte_deterministic'
}
finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

$negativeCases = @(
    [pscustomobject]@{
        case_id = 'active_authorization'
        rejected = $holdout.active_behavior_authorization -eq $false
    },
    [pscustomobject]@{
        case_id = 'performance_acceptance'
        rejected = $holdout.performance_acceptance_authorization -eq $false
    },
    [pscustomobject]@{
        case_id = 'production_activation'
        rejected = $holdout.production_activation_authorization -eq $false
    },
    [pscustomobject]@{
        case_id = 'non_upload_activation_holdout'
        rejected = @($activeHoldouts |
            Where-Object scenario -CNE 'upload').Count -eq 0
    },
    [pscustomobject]@{
        case_id = 'training_point_reuse'
        rejected = @($activeHoldouts | Where-Object {
            $trainingShapes.Contains((Get-WorkloadShape $_))
        }).Count -eq 0
    }
)
Assert-HoldoutCondition (
    @($negativeCases | Where-Object rejected -EQ $false).Count -eq 0
) 'performance_holdout_negative_case_failed'

$result = [pscustomobject][ordered]@{
    valid_campaign_count = 2
    holdout_workload_count = $holdouts.Count
    activation_expected_holdout_count = $activeHoldouts.Count
    inactive_holdout_count = $inactiveHoldouts.Count
    deterministic_generation = $true
    negative_case_count = $negativeCases.Count
    content_sha256 = [string]$holdout.content_sha256
    active_behavior_authorization = $false
    production_activation_authorization = $false
}
if ($PassThru) {
    return $result
}
$result | ConvertTo-Json -Depth 10
