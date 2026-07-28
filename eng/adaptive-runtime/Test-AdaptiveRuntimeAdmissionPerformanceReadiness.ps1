# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\admission-performance-readiness-tests'
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

function Read-Repo([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function Write-TemporaryDocument([object] $Document, [string] $Name) {
    $path = Join-Path $TemporaryRoot $Name
    Write-AdaptiveRuntimeCanonicalDocument $Document $path
    return $path
}

function Copy-Document([object] $Document) {
    $Document | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Assert-CompileRejects(
    [object] $Campaign,
    [string] $Name,
    [string] $ExpectedCode
) {
    [void](Set-AdaptiveRuntimeDocumentHash $Campaign)
    $campaignPath = Write-TemporaryDocument $Campaign "$Name.campaign.json"
    $manifestPath = Join-Path $TemporaryRoot "$Name.manifest.json"
    try {
        & (Join-Path $PSScriptRoot `
            'Compile-AdaptiveRuntimeAdmissionPerformanceCampaign.ps1') `
            -RepositoryRoot $RepositoryRoot `
            -CampaignPath $campaignPath `
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

$factorPath =
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-factor-cell-space-v3.json'
$campaignPath =
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'
$factorSchema =
    'schemas\adaptive-runtime-factor-cell-space-v3.schema.json'
$campaignSchema =
    'schemas\adaptive-runtime-send-admission-performance-campaign-v1.schema.json'
$manifestSchema =
    'schemas\adaptive-runtime-send-admission-performance-manifest-v1.schema.json'

$factor = Read-Repo $factorPath
$campaign = Read-Repo $campaignPath
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $factor) `
    'factor_hash_invalid'
Assert-Ready (Test-AdaptiveRuntimeJsonSchema $factor (
    Join-Path $RepositoryRoot $factorSchema)) 'factor_schema_invalid'
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $campaign) `
    'campaign_hash_invalid'
Assert-Ready (Test-AdaptiveRuntimeJsonSchema $campaign (
    Join-Path $RepositoryRoot $campaignSchema)) 'campaign_schema_invalid'

$familyRef = @($factor.catalog_refs | Where-Object {
    $_.document_id -ceq 'adaptive_runtime_experiment_family_catalog_v5'
})
Assert-Ready (
    $familyRef.Count -eq 1 -and
    [int]$familyRef[0].document_version -eq 5 -and
    [string]$familyRef[0].content_sha256 -ceq
        'cfee17afcc28da35e657b2d1331bde68c752b5a3487f0af69087c12df6530b93'
) 'factor_family_v5_binding_invalid'
Assert-Ready (
    $factor.covering_array_generator_implemented -eq $false -and
    [int]$factor.covering_array_trigger_effective_cell_count -eq 65
) 'factor_covering_array_boundary_invalid'

$space = @($factor.family_spaces |
    Where-Object family_id -ceq 'send_admission_composition')
$eligible = @($space[0].planned_cells |
    Where-Object classification -ceq 'reviewed_exact_exhaustive')
$blocked = @($space[0].planned_cells |
    Where-Object classification -ceq 'review_blocked')
Assert-Ready ($eligible.Count -eq 8) 'eligible_cell_count_invalid'
Assert-Ready ($blocked.Count -eq 4) 'blocked_cell_count_invalid'
Assert-Ready (
    @($blocked | Where-Object {
        @($_.reason_codes) -contains
            'shadow_recommendation_value_mismatch'
    }).Count -eq 4
) 'bounded_blocker_missing'

$expectedCellIds = @(
    0..7 | ForEach-Object {
        "cell.send_admission_composition.correctness.a$_"
    }
)
Assert-Ready (
    (ConvertTo-Json @($eligible.cell_id | Sort-Object) -Compress) -ceq
    (ConvertTo-Json $expectedCellIds -Compress)
) 'eligible_cell_ids_invalid'
Assert-Ready (
    $campaign.measurement_capability_authorized -eq $true -and
    $campaign.timing_execution_authorized -eq $false -and
    $campaign.active_behavior_authorization -eq $false -and
    $campaign.performance_acceptance_authorization -eq $false -and
    $campaign.production_activation_authorization -eq $false
) 'campaign_authorization_boundary_invalid'
Assert-Ready (
    @($campaign.dry_run_workloads |
        Where-Object timing_eligible -ne $false).Count -eq 0
) 'campaign_dry_run_timing_enabled'

$manifestOnePath = Join-Path $TemporaryRoot 'manifest-one.json'
$manifestTwoPath = Join-Path $TemporaryRoot 'manifest-two.json'
& (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeAdmissionPerformanceCampaign.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -CampaignPath (Join-Path $RepositoryRoot $campaignPath) `
    -OutputPath $manifestOnePath | Out-Null
& (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeAdmissionPerformanceCampaign.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -CampaignPath (Join-Path $RepositoryRoot $campaignPath) `
    -OutputPath $manifestTwoPath | Out-Null
$manifestOne = Read-AdaptiveRuntimeJsonDocument $manifestOnePath
$manifestTwo = Read-AdaptiveRuntimeJsonDocument $manifestTwoPath
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $manifestOne) `
    'manifest_hash_invalid'
Assert-Ready (Test-AdaptiveRuntimeJsonSchema $manifestOne (
    Join-Path $RepositoryRoot $manifestSchema)) 'manifest_schema_invalid'
Assert-Ready (
    [string]$manifestOne.content_sha256 -ceq
    [string]$manifestTwo.content_sha256
) 'manifest_replay_hash_mismatch'
Assert-Ready (
    @($manifestOne.compiled_cells).Count -eq 8 -and
    @($manifestOne.compiled_work_items).Count -eq 8
) 'manifest_compiled_counts_invalid'
Assert-Ready (
    [string]$manifestOne.host_selection_state -ceq
        'decision_required' -and
    [string]$manifestOne.workload_selection_state -ceq
        'decision_required' -and
    $manifestOne.timing_execution_authorized -eq $false -and
    $manifestOne.no_timing_observations -eq $true
) 'manifest_measurement_stop_invalid'

$covering = Copy-Document $campaign
$covering.covering_array_generator_implemented = $true
Assert-CompileRejects $covering 'covering-array' `
    'covering_array_generator_implemented'

$timing = Copy-Document $campaign
$timing.timing_execution_authorized = $true
Assert-CompileRejects $timing 'timing-execution' `
    'timing_execution_authorized'

$boundedCampaign = Copy-Document $campaign
$boundedCampaign.planned_cells[7].oversized_write_admission_quantum =
    'bounded_multi_fragment'
[void](Set-AdaptiveRuntimeDocumentHash $boundedCampaign.planned_cells[7])
Assert-CompileRejects $boundedCampaign 'bounded-value' `
    'planned_cells/7/oversized_write_admission_quantum'

$stale = Copy-Document $campaign
$stale.source_document_refs[0].content_sha256 = '0' * 64
Assert-CompileRejects $stale 'stale-source' `
    'admission_performance_source_binding_stale'

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    reviewed_cell_count = $eligible.Count
    blocked_cell_count = $blocked.Count
    compiled_work_item_count = @($manifestOne.compiled_work_items).Count
    manifest_sha256 = [string]$manifestOne.content_sha256
    covering_array_generator_implemented = $false
    timing_execution_authorized = $false
    actual_measurements_run = 0
} | ConvertTo-Json -Depth 8
