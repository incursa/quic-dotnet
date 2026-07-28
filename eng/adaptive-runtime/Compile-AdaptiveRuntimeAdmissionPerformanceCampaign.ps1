# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'),
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Compile([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Read-Control([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function New-DocumentRef([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Get-RefKey([object] $Reference) {
    "$($Reference.document_id)|$($Reference.schema_version)|$(
        $Reference.document_version)|$($Reference.content_sha256)"
}

$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $campaign) `
    'admission_performance_campaign_hash_invalid'
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $campaign (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-campaign-v1.schema.json')
) 'admission_performance_campaign_schema_invalid'

$sources = [ordered]@{
    family = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v5.json'
    factor = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-factor-cell-space-v3.json'
    correctness_plan = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-correctness-plan-v1.json'
    relationship = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-policy-relationship-graph-v3.json'
    constraint = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-combination-constraint-catalog-v2.json'
    batch_review = Read-Control `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\batch-single-eligible.review.json'
    buffer_review = Read-Control `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\buffer-memory-conservative.review.json'
    oversized_review = Read-Control `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-single-fragment.review.json'
}
foreach ($entry in $sources.GetEnumerator()) {
    Assert-Compile (Test-AdaptiveRuntimeDocumentHash $entry.Value) `
        "admission_performance_source_hash_invalid:$($entry.Key)"
}

$declaredSourceKeys = @($campaign.source_document_refs |
    ForEach-Object { Get-RefKey $_ } |
    Sort-Object -CaseSensitive)
$actualSourceKeys = @($sources.Values |
    ForEach-Object { Get-RefKey $_ } |
    Sort-Object -CaseSensitive)
Assert-Compile (
    (ConvertTo-Json $declaredSourceKeys -Compress) -ceq
    (ConvertTo-Json $actualSourceKeys -Compress)
) 'admission_performance_source_binding_stale'

Assert-Compile (
    [string]$campaign.authorization_id -ceq
        'send_admission_composition_performance_v1' -and
    [string]$campaign.campaign_id -ceq
        'campaign.send_admission_composition.performance.v1' -and
    [string]$campaign.family_id -ceq 'send_admission_composition' -and
    [string]$campaign.execution_purpose -ceq 'offline_performance'
) 'admission_performance_authorization_identity_invalid'
Assert-Compile (
    [string]$campaign.generation_mode -ceq 'exhaustive_explicit' -and
    $campaign.covering_array_generator_implemented -eq $false -and
    [int]$campaign.covering_array_trigger_effective_cell_count -eq 65
) 'admission_performance_covering_array_boundary_invalid'
Assert-Compile (
    $campaign.measurement_capability_authorized -eq $true -and
    $campaign.timing_execution_authorized -eq $false -and
    $campaign.active_behavior_authorization -eq $false -and
    $campaign.performance_acceptance_authorization -eq $false -and
    $campaign.production_activation_authorization -eq $false
) 'admission_performance_authorization_boundary_invalid'

$admissionSpace = @($sources.factor.family_spaces |
    Where-Object family_id -ceq 'send_admission_composition')
Assert-Compile ($admissionSpace.Count -eq 1) `
    'admission_performance_factor_space_missing'
$eligibleFactorCells = @($admissionSpace[0].planned_cells |
    Where-Object classification -ceq 'reviewed_exact_exhaustive' |
    Sort-Object cell_order)
$blockedFactorCells = @($admissionSpace[0].planned_cells |
    Where-Object classification -ceq 'review_blocked')
Assert-Compile (
    $eligibleFactorCells.Count -eq 8 -and
    $blockedFactorCells.Count -eq 4 -and
    @($blockedFactorCells.reason_codes |
        Where-Object {
            $_ -contains 'shadow_recommendation_value_mismatch'
        }).Count -eq 4
) 'admission_performance_factor_partition_invalid'

$expected = @(
    'a0|legacy_current|legacy_current|legacy_current',
    'a1|legacy_current|legacy_current|memory_conservative',
    'a2|legacy_current|single_eligible|legacy_current',
    'a3|legacy_current|single_eligible|memory_conservative',
    'a4|single_fragment|legacy_current|legacy_current',
    'a5|single_fragment|legacy_current|memory_conservative',
    'a6|single_fragment|single_eligible|legacy_current',
    'a7|single_fragment|single_eligible|memory_conservative'
)
$actual = @($campaign.planned_cells | ForEach-Object {
    "$(([string]$_.cell_id).Split('.')[-1])|$(
        $_.oversized_write_admission_quantum)|$(
        $_.application_send_batch_formation)|$(
        $_.buffer_copy_coalescing)"
})
Assert-Compile (
    (ConvertTo-Json $actual -Compress) -ceq
    (ConvertTo-Json $expected -Compress)
) 'admission_performance_exact_cell_matrix_invalid'
foreach ($cell in @($campaign.planned_cells)) {
    Assert-Compile (
        (Get-AdaptiveRuntimeDocumentHash $cell) -ceq
            [string]$cell.content_sha256
    ) "admission_performance_cell_hash_invalid:$($cell.cell_id)"
}

$factorCellIds = @($eligibleFactorCells.cell_id | Sort-Object)
$campaignCellIds = @($campaign.planned_cells.cell_id | Sort-Object)
Assert-Compile (
    (ConvertTo-Json $factorCellIds -Compress) -ceq
    (ConvertTo-Json $campaignCellIds -Compress)
) 'admission_performance_factor_campaign_cell_mismatch'
Assert-Compile (
    @($campaign.dry_run_workloads |
        Where-Object timing_eligible -ne $false).Count -eq 0
) 'admission_performance_dry_run_workload_timing_enabled'

$compiledCells = @($campaign.planned_cells | ForEach-Object {
    [pscustomobject][ordered]@{
        cell_id = [string]$_.cell_id
        content_sha256 = [string]$_.content_sha256
    }
})
$compiledWork = [Collections.Generic.List[object]]::new()
foreach ($workload in @($campaign.dry_run_workloads)) {
    foreach ($cell in @($campaign.planned_cells)) {
        $suffix = ([string]$cell.cell_id).Split('.')[-1]
        [void]$compiledWork.Add([pscustomobject][ordered]@{
            work_item_id = "dry_run.$($workload.workload_id).$suffix"
            cell_id = [string]$cell.cell_id
            workload_id = [string]$workload.workload_id
            execution_state = 'blocked_pending_host_and_workload'
        })
    }
}

$manifest = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-performance-manifest-v1'
    document_id =
        'manifest.send_admission_composition.performance.dry_run.v1'
    document_version = 1
    content_sha256 = '0' * 64
    authorization_id = 'send_admission_composition_performance_v1'
    execution_purpose = 'offline_performance_dry_run'
    campaign_ref = New-DocumentRef $campaign
    source_document_refs = @($sources.Values |
        ForEach-Object { New-DocumentRef $_ })
    compiled_cells = $compiledCells
    compiled_work_items = $compiledWork.ToArray()
    host_selection_state = 'decision_required'
    workload_selection_state = 'decision_required'
    measurement_capability_authorized = $true
    timing_execution_authorized = $false
    no_timing_observations = $true
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    production_activation_authorization = $false
    trace_references = $campaign.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $manifest (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-manifest-v1.schema.json')
) 'admission_performance_manifest_schema_invalid'
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $manifest) `
    'admission_performance_manifest_hash_invalid'
Write-AdaptiveRuntimeCanonicalDocument $manifest $OutputPath

if ($PassThru) {
    $manifest
}
else {
    [pscustomobject][ordered]@{
        output_path = [IO.Path]::GetFullPath($OutputPath)
        manifest_sha256 = [string]$manifest.content_sha256
        compiled_cell_count = @($manifest.compiled_cells).Count
        compiled_work_item_count = @($manifest.compiled_work_items).Count
        host_selection_state = [string]$manifest.host_selection_state
        workload_selection_state =
            [string]$manifest.workload_selection_state
        timing_execution_authorized =
            [bool]$manifest.timing_execution_authorized
        no_timing_observations = [bool]$manifest.no_timing_observations
    } | ConvertTo-Json -Depth 8
}
