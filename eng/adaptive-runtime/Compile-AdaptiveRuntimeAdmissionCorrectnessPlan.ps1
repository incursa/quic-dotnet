# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $SourceCommit,
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [Parameter(Mandatory = $true)][string] $OutputRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Compile([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}
function Read-Control([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}
function New-Trace {
    [pscustomobject][ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0241',
            'REQ-QUIC-CRT-0242',
            'REQ-QUIC-CRT-0243',
            'REQ-QUIC-CRT-0244',
            'REQ-QUIC-CRT-0245',
            'REQ-QUIC-CRT-0246'
        )
        architecture_ids = @('ARC-QUIC-CRT-0116')
        work_item_ids = @('WI-QUIC-CRT-0117')
        verification_ids = @('VER-QUIC-CRT-0118')
    }
}
function Get-RefKey([object] $Value) {
    "$($Value.document_id)|$($Value.schema_version)|$(
        $Value.document_version)|$($Value.content_sha256)"
}
function Get-CellRef([object] $Cell) {
    [pscustomobject][ordered]@{
        cell_id = [string]$Cell.cell_id
        content_sha256 = [string]$Cell.content_sha256
    }
}

Assert-Compile ($SourceCommit -match '^[0-9a-f]{40}$') `
    'admission_source_commit_invalid'
Assert-Compile (Test-Path -LiteralPath $BinaryPath -PathType Leaf) `
    'admission_binary_missing'
$plan = Read-AdaptiveRuntimeJsonDocument $PlanPath
Assert-Compile (Test-AdaptiveRuntimeDocumentHash $plan) `
    'admission_plan_hash_invalid'
Assert-Compile (
    Test-AdaptiveRuntimeJsonSchema $plan (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-correctness-plan-v1.schema.json')
) 'admission_plan_schema_invalid'

$sources = [ordered]@{
    axis = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-policy-axis-contracts-v2.json'
    behavior = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v3.json'
    relationship = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-policy-relationship-graph-v3.json'
    constraint = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-combination-constraint-catalog-v2.json'
    family = Read-Control `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v5.json'
    batch = Read-Control `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\batch-single-eligible.review.json'
    buffer = Read-Control `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\buffer-memory-conservative.review.json'
    oversized = Read-Control `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-single-fragment.review.json'
}
foreach ($document in $sources.Values) {
    Assert-Compile (Test-AdaptiveRuntimeDocumentHash $document) `
        "admission_source_hash_invalid:$($document.document_id)"
}
$declaredSourceKeys = @($plan.source_document_refs |
    ForEach-Object { Get-RefKey $_ } | Sort-Object -CaseSensitive)
$actualSourceKeys = @($sources.Values |
    ForEach-Object { Get-RefKey $_ } | Sort-Object -CaseSensitive)
Assert-Compile (
    (ConvertTo-Json $declaredSourceKeys -Compress) -ceq
    (ConvertTo-Json $actualSourceKeys -Compress)
) 'admission_plan_source_binding_stale'

Assert-Compile (
    [string]$sources.batch.review_outcome -ceq 'passed' -and
    [string]$sources.buffer.review_outcome -ceq 'passed' -and
    [string]$sources.oversized.review_outcome -ceq 'passed' -and
    $sources.oversized.promotion_eligibility -eq $true
) 'admission_reviewed_proof_precondition_failed'
$family = @($sources.family.experiment_families |
    Where-Object family_id -ceq 'send_admission_composition')
Assert-Compile ($family.Count -eq 1) 'admission_family_missing'
$familyProofIds = @($family[0].actuation_proof_refs)
Assert-Compile (
    $familyProofIds -contains
        'proof.application_send_batch_formation.single_eligible.reviewed_80113e61' -and
    $familyProofIds -contains
        'proof.buffer_copy_coalescing.memory_conservative.reviewed_80113e61' -and
    $familyProofIds -contains
        'proof.oversized_write_admission_quantum.single_fragment.runtime-proof-capture-20260727'
) 'admission_family_current_proof_binding_missing'
Assert-Compile (
    @($sources.family.reviewed_actuation_proofs |
        Where-Object policy_value -ceq 'bounded_multi_fragment').Count -eq 0
) 'admission_bounded_proof_authorized'

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
$actual = @($plan.planned_cells | ForEach-Object {
    "$(([string]$_.cell_id).Split('.')[-1])|$(
        $_.oversized_write_admission_quantum)|$(
        $_.application_send_batch_formation)|$(
        $_.buffer_copy_coalescing)"
})
Assert-Compile (
    (ConvertTo-Json $actual -Compress) -ceq
    (ConvertTo-Json $expected -Compress)
) 'admission_exact_cell_matrix_invalid'
foreach ($cell in @($plan.planned_cells)) {
    Assert-Compile (
        (Get-AdaptiveRuntimeDocumentHash $cell) -ceq
            [string]$cell.content_sha256
    ) "admission_cell_hash_invalid:$($cell.cell_id)"
}
$levels = @($plan.allowed_axis_levels | ForEach-Object {
    "$($_.axis_id)=$(@($_.levels) -join ',')"
} | Sort-Object -CaseSensitive)
Assert-Compile (
    (ConvertTo-Json $levels -Compress) -ceq (ConvertTo-Json @(
        'application_send_batch_formation=legacy_current,single_eligible',
        'buffer_copy_coalescing=legacy_current,memory_conservative',
        'oversized_write_admission_quantum=legacy_current,single_fragment'
    ) -Compress)
) 'admission_allowed_levels_invalid'
Assert-Compile (
    @($plan.fixed_axis_values | Where-Object {
        $_.configured_value -cne 'legacy_current'
    }).Count -eq 0 -and
    @($plan.fixed_axis_values.axis_id | Sort-Object) -join '|' -ceq
        'application_send_turn_planning|queued_send_burst_budget'
) 'admission_fixed_axis_boundary_invalid'
Assert-Compile (
    $plan.active_behavior_authorization -eq $false -and
    $plan.performance_acceptance_authorization -eq $false -and
    [string]$plan.execution_purpose -ceq 'correctness_only'
) 'admission_prohibited_authorization'

$trace = New-Trace
$cellRefs = @($plan.planned_cells | ForEach-Object {
    Get-CellRef $_
})
$validation = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-send-admission-plan-validation-v1'
    document_id = 'validation.adaptive_runtime_send_admission_correctness_plan_v1'
    document_version = 1
    content_sha256 = '0' * 64
    validated_plan_ref = New-AdaptiveRuntimeDocumentRef $plan
    validation_classification = 'valid_exact_eight_cell_correctness'
    validated_cell_refs = $cellRefs
    validation_errors = @()
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $validation)
$binaryHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
$catalogRefs = @(
    $sources.axis,
    $sources.behavior,
    $sources.relationship,
    $sources.constraint,
    $sources.family
) | ForEach-Object { New-AdaptiveRuntimeDocumentRef $_ }
$reviewRefs = @(
    $sources.batch,
    $sources.buffer,
    $sources.oversized
) | ForEach-Object { New-AdaptiveRuntimeDocumentRef $_ }
$manifest = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-compiled-manifest-v1'
    document_id =
        "manifest.adaptive_runtime_send_admission_correctness_plan_v1.$($SourceCommit.Substring(0,12))"
    document_version = 1
    content_sha256 = '0' * 64
    authorization_id = 'send_admission_composition_correctness_v1'
    execution_purpose = 'correctness_only'
    source_commit = $SourceCommit
    source_plan_ref = New-AdaptiveRuntimeDocumentRef $plan
    source_validation_ref = New-AdaptiveRuntimeDocumentRef $validation
    catalog_refs = $catalogRefs
    reviewed_proof_refs = $reviewRefs
    compiled_cell_refs = $cellRefs
    binary_provenance = [pscustomobject][ordered]@{
        path = (Resolve-Path $BinaryPath).Path
        content_sha256 = $binaryHash
    }
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
$authorization = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-correctness-authorization-v1'
    document_id =
        'authorization.send_admission_composition_correctness_v1'
    document_version = 1
    content_sha256 = '0' * 64
    authorization_id = 'send_admission_composition_correctness_v1'
    family_id = 'send_admission_composition'
    execution_purpose = 'correctness_only'
    source_commit = $SourceCommit
    compiled_manifest_ref = New-AdaptiveRuntimeDocumentRef $manifest
    family_catalog_ref = New-AdaptiveRuntimeDocumentRef $sources.family
    relationship_catalog_ref =
        New-AdaptiveRuntimeDocumentRef $sources.relationship
    constraint_catalog_ref =
        New-AdaptiveRuntimeDocumentRef $sources.constraint
    axis_catalog_ref = New-AdaptiveRuntimeDocumentRef $sources.axis
    behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $sources.behavior
    reviewed_proof_refs = $reviewRefs
    allowed_axis_levels = $plan.allowed_axis_levels
    fixed_axis_values = $plan.fixed_axis_values
    authorized_cell_refs = $cellRefs
    invalidation_policy =
        'invalid_on_any_bound_hash_version_source_or_cell_change'
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $authorization)

$schemaMap = [ordered]@{
    validation = 'adaptive-runtime-send-admission-plan-validation-v1.schema.json'
    manifest = 'adaptive-runtime-send-admission-compiled-manifest-v1.schema.json'
    authorization =
        'adaptive-runtime-send-admission-correctness-authorization-v1.schema.json'
}
foreach ($entry in $schemaMap.GetEnumerator()) {
    $document = Get-Variable -Name $entry.Key -ValueOnly
    Assert-Compile (
        Test-AdaptiveRuntimeJsonSchema $document (
            Join-Path (Join-Path $RepositoryRoot 'schemas') $entry.Value)
    ) "admission_generated_schema_invalid:$($entry.Key)"
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
Write-AdaptiveRuntimeCanonicalDocument $validation (
    Join-Path $OutputRoot 'plan-validation.json')
Write-AdaptiveRuntimeCanonicalDocument $manifest (
    Join-Path $OutputRoot 'compiled-manifest.json')
Write-AdaptiveRuntimeCanonicalDocument $authorization (
    Join-Path $OutputRoot 'correctness-authorization.json')
if ($PassThru) {
    [pscustomobject][ordered]@{
        validation = $validation
        manifest = $manifest
        authorization = $authorization
    }
}
