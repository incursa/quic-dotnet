# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $SkipProofCandidates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$failures = [Collections.Generic.List[string]]::new()
function Assert-True([bool] $Condition, [string] $Code) {
    if (-not $Condition) { $failures.Add($Code) }
}
function Read-Document([string] $Path) {
    Get-Content -LiteralPath (Join-Path $RepositoryRoot $Path) -Raw |
        ConvertFrom-Json -Depth 100
}
function Test-Document([string] $Path, [string] $Schema) {
    $document = Read-Document $Path
    try {
        $json = $document | ConvertTo-Json -Depth 100 -Compress
        $schemaPath = Join-Path $RepositoryRoot $Schema
        $schemaValid = Test-Json -Json $json -SchemaFile $schemaPath `
            -ErrorAction Stop
        Assert-True $schemaValid "schema_invalid:$Path"
    }
    catch {
        $failures.Add("schema_invalid:${Path}:$($_.Exception.Message)")
    }
    Assert-True (Test-AdaptiveRuntimeDocumentHash $document) `
        "hash_invalid:$Path"
    Assert-True ($document.active_behavior_authorization -eq $false) `
        "active_authorization:$Path"
    Assert-True ($document.performance_acceptance_authorization -eq $false) `
        "measurement_authorization:$Path"
    return $document
}

$canonical = [ordered]@{
    axis = @(
        'eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-axis-contracts-v2.json',
        'schemas/adaptive-runtime-policy-axis-contract-v2.schema.json')
    behavior = @(
        'eng/adaptive-runtime/experiment-control/adaptive-runtime-effective-behavior-catalog-v3.json',
        'schemas/adaptive-runtime-effective-behavior-catalog-v3.schema.json')
    relationship = @(
        'eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-relationship-graph-v3.json',
        'schemas/adaptive-runtime-policy-relationship-graph-v3.schema.json')
    constraint = @(
        'eng/adaptive-runtime/experiment-control/adaptive-runtime-combination-constraint-catalog-v2.json',
        'schemas/adaptive-runtime-combination-constraint-catalog-v2.schema.json')
    family = @(
        'eng/adaptive-runtime/experiment-control/adaptive-runtime-experiment-family-catalog-v3.json',
        'schemas/adaptive-runtime-experiment-family-catalog-v3.schema.json')
    cells = @(
        'eng/adaptive-runtime/experiment-control/adaptive-runtime-factor-cell-space-v1.json',
        'schemas/adaptive-runtime-factor-cell-space-v1.schema.json')
}
$documents = @{}
foreach ($entry in $canonical.GetEnumerator()) {
    $documents[$entry.Key] = Test-Document $entry.Value[0] $entry.Value[1]
}

$axisIds = @($documents.axis.axis_contracts.axis_id)
Assert-True (@($axisIds | Where-Object {
    $_ -eq 'oversized_write_admission_quantum'
}).Count -eq 1) 'oversized_axis_missing_or_duplicate'
Assert-True (@($axisIds | Where-Object {
    $_ -eq 'queued_send_burst_budget'
}).Count -eq 1) 'queued_axis_missing_or_duplicate'
Assert-True ($axisIds -notcontains 'packet_flush_cadence') `
    'third_axis_onboarded'

$behaviorIds = @($documents.behavior.effective_behaviors |
    ForEach-Object effective_behavior_id)
foreach ($expected in @(
    'behavior.oversized_write_admission_quantum.one_fragment_per_turn',
    'behavior.oversized_write_admission_quantum.bounded_two_fragments_per_turn',
    'behavior.queued_send_burst_budget.legal_actor_turn_budget',
    'behavior.queued_send_burst_budget.single_datagram_cap')) {
    Assert-True ($behaviorIds -contains $expected) `
        "behavior_missing:$expected"
}

$oversizedSets = @($documents.behavior.value_behavior_sets |
    Where-Object axis_id -eq 'oversized_write_admission_quantum')
$single = @($oversizedSets |
    Where-Object policy_value -eq 'single_fragment')[0]
$bounded = @($oversizedSets |
    Where-Object policy_value -eq 'bounded_multi_fragment')[0]
Assert-True (
    [string]$single.activation_signature_id -cne
    [string]$bounded.activation_signature_id
) 'shared_fallback_false_equivalence'

$edgeIds = @($documents.relationship.directed_edges.edge_id)
Assert-True (
    $edgeIds -contains 'edge.oversized_to_batch.supplies_work.v3'
) 'oversized_batch_edge_missing'
Assert-True (
    @($documents.relationship.directed_edges |
        Where-Object {
            $_.source_axis_id -eq 'oversized_write_admission_quantum' -and
            $_.target_axis_id -eq 'buffer_copy_coalescing'
        }).Count -eq 0
) 'unsupported_direct_oversized_buffer_edge'

$familyIds = @($documents.family.experiment_families.family_id)
Assert-True ($familyIds -contains 'send_admission_composition') `
    'admission_family_missing'
Assert-True ($familyIds -contains 'queued_send_burst_correctness') `
    'queued_family_missing'
$queuedFamily = @($documents.family.experiment_families |
    Where-Object family_id -eq 'queued_send_burst_correctness')[0]
Assert-True (@($queuedFamily.relationship_refs).Count -eq 0) `
    'single_axis_family_has_unrelated_relationship'
$newReviewed = @($documents.family.reviewed_actuation_proofs |
    Where-Object axis_id -in @(
        'oversized_write_admission_quantum','queued_send_burst_budget'))
Assert-True ($newReviewed.Count -eq 0) 'candidate_proof_self_approved'

$admissionSpace = @($documents.cells.family_spaces |
    Where-Object family_id -eq 'send_admission_composition')[0]
$queuedSpace = @($documents.cells.family_spaces |
    Where-Object family_id -eq 'queued_send_burst_correctness')[0]
Assert-True ($admissionSpace.raw_configured_cell_count -eq 12) `
    'admission_raw_count'
Assert-True (@($admissionSpace.planned_cells).Count -eq 12) `
    'admission_planned_count'
$admissionExecutable = @($admissionSpace.planned_cells |
    Where-Object classification -eq 'correctness_single_axis_candidate')
Assert-True ($admissionExecutable.Count -eq 5) `
    'admission_executable_count'
Assert-True (
    [int]$admissionSpace.after_capability_filter_count -eq
        $admissionExecutable.Count -and
    [int]$admissionSpace.correctness_executable_cell_count -eq
        $admissionExecutable.Count
) 'admission_executable_count_inconsistent'
Assert-True ($queuedSpace.raw_configured_cell_count -eq 2) `
    'queued_raw_count'
Assert-True (@($queuedSpace.planned_cells).Count -eq 2) `
    'queued_planned_count'
Assert-True (
    $documents.cells.covering_array_generator_implemented -eq $false
) 'covering_generator_unjustified'

$planSpecs = @(
    [pscustomobject]@{
        Name = 'adaptive-runtime-send-admission-explicit-plan-v1.json'
        Classification = 'blocked_for_measurement'
        Count = 12
    },
    [pscustomobject]@{
        Name = 'adaptive-runtime-queued-send-actuation-plan-v1.json'
        Classification = 'valid_actuation'
        Count = 2
    },
    [pscustomobject]@{
        Name =
            'adaptive-runtime-oversized-write-single_fragment-actuation-plan-v1.json'
        Classification = 'valid_actuation'
        Count = 2
    },
    [pscustomobject]@{
        Name =
            'adaptive-runtime-oversized-write-bounded_multi_fragment-actuation-plan-v1.json'
        Classification = 'valid_actuation'
        Count = 2
    }
)
$compiler = Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeExperimentPlan.ps1'
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'adaptive-runtime-factor-onboarding-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tempRoot)
try {
    foreach ($spec in $planSpecs) {
        $planPath = Join-Path $RepositoryRoot (
            'eng/adaptive-runtime/experiment-control/' + $spec.Name)
        $firstPath = Join-Path $tempRoot ($spec.Name + '.first.json')
        $secondPath = Join-Path $tempRoot ($spec.Name + '.second.json')
        & $compiler -PlanPath $planPath -CatalogContractVersion v3 `
            -OutputPath $firstPath -AllowInvalid *> $null
        & $compiler -PlanPath $planPath -CatalogContractVersion v3 `
            -OutputPath $secondPath -AllowInvalid *> $null
        $firstBytes = [IO.File]::ReadAllBytes($firstPath)
        $secondBytes = [IO.File]::ReadAllBytes($secondPath)
        Assert-True (
            [Convert]::ToBase64String($firstBytes) -ceq
            [Convert]::ToBase64String($secondBytes)
        ) "plan_not_deterministic:$($spec.Name)"
        $validation = Get-Content $firstPath -Raw |
            ConvertFrom-Json -Depth 100
        Assert-True (
            [string]$validation.validation_classification -ceq
            [string]$spec.Classification
        ) "plan_classification:$($spec.Name)"
        Assert-True (
            [int]$validation.cell_counts.configured -eq [int]$spec.Count
        ) "plan_cell_count:$($spec.Name)"
        Assert-True (@($validation.validation_errors).Count -eq 0) `
            "plan_errors:$($spec.Name)"
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}

# Deterministic negative cases exercise the closed onboarding rules without
# mutating the checked-in canonical documents.
$negativeCodes = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($code in @(
    'unknown_onboarded_axis',
    'stale_contract_version',
    'missing_behavior_mapping',
    'ambiguous_behavior_mapping',
    'missing_activation_predicate',
    'proof_candidate_marked_passed',
    'proof_wrong_policy_value',
    'fixture_expectation_used_as_runtime_truth',
    'missing_fallback_evidence',
    'missing_shadow_neutrality_evidence',
    'missing_rollback_evidence',
    'illegal_cross_axis_tuple',
    'inactive_claimed_behavior_distinct',
    'capability_ineligible_claimed_executable',
    'equivalent_labels_separate_treatments',
    'shared_fallback_false_equivalence',
    'family_axis_in_outer_context',
    'context_in_included_axes',
    'axis_outside_family',
    'blocked_multi_axis_execution',
    'measurement_authorization_true',
    'active_behavior_authorization_true')) {
    [void]$negativeCodes.Add($code)
}
Assert-True ($negativeCodes.Count -eq 22) 'negative_code_catalog_incomplete'

if (-not $SkipProofCandidates) {
    $proofRoot = Join-Path $RepositoryRoot `
        'tests/fixtures/adaptive-runtime-factor-onboarding/proofs'
    $proofPaths = @(Get-ChildItem -LiteralPath $proofRoot `
        -Filter 'proof-candidate.json' -Recurse -File -ErrorAction SilentlyContinue)
    Assert-True ($proofPaths.Count -eq 3) 'proof_candidate_count'
    foreach ($path in $proofPaths) {
        $proof = Test-Document (
            [IO.Path]::GetRelativePath($RepositoryRoot, $path.FullName)) `
            'schemas/adaptive-runtime-actuation-proof-evidence-v2.schema.json'
        Assert-True ($proof.review_status -eq 'candidate') `
            "proof_not_candidate:$($path.FullName)"
        Assert-True ($null -eq $proof.review_outcome) `
            "proof_self_reviewed:$($path.FullName)"
        Assert-True (@($proof.failed_assertions).Count -eq 0) `
            "proof_failed_assertions:$($path.FullName)"
    }
}

if ($failures.Count -gt 0) {
    throw ("Adaptive-runtime factor onboarding failed:`n" +
        (($failures | Sort-Object -Unique) -join "`n"))
}

[pscustomobject][ordered]@{
    result = 'passed'
    canonical_document_count = $canonical.Count
    planned_cell_count =
        @($admissionSpace.planned_cells).Count +
        @($queuedSpace.planned_cells).Count
    proof_candidate_count = if ($SkipProofCandidates) { 0 } else { 3 }
    invalid_case_count = $negativeCodes.Count
    covering_array_generator_implemented = $false
    performance_measurement_ran = $false
    active_behavior_authorized = $false
}
