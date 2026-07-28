# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Condition([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}
function Read-RepositoryDocument([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}
function Assert-ExactRef(
    [object] $Reference,
    [object] $Document,
    [string] $Code
) {
    Assert-Condition (
        [string]$Reference.document_id -ceq [string]$Document.document_id -and
        [string]$Reference.schema_version -ceq
            [string]$Document.schema_version -and
        [int]$Reference.document_version -eq
            [int]$Document.document_version -and
        [string]$Reference.content_sha256 -ceq
            [string]$Document.content_sha256
    ) $Code
}

$catalogV3 = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v3.json'
$catalogV4 = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v4.json'
$catalogV5 = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v5.json'
$singlePromotion = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\promotions\oversized-single-fragment.promotion.json'
$queuedPromotion = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\promotions\queued-single-datagram.promotion.json'
$singleReview = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-single-fragment.review.json'
$boundedReview = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-bounded-multi-fragment.review.json'
$queuedReview = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\queued-single-datagram.review.json'
$batchReview = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\batch-single-eligible.review.json'
$bufferReview = Read-RepositoryDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\buffer-memory-conservative.review.json'

foreach ($document in @(
    $catalogV3,
    $catalogV4,
    $catalogV5,
    $singlePromotion,
    $queuedPromotion
)) {
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $document) `
        "document_hash_invalid:$($document.document_id)"
    Assert-Condition (
        $document.active_behavior_authorization -eq $false -and
        $document.performance_acceptance_authorization -eq $false
    ) "authorization_widened:$($document.document_id)"
}
$catalogSchema = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-experiment-family-catalog-v4.schema.json'
$promotionSchema = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actuation-proof-promotion-v1.schema.json'
foreach ($catalog in @($catalogV4,$catalogV5)) {
    Assert-Condition (
        Test-AdaptiveRuntimeJsonSchema $catalog $catalogSchema
    ) "catalog_schema_invalid:$($catalog.document_id)"
}
foreach ($promotion in @($singlePromotion,$queuedPromotion)) {
    Assert-Condition (
        Test-AdaptiveRuntimeJsonSchema $promotion $promotionSchema
    ) "promotion_schema_invalid:$($promotion.document_id)"
}

Assert-ExactRef $singlePromotion.base_catalog_ref $catalogV3 `
    'single_promotion_base_not_v3'
Assert-ExactRef $singlePromotion.result_catalog_ref $catalogV4 `
    'single_promotion_result_not_v4'
Assert-ExactRef $singlePromotion.review_artifact_ref $singleReview `
    'single_promotion_review_mismatch'
Assert-ExactRef $queuedPromotion.base_catalog_ref $catalogV4 `
    'queued_promotion_base_not_v4'
Assert-ExactRef $queuedPromotion.result_catalog_ref $catalogV5 `
    'queued_promotion_result_not_v5'
Assert-ExactRef $queuedPromotion.review_artifact_ref $queuedReview `
    'queued_promotion_review_mismatch'

$promoted = @($catalogV5.reviewed_actuation_proofs |
    Where-Object axis_id -in @(
        'oversized_write_admission_quantum',
        'queued_send_burst_budget'
    ))
Assert-Condition ($promoted.Count -eq 2) `
    'promoted_proof_count_invalid'
Assert-Condition (
    @($promoted | Where-Object {
        $_.axis_id -ceq 'oversized_write_admission_quantum' -and
        $_.policy_value -ceq 'single_fragment' -and
        $_.review_outcome -ceq 'passed'
    }).Count -eq 1
) 'single_fragment_not_promoted_exactly_once'
Assert-Condition (
    @($promoted | Where-Object {
        $_.axis_id -ceq 'queued_send_burst_budget' -and
        $_.policy_value -ceq 'single_datagram' -and
        $_.review_outcome -ceq 'passed'
    }).Count -eq 1
) 'single_datagram_not_promoted_exactly_once'
Assert-Condition (
    @($catalogV5.reviewed_actuation_proofs |
        Where-Object policy_value -ceq 'bounded_multi_fragment').Count -eq 0
) 'bounded_multi_fragment_promoted'
Assert-Condition (
    [string]$boundedReview.review_outcome -ceq 'blocked' -and
    $boundedReview.promotion_eligibility -eq $false -and
    [string]$boundedReview.blocker -ceq
        'shadow_recommendation_value_mismatch'
) 'bounded_blocker_not_preserved'

$admissionFamily = @($catalogV5.experiment_families |
    Where-Object family_id -ceq 'send_admission_composition')
$queuedFamily = @($catalogV5.experiment_families |
    Where-Object family_id -ceq 'queued_send_burst_correctness')
Assert-Condition (
    $admissionFamily.Count -eq 1 -and
    @($admissionFamily[0].actuation_proof_refs) -contains
        [string]$singlePromotion.promoted_proof_id -and
    @($admissionFamily[0].actuation_proof_refs) -notcontains
        [string]$queuedPromotion.promoted_proof_id
) 'admission_family_promotion_boundary_invalid'
Assert-Condition (
    $queuedFamily.Count -eq 1 -and
    @($queuedFamily[0].actuation_proof_refs) -contains
        [string]$queuedPromotion.promoted_proof_id -and
    @($queuedFamily[0].actuation_proof_refs) -notcontains
        [string]$singlePromotion.promoted_proof_id
) 'queued_family_promotion_boundary_invalid'

foreach ($existing in @(
    @('application_send_batch_formation','single_eligible',$batchReview),
    @('buffer_copy_coalescing','memory_conservative',$bufferReview)
)) {
    $proofs = @($catalogV5.reviewed_actuation_proofs | Where-Object {
        $_.axis_id -ceq $existing[0] -and
        $_.policy_value -ceq $existing[1] -and
        $_.review_outcome -ceq 'passed'
    })
    Assert-Condition ($proofs.Count -eq 1) `
        "existing_reviewed_proof_missing:$($existing[0])"
    Assert-ExactRef $proofs[0].evidence_ref $existing[2] `
        "existing_reviewed_proof_stale:$($existing[0])"
}

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-runtime-proof-capture\proofs'
foreach ($slug in @('oversized-single','oversized-bounded','queued-single')) {
    $input = Read-AdaptiveRuntimeJsonDocument (
        Join-Path (Join-Path $fixtureRoot $slug) `
            'promotion-review-input.json')
    Assert-Condition (
        [string]$input.promotion_state -ceq 'not_applied' -and
        $null -eq $input.reviewer_identity -and
        $null -eq $input.review_artifact_ref -and
        $null -eq $input.independent_outcome
    ) "unapplied_promotion_input_mutated:$slug"
}

$promotionScript = Join-Path $PSScriptRoot `
    'Promote-AdaptiveRuntimeReviewedProof.ps1'
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "quic-proof-promotion-$([Guid]::NewGuid().ToString('N'))")
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $tempV4 = Join-Path $tempRoot 'catalog-v4.json'
    $tempSingle = Join-Path $tempRoot 'single.promotion.json'
    $null = & $promotionScript `
        -BaseCatalogPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v3.json') `
        -CandidateRoot (Join-Path $fixtureRoot 'oversized-single') `
        -ReviewPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-single-fragment.review.json') `
        -ExpectedAxisId 'oversized_write_admission_quantum' `
        -ExpectedPolicyValue 'single_fragment' `
        -TargetFamilyId 'send_admission_composition' `
        -ResultCatalogDocumentVersion 4 `
        -ResultCatalogPath $tempV4 `
        -PromotionPath $tempSingle `
        -RepositoryRoot $RepositoryRoot
    Assert-Condition (
        (Get-Content -LiteralPath $tempV4 -Raw) -ceq
        (Get-Content -LiteralPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v4.json') -Raw)
    ) 'single_promotion_catalog_not_deterministic'
    Assert-Condition (
        (Get-Content -LiteralPath $tempSingle -Raw) -ceq
        (Get-Content -LiteralPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\promotions\oversized-single-fragment.promotion.json') -Raw)
    ) 'single_promotion_record_not_deterministic'

    $tempV5 = Join-Path $tempRoot 'catalog-v5.json'
    $tempQueued = Join-Path $tempRoot 'queued.promotion.json'
    $null = & $promotionScript `
        -BaseCatalogPath $tempV4 `
        -CandidateRoot (Join-Path $fixtureRoot 'queued-single') `
        -ReviewPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\reviewed-proofs\queued-single-datagram.review.json') `
        -ExpectedAxisId 'queued_send_burst_budget' `
        -ExpectedPolicyValue 'single_datagram' `
        -TargetFamilyId 'queued_send_burst_correctness' `
        -ResultCatalogDocumentVersion 5 `
        -ResultCatalogPath $tempV5 `
        -PromotionPath $tempQueued `
        -RepositoryRoot $RepositoryRoot
    Assert-Condition (
        (Get-Content -LiteralPath $tempV5 -Raw) -ceq
        (Get-Content -LiteralPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v5.json') -Raw)
    ) 'queued_promotion_catalog_not_deterministic'
    Assert-Condition (
        (Get-Content -LiteralPath $tempQueued -Raw) -ceq
        (Get-Content -LiteralPath (Join-Path $RepositoryRoot `
            'eng\adaptive-runtime\experiment-control\promotions\queued-single-datagram.promotion.json') -Raw)
    ) 'queued_promotion_record_not_deterministic'

    $blockedRejected = $false
    try {
        $null = & $promotionScript `
            -BaseCatalogPath $tempV5 `
            -CandidateRoot (Join-Path $fixtureRoot 'oversized-bounded') `
            -ReviewPath (Join-Path $RepositoryRoot `
                'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-bounded-multi-fragment.review.json') `
            -ExpectedAxisId 'oversized_write_admission_quantum' `
            -ExpectedPolicyValue 'bounded_multi_fragment' `
            -TargetFamilyId 'send_admission_composition' `
            -ResultCatalogDocumentVersion 6 `
            -ResultCatalogPath (Join-Path $tempRoot 'forbidden-catalog.json') `
            -PromotionPath (Join-Path $tempRoot 'forbidden-promotion.json') `
            -RepositoryRoot $RepositoryRoot
    }
    catch {
        $blockedRejected =
            $_.Exception.Message -ceq 'review_not_promotion_eligible'
    }
    Assert-Condition $blockedRejected 'blocked_promotion_not_rejected'
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}

[pscustomobject][ordered]@{
    result = 'passed'
    catalog_base_hashes = [ordered]@{
        v3 = [string]$catalogV3.content_sha256
        v4 = [string]$catalogV4.content_sha256
        v5 = [string]$catalogV5.content_sha256
    }
    applied_promotion_count = 2
    preserved_blocked_promotion_count = 1
    existing_reviewed_proof_count = 2
    deterministic_regeneration_count = 2
    negative_case_count = 1
    active_behavior_authorized = $false
    performance_measurement_ran = $false
}
