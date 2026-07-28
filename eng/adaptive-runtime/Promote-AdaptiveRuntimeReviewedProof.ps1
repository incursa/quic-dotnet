# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $BaseCatalogPath,
    [Parameter(Mandatory = $true)][string] $CandidateRoot,
    [Parameter(Mandatory = $true)][string] $ReviewPath,
    [Parameter(Mandatory = $true)][string] $ExpectedAxisId,
    [Parameter(Mandatory = $true)][string] $ExpectedPolicyValue,
    [Parameter(Mandatory = $true)][string] $TargetFamilyId,
    [Parameter(Mandatory = $true)][int] $ResultCatalogDocumentVersion,
    [Parameter(Mandatory = $true)][string] $ResultCatalogPath,
    [Parameter(Mandatory = $true)][string] $PromotionPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Promotion([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}
function Read-Candidate([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $CandidateRoot $RelativePath)
}
function Test-ExactRef([object] $Reference, [object] $Document) {
    Test-AdaptiveRuntimeDocumentRef $Reference $Document
}
function Test-CanonicalFileHash(
    [string] $Path,
    [object] $Document
) {
    $declared = [string]$Document.content_sha256
    if ($declared -notmatch '^[0-9a-f]{64}$') {
        return $false
    }
    $canonicalWithHash = Get-Content -LiteralPath $Path -Raw
    $hashProperty = '"content_sha256":"' + $declared + '",'
    $index = $canonicalWithHash.IndexOf(
        $hashProperty,
        [StringComparison]::Ordinal)
    if ($index -lt 0) {
        return $false
    }
    $canonicalWithoutHash = $canonicalWithHash.Remove(
        $index,
        $hashProperty.Length)
    (Get-AdaptiveRuntimeSha256 $canonicalWithoutHash) -ceq $declared
}

$baseCatalog = Read-AdaptiveRuntimeJsonDocument $BaseCatalogPath
$proof = Read-Candidate 'proof-candidate.json'
$capture = Read-Candidate 'mechanism-capture.json'
$operationEvidence = Read-Candidate 'inputs\operation_evidence.json'
$projection = Read-Candidate 'expected\projection.json'
$unappliedInput = Read-Candidate 'promotion-review-input.json'
$review = Read-AdaptiveRuntimeJsonDocument $ReviewPath
Write-Verbose 'promotion inputs loaded'

foreach ($document in @(
    $baseCatalog,
    $proof,
    $capture,
    $operationEvidence,
    $projection,
    $unappliedInput
)) {
    Write-Verbose "verifying input hash: $($document.document_id)"
    Assert-Promotion (Test-AdaptiveRuntimeDocumentHash $document) `
        "promotion_input_hash_invalid:$($document.document_id)"
}
Assert-Promotion (Test-CanonicalFileHash $ReviewPath $review) `
    "promotion_input_hash_invalid:$($review.document_id)"
Write-Verbose 'promotion input hashes verified'
Assert-Promotion (
    [string]$proof.axis_id -ceq $ExpectedAxisId -and
    [string]$proof.policy_value -ceq $ExpectedPolicyValue -and
    [string]$review.axis_id -ceq $ExpectedAxisId -and
    [string]$review.policy_value -ceq $ExpectedPolicyValue
) 'promotion_target_mismatch'
Assert-Promotion (
    (Test-ExactRef $unappliedInput.proof_ref $proof) -and
    (Test-ExactRef $unappliedInput.mechanism_capture_ref $capture) -and
    (Test-ExactRef $unappliedInput.operation_evidence_ref $operationEvidence) -and
    (Test-ExactRef $unappliedInput.projection_ref $projection)
) 'unapplied_promotion_input_reference_mismatch'
Assert-Promotion (
    (Test-ExactRef $review.candidate_ref $proof) -and
    [string]$review.proof_hash -ceq [string]$proof.content_sha256 -and
    [string]$review.recomputed_projection_sha256 -ceq
        [string]$projection.content_sha256 -and
    [string]$review.review_outcome -ceq 'passed' -and
    $review.promotion_eligibility -eq $true -and
    @($review.failed_assertions).Count -eq 0
) 'review_not_promotion_eligible'
Assert-Promotion (
    $proof.active_behavior_authorization -eq $false -and
    $proof.performance_acceptance_authorization -eq $false -and
    $review.active_behavior_authorization -eq $false -and
    $review.performance_acceptance_authorization -eq $false -and
    $baseCatalog.active_behavior_authorization -eq $false -and
    $baseCatalog.performance_acceptance_authorization -eq $false
) 'promotion_authorization_widening'
Assert-Promotion (
    $ResultCatalogDocumentVersion -eq
        ([int]$baseCatalog.document_version + 1)
) 'result_catalog_version_not_sequential'
Write-Verbose 'promotion eligibility and sequential base verified'

$resultCatalog = $baseCatalog |
    ConvertTo-Json -Depth 100 -Compress |
    ConvertFrom-Json -Depth 100
$resultCatalog.schema_version =
    'adaptive-runtime-experiment-family-catalog-v4'
$resultCatalog.document_id =
    "adaptive_runtime_experiment_family_catalog_v$ResultCatalogDocumentVersion"
$resultCatalog.document_version = $ResultCatalogDocumentVersion
$resultCatalog.content_sha256 = '0' * 64
$trace = [pscustomobject][ordered]@{
    requirement_ids = @('REQ-QUIC-CRT-0241','REQ-QUIC-CRT-0242')
    architecture_ids = @('ARC-QUIC-CRT-0116')
    work_item_ids = @('WI-QUIC-CRT-0117')
    verification_ids = @('VER-QUIC-CRT-0118')
}
$resultCatalog.trace_references = $trace

$promotedProofId = "proof.$ExpectedAxisId.$ExpectedPolicyValue.runtime-proof-capture-20260727"
Assert-Promotion (
    @($resultCatalog.reviewed_actuation_proofs |
        Where-Object proof_id -ceq $promotedProofId).Count -eq 0
) 'proof_already_promoted'
$newProof = [pscustomobject][ordered]@{
    proof_id = $promotedProofId
    axis_id = $ExpectedAxisId
    policy_value = $ExpectedPolicyValue
    proof_version = 1
    review_outcome = 'passed'
    evidence_ref = New-AdaptiveRuntimeDocumentRef $review
}
$resultCatalog.reviewed_actuation_proofs = @(
    @($resultCatalog.reviewed_actuation_proofs) + $newProof |
        Sort-Object axis_id, policy_value, proof_id
)
$family = @($resultCatalog.experiment_families |
    Where-Object family_id -ceq $TargetFamilyId)
Assert-Promotion ($family.Count -eq 1) 'promotion_target_family_missing'
$family[0].actuation_proof_refs = @(
    @($family[0].actuation_proof_refs) + $promotedProofId |
        Sort-Object -CaseSensitive -Unique
)
[void](Set-AdaptiveRuntimeDocumentHash $resultCatalog)
Write-Verbose 'result catalog constructed and hashed'

$catalogSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-experiment-family-catalog-v4.schema.json'
Assert-Promotion (
    Test-AdaptiveRuntimeJsonSchema $resultCatalog $catalogSchemaPath
) 'result_catalog_schema_invalid'
Write-Verbose 'result catalog schema verified'

$promotion = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-actuation-proof-promotion-v1'
    document_id =
        "promotion.$ExpectedAxisId.$ExpectedPolicyValue.runtime-proof-capture-20260727"
    document_version = 1
    content_sha256 = '0' * 64
    axis_id = $ExpectedAxisId
    policy_value = $ExpectedPolicyValue
    promoted_proof_id = $promotedProofId
    proof_ref = New-AdaptiveRuntimeDocumentRef $proof
    mechanism_capture_ref = New-AdaptiveRuntimeDocumentRef $capture
    operation_evidence_ref = New-AdaptiveRuntimeDocumentRef $operationEvidence
    projection_ref = New-AdaptiveRuntimeDocumentRef $projection
    review_artifact_ref = New-AdaptiveRuntimeDocumentRef $review
    base_catalog_ref = New-AdaptiveRuntimeDocumentRef $baseCatalog
    result_catalog_ref = New-AdaptiveRuntimeDocumentRef $resultCatalog
    reviewer_identity = [string]$review.reviewer_identity
    independent_outcome = 'passed'
    promotion_state = 'applied'
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $promotion)
Write-Verbose 'promotion record constructed and hashed'
$promotionSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actuation-proof-promotion-v1.schema.json'
Assert-Promotion (
    Test-AdaptiveRuntimeJsonSchema $promotion $promotionSchemaPath
) 'promotion_record_schema_invalid'
Write-Verbose 'promotion record schema verified'

Write-AdaptiveRuntimeCanonicalDocument $resultCatalog $ResultCatalogPath
Write-AdaptiveRuntimeCanonicalDocument $promotion $PromotionPath
[pscustomobject][ordered]@{
    result = 'promoted'
    axis_id = $ExpectedAxisId
    policy_value = $ExpectedPolicyValue
    proof_hash = [string]$proof.content_sha256
    review_hash = [string]$review.content_sha256
    base_catalog_hash = [string]$baseCatalog.content_sha256
    result_catalog_hash = [string]$resultCatalog.content_sha256
    result_catalog_version = $ResultCatalogDocumentVersion
    promotion_hash = [string]$promotion.content_sha256
    active_behavior_authorized = $false
    performance_measurement_ran = $false
}
