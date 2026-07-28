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

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-runtime-proof-capture\proofs'
$reviewRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs'
$reviewScript = Join-Path $PSScriptRoot `
    'Review-AdaptiveRuntimeRuntimeProof.ps1'
$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actuation-proof-review-v2.schema.json'
$reviewerIdentity = 'codex.primary.autonomous-reviewer'
$reviewTimestamp = '2026-07-28T00:00:00.000Z'

function Assert-Condition([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}

$configurations = @(
    [pscustomobject]@{
        Slug = 'oversized-single'
        Axis = 'oversized_write_admission_quantum'
        Value = 'single_fragment'
        File = 'oversized-single-fragment.review.json'
        Outcome = 'passed'
        Promotion = $true
        Blocker = $null
    },
    [pscustomobject]@{
        Slug = 'oversized-bounded'
        Axis = 'oversized_write_admission_quantum'
        Value = 'bounded_multi_fragment'
        File = 'oversized-bounded-multi-fragment.review.json'
        Outcome = 'blocked'
        Promotion = $false
        Blocker = 'shadow_recommendation_value_mismatch'
    },
    [pscustomobject]@{
        Slug = 'queued-single'
        Axis = 'queued_send_burst_budget'
        Value = 'single_datagram'
        File = 'queued-single-datagram.review.json'
        Outcome = 'passed'
        Promotion = $true
        Blocker = $null
    }
)

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "quic-runtime-proof-review-$([Guid]::NewGuid().ToString('N'))")
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $results = [Collections.Generic.List[object]]::new()
    foreach ($configuration in $configurations) {
        $committedPath = Join-Path $reviewRoot $configuration.File
        $generatedPath = Join-Path $tempRoot $configuration.File
        $review = & $reviewScript `
            -CandidateRoot (Join-Path $fixtureRoot $configuration.Slug) `
            -ExpectedAxisId $configuration.Axis `
            -ExpectedPolicyValue $configuration.Value `
            -ReviewerIdentity $reviewerIdentity `
            -ReviewTimestamp $reviewTimestamp `
            -OutputPath $generatedPath `
            -RepositoryRoot $RepositoryRoot
        Assert-Condition (
            Test-AdaptiveRuntimeJsonSchema $review $schemaPath
        ) "review_schema_invalid:$($configuration.Slug)"
        Assert-Condition (
            Test-AdaptiveRuntimeDocumentHash $review
        ) "review_hash_invalid:$($configuration.Slug)"
        Assert-Condition (
            [string]$review.review_outcome -ceq $configuration.Outcome -and
            [bool]$review.promotion_eligibility -eq $configuration.Promotion -and
            [string]$review.blocker -ceq [string]$configuration.Blocker -and
            $review.active_behavior_authorization -eq $false -and
            $review.performance_acceptance_authorization -eq $false
        ) "review_disposition_invalid:$($configuration.Slug)"
        Assert-Condition (
            (Get-Content -LiteralPath $generatedPath -Raw) -ceq
            (Get-Content -LiteralPath $committedPath -Raw)
        ) "review_not_deterministic:$($configuration.Slug)"
        $results.Add([pscustomobject][ordered]@{
            proof_id = [string]$review.proof_id
            proof_hash = [string]$review.proof_hash
            review_hash = [string]$review.content_sha256
            outcome = [string]$review.review_outcome
            promotion_eligibility = [bool]$review.promotion_eligibility
            failed_assertion_count = @($review.failed_assertions).Count
        })
    }

    $boundedSource = Get-Content -LiteralPath (
        Join-Path (Join-Path $fixtureRoot 'oversized-bounded') `
            'mechanism-capture.json') -Raw | ConvertFrom-Json -Depth 100
    $boundedSource.operations[3].shadow_recommendation =
        'bounded_multi_fragment'
    [void](Set-AdaptiveRuntimeDocumentHash $boundedSource)
    $mutatedRoot = Join-Path $tempRoot 'mutated-bounded'
    Copy-Item -LiteralPath (
        Join-Path $fixtureRoot 'oversized-bounded') `
        -Destination $mutatedRoot -Recurse
    Write-AdaptiveRuntimeCanonicalDocument $boundedSource (
        Join-Path $mutatedRoot 'mechanism-capture.json')
    $mutatedReview = & $reviewScript `
        -CandidateRoot $mutatedRoot `
        -ExpectedAxisId 'oversized_write_admission_quantum' `
        -ExpectedPolicyValue 'bounded_multi_fragment' `
        -ReviewerIdentity $reviewerIdentity `
        -ReviewTimestamp $reviewTimestamp `
        -OutputPath (Join-Path $tempRoot 'mutated-review.json') `
        -RepositoryRoot $RepositoryRoot
    $negativeRejected =
        [string]$mutatedReview.review_outcome -ceq 'failed' -and
        @($mutatedReview.failed_assertions) -contains
            'runtime_mechanism_capture_exact'
    Assert-Condition $negativeRejected `
        'mutated_capture_reference_not_rejected'

    [pscustomobject][ordered]@{
        result = 'passed'
        proof_review_count = $results.Count
        passed_review_count = @($results |
            Where-Object outcome -ceq 'passed').Count
        blocked_review_count = @($results |
            Where-Object outcome -ceq 'blocked').Count
        promotion_eligible_count = @($results |
            Where-Object promotion_eligibility -eq $true).Count
        negative_case_count = 1
        reviews = @($results)
        active_behavior_authorized = $false
        performance_measurement_ran = $false
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
