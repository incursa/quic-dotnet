# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $FixtureRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..\tests\fixtures\adaptive-runtime-send-composition-correctness\interaction')).Path,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Copy-Document([object] $Value) {
    $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}
function Read-Input([string] $Name) {
    Read-AdaptiveRuntimeJsonDocument (
        Join-Path $FixtureRoot "inputs\$Name.json")
}

$plan = Read-Input 'experiment_plan'
$validation = Read-Input 'plan_validation'
$manifest = Read-Input 'compiled_execution_manifest'
$evidence = Read-Input 'operation_evidence'
$behavior = Read-Input 'behavior_materialization'
$outcome = Read-Input 'outcome_materialization'
$classifications = Read-Input 'classifications'
$inventory = Read-Input 'artifact_inventory'
$metrics = Read-Input 'metric_observations'
$capture = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $FixtureRoot 'mechanism-capture.json')
$proof = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $FixtureRoot 'interaction-proof.json')
$review = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $FixtureRoot 'interaction-review.json')
$projection = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $FixtureRoot 'expected\projection.json')
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')
$compatibility = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')

$schemaMap = @{
    'adaptive-runtime-send-composition-mechanism-capture-v1' =
        'adaptive-runtime-send-composition-mechanism-capture-v1.schema.json'
    'adaptive-runtime-experiment-plan-v1' =
        'adaptive-runtime-experiment-plan-v1.schema.json'
    'adaptive-runtime-experiment-plan-validation-v2' =
        'adaptive-runtime-experiment-plan-validation-v2.schema.json'
    'adaptive-runtime-compiled-execution-manifest-v1' =
        'adaptive-runtime-compiled-execution-manifest-v1.schema.json'
    'adaptive-runtime-operation-evidence-v3' =
        'adaptive-runtime-operation-evidence-v3.schema.json'
    'adaptive-runtime-effective-behavior-materialization-v3' =
        'adaptive-runtime-effective-behavior-materialization-v3.schema.json'
    'adaptive-runtime-operation-outcome-materialization-v2' =
        'adaptive-runtime-operation-outcome-materialization-v2.schema.json'
    'adaptive-runtime-experiment-evidence-projection-v3' =
        'adaptive-runtime-experiment-evidence-projection-v3.schema.json'
    'adaptive-runtime-send-composition-interaction-proof-v1' =
        'adaptive-runtime-send-composition-interaction-proof-v1.schema.json'
    'adaptive-runtime-send-composition-interaction-review-v1' =
        'adaptive-runtime-send-composition-interaction-review-v1.schema.json'
}
$documents = @(
    $capture,$plan,$validation,$manifest,$evidence,$behavior,$outcome,$projection,
    $proof,$review)
$validDocuments = 0
foreach ($document in $documents) {
    if (-not (Test-AdaptiveRuntimeDocumentHash $document)) {
        throw "invalid_hash:$($document.document_id)"
    }
    if (-not (Test-AdaptiveRuntimeJsonSchema $document (
        Join-Path $RepositoryRoot "schemas\$($schemaMap[$document.schema_version])"))) {
        throw "invalid_schema:$($document.document_id)"
    }
    $validDocuments++
}

$reviewOutput = Join-Path ([System.IO.Path]::GetTempPath()) (
    "send-composition-review-$([Guid]::NewGuid().ToString('N')).json")
try {
    $reviewed = & (Join-Path $PSScriptRoot `
        'Review-AdaptiveRuntimeSendCompositionInteraction.ps1') `
        -EvidenceRoot $FixtureRoot -OutputPath $reviewOutput
    if ($reviewed.review_outcome -ne 'passed') {
        throw 'interaction_review_not_passed'
    }
}
finally {
    Remove-Item -LiteralPath $reviewOutput -Force -ErrorAction SilentlyContinue
}

$detected = [System.Collections.Generic.List[string]]::new()
function Add-Detected([string] $Name, [bool] $Condition) {
    if (-not $Condition) { throw "negative_not_detected:$Name" }
    $detected.Add($Name)
}
function Get-Errors(
    [object] $EvidenceValue,
    [object] $ClassificationsValue = $classifications
) {
    @(Get-AdaptiveRuntimeEvidenceV3Errors -Evidence $EvidenceValue `
        -Catalog $catalog -PlanValidation $validation `
        -ClassificationSet $ClassificationsValue `
        -CompatibilityCatalog $compatibility -ArtifactInventory $inventory)
}
function Test-RejectedPlanMutation(
    [string] $Name,
    [scriptblock] $Mutation
) {
    $mutatedPlan = Copy-Document $plan
    & $Mutation $mutatedPlan
    [void](Set-AdaptiveRuntimeDocumentHash $mutatedPlan)
    $temporaryPlan = Join-Path ([System.IO.Path]::GetTempPath()) (
        "send-composition-plan-$([Guid]::NewGuid().ToString('N')).json")
    try {
        Write-AdaptiveRuntimeCanonicalDocument $mutatedPlan $temporaryPlan
        $result = & (Join-Path $PSScriptRoot `
            'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
            -PlanPath $temporaryPlan -CatalogContractVersion v2 `
            -RepositoryRoot $RepositoryRoot -AllowInvalid -PassThru
        $executable = @($result.expanded_planned_cells | Where-Object {
            $_.execution_state -eq 'executable'
        })
        Add-Detected $Name (
            $result.validation_classification -ne 'valid_interaction_screen' -or
            $executable.Count -eq 0)
    }
    finally {
        Remove-Item -LiteralPath $temporaryPlan -Force `
            -ErrorAction SilentlyContinue
    }
}

$mutated = Copy-Document $evidence
$mutated.operations = @($mutated.operations | Select-Object -Skip 1)
Add-Detected 'missing_operation' (
    @($mutated.operations).Count -ne @($behavior.derivations).Count)

$mutated = Copy-Document $evidence
$mutated.operations = @($mutated.operations) + @($mutated.operations[0])
Add-Detected 'duplicate_operation' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.operations[0].candidate_value = 'legacy_current'
Add-Detected 'wrong_decision' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.operations[0].epoch_sequence = 99
Add-Detected 'wrong_epoch' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.operations[0].connection_key = 'connection.wrong'
Add-Detected 'wrong_connection' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.operations[0].run_id = 'run.wrong'
Add-Detected 'wrong_run' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.releases[0].decision_epoch_sequence = 2
Add-Detected 'forged_release_epoch' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.releases = @($mutated.releases | Select-Object -Skip 1)
Add-Detected 'missing_release' (@(Get-Errors $mutated).Count -gt 0)

$mutated = Copy-Document $evidence
$mutated.releases = @($mutated.releases) + @($mutated.releases[0])
Add-Detected 'duplicate_release' (@(Get-Errors $mutated).Count -gt 0)

$mutatedClassifications = Copy-Document $classifications
$primary = Copy-Document $mutatedClassifications.payload.classifications[0]
$primary.classification_id = 'classification.contradictory'
$primary.kind = 'invalid'
$mutatedClassifications.payload.classifications =
    @($mutatedClassifications.payload.classifications) + @($primary)
Add-Detected 'contradictory_classification' (
    @(Get-Errors $evidence $mutatedClassifications).Count -gt 0)

$recomputedBehavior =
    New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$mutated = Copy-Document $behavior
$mutated.aggregates = @($mutated.aggregates | Select-Object -Skip 1)
Add-Detected 'behavior_recompute_mismatch' (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $mutated) -cne
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedBehavior))

$recomputedOutcome =
    New-AdaptiveRuntimeOutcomeMaterializationV2 `
        $evidence $catalog $classifications
$mutated = Copy-Document $outcome
$mutated.aggregates = @($mutated.aggregates | Select-Object -Skip 1)
Add-Detected 'outcome_recompute_mismatch' (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $mutated) -cne
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedOutcome))

$mutated = Copy-Document $projection
$mutated.experiment_plan.content_sha256 = 'f' * 64
Add-Detected 'projection_input_substitution' (
    $mutated.experiment_plan.content_sha256 -cne
        $plan.content_sha256)

$mutated = Copy-Document $metrics
$mutated.payload.metric_observations[0].metric_id =
    'metric.performance.throughput'
Add-Detected 'performance_metric_as_proof' (
    @($mutated.payload.metric_observations | Where-Object {
        -not ([string]$_.metric_id).StartsWith(
            'metric.correctness.', [StringComparison]::Ordinal)
    }).Count -gt 0)

$mutated = Copy-Document $capture
$rollback = @($mutated.operations | Where-Object {
    $_.interaction_case -eq 'rollback'
})[0]
$rollback.evidence.forced_value = 'single_eligible'
Add-Detected 'rollback_retains_forced_value' (
    $null -ne $rollback.evidence.forced_value)

Add-Detected 'candidate_proof_not_authoritative' (
    @($plan.reviewed_actuation_proof_refs | Where-Object {
        $_.schema_version -ne
            'adaptive-runtime-actuation-proof-review-v1'
    }).Count -eq 0)
Add-Detected 'exact_two_axis_cell_only' (
    @($manifest.correctness_interaction_authorization.axis_values).Count -eq
        2 -and
    [int]$manifest.correctness_interaction_authorization.
        maximum_behavior_distinct_axes -eq 2)
Add-Detected 'active_authorization_denied' (
    $manifest.active_behavior_authorization -eq $false -and
    $proof.active_behavior_authorization -eq $false)
Add-Detected 'performance_authorization_denied' (
    $manifest.performance_acceptance_authorization -eq $false -and
    $proof.performance_acceptance_authorization -eq $false)
Test-RejectedPlanMutation 'candidate_proof_used_as_passed' {
    param($value)
    $candidate = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $RepositoryRoot `
            'tests\fixtures\adaptive-runtime-send-composition-correctness\single-axis\batch\proof-candidate.json')
    $value.reviewed_actuation_proof_refs[0] =
        New-AdaptiveRuntimeDocumentRef $candidate
}
Test-RejectedPlanMutation 'wrong_policy_value_proof' {
    param($value)
    $value.treatments[0].forced_value = 'legacy_current'
    $value.treatments[0].candidate_value = 'legacy_current'
}
Test-RejectedPlanMutation 'stale_proof_hash' {
    param($value)
    $value.reviewed_actuation_proof_refs[0].content_sha256 = 'f' * 64
}
Test-RejectedPlanMutation 'stale_catalog' {
    param($value)
    $value.source_document_refs[1].content_sha256 = 'f' * 64
}
Test-RejectedPlanMutation 'family_mismatch' {
    param($value)
    $value.family_id = 'send_planning_verification'
}
Test-RejectedPlanMutation 'third_varied_axis' {
    param($value)
    $value.varied_axis_ids =
        @($value.varied_axis_ids) + @('application_send_turn_planning')
    $value.fixed_axis_ids = @('receive_credit')
    $value.fixed_axis_values = @([pscustomobject]@{
        axis_id = 'receive_credit'
        configured_value = 'legacy_current'
    })
}
Test-RejectedPlanMutation 'unsupported_combination' {
    param($value)
    $value.fixed_axis_ids = @('buffer_copy_coalescing')
    $value.fixed_axis_values = @([pscustomobject]@{
        axis_id = 'buffer_copy_coalescing'
        configured_value = 'legacy_current'
    })
}
Test-RejectedPlanMutation 'active_authorization_true' {
    param($value)
    $value.active_behavior_authorization = $true
}
Test-RejectedPlanMutation 'performance_authorization_true' {
    param($value)
    $value.performance_acceptance_authorization = $true
}

[pscustomobject][ordered]@{
    valid_documents = $validDocuments
    valid_interaction_review = 1
    interaction_operations = @($evidence.operations).Count
    interaction_releases = @($evidence.releases).Count
    behavior_aggregates = @($behavior.aggregates).Count
    outcome_aggregates = @($outcome.aggregates).Count
    adversarial_cases = $detected.Count
    adversarial_case_ids = @($detected | Sort-Object -CaseSensitive)
    projection_sha256 = $projection.content_sha256
    interaction_review_sha256 = $review.content_sha256
    measurement_frozen = $true
    active_behavior_authorized = $false
} | ConvertTo-Json -Depth 10
