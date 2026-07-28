# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CandidateRoot,
    [Parameter(Mandatory = $true)][string] $ExpectedAxisId,
    [Parameter(Mandatory = $true)][string] $ExpectedPolicyValue,
    [Parameter(Mandatory = $true)][string] $ReviewerIdentity,
    [Parameter(Mandatory = $true)][string] $ReviewTimestamp,
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

$schemaRoot = Join-Path $RepositoryRoot 'schemas'
$catalogRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control'

function Assert-Argument([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}

Assert-Argument (
    $ReviewerIdentity -match '^[a-z0-9][a-z0-9._-]*$'
) 'reviewer_identity_invalid'
$parsedTimestamp = [DateTimeOffset]::MinValue
Assert-Argument (
    [DateTimeOffset]::TryParse(
        $ReviewTimestamp,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsedTimestamp)
) 'review_timestamp_invalid'
$canonicalTimestamp = $parsedTimestamp.ToUniversalTime().
    ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)

function Read-ProofDocument([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $CandidateRoot $RelativePath)
}

function Get-DocumentKey([object] $Document) {
    "$($Document.document_id)|$($Document.schema_version)|$(
        $Document.document_version)|$($Document.content_sha256)"
}

function Get-OperationKey([object] $Operation) {
    "$($Operation.run_id)|$($Operation.connection_key)|$(
        $Operation.epoch_sequence)|$($Operation.axis_id)|$(
        $Operation.decision_instance_id)|$($Operation.operation_id)"
}

function Get-CaptureOperationKey([object] $Capture, [object] $Operation) {
    "$($Capture.run_id)|$($Operation.connection_key)|$(
        $Operation.epoch_sequence)|$($Capture.axis_id)|$(
        $Operation.decision_instance_id)|$($Operation.operation_id)"
}

$proof = Read-ProofDocument 'proof-candidate.json'
$capture = Read-ProofDocument 'mechanism-capture.json'
$plan = Read-ProofDocument 'inputs\experiment_plan.json'
$validation = Read-ProofDocument 'inputs\plan_validation.json'
$manifest = Read-ProofDocument 'inputs\compiled_execution_manifest.json'
$run = Read-ProofDocument 'inputs\experiment_run.json'
$hostDocument = Read-ProofDocument 'inputs\host_fingerprint.json'
$binary = Read-ProofDocument 'inputs\binary_cohort.json'
$workload = Read-ProofDocument 'inputs\workload_instance.json'
$requested = Read-ProofDocument 'inputs\requested_workload_shape.json'
$effective = Read-ProofDocument 'inputs\effective_workload_shape.json'
$evidence = Read-ProofDocument 'inputs\operation_evidence.json'
$behavior = Read-ProofDocument 'inputs\behavior_materialization.json'
$outcome = Read-ProofDocument 'inputs\outcome_materialization.json'
$metrics = Read-ProofDocument 'inputs\metric_observations.json'
$inventory = Read-ProofDocument 'inputs\artifact_inventory.json'
$classifications = Read-ProofDocument 'inputs\classifications.json'
$projection = Read-ProofDocument 'expected\projection.json'
$behaviorCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v3.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-classification-compatibility-catalog-v1.json')
$runtimeExportPath = Join-Path $CandidateRoot 'runtime-sink-export.json'
$runtimeExportJson = Get-Content -LiteralPath $runtimeExportPath -Raw
$runtimeExport = $runtimeExportJson | ConvertFrom-Json -Depth 100
$runtimeExportFileHash = (Get-FileHash -LiteralPath $runtimeExportPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()

Assert-Argument (
    [string]$proof.axis_id -ceq $ExpectedAxisId -and
    [string]$proof.policy_value -ceq $ExpectedPolicyValue
) 'review_target_mismatch'

$assertions = [Collections.Generic.List[object]]::new()
$failed = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
function Add-ReviewAssertion(
    [string] $Id,
    [bool] $Passed,
    [string] $Evidence,
    [switch] $NotApplicable
) {
    $status = if ($NotApplicable) {
        'not_applicable'
    }
    elseif ($Passed) {
        'passed'
    }
    else {
        'failed'
    }
    $assertions.Add([pscustomobject][ordered]@{
        assertion_id = $Id
        status = $status
        evidence = $Evidence
    })
    if (-not $Passed -and -not $NotApplicable) {
        [void]$failed.Add($Id)
    }
}

$documentMap = [ordered]@{
    proof = $proof
    mechanism_capture = $capture
    experiment_plan = $plan
    plan_validation = $validation
    compiled_execution_manifest = $manifest
    experiment_run = $run
    host_fingerprint = $hostDocument
    binary_cohort = $binary
    workload_instance = $workload
    requested_workload_shape = $requested
    effective_workload_shape = $effective
    operation_evidence = $evidence
    behavior_materialization = $behavior
    outcome_materialization = $outcome
    metric_observations = $metrics
    artifact_inventory = $inventory
    classifications = $classifications
    projection = $projection
}
$envelopeOnlySchemaVersions = @(
    'adaptive-runtime-artifact-inventory-v1',
    'adaptive-runtime-binary-cohort-v1',
    'adaptive-runtime-classification-set-v1',
    'adaptive-runtime-experiment-run-v1',
    'adaptive-runtime-host-fingerprint-v1',
    'adaptive-runtime-metric-observations-v1',
    'adaptive-runtime-workload-instance-v1',
    'adaptive-runtime-workload-shape-v1'
)
$schemaAndHashValid = $true
$publishedSchemaCount = 0
$envelopeOnlyCount = 0
foreach ($document in $documentMap.Values) {
    if (-not (Test-AdaptiveRuntimeDocumentHash $document)) {
        $schemaAndHashValid = $false
        continue
    }
    $schemaPath = Join-Path $schemaRoot "$($document.schema_version).schema.json"
    if (-not (Test-Path -LiteralPath $schemaPath)) {
        if ([string]$document.schema_version -notin
            $envelopeOnlySchemaVersions) {
            $schemaAndHashValid = $false
        }
        else {
            $envelopeOnlyCount++
        }
        continue
    }
    $publishedSchemaCount++
    try {
        if (-not (Test-AdaptiveRuntimeJsonSchema $document $schemaPath)) {
            $schemaAndHashValid = $false
        }
    }
    catch {
        $schemaAndHashValid = $false
    }
}
$runtimeExportSchemaValid = Test-Json -Json $runtimeExportJson -SchemaFile (
    Join-Path $schemaRoot `
        'adaptive-runtime-runtime-proof-sink-export-v1.schema.json')
Add-ReviewAssertion 'published_schemas_and_content_hashes_exact' (
    $schemaAndHashValid -and $runtimeExportSchemaValid
) "canonical_documents=$($documentMap.Count);published_schemas=$publishedSchemaCount;envelope_only_documents=$envelopeOnlyCount;runtime_export_schema=$runtimeExportSchemaValid"

$planExact = Test-AdaptiveRuntimeDocumentRef $proof.source_plan_ref $plan
Add-ReviewAssertion 'source_plan_exact' $planExact `
    "hash=$($plan.content_sha256)"
$validationExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.plan_validation_ref $validation) -and
    [string]$validation.validated_plan_ref.content_sha256 -ceq
        [string]$plan.content_sha256
Add-ReviewAssertion 'plan_validation_exact' $validationExact `
    "hash=$($validation.content_sha256)"
$manifestExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.compiled_manifest_ref $manifest) -and
    [string]$manifest.source_plan_ref.content_sha256 -ceq
        [string]$plan.content_sha256 -and
    [string]$manifest.source_validation_ref.content_sha256 -ceq
        [string]$validation.content_sha256
Add-ReviewAssertion 'compiled_manifest_exact' $manifestExact `
    "hash=$($manifest.content_sha256)"

$sourceCommitExact =
    [string]$proof.source_commit -ceq [string]$manifest.source_commit -and
    [string]$proof.source_commit -ceq [string]$binary.payload.source_commit -and
    [string]$proof.source_commit -ceq [string]$capture.runtime_source.source_commit -and
    [string]$proof.source_commit -ceq [string]$runtimeExport.source_commit
Add-ReviewAssertion 'source_commit_exact' $sourceCommitExact `
    "source_commit=$($proof.source_commit)"

$binaryPath = [string]$binary.payload.binary_path
$binaryFileHash = if (Test-Path -LiteralPath $binaryPath) {
    (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).
        Hash.ToLowerInvariant()
}
else {
    'missing'
}
$manifestBinary = @($manifest.binary_provenance |
    Where-Object role -ceq 'test_binary')
$binaryExact =
    $manifestBinary.Count -eq 1 -and
    $binaryFileHash -ceq [string]$binary.payload.binary_sha256 -and
    $binaryFileHash -ceq [string]$manifestBinary[0].content_sha256 -and
    $binaryFileHash -ceq [string]$capture.runtime_source.binary_sha256 -and
    $binaryFileHash -ceq [string]$runtimeExport.binary_sha256
Add-ReviewAssertion 'binary_hash_exact' $binaryExact `
    "binary_sha256=$binaryFileHash"

$hostExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.host_fingerprint_ref $hostDocument) -and
    [string]$hostDocument.payload.fingerprint_id -ceq
        [string]$manifest.host_fingerprint.fingerprint_id
Add-ReviewAssertion 'host_identity_exact' $hostExact `
    "host=$($hostDocument.payload.fingerprint_id)"
$runExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.experiment_run_ref $run) -and
    [string]$run.payload.run_id -ceq [string]$capture.run_id -and
    [string]$run.payload.compiled_manifest_ref.content_sha256 -ceq
        [string]$manifest.content_sha256
Add-ReviewAssertion 'experiment_run_exact' $runExact `
    "run_id=$($run.payload.run_id)"
$workloadExact =
    @($run.payload.workload_instance_ids) -contains
        [string]$workload.payload.workload_instance_id -and
    [string]$workload.payload.run_ref.content_sha256 -ceq
        [string]$run.content_sha256 -and
    [string]$workload.payload.requested_shape_ref.content_sha256 -ceq
        [string]$requested.content_sha256 -and
    [string]$workload.payload.effective_shape_ref.content_sha256 -ceq
        [string]$effective.content_sha256
Add-ReviewAssertion 'workload_identities_exact' $workloadExact `
    "workload=$($workload.payload.workload_instance_id)"

$runtimeSourceExact =
    [string]$capture.capture_mode -ceq 'runtime_evidence_sink' -and
    [string]$capture.runtime_source.export_id -ceq
        [string]$runtimeExport.export_id -and
    [string]$capture.runtime_source.file_sha256 -ceq
        $runtimeExportFileHash
Add-ReviewAssertion 'runtime_source_provenance_exact' $runtimeSourceExact `
    "export_id=$($runtimeExport.export_id);file_sha256=$runtimeExportFileHash"

$captureRefExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.mechanism_capture_ref $capture) -and
    [string]$capture.axis_id -ceq $ExpectedAxisId -and
    [string]$capture.policy_value -ceq $ExpectedPolicyValue -and
    [int]$capture.forced_behavior_distinct_axis_count -eq 1
Add-ReviewAssertion 'runtime_mechanism_capture_exact' $captureRefExact `
    "hash=$($capture.content_sha256);operations=$(@($capture.operations).Count)"
$evidenceRefExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.operation_evidence_ref $evidence) -and
    [string]$evidence.run_id -ceq [string]$capture.run_id
Add-ReviewAssertion 'operation_evidence_exact' $evidenceRefExact `
    "hash=$($evidence.content_sha256);operations=$(@($evidence.operations).Count)"

$evidenceKeys = @($evidence.operations | ForEach-Object {
    Get-OperationKey $_
} | Sort-Object -CaseSensitive)
$captureKeys = @($capture.operations | ForEach-Object {
    Get-CaptureOperationKey $capture $_
} | Sort-Object -CaseSensitive)
$identityExact =
    (ConvertTo-Json $evidenceKeys -Compress) -ceq
        (ConvertTo-Json $captureKeys -Compress) -and
    @($evidenceKeys | Sort-Object -Unique).Count -eq $evidenceKeys.Count
Add-ReviewAssertion 'complete_composite_identities_exact' $identityExact `
    "operation_count=$($evidenceKeys.Count);unique_count=$(@($evidenceKeys | Sort-Object -Unique).Count)"

$recomputedBehavior = New-AdaptiveRuntimeBehaviorMaterializationV3 `
    $evidence $behaviorCatalog
$behaviorExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.behavior_materialization_ref $behavior) -and
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedBehavior `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior `
        -IncludeRootContentSha256)
Add-ReviewAssertion 'behavior_materialization_recomputed' $behaviorExact `
    "hash=$($recomputedBehavior.content_sha256)"
$recomputedOutcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $behaviorCatalog $classifications
$outcomeExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.outcome_materialization_ref $outcome) -and
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedOutcome `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome `
        -IncludeRootContentSha256)
Add-ReviewAssertion 'outcome_materialization_recomputed' $outcomeExact `
    "hash=$($recomputedOutcome.content_sha256)"

$classificationTargetsExact = @($classifications.payload.classifications |
    Where-Object {
        $_.target.target_kind -ceq 'operation' -and
        (Get-OperationKey $_.target) -notin $evidenceKeys
    }).Count -eq 0
Add-ReviewAssertion 'classifications_exact' $classificationTargetsExact `
    "classification_count=$(@($classifications.payload.classifications).Count)"
$inventoryRefs = @($inventory.payload.artifacts.document_ref |
    ForEach-Object {
        "$($_.document_id)|$($_.schema_version)|$(
            $_.document_version)|$($_.content_sha256)"
    })
$inputKeys = @($documentMap.GetEnumerator() |
    Where-Object Key -notin @(
        'proof',
        'mechanism_capture',
        'artifact_inventory',
        'projection'
    ) |
    ForEach-Object { Get-DocumentKey $_.Value })
$inventoryExact = @($inputKeys | Where-Object {
    $_ -notin $inventoryRefs
}).Count -eq 0
Add-ReviewAssertion 'artifact_inventory_exact' $inventoryExact `
    "inventory_count=$($inventoryRefs.Count)"

$projectionScript = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1'
$projectionParameters = @{
    PlanPath = Join-Path $CandidateRoot 'inputs\experiment_plan.json'
    PlanValidationPath = Join-Path $CandidateRoot 'inputs\plan_validation.json'
    CompiledManifestPath =
        Join-Path $CandidateRoot 'inputs\compiled_execution_manifest.json'
    ExperimentRunPath = Join-Path $CandidateRoot 'inputs\experiment_run.json'
    HostFingerprintPath = Join-Path $CandidateRoot 'inputs\host_fingerprint.json'
    BinaryCohortPath = Join-Path $CandidateRoot 'inputs\binary_cohort.json'
    WorkloadInstancePath = Join-Path $CandidateRoot 'inputs\workload_instance.json'
    RequestedWorkloadShapePath =
        Join-Path $CandidateRoot 'inputs\requested_workload_shape.json'
    EffectiveWorkloadShapePath =
        Join-Path $CandidateRoot 'inputs\effective_workload_shape.json'
    OperationEvidencePath = Join-Path $CandidateRoot 'inputs\operation_evidence.json'
    BehaviorMaterializationPath =
        Join-Path $CandidateRoot 'inputs\behavior_materialization.json'
    OutcomeMaterializationPath =
        Join-Path $CandidateRoot 'inputs\outcome_materialization.json'
    MetricObservationsPath =
        Join-Path $CandidateRoot 'inputs\metric_observations.json'
    ArtifactInventoryPath =
        Join-Path $CandidateRoot 'inputs\artifact_inventory.json'
    ClassificationsPath = Join-Path $CandidateRoot 'inputs\classifications.json'
    BehaviorCatalogPath =
        Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v3.json'
    ClassificationCompatibilityCatalogPath = Join-Path $catalogRoot `
        'adaptive-runtime-classification-compatibility-catalog-v1.json'
    SchemaRoot = $schemaRoot
    PassThru = $true
}
$recomputedProjection = & $projectionScript @projectionParameters
$projectionExact =
    (Test-AdaptiveRuntimeDocumentRef $proof.projection_ref $projection) -and
    (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedProjection `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection `
        -IncludeRootContentSha256)
Add-ReviewAssertion 'analytical_projection_recomputed' $projectionExact `
    "hash=$($recomputedProjection.content_sha256)"
$canonicalBytesExact = @($documentMap.Values | Where-Object {
    (Get-AdaptiveRuntimeDocumentHash $_) -cne [string]$_.content_sha256
}).Count -eq 0
Add-ReviewAssertion 'canonical_bytes_and_hashes_recomputed' `
    $canonicalBytesExact "document_count=$($documentMap.Count)"

$focusedBinding =
    [string]$proof.harness_id -ceq
        'incursa.quic.tests.req-quic-crt-0238.runtime-proof-capture' -and
    @($proof.trace_references.requirement_ids) -contains
        'REQ-QUIC-CRT-0238'
Add-ReviewAssertion 'focused_mechanism_test_binding_exact' $focusedBinding `
    "harness=$($proof.harness_id)"

function Get-CaptureCase([string] $Name) {
    @($capture.operations | Where-Object capture_case -ceq $Name)
}
$positive = @(Get-CaptureCase 'positive_actuation')
$inactive = @(Get-CaptureCase 'structurally_inactive')
$fallback = @(Get-CaptureCase 'safety_fallback')
$shadow = @(Get-CaptureCase 'shadow_neutrality')
$rollback = @(Get-CaptureCase 'rollback')
$casesExact = $positive.Count -eq 1 -and $inactive.Count -eq 1 -and
    $fallback.Count -eq 1 -and $shadow.Count -eq 1 -and
    $rollback.Count -eq 1
Add-ReviewAssertion 'required_cases_exact' $casesExact `
    "positive=$($positive.Count);inactive=$($inactive.Count);fallback=$($fallback.Count);shadow=$($shadow.Count);rollback=$($rollback.Count)"
$positiveExact = $positive.Count -eq 1 -and
    [string]$positive[0].forced_value -ceq $ExpectedPolicyValue -and
    [string]$positive[0].candidate_value -ceq $ExpectedPolicyValue -and
    [string]$positive[0].operation_eligibility_result -ceq 'eligible' -and
    [string]$positive[0].applied_value -ceq $ExpectedPolicyValue -and
    [long]$positive[0].legal_work_count -gt
        [long]$positive[0].applied_work_count
Add-ReviewAssertion 'candidate_eligibility_and_application_exact' `
    $positiveExact "legal=$(if($positive.Count){$positive[0].legal_work_count}else{0});applied=$(if($positive.Count){$positive[0].applied_work_count}else{0})"
$inactiveExact = $inactive.Count -eq 1 -and
    [string]$inactive[0].result -ceq 'inactive'
Add-ReviewAssertion 'inactive_case_retained' $inactiveExact `
    "legal=$(if($inactive.Count){$inactive[0].legal_work_count}else{0})"
$fallbackExact = $fallback.Count -eq 1 -and
    [string]$fallback[0].candidate_value -ceq $ExpectedPolicyValue -and
    [string]$fallback[0].result -in @('fallback','clamped') -and
    -not [string]::IsNullOrWhiteSpace(
        [string]$fallback[0].fallback_or_safety_reason)
Add-ReviewAssertion 'safety_fallback_authoritative' $fallbackExact `
    "result=$(if($fallback.Count){$fallback[0].result}else{'missing'})"
$shadowNonActuating = $shadow.Count -eq 1 -and
    $null -eq $shadow[0].forced_value -and
    [string]$shadow[0].applied_value -ceq 'legacy_current'
Add-ReviewAssertion 'shadow_recommendation_non_actuating' `
    $shadowNonActuating "applied=$(if($shadow.Count){$shadow[0].applied_value}else{'missing'})"
$shadowMatches = $shadow.Count -eq 1 -and
    [string]$shadow[0].shadow_recommendation -ceq $ExpectedPolicyValue
Add-ReviewAssertion 'shadow_recommendation_matches_value' `
    $shadowMatches "recommendation=$(if($shadow.Count){$shadow[0].shadow_recommendation}else{'missing'})"
$rollbackExact = $rollback.Count -eq 1 -and
    $null -eq $rollback[0].forced_value -and
    [string]$rollback[0].candidate_value -ceq 'legacy_current' -and
    [string]$rollback[0].applied_value -ceq 'legacy_current'
Add-ReviewAssertion 'rollback_restores_legacy' $rollbackExact `
    "applied=$(if($rollback.Count){$rollback[0].applied_value}else{'missing'})"

$performanceAbsent =
    @($metrics.payload.metric_observations | Where-Object {
        [string]$_.analytical_use -cne 'correctness_only' -or
        -not ([string]$_.metric_id).StartsWith(
            'metric.correctness.', [StringComparison]::Ordinal)
    }).Count -eq 0 -and
    $proof.performance_acceptance_authorization -eq $false -and
    $manifest.performance_acceptance_authorization -eq $false
Add-ReviewAssertion 'performance_facts_absent' $performanceAbsent `
    "metric_count=$(@($metrics.payload.metric_observations).Count)"
$expectationFactsAbsent =
    [string]$capture.capture_mode -ceq 'runtime_evidence_sink' -and
    @($capture.operations | Where-Object {
        $null -eq $_.runtime_source_identity
    }).Count -eq 0
Add-ReviewAssertion 'fixture_or_expectation_mechanism_facts_absent' `
    $expectationFactsAbsent "capture_mode=$($capture.capture_mode)"
$candidateState =
    [string]$proof.review_status -ceq 'candidate' -and
    $null -eq $proof.review_outcome -and
    $proof.active_behavior_authorization -eq $false -and
    $proof.performance_acceptance_authorization -eq $false
Add-ReviewAssertion 'candidate_state_and_authorizations_exact' `
    $candidateState "review_status=$($proof.review_status);active=$($proof.active_behavior_authorization);performance=$($proof.performance_acceptance_authorization)"

if ($ExpectedAxisId -ceq 'oversized_write_admission_quantum') {
    $expectedFragments = if ($ExpectedPolicyValue -ceq 'single_fragment') {
        1
    }
    else {
        2
    }
    $fragmentExact = $positive.Count -eq 1 -and
        [long]$positive[0].applied_work_count -eq $expectedFragments -and
        [long]$positive[0].legal_work_count -gt $expectedFragments
    Add-ReviewAssertion 'oversized_initial_fragment_count_exact' `
        $fragmentExact "legal=$($positive[0].legal_work_count);initial=$($positive[0].applied_work_count)"
    $details = $positive[0].mechanism_details
    $expectedContinuationCount = [long][Math]::Ceiling(
        ([double]$positive[0].legal_work_count -
            [double]$positive[0].applied_work_count) /
        [double]$positive[0].applied_work_count)
    $continuationSchedulingExact =
        [long]$details.first_continuation_sequence -eq 1 -and
        (
            (
                $ExpectedPolicyValue -ceq 'single_fragment' -and
                [long]$details.continuation_posts -eq 0 -and
                [long]$details.continuation_request_id -eq 0
            ) -or
            (
                $ExpectedPolicyValue -ceq 'bounded_multi_fragment' -and
                [long]$details.continuation_posts -eq
                    $expectedContinuationCount -and
                [long]$details.continuation_request_id -gt 0
            )
        )
    $continuationExact =
        [long]$details.continuation_count -eq
            $expectedContinuationCount -and
        $continuationSchedulingExact -and
        [long]$details.committed_fragments -eq
            [long]$positive[0].legal_work_count
    Add-ReviewAssertion 'oversized_continuation_identity_and_count_exact' `
        $continuationExact "continuations=$($details.continuation_count);request=$($details.continuation_request_id);first_sequence=$($details.first_continuation_sequence)"
    $completionExact = [long]$details.completion_count -eq 1
    Add-ReviewAssertion 'oversized_terminal_completion_exact_once' `
        $completionExact "completion_count=$($details.completion_count)"
}
else {
    $queuedExact = $positive.Count -eq 1 -and
        [long]$positive[0].legal_work_count -gt 1 -and
        [long]$positive[0].applied_work_count -eq 1 -and
        [long]$positive[0].mechanism_details.queued_writes_before -gt
            [long]$positive[0].mechanism_details.queued_writes_after
    Add-ReviewAssertion 'queued_budget_and_work_identity_exact' `
        $queuedExact "legal=$($positive[0].legal_work_count);before=$($positive[0].mechanism_details.queued_writes_before);after=$($positive[0].mechanism_details.queued_writes_after)"
    $wakeExact =
        [bool]$positive[0].mechanism_details.follow_on_wake_required -and
        [long]$positive[0].mechanism_details.follow_on_wake_generation -gt 0 -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$positive[0].mechanism_details.follow_on_wake_due_ticks)
    Add-ReviewAssertion 'queued_follow_on_wake_identity_exact' `
        $wakeExact "turn=$($positive[0].mechanism_details.actor_turn_sequence);generation=$($positive[0].mechanism_details.follow_on_wake_generation);due=$($positive[0].mechanism_details.follow_on_wake_due_ticks)"
}

$failedAssertions = @($failed | Sort-Object -CaseSensitive)
$onlyBoundedBlocker =
    $ExpectedPolicyValue -ceq 'bounded_multi_fragment' -and
    $failedAssertions.Count -eq 1 -and
    $failedAssertions[0] -ceq 'shadow_recommendation_matches_value'
$reviewOutcome = if ($failedAssertions.Count -eq 0) {
    'passed'
}
elseif ($onlyBoundedBlocker) {
    'blocked'
}
else {
    'failed'
}
$blocker = if ($onlyBoundedBlocker) {
    'shadow_recommendation_value_mismatch'
}
else {
    $null
}
$reviewedRefs = @($documentMap.Values | ForEach-Object {
    New-AdaptiveRuntimeDocumentRef $_
} | Sort-Object document_id)
$review = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-actuation-proof-review-v2'
    document_id = "review.$($proof.proof_candidate_id).v2"
    document_version = 2
    content_sha256 = '0' * 64
    review_id = "review.$($proof.proof_candidate_id).v2"
    proof_id = [string]$proof.proof_candidate_id
    proof_hash = [string]$proof.content_sha256
    candidate_ref = New-AdaptiveRuntimeDocumentRef $proof
    axis_id = $ExpectedAxisId
    policy_value = $ExpectedPolicyValue
    source_commit = [string]$proof.source_commit
    binary_sha256 = [string]$binary.payload.binary_sha256
    reviewer_identity = $ReviewerIdentity
    review_timestamp = $canonicalTimestamp
    reviewed_evidence_refs = $reviewedRefs
    assertion_results = @($assertions | Sort-Object assertion_id)
    failed_assertions = $failedAssertions
    review_outcome = $reviewOutcome
    promotion_eligibility = $reviewOutcome -ceq 'passed'
    blocker = $blocker
    recomputed_behavior_materialization_sha256 =
        [string]$recomputedBehavior.content_sha256
    recomputed_outcome_materialization_sha256 =
        [string]$recomputedOutcome.content_sha256
    recomputed_projection_sha256 =
        [string]$recomputedProjection.content_sha256
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $proof.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $review)
if (-not (Test-AdaptiveRuntimeJsonSchema $review (
    Join-Path $schemaRoot `
        'adaptive-runtime-actuation-proof-review-v2.schema.json'))) {
    throw 'runtime_proof_review_schema_invalid'
}
Write-AdaptiveRuntimeCanonicalDocument $review $OutputPath
$review
