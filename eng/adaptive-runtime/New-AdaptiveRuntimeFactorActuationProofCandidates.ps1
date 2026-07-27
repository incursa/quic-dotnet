# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [Parameter(Mandatory = $true)][string] $RuntimeCaptureRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $OutputRoot = (Join-Path $RepositoryRoot `
        'tests\fixtures\adaptive-runtime-runtime-proof-capture\proofs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$trace = [pscustomobject][ordered]@{
    requirement_ids = @(
        'REQ-QUIC-CRT-0235',
        'REQ-QUIC-CRT-0236',
        'REQ-QUIC-CRT-0237',
        'REQ-QUIC-CRT-0238',
        'REQ-QUIC-CRT-0239',
        'REQ-QUIC-CRT-0240'
    )
    architecture_ids = @('ARC-QUIC-CRT-0113')
    work_item_ids = @('WI-QUIC-CRT-0114')
    verification_ids = @('VER-QUIC-CRT-0115')
}

function Assert-CaptureCondition {
    param([bool] $Condition, [string] $Code)
    if (-not $Condition) {
        throw $Code
    }
}

function Test-RuntimeExportSchema {
    param([object] $Export)
    $schemaPath = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-runtime-proof-sink-export-v1.schema.json'
    $errors = @()
    $valid = ($Export | ConvertTo-Json -Depth 100 -Compress) |
        Test-Json -SchemaFile $schemaPath -ErrorAction SilentlyContinue `
            -ErrorVariable errors
    if (-not $valid) {
        $detail = @($errors | ForEach-Object Exception |
            ForEach-Object Message) -join '; '
        throw "runtime_capture_schema_invalid:$detail"
    }
}

function Read-RuntimeExport {
    param(
        [string] $Path,
        [string] $ExpectedAxis,
        [string] $ExpectedValue,
        [string] $ExpectedSourceKind,
        [string] $ExpectedCommit,
        [string] $ExpectedBinaryHash
    )
    Assert-CaptureCondition (Test-Path -LiteralPath $Path) `
        'runtime_capture_source_missing'
    $export = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    Test-RuntimeExportSchema $export
    Assert-CaptureCondition (
        [string]$export.axis_id -ceq $ExpectedAxis -and
        [string]$export.policy_value -ceq $ExpectedValue -and
        [string]$export.source_kind -ceq $ExpectedSourceKind
    ) 'runtime_capture_source_identity_mismatch'
    Assert-CaptureCondition (
        [string]$export.source_commit -ceq $ExpectedCommit
    ) 'runtime_capture_source_commit_mismatch'
    Assert-CaptureCondition (
        [string]$export.binary_sha256 -ceq $ExpectedBinaryHash
    ) 'runtime_capture_binary_hash_mismatch'
    $caseNames = @(
        'positive_actuation',
        'structurally_inactive',
        'safety_fallback',
        'shadow_neutrality',
        'rollback')
    foreach ($caseName in $caseNames) {
        Assert-CaptureCondition (
            @($export.records | Where-Object capture_case -ceq $caseName).
                Count -eq 1
        ) 'runtime_capture_case_missing_or_duplicate'
    }
    $identities = @($export.records | ForEach-Object {
        "$($_.capture_case)|$($_.decision_instance_id)|$($_.operation_id)"
    })
    Assert-CaptureCondition (
        @($identities | Sort-Object -Unique).Count -eq $identities.Count
    ) 'runtime_capture_operation_identity_duplicate'
    return [pscustomobject][ordered]@{
        Path = (Resolve-Path -LiteralPath $Path).Path
        FileSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
            Hash.ToLowerInvariant()
        Document = $export
    }
}

function Get-OversizedMechanismEventId {
    param([object] $Record)
    if ([long]$Record.initial_committed_fragments -eq 1) {
        return 'mechanism_event.oversized_write.one_fragment_per_turn'
    }
    if ([long]$Record.initial_committed_fragments -eq 2) {
        return 'mechanism_event.oversized_write.bounded_two_fragments_per_turn'
    }
    throw 'runtime_capture_oversized_mechanism_unclassifiable'
}

function Convert-OversizedRecord {
    param(
        [object] $Record,
        [object] $Export,
        [int] $RecordIndex,
        [string] $Slug
    )
    $caseName = [string]$Record.capture_case
    $result = switch ($caseName) {
        'structurally_inactive' { 'inactive' }
        'safety_fallback' { 'fallback' }
        default { 'applied' }
    }
    $eligibilityReason = switch ($caseName) {
        'structurally_inactive' { 'structurally_inactive' }
        'safety_fallback' { 'canceled_after_initial_commit' }
        'shadow_neutrality' { 'shadow_only' }
        default { 'eligible' }
    }
    [pscustomobject][ordered]@{
        connection_key = "connection.$Slug.$($caseName.Replace('_','-'))"
        epoch_sequence = 1
        decision_instance_id = [long]$Record.decision_instance_id
        operation_id = [long]$Record.operation_id
        runtime_source_identity = [pscustomobject][ordered]@{
            export_id = [string]$Export.export_id
            record_index = $RecordIndex
            decision_instance_id = [long]$Record.decision_instance_id
            operation_id = [long]$Record.operation_id
        }
        configured_value = [string]$Record.configured_value
        forced_value = $Record.forced_value
        shadow_recommendation = $Record.shadow_recommendation
        candidate_value = [string]$Record.candidate_value
        operation_eligibility_result = 'eligible'
        operation_eligibility_reason = $eligibilityReason
        applied_value = [string]$Record.applied_value
        operation_kind = 'logical_write'
        mechanism_event_id = Get-OversizedMechanismEventId $Record
        mechanism_details = [pscustomobject][ordered]@{
            runtime_request_id = [long]$Record.runtime_request_id
            logical_write_bytes = [long]$Record.logical_write_bytes
            maximum_fragment_bytes = [long]$Record.maximum_fragment_bytes
            initial_committed_fragments =
                [long]$Record.initial_committed_fragments
            initial_committed_bytes = [long]$Record.initial_committed_bytes
            committed_fragments = [long]$Record.committed_fragments
            committed_bytes = [long]$Record.committed_bytes
            continuation_count = [long]$Record.continuation_count
            continuation_posts = [long]$Record.continuation_posts
            first_continuation_sequence =
                [long]$Record.first_continuation_sequence
            continuation_request_id =
                [long]$Record.continuation_request_id
            completion_count = [long]$Record.completion_count
        }
        legal_work_count = [long]$Record.legal_fragment_count
        applied_work_count = [long]$Record.initial_committed_fragments
        legal_bytes = [long]$Record.logical_write_bytes
        applied_bytes = [long]$Record.initial_committed_bytes
        result = $result
        fallback_or_safety_reason = if ($caseName -ceq 'safety_fallback') {
            ([string]$Record.terminal_outcome).ToLowerInvariant()
        } elseif ($caseName -ceq 'structurally_inactive') {
            'one_fragment_fit'
        } else { $null }
        terminal_outcome =
            ([string]$Record.terminal_outcome).ToLowerInvariant()
        capture_case = $caseName
    }
}

function Get-QueuedMechanismEventId {
    param([object] $Record)
    if ([long]$Record.legal_maximum_datagrams -gt 1 -and
        [long]$Record.applied_maximum_datagrams -eq 1) {
        return 'mechanism_event.queued_send.single_datagram_cap'
    }
    return 'mechanism_event.queued_send.legal_actor_turn_budget'
}

function Convert-QueuedRecord {
    param(
        [object] $Record,
        [object] $Export,
        [int] $RecordIndex,
        [string] $Slug
    )
    $caseName = [string]$Record.capture_case
    $result = switch ($caseName) {
        'structurally_inactive' { 'inactive' }
        'safety_fallback' { 'clamped' }
        default { 'applied' }
    }
    $eligibility = if ($caseName -ceq 'safety_fallback') {
        'clamped'
    } else { 'eligible' }
    $eligibilityReason = switch ($caseName) {
        'structurally_inactive' { 'structurally_inactive' }
        'safety_fallback' { 'legal_budget_clamp' }
        'shadow_neutrality' { 'shadow_only' }
        default { 'eligible' }
    }
    [pscustomobject][ordered]@{
        connection_key = "connection.$Slug.$($caseName.Replace('_','-'))"
        epoch_sequence = 1
        decision_instance_id = [long]$Record.decision_instance_id
        operation_id = [long]$Record.operation_id
        runtime_source_identity = [pscustomobject][ordered]@{
            export_id = [string]$Export.export_id
            record_index = $RecordIndex
            decision_instance_id = [long]$Record.decision_instance_id
            operation_id = [long]$Record.operation_id
        }
        configured_value = [string]$Record.configured_value
        forced_value = $Record.forced_value
        shadow_recommendation = $Record.shadow_recommendation
        candidate_value = [string]$Record.candidate_value
        operation_eligibility_result = $eligibility
        operation_eligibility_reason = $eligibilityReason
        applied_value = [string]$Record.applied_value
        operation_kind = 'send_turn'
        mechanism_event_id = Get-QueuedMechanismEventId $Record
        mechanism_details = [pscustomobject][ordered]@{
            actor_turn_sequence = [long]$Record.actor_turn_sequence
            queued_writes_before = [long]$Record.queued_writes_before
            queued_writes_after = [long]$Record.queued_writes_after
            follow_on_wake_required = [bool]$Record.follow_on_wake_required
            follow_on_wake_due_ticks = $Record.follow_on_wake_due_ticks
            follow_on_wake_generation =
                [long]$Record.follow_on_wake_generation
        }
        legal_work_count = [Math]::Min(
            [long]$Record.legal_maximum_datagrams,
            [long]$Record.queued_writes_before)
        applied_work_count = [Math]::Min(
            [long]$Record.applied_maximum_datagrams,
            [long]$Record.queued_writes_before)
        legal_bytes = [long]$Record.queued_bytes_before
        applied_bytes = [long]$Record.queued_bytes_before -
            [long]$Record.queued_bytes_after
        result = $result
        fallback_or_safety_reason = if ($caseName -ceq 'safety_fallback') {
            'legal_budget_clamp'
        } elseif ($caseName -ceq 'structurally_inactive') {
            'legal_budget_one'
        } else { $null }
        terminal_outcome = ([string]$Record.outcome).ToLowerInvariant()
        capture_case = $caseName
    }
}

function New-CaptureFromRuntimeExport {
    param(
        [object] $RuntimeExport,
        [string] $Slug
    )
    $source = $RuntimeExport.Document
    $operations = for ($index = 0; $index -lt $source.records.Count; $index++) {
        if ([string]$source.axis_id -ceq
            'oversized_write_admission_quantum') {
            Convert-OversizedRecord $source.records[$index] $source `
                $index $Slug
        }
        else {
            Convert-QueuedRecord $source.records[$index] $source $index $Slug
        }
    }
    $capture = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-actuation-mechanism-capture-v3'
        document_id = "mechanism_capture.$Slug"
        document_version = 3
        content_sha256 = '0' * 64
        axis_id = [string]$source.axis_id
        policy_value = [string]$source.policy_value
        harness_id = 'incursa.quic.tests.req-quic-crt-0238.runtime-proof-capture'
        capture_mode = 'runtime_evidence_sink'
        runtime_source = [pscustomobject][ordered]@{
            schema_version = [string]$source.schema_version
            export_id = [string]$source.export_id
            file_sha256 = [string]$RuntimeExport.FileSha256
            source_commit = [string]$source.source_commit
            binary_sha256 = [string]$source.binary_sha256
            capture_session_id = [string]$source.capture_session_id
            source_kind = [string]$source.source_kind
        }
        run_id = "run.runtime_proof_capture.$Slug"
        binary_cohort_id = 'binary.runtime_proof_capture.correctness'
        forced_behavior_distinct_axis_count = 1
        operations = @($operations)
        releases = @()
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $trace
    }
    [void](Set-AdaptiveRuntimeDocumentHash $capture)
    return $capture
}

$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
$binaryHash = (Get-FileHash -LiteralPath $resolvedBinary -Algorithm SHA256).
    Hash.ToLowerInvariant()
$sourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
Assert-CaptureCondition ($LASTEXITCODE -eq 0) `
    'runtime_capture_source_commit_unresolved'

$specs = @(
    [pscustomobject]@{
        Slug = 'oversized-single'
        Plan = 'adaptive-runtime-oversized-write-single_fragment-actuation-plan-v1.json'
        File = 'oversized-single.runtime.json'
        Axis = 'oversized_write_admission_quantum'
        Value = 'single_fragment'
        SourceKind = 'quic_oversized_write_admission_evidence_sink'
    },
    [pscustomobject]@{
        Slug = 'oversized-bounded'
        Plan = 'adaptive-runtime-oversized-write-bounded_multi_fragment-actuation-plan-v1.json'
        File = 'oversized-bounded.runtime.json'
        Axis = 'oversized_write_admission_quantum'
        Value = 'bounded_multi_fragment'
        SourceKind = 'quic_oversized_write_admission_evidence_sink'
    },
    [pscustomobject]@{
        Slug = 'queued-single'
        Plan = 'adaptive-runtime-queued-send-actuation-plan-v1.json'
        File = 'queued-single.runtime.json'
        Axis = 'queued_send_burst_budget'
        Value = 'single_datagram'
        SourceKind = 'quic_queued_send_burst_evidence_sink'
    }
)

$catalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
$compiler = Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1'
$manifestCompiler = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeCompiledExecutionManifest.ps1'
$proofCompiler = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeIndependentActuationProof.ps1'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'adaptive-runtime-runtime-proofs-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temporaryRoot)
try {
    foreach ($spec in $specs) {
        $runtimeExport = Read-RuntimeExport `
            (Join-Path $RuntimeCaptureRoot $spec.File) `
            $spec.Axis $spec.Value $spec.SourceKind $sourceCommit $binaryHash
        $sourceRoot = Join-Path $temporaryRoot $spec.Slug
        [void](New-Item -ItemType Directory -Path $sourceRoot)
        $planPath = Join-Path $catalogRoot $spec.Plan
        $validationPath = Join-Path $sourceRoot 'plan-validation.json'
        $manifestPath = Join-Path $sourceRoot 'compiled-manifest.json'
        $capturePath = Join-Path $sourceRoot 'mechanism-capture.json'
        & $compiler -PlanPath $planPath -CatalogContractVersion v3 `
            -OutputPath $validationPath | Out-Null
        & $manifestCompiler -PlanPath $planPath `
            -ValidationPath $validationPath -BinaryPath $resolvedBinary `
            -RunnerPath $compiler -RunnerVersion 'runtime-proof-capture-v1' `
            -OutputPath $manifestPath `
            -ResolvedCapability @(
                'adaptive_runtime_internal_forced_mode=available',
                'single_behavior_distinct_axis_only=available') | Out-Null
        $capture = New-CaptureFromRuntimeExport $runtimeExport $spec.Slug
        Write-AdaptiveRuntimeCanonicalDocument $capture $capturePath
        $spec | Add-Member -NotePropertyName SourceRoot `
            -NotePropertyValue $sourceRoot
        $spec | Add-Member -NotePropertyName RuntimeExportPath `
            -NotePropertyValue $runtimeExport.Path
    }

    $familyCatalog = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $catalogRoot `
            'adaptive-runtime-experiment-family-catalog-v3.json')
    foreach ($spec in $specs) {
        $planPath = Join-Path $catalogRoot $spec.Plan
        $proofRoot = Join-Path $OutputRoot $spec.Slug
        & $proofCompiler -MechanismCapturePath (
                Join-Path $spec.SourceRoot 'mechanism-capture.json') `
            -PlanPath $planPath -ValidationPath (
                Join-Path $spec.SourceRoot 'plan-validation.json') `
            -ManifestPath (
                Join-Path $spec.SourceRoot 'compiled-manifest.json') `
            -OutputRoot $proofRoot `
            -CandidateGenerationId 'runtime-proof-capture-20260727' |
            Out-Null
        [System.IO.File]::Copy(
            $spec.RuntimeExportPath,
            (Join-Path $proofRoot 'runtime-sink-export.json'),
            $true)
        $proof = Read-AdaptiveRuntimeJsonDocument (
            Join-Path $proofRoot 'proof-candidate.json')
        $capture = Read-AdaptiveRuntimeJsonDocument (
            Join-Path $proofRoot 'mechanism-capture.json')
        $evidence = Read-AdaptiveRuntimeJsonDocument (
            Join-Path $proofRoot 'inputs\operation_evidence.json')
        $projection = Read-AdaptiveRuntimeJsonDocument (
            Join-Path $proofRoot 'expected\projection.json')
        $promotion = [pscustomobject][ordered]@{
            schema_version =
                'adaptive-runtime-actuation-proof-promotion-input-v1'
            document_id =
                "promotion_input.$($spec.Axis).$($spec.Value)"
            document_version = 1
            content_sha256 = '0' * 64
            axis_id = $spec.Axis
            policy_value = $spec.Value
            proof_ref = New-AdaptiveRuntimeDocumentRef $proof
            mechanism_capture_ref =
                New-AdaptiveRuntimeDocumentRef $capture
            operation_evidence_ref =
                New-AdaptiveRuntimeDocumentRef $evidence
            projection_ref = New-AdaptiveRuntimeDocumentRef $projection
            reviewed_proof_catalog_base_hash =
                [string]$familyCatalog.content_sha256
            reviewer_identity = $null
            review_artifact_ref = $null
            independent_outcome = $null
            promotion_state = 'not_applied'
            active_behavior_authorization = $false
            performance_acceptance_authorization = $false
            trace_references = $trace
        }
        [void](Set-AdaptiveRuntimeDocumentHash $promotion)
        Write-AdaptiveRuntimeCanonicalDocument $promotion (
            Join-Path $proofRoot 'promotion-review-input.json')
    }
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
}

[pscustomobject][ordered]@{
    result = 'generated_from_runtime_evidence_sinks'
    proof_candidate_count = $specs.Count
    source_commit = $sourceCommit
    binary_sha256 = $binaryHash
    output_root = $OutputRoot
    performance_measurement_ran = $false
    active_behavior_authorized = $false
}
