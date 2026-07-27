# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $OutputRoot = (Join-Path $RepositoryRoot `
        'tests\fixtures\adaptive-runtime-factor-onboarding\proofs')
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

function New-CaptureOperation {
    param(
        [string] $Case,
        [string] $Connection,
        [long] $Identity,
        [string] $Configured,
        [AllowNull()][string] $Forced,
        [AllowNull()][string] $Shadow,
        [string] $Candidate,
        [string] $Eligibility,
        [string] $EligibilityReason,
        [string] $Applied,
        [string] $OperationKind,
        [string] $MechanismEvent,
        [long] $LegalCount,
        [long] $AppliedCount,
        [long] $LegalBytes,
        [long] $AppliedBytes,
        [string] $Result,
        [AllowNull()][string] $FallbackReason,
        [string] $TerminalOutcome
    )
    return [pscustomobject][ordered]@{
        connection_key = $Connection
        epoch_sequence = 1
        decision_instance_id = $Identity
        operation_id = $Identity
        configured_value = $Configured
        forced_value = $Forced
        shadow_recommendation = $Shadow
        candidate_value = $Candidate
        operation_eligibility_result = $Eligibility
        operation_eligibility_reason = $EligibilityReason
        applied_value = $Applied
        operation_kind = $OperationKind
        mechanism_event_id = $MechanismEvent
        legal_work_count = $LegalCount
        applied_work_count = $AppliedCount
        legal_bytes = $LegalBytes
        applied_bytes = $AppliedBytes
        result = $Result
        fallback_or_safety_reason = $FallbackReason
        terminal_outcome = $TerminalOutcome
        capture_case = $Case
    }
}

function New-Capture {
    param(
        [string] $Axis,
        [string] $Value,
        [string] $Slug,
        [object[]] $Operations
    )
    $capture = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-actuation-mechanism-capture-v2'
        document_id = "mechanism_capture.$Slug"
        document_version = 2
        content_sha256 = '0' * 64
        axis_id = $Axis
        policy_value = $Value
        harness_id = "incursa.quic.tests.req-quic-crt-0238.$Slug"
        capture_mode = 'focused_correctness_mechanism_harness'
        run_id = "run.factor_onboarding.$Slug"
        binary_cohort_id = 'binary.factor_onboarding.correctness'
        forced_behavior_distinct_axis_count = 1
        operations = @($Operations)
        releases = @()
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $trace
    }
    [void](Set-AdaptiveRuntimeDocumentHash $capture)
    return $capture
}

function New-OversizedCapture {
    param(
        [ValidateSet('single_fragment','bounded_multi_fragment')]
        [string] $Value
    )
    $slug = "oversized_write.$Value"
    $positiveApplied = if ($Value -ceq 'single_fragment') { 1 } else { 2 }
    $positiveEvent = if ($Value -ceq 'single_fragment') {
        'mechanism_event.oversized_write.one_fragment_per_turn'
    }
    else {
        'mechanism_event.oversized_write.bounded_two_fragments_per_turn'
    }
    $rollbackApplied = if ($Value -ceq 'single_fragment') { 2 } else { 1 }
    $rollbackEvent = if ($rollbackApplied -eq 2) {
        'mechanism_event.oversized_write.bounded_two_fragments_per_turn'
    }
    else {
        'mechanism_event.oversized_write.one_fragment_per_turn'
    }
    $fallbackApplied = if ($Value -ceq 'bounded_multi_fragment') { 1 } else { 0 }
    $fallbackValue = if ($Value -ceq 'bounded_multi_fragment') {
        'single_fragment'
    }
    else {
        'single_fragment'
    }
    $fallbackEvent = if ($fallbackApplied -eq 1) {
        'mechanism_event.oversized_write.one_fragment_per_turn'
    }
    else {
        'mechanism_event.oversized_write.no_dispatch'
    }
    $operations = @(
        (New-CaptureOperation -Case positive_actuation `
            -Connection "connection.$slug.positive" -Identity 101 `
            -Configured legacy_current -Forced $Value -Shadow $null `
            -Candidate $Value -Eligibility eligible `
            -EligibilityReason eligible -Applied $Value `
            -OperationKind logical_write -MechanismEvent $positiveEvent `
            -LegalCount 2 -AppliedCount $positiveApplied `
            -LegalBytes 65536 -AppliedBytes (32768 * $positiveApplied) `
            -Result applied -FallbackReason $null `
            -TerminalOutcome logical_write_completed),
        (New-CaptureOperation -Case structurally_inactive `
            -Connection "connection.$slug.inactive" -Identity 102 `
            -Configured legacy_current -Forced $Value -Shadow $null `
            -Candidate $Value -Eligibility eligible `
            -EligibilityReason structurally_inactive `
            -Applied $Value -OperationKind logical_write `
            -MechanismEvent $positiveEvent -LegalCount 1 -AppliedCount 1 `
            -LegalBytes 16384 -AppliedBytes 16384 -Result inactive `
            -FallbackReason one_fragment_fit `
            -TerminalOutcome logical_write_completed),
        (New-CaptureOperation -Case safety_fallback `
            -Connection "connection.$slug.fallback" -Identity 103 `
            -Configured legacy_current -Forced $Value -Shadow $null `
            -Candidate $Value -Eligibility ineligible `
            -EligibilityReason terminal_guard -Applied $fallbackValue `
            -OperationKind logical_write -MechanismEvent $fallbackEvent `
            -LegalCount 2 -AppliedCount $fallbackApplied `
            -LegalBytes 65536 -AppliedBytes (32768 * $fallbackApplied) `
            -Result fallback -FallbackReason terminal_guard `
            -TerminalOutcome terminal),
        (New-CaptureOperation -Case shadow_neutrality `
            -Connection "connection.$slug.shadow" -Identity 104 `
            -Configured legacy_current -Forced $null -Shadow single_fragment `
            -Candidate single_fragment -Eligibility eligible `
            -EligibilityReason shadow_only -Applied legacy_current `
            -OperationKind logical_write -MechanismEvent $rollbackEvent `
            -LegalCount 2 -AppliedCount $rollbackApplied `
            -LegalBytes 65536 -AppliedBytes (32768 * $rollbackApplied) `
            -Result applied -FallbackReason $null `
            -TerminalOutcome logical_write_completed),
        (New-CaptureOperation -Case rollback `
            -Connection "connection.$slug.rollback" -Identity 105 `
            -Configured legacy_current -Forced $null -Shadow $null `
            -Candidate legacy_current -Eligibility eligible `
            -EligibilityReason eligible -Applied legacy_current `
            -OperationKind logical_write -MechanismEvent $rollbackEvent `
            -LegalCount 2 -AppliedCount $rollbackApplied `
            -LegalBytes 65536 -AppliedBytes (32768 * $rollbackApplied) `
            -Result applied -FallbackReason $null `
            -TerminalOutcome logical_write_completed)
    )
    return New-Capture `
        -Axis oversized_write_admission_quantum `
        -Value $Value -Slug $slug -Operations $operations
}

function New-QueuedCapture {
    $slug = 'queued_send.single_datagram'
    $operations = @(
        (New-CaptureOperation -Case positive_actuation `
            -Connection "connection.$slug.positive" -Identity 201 `
            -Configured legacy_current -Forced single_datagram -Shadow $null `
            -Candidate single_datagram -Eligibility eligible `
            -EligibilityReason eligible -Applied single_datagram `
            -OperationKind send_turn `
            -MechanismEvent mechanism_event.queued_send.single_datagram_cap `
            -LegalCount 8 -AppliedCount 1 -LegalBytes 11840 `
            -AppliedBytes 1480 -Result applied -FallbackReason $null `
            -TerminalOutcome burst_limit_reached),
        (New-CaptureOperation -Case structurally_inactive `
            -Connection "connection.$slug.inactive" -Identity 202 `
            -Configured legacy_current -Forced single_datagram -Shadow $null `
            -Candidate single_datagram -Eligibility eligible `
            -EligibilityReason structurally_inactive `
            -Applied single_datagram -OperationKind send_turn `
            -MechanismEvent mechanism_event.queued_send.single_datagram_cap `
            -LegalCount 1 -AppliedCount 1 -LegalBytes 1480 `
            -AppliedBytes 1480 -Result inactive `
            -FallbackReason legal_budget_one -TerminalOutcome queue_drained),
        (New-CaptureOperation -Case safety_fallback `
            -Connection "connection.$slug.fallback" -Identity 203 `
            -Configured legacy_current -Forced single_datagram -Shadow $null `
            -Candidate single_datagram -Eligibility ineligible `
            -EligibilityReason disposal_guard -Applied legacy_current `
            -OperationKind send_turn `
            -MechanismEvent mechanism_event.queued_send.no_send `
            -LegalCount 0 -AppliedCount 0 -LegalBytes 0 -AppliedBytes 0 `
            -Result fallback -FallbackReason disposal_guard `
            -TerminalOutcome disposed),
        (New-CaptureOperation -Case shadow_neutrality `
            -Connection "connection.$slug.shadow" -Identity 204 `
            -Configured legacy_current -Forced $null -Shadow legacy_current `
            -Candidate legacy_current -Eligibility eligible `
            -EligibilityReason shadow_only -Applied legacy_current `
            -OperationKind send_turn `
            -MechanismEvent mechanism_event.queued_send.legal_actor_turn_budget `
            -LegalCount 8 -AppliedCount 8 -LegalBytes 11840 `
            -AppliedBytes 11840 -Result applied -FallbackReason $null `
            -TerminalOutcome queue_drained),
        (New-CaptureOperation -Case rollback `
            -Connection "connection.$slug.rollback" -Identity 205 `
            -Configured legacy_current -Forced $null -Shadow $null `
            -Candidate legacy_current -Eligibility eligible `
            -EligibilityReason eligible -Applied legacy_current `
            -OperationKind send_turn `
            -MechanismEvent mechanism_event.queued_send.legal_actor_turn_budget `
            -LegalCount 8 -AppliedCount 8 -LegalBytes 11840 `
            -AppliedBytes 11840 -Result applied -FallbackReason $null `
            -TerminalOutcome queue_drained)
    )
    return New-Capture -Axis queued_send_burst_budget `
        -Value single_datagram -Slug $slug -Operations $operations
}

$specs = @(
    [pscustomobject]@{
        Slug = 'oversized-single'
        Plan = 'adaptive-runtime-oversized-write-single_fragment-actuation-plan-v1.json'
        Capture = New-OversizedCapture single_fragment
    },
    [pscustomobject]@{
        Slug = 'oversized-bounded'
        Plan = 'adaptive-runtime-oversized-write-bounded_multi_fragment-actuation-plan-v1.json'
        Capture = New-OversizedCapture bounded_multi_fragment
    },
    [pscustomobject]@{
        Slug = 'queued-single'
        Plan = 'adaptive-runtime-queued-send-actuation-plan-v1.json'
        Capture = New-QueuedCapture
    }
)

$catalogRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control'
$compiler = Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeExperimentPlan.ps1'
$manifestCompiler = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeCompiledExecutionManifest.ps1'
$proofCompiler = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeIndependentActuationProof.ps1'

foreach ($spec in $specs) {
    $proofRoot = Join-Path $OutputRoot $spec.Slug
    $sourceRoot = Join-Path $proofRoot 'source'
    [void](New-Item -ItemType Directory -Path $sourceRoot -Force)
    $planPath = Join-Path $catalogRoot $spec.Plan
    $validationPath = Join-Path $sourceRoot 'plan-validation.json'
    $manifestPath = Join-Path $sourceRoot 'compiled-manifest.json'
    $capturePath = Join-Path $sourceRoot 'mechanism-capture.json'

    & $compiler -PlanPath $planPath -CatalogContractVersion v3 `
        -OutputPath $validationPath | Out-Null
    & $manifestCompiler -PlanPath $planPath `
        -ValidationPath $validationPath -BinaryPath $BinaryPath `
        -RunnerPath $compiler -RunnerVersion 'factor-onboarding-v1' `
        -OutputPath $manifestPath `
        -ResolvedCapability @(
            'adaptive_runtime_internal_forced_mode=available',
            'single_behavior_distinct_axis_only=available') | Out-Null
    Write-AdaptiveRuntimeCanonicalDocument $spec.Capture $capturePath
    & $proofCompiler -MechanismCapturePath $capturePath `
        -PlanPath $planPath -ValidationPath $validationPath `
        -ManifestPath $manifestPath -OutputRoot $proofRoot `
        -CandidateGenerationId 'factor-onboarding-20260726' | Out-Null
}

[pscustomobject][ordered]@{
    result = 'generated'
    proof_candidate_count = $specs.Count
    output_root = $OutputRoot
    performance_measurement_ran = $false
    active_behavior_authorized = $false
}
