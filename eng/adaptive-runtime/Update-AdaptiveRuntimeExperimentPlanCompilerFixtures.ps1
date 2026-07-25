# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param([string] $RepositoryRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
}
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$catalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
$fixtureRoot = Join-Path $RepositoryRoot 'tests\fixtures\adaptive-runtime-experiment-plan-compiler'
$validRoot = Join-Path $fixtureRoot 'valid'
$warningRoot = Join-Path $fixtureRoot 'warning'
$invalidRoot = Join-Path $fixtureRoot 'invalid'
$alternateCatalogRoot = Join-Path $fixtureRoot 'catalogs-stage5'
foreach ($path in @($validRoot, $warningRoot, $invalidRoot, $alternateCatalogRoot)) {
    if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -ItemType Directory -Path $path) }
}

$catalogNames = @(
    'adaptive-runtime-policy-axis-contracts-v1.json',
    'adaptive-runtime-effective-behavior-catalog-v1.json',
    'adaptive-runtime-policy-relationship-graph-v1.json',
    'adaptive-runtime-combination-constraint-catalog-v1.json',
    'adaptive-runtime-experiment-family-catalog-v1.json'
)
$catalogs = @{}
foreach ($name in $catalogNames) {
    $document = Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $catalogRoot $name)
    $catalogs[[string]$document.document_id] = $document
}

function New-DocumentRef([object] $Document) {
    return [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Copy-JsonValue([object] $Value) {
    return ($Value | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json -Depth 100)
}

function New-Plan {
    param(
        [string] $PlanId,
        [string] $ExperimentType,
        [System.Collections.IDictionary] $AxisValues,
        [string[]] $FixedAxes,
        [string] $ExecutionStatus = 'ready',
        [switch] $PreserveEquivalent,
        [switch] $CapabilityPending,
        [hashtable] $ActivationByCellIndex = @{},
        [object] $HistoryControls = $null,
        [object] $ProfileDefinition = $null
    )

    $treatments = [System.Collections.Generic.List[object]]::new()
    $treatmentOrder = [System.Collections.Generic.List[string]]::new()
    $valueSets = [System.Collections.Generic.List[object]]::new()
    $orderIndex = 0
    foreach ($axisId in $AxisValues.Keys) {
        $axisTreatments = [System.Collections.Generic.List[object]]::new()
        foreach ($value in @($AxisValues[$axisId])) {
            $treatmentId = "treatment.$axisId.$value"
            $treatment = [ordered]@{
                treatment_id = $treatmentId
                order_index = $orderIndex
                axis_id = $axisId
                configured_value = $value
                candidate_value = $value
            }
            if ($value -ne 'legacy_current') { $treatment.forced_value = $value }
            $treatments.Add([pscustomobject]$treatment)
            $treatmentOrder.Add($treatmentId)
            $axisTreatments.Add([pscustomobject]@{ treatment_id = $treatmentId; axis_id = $axisId })
            $orderIndex++
        }
        $valueSets.Add(@($axisTreatments))
    }

    $combinations = @(,@())
    foreach ($valueSet in $valueSets) {
        $next = [System.Collections.Generic.List[object]]::new()
        foreach ($prefix in $combinations) {
            foreach ($entry in @($valueSet)) {
                $next.Add(@($prefix) + @($entry))
            }
        }
        $combinations = @($next)
    }

    $cells = [System.Collections.Generic.List[object]]::new()
    $cellIndex = 0
    foreach ($combination in $combinations) {
        $cell = [ordered]@{
            cell_id = "cell.$PlanId.$('{0:d3}' -f $cellIndex)"
            cell_order = $cellIndex
            treatment_ids = @($combination.treatment_id)
            axis_ids = @($combination.axis_id | Sort-Object -Unique)
            expected_equivalence_group_id = "declared.$PlanId.$('{0:d3}' -f $cellIndex)"
            execution_state = if ($ExecutionStatus -eq 'ready') { 'ready' } else { 'blocked' }
            performance_comparable = $false
            activation_expectation = if ($ActivationByCellIndex.ContainsKey($cellIndex)) {
                [string]$ActivationByCellIndex[$cellIndex]
            } else { 'reachable' }
        }
        $cells.Add([pscustomobject]$cell)
        $cellIndex++
    }

    $axisCatalog = $catalogs['adaptive_runtime_policy_axis_contracts_v1']
    $predicateRefs = @(
        foreach ($axisId in $AxisValues.Keys) {
            $contract = @($axisCatalog.axis_contracts | Where-Object axis_id -eq $axisId) | Select-Object -First 1
            if ($null -ne $contract -and $null -ne $contract.readiness) {
                $contract.readiness.activation_predicate_refs
                $contract.readiness.behavior_distinctness_predicate_refs
            }
        }
    ) | ForEach-Object { [string]$_ } | Sort-Object -Unique

    $fixedAxisValues = @($FixedAxes | ForEach-Object {
        [pscustomobject][ordered]@{ axis_id = $_; configured_value = 'legacy_current' }
    })
    $plan = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-experiment-plan-v1'
        document_id = "adaptive_runtime_experiment_plan_$($PlanId)_v1"
        document_version = 1
        content_sha256 = ('0' * 64)
        trace_references = New-AdaptiveRuntimeTraceReferences
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        experiment_plan_id = "experiment_plan.$PlanId.v1"
        family_id = 'send_composition'
        experiment_type = $ExperimentType
        fixed_axis_ids = @($FixedAxes)
        fixed_axis_values = $fixedAxisValues
        varied_axis_ids = @($AxisValues.Keys)
        treatment_order = @($treatmentOrder)
        treatments = @($treatments)
        planned_cells = @($cells)
        execution_status = $ExecutionStatus
        expected_capabilities = @([pscustomobject][ordered]@{
            capability_id = 'adaptive_runtime_internal_forced_mode'
            expectation = 'required'
            resolution = if ($CapabilityPending) { 'pending' } else { 'deferred_to_manifest' }
        })
        preserve_equivalent_cells_for_verification = [bool]$PreserveEquivalent
        required_predicate_refs = @($predicateRefs)
        execution_order_policy = 'deterministic'
        source_document_refs = @($catalogs.Values | Sort-Object document_id | ForEach-Object { New-DocumentRef $_ })
        notes = @('Compiler fixture; measurement and active behavior remain unauthorized.')
    }
    if ($null -ne $HistoryControls) {
        $plan | Add-Member -NotePropertyName history_controls -NotePropertyValue $HistoryControls
    }
    if ($null -ne $ProfileDefinition) {
        $plan | Add-Member -NotePropertyName profile_definition -NotePropertyValue $ProfileDefinition
    }
    [void](Set-AdaptiveRuntimeDocumentHash -Document $plan)
    return $plan
}

function Write-Plan([object] $Plan, [string] $Directory, [string] $FileName) {
    $path = Join-Path $Directory $FileName
    Write-AdaptiveRuntimeCanonicalDocument -Document $Plan -Path $path
    return $path
}

$plans = [ordered]@{}
$plans['batch-actuation'] = New-Plan -PlanId 'batch_actuation' -ExperimentType 'actuation_validation' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing')
$plans['buffer-actuation'] = New-Plan -PlanId 'buffer_actuation' -ExperimentType 'actuation_validation' `
    -AxisValues ([ordered]@{ buffer_copy_coalescing = @('legacy_current','memory_conservative') }) `
    -FixedAxes @('application_send_batch_formation','application_send_turn_planning')
$plans['batch-isolated'] = New-Plan -PlanId 'batch_isolated' -ExperimentType 'isolated_counterfactual' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing')
$plans['buffer-isolated'] = New-Plan -PlanId 'buffer_isolated' -ExperimentType 'isolated_counterfactual' `
    -AxisValues ([ordered]@{ buffer_copy_coalescing = @('legacy_current','memory_conservative') }) `
    -FixedAxes @('application_send_batch_formation','application_send_turn_planning')
$plans['interaction'] = New-Plan -PlanId 'send_composition_interaction' -ExperimentType 'interaction_screen' `
    -AxisValues ([ordered]@{
        application_send_batch_formation = @('legacy_current','single_eligible')
        buffer_copy_coalescing = @('legacy_current','memory_conservative')
    }) -FixedAxes @('application_send_turn_planning') -ExecutionStatus 'blocked_by_capability'
$plans['send-verification'] = New-Plan -PlanId 'send_turn_verification' -ExperimentType 'actuation_validation' `
    -AxisValues ([ordered]@{ application_send_turn_planning = @('legacy_current','conservative') }) `
    -FixedAxes @('application_send_batch_formation','buffer_copy_coalescing') -PreserveEquivalent
$plans['capability-pending'] = New-Plan -PlanId 'batch_capability_pending' -ExperimentType 'actuation_validation' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing') -CapabilityPending
$plans['inactive'] = New-Plan -PlanId 'batch_expected_inactive' -ExperimentType 'actuation_validation' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing') `
    -ActivationByCellIndex @{ 1 = 'structurally_inactive' }
$plans['distinctness-unknown'] = New-Plan -PlanId 'batch_distinctness_unknown' -ExperimentType 'actuation_validation' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing') `
    -ActivationByCellIndex @{ 1 = 'unknown' }
$plans['send-equivalent-isolated'] = New-Plan -PlanId 'send_turn_equivalent_isolated' -ExperimentType 'isolated_counterfactual' `
    -AxisValues ([ordered]@{ application_send_turn_planning = @('legacy_current','conservative') }) `
    -FixedAxes @('application_send_batch_formation','buffer_copy_coalescing')
$historyControls = [pscustomobject][ordered]@{
    warmup = 'one_declared_warmup_epoch'
    initial_state = 'fresh_connection'
    reset_carryover = 'reset_each_cell'
    ordered_observations = @('warmup','treatment','recovery','cooldown','terminal')
    recovery = 'explicit_recovery_observation'
    cooldown = 'one_declared_cooldown_epoch'
    terminal_handling = 'retain_terminal_and_failure_evidence'
}
$plans['feedback'] = New-Plan -PlanId 'send_composition_feedback' -ExperimentType 'feedback_loop' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing') -HistoryControls $historyControls
$profile = [pscustomobject][ordered]@{
    profile_id = 'profile.send_composition.transparent.v1'
    profile_treatment_ids = @(
        'treatment.application_send_batch_formation.legacy_current',
        'treatment.application_send_batch_formation.single_eligible'
    )
    transparent = $true
}
$plans['profile'] = New-Plan -PlanId 'send_composition_profile' -ExperimentType 'profile_validation' `
    -AxisValues ([ordered]@{ application_send_batch_formation = @('legacy_current','single_eligible') }) `
    -FixedAxes @('application_send_turn_planning','buffer_copy_coalescing') -ProfileDefinition $profile

$validKeys = @('batch-actuation','buffer-actuation','batch-isolated','buffer-isolated','interaction','feedback','profile')
$warningKeys = @(
    'send-verification',
    'send-equivalent-isolated',
    'capability-pending',
    'inactive',
    'distinctness-unknown'
)
$fixtureExpectations = [ordered]@{}
foreach ($key in $validKeys) {
    $path = Write-Plan $plans[$key] $validRoot "$key.plan.json"
    $validationPath = Join-Path $validRoot "$key.validation.json"
    $validation = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
        -PlanPath $path -CatalogRoot $catalogRoot -RepositoryRoot $RepositoryRoot `
        -OutputPath $validationPath -PassThru
    $fixtureExpectations["valid/$key.plan.json"] = [ordered]@{
        classification = $validation.validation_classification
        configured = $validation.cell_counts.configured
        expected_effective = $validation.cell_counts.expected_effective
    }
}
foreach ($key in $warningKeys) {
    $path = Write-Plan $plans[$key] $warningRoot "$key.plan.json"
    $validationPath = Join-Path $warningRoot "$key.validation.json"
    $validation = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
        -PlanPath $path -CatalogRoot $catalogRoot -RepositoryRoot $RepositoryRoot `
        -OutputPath $validationPath -PassThru
    $fixtureExpectations["warning/$key.plan.json"] = [ordered]@{
        classification = $validation.validation_classification
        configured = $validation.cell_counts.configured
        expected_effective = $validation.cell_counts.expected_effective
        warning_codes = @($validation.validation_warnings.warning_code | Sort-Object -Unique)
    }
}

$invalidPlans = [ordered]@{}
function Add-InvalidPlan([string] $Name, [object] $Plan, [string[]] $Codes, [string] $Catalog = 'canonical') {
    [void](Set-AdaptiveRuntimeDocumentHash -Document $Plan)
    Write-AdaptiveRuntimeCanonicalDocument -Document $Plan -Path (Join-Path $invalidRoot "$Name.plan.json")
    $invalidPlans["$Name.plan.json"] = [ordered]@{ error_codes = $Codes; catalog = $Catalog }
}

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.varied_axis_ids = @('unsupported_axis')
$clone.treatments | ForEach-Object { $_.axis_id = 'unsupported_axis' }
$clone.planned_cells | ForEach-Object { $_.axis_ids = @('unsupported_axis') }
$clone.fixed_axis_ids = @('application_send_turn_planning','buffer_copy_coalescing')
Add-InvalidPlan 'unsupported-axis' $clone @('unknown_axis','axis_outside_experiment_family')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.treatments[1].configured_value = 'illegal_value'
$clone.treatments[1].candidate_value = 'illegal_value'
$clone.treatments[1].forced_value = 'illegal_value'
Add-InvalidPlan 'illegal-policy-value' $clone @('unknown_policy_value')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.treatments[1].PSObject.Properties.Remove('forced_value')
Add-InvalidPlan 'actuation-missing-forced-value' $clone @('axis_not_forceable','experiment_type_axis_count_invalid')

$clone = Copy-JsonValue $plans['interaction']
$clone.varied_axis_ids = @('application_send_batch_formation','application_send_turn_planning')
$clone.fixed_axis_ids = @('buffer_copy_coalescing')
$clone.fixed_axis_values = @([pscustomobject]@{ axis_id = 'buffer_copy_coalescing'; configured_value = 'legacy_current' })
Add-InvalidPlan 'illegal-combination' $clone @('cross_axis_constraint_violation')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.planned_cells[1].activation_expectation = 'unreachable'
Add-InvalidPlan 'unreachable-activation' $clone @('activation_predicate_unreachable')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.fixed_axis_values[1].configured_value = 'memory_conservative'
Add-InvalidPlan 'invalid-adjacent-axis-value' $clone @('fixed_axis_not_legacy_current')

$clone = Copy-JsonValue $plans['interaction']
$clone.experiment_type = 'isolated_counterfactual'
$clone.execution_status = 'ready'
Add-InvalidPlan 'multiple-varied-isolated' $clone @('experiment_type_axis_count_invalid')

$clone = Copy-JsonValue $plans['feedback']
$clone.PSObject.Properties.Remove('history_controls')
Add-InvalidPlan 'missing-feedback-history' $clone @('feedback_loop_history_missing')

$clone = Copy-JsonValue $plans['send-verification']
$clone.planned_cells[0].performance_comparable = $true
Add-InvalidPlan 'equivalent-performance-comparable' $clone @('equivalent_cells_performance_comparable')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.source_document_refs[0].document_version = 99
Add-InvalidPlan 'stale-contract-reference' $clone @('stale_contract_reference')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone | Add-Member -NotePropertyName unexpected_field -NotePropertyValue $true
Add-InvalidPlan 'unknown-field' $clone @('unknown_field')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone | Add-Member -NotePropertyName runtime_controller_inputs -NotePropertyValue @('workload_id')
Add-InvalidPlan 'prohibited-runtime-controller-input' $clone @('prohibited_runtime_controller_input')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.fixed_axis_ids = @('application_send_turn_planning','application_send_turn_planning')
Add-InvalidPlan 'duplicate-axis-reference' $clone @('duplicate_axis_reference')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.required_predicate_refs = @('predicate.does.not.exist')
Add-InvalidPlan 'missing-predicate-reference' $clone @('missing_canonical_predicate_reference')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.active_behavior_authorization = $true
Add-InvalidPlan 'active-authorization' $clone @('active_behavior_unauthorized')

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.performance_acceptance_authorization = $true
Add-InvalidPlan 'performance-authorization' $clone @('performance_acceptance_unauthorized')

$clone = Copy-JsonValue $plans['batch-actuation']
[void](Set-AdaptiveRuntimeDocumentHash -Document $clone)
$clone.content_sha256 = ('f' * 64)
[System.IO.File]::WriteAllText(
    (Join-Path $invalidRoot 'plan-hash-mismatch.plan.json'),
    (ConvertTo-AdaptiveRuntimeCanonicalJson -Value $clone -IncludeRootContentSha256),
    [System.Text.UTF8Encoding]::new($false))
$invalidPlans['plan-hash-mismatch.plan.json'] = [ordered]@{ error_codes = @('hash_mismatch'); catalog = 'canonical' }

$clone = Copy-JsonValue $plans['batch-actuation']
$clone.experiment_type = 'not_supported'
Add-InvalidPlan 'unsupported-experiment-type' $clone @('unsupported_experiment_type')

# Add a preparation-only Stage 5 declaration catalog without changing the canonical first-slice catalog.
foreach ($name in $catalogNames) {
    Copy-Item -LiteralPath (Join-Path $catalogRoot $name) -Destination (Join-Path $alternateCatalogRoot $name) -Force
}
$alternateAxis = Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $alternateCatalogRoot $catalogNames[0])
$alternateAxis.axis_contracts += [pscustomobject][ordered]@{
    axis_id = 'ack_behavior_profile'
    status = 'preparation_only'
    executable = $false
    policy_values = @('legacy_current','conservative')
    authority = [ordered]@{ owner='connection_actor'; scope='ack_state'; boundary='preparation_only'; latch='packet_number_space' }
    scope = 'ack_state'
    boundary = 'preparation_only'
    latch = 'packet_number_space'
    selected_value_compatibility = @(
        [pscustomobject][ordered]@{ selected_value='legacy_current'; candidate_value='legacy_current'; compatible=$true; comparison_mode='blocked_by_capability' }
    )
    canonical_predicates = @(
        [pscustomobject][ordered]@{ predicate_id='predicate.ack.preparation_only'; description='No executable ACK behavior axis is authorized.' }
    )
    safety_clamps = @(
        [pscustomobject][ordered]@{ clamp_id='clamp.ack.no_execution'; description='Preparation declarations cannot execute.' }
    )
    readiness = [ordered]@{
        forceable=$false
        rollback_proof_status='missing'
        actuation_validation_status='blocked'
        behavior_distinctness_status='unproven'
        activation_predicate_refs=@('predicate.ack.preparation_only')
        behavior_distinctness_predicate_refs=@('predicate.ack.preparation_only')
        required_capability_ids=@()
    }
    trace_references = $alternateAxis.trace_references
}
$alternateAxis.axis_contracts += [pscustomobject][ordered]@{
    axis_id = 'ready_stream_fairness'
    status = 'blocked'
    executable = $false
    policy_values = @('legacy_current','conservative')
    authority = [ordered]@{ owner='connection_actor'; scope='send_turn'; boundary='inventory_only'; latch='one_turn' }
    scope = 'send_turn'
    boundary = 'inventory_only'
    latch = 'one_turn'
    selected_value_compatibility = @(
        [pscustomobject][ordered]@{ selected_value='legacy_current'; candidate_value='legacy_current'; compatible=$true; comparison_mode='blocked_by_capability' }
    )
    canonical_predicates = @(
        [pscustomobject][ordered]@{ predicate_id='predicate.ready_stream.blocked'; description='No reviewed bounded runnable set exists.' }
    )
    safety_clamps = @(
        [pscustomobject][ordered]@{ clamp_id='clamp.ready_stream.no_execution'; description='Blocked inventory cannot execute.' }
    )
    readiness = [ordered]@{
        forceable=$false
        rollback_proof_status='missing'
        actuation_validation_status='blocked'
        behavior_distinctness_status='unproven'
        activation_predicate_refs=@('predicate.ready_stream.blocked')
        behavior_distinctness_predicate_refs=@('predicate.ready_stream.blocked')
        required_capability_ids=@()
    }
    trace_references = $alternateAxis.trace_references
}
Write-AdaptiveRuntimeCanonicalDocument -Document $alternateAxis -Path (Join-Path $alternateCatalogRoot $catalogNames[0])

$alternateFamily = Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $alternateCatalogRoot $catalogNames[4])
$alternateFamily.experiment_families += [pscustomobject][ordered]@{
    family_id = 'stage5_declarations'
    contexts = @('ack_behavior_profile','application_send_batch_formation','ready_stream_fairness')
    metrics = @('correctness_only')
    history = @([pscustomobject][ordered]@{ history_id='history.stage5.preparation'; status='blocked'; notes=@('Preparation only.') })
    promotion = [ordered]@{ status='blocked'; measurement_authorized=$false; active_behavior_authorization=$false; performance_acceptance_authorization=$false }
    guard_refs = @('guard.stage5.no_execution')
    predicate_refs = @('predicate.ack.preparation_only')
    supported_experiment_types = @('actuation_validation','interaction_screen','isolated_counterfactual')
    blocked_experiment_types = @('feedback_loop','profile_validation')
    notes = @('Fixture-only preparation declaration.')
}
Write-AdaptiveRuntimeCanonicalDocument -Document $alternateFamily -Path (Join-Path $alternateCatalogRoot $catalogNames[4])

$stage5Plan = Copy-JsonValue $plans['batch-actuation']
$stage5Plan.document_id = 'adaptive_runtime_experiment_plan_stage5_preparation_v1'
$stage5Plan.experiment_plan_id = 'experiment_plan.stage5_preparation.v1'
$stage5Plan.family_id = 'stage5_declarations'
$stage5Plan.fixed_axis_ids = @('application_send_batch_formation')
$stage5Plan.fixed_axis_values = @([pscustomobject]@{ axis_id='application_send_batch_formation'; configured_value='legacy_current' })
$stage5Plan.varied_axis_ids = @('ack_behavior_profile')
$stage5Plan.treatments | ForEach-Object {
    $_.axis_id = 'ack_behavior_profile'
    $_.configured_value = if ($_.order_index -eq 0) { 'legacy_current' } else { 'conservative' }
    $_.candidate_value = $_.configured_value
    if ($_.order_index -ne 0) { $_.forced_value = 'conservative' }
}
$stage5Plan.planned_cells | ForEach-Object { $_.axis_ids = @('ack_behavior_profile') }
$stage5Plan.required_predicate_refs = @('predicate.ack.preparation_only')
$stage5Plan.source_document_refs = @(
    foreach ($name in $catalogNames) {
        New-DocumentRef (Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $alternateCatalogRoot $name))
    }
)
Add-InvalidPlan 'stage5-preparation-only' $stage5Plan @('preparation_only_axis') 'stage5'

$blockedPlan = Copy-JsonValue $stage5Plan
$blockedPlan.document_id = 'adaptive_runtime_experiment_plan_blocked_axis_v1'
$blockedPlan.experiment_plan_id = 'experiment_plan.blocked_axis.v1'
$blockedPlan.varied_axis_ids = @('ready_stream_fairness')
$blockedPlan.treatments | ForEach-Object {
    $_.axis_id = 'ready_stream_fairness'
    $_.configured_value = if ($_.order_index -eq 0) { 'legacy_current' } else { 'conservative' }
    $_.candidate_value = $_.configured_value
    if ($_.order_index -ne 0) { $_.forced_value = 'conservative' }
}
$blockedPlan.planned_cells | ForEach-Object { $_.axis_ids = @('ready_stream_fairness') }
$blockedPlan.required_predicate_refs = @('predicate.ready_stream.blocked')
Add-InvalidPlan 'blocked-axis' $blockedPlan @('blocked_axis') 'stage5'

$outsideFamilyPlan = Copy-JsonValue $plans['interaction']
$outsideFamilyPlan.document_id = 'adaptive_runtime_experiment_plan_axis_outside_family_v1'
$outsideFamilyPlan.experiment_plan_id = 'experiment_plan.axis_outside_family.v1'
$outsideFamilyPlan.varied_axis_ids = @('application_send_batch_formation','ack_behavior_profile')
foreach ($treatment in @($outsideFamilyPlan.treatments | Where-Object axis_id -eq 'buffer_copy_coalescing')) {
    $treatment.axis_id = 'ack_behavior_profile'
    if ($treatment.configured_value -eq 'memory_conservative') {
        $treatment.configured_value = 'conservative'
        $treatment.candidate_value = 'conservative'
    }
}
$outsideFamilyPlan.planned_cells | ForEach-Object {
    $_.axis_ids = @('application_send_batch_formation','ack_behavior_profile')
}
Add-InvalidPlan 'axis-outside-interaction-family' $outsideFamilyPlan @('axis_outside_experiment_family') 'stage5'

$invalidExpectationText = [pscustomobject]$invalidPlans | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText(
    (Join-Path $invalidRoot 'expectations.json'),
    $invalidExpectationText,
    [System.Text.UTF8Encoding]::new($false))
$fixtureExpectationText = [pscustomobject]$fixtureExpectations | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText(
    (Join-Path $fixtureRoot 'expectations.json'),
    $fixtureExpectationText,
    [System.Text.UTF8Encoding]::new($false))

# Static valid and invalid manifest-link fixtures. A later focused proof produces a real post-build manifest.
$manifestPlanPath = Join-Path $validRoot 'batch-actuation.plan.json'
$manifestValidationPath = Join-Path $validRoot 'batch-actuation.validation.json'
$manifestPlan = Read-AdaptiveRuntimeJsonDocument $manifestPlanPath
$manifestValidation = Read-AdaptiveRuntimeJsonDocument $manifestValidationPath
$manifest = [pscustomobject][ordered]@{
    schema_version='adaptive-runtime-compiled-execution-manifest-v1'
    document_id='manifest.fixture.batch_actuation'
    document_version=1
    content_sha256=('0' * 64)
    trace_references=New-AdaptiveRuntimeTraceReferences
    active_behavior_authorization=$false
    performance_acceptance_authorization=$false
    compiled_execution_manifest_id='manifest.fixture.batch_actuation.v1'
    source_plan_ref=New-DocumentRef $manifestPlan
    source_validation_ref=New-DocumentRef $manifestValidation
    source_commit=('a' * 40)
    binary_provenance=@([pscustomobject]@{role='test_binary';path='fixture/bin/Incursa.Quic.Tests.dll';content_sha256=('b' * 64)})
    runner_identity=[ordered]@{runner_id='fixture_runner';version='1.0.0';path='fixture/runner.ps1';content_sha256=('c' * 64)}
    host_fingerprint=[ordered]@{fingerprint_id='host.fixture';machine_name='fixture';os='fixture';architecture='x64';processor_count=1}
    host_capabilities=[ordered]@{
        host_id='host.fixture';os='fixture';architecture='x64';processor_count=1
        capability_flags=@('post_build_refs_present','single_axis_executable','source_plan_valid')
        resolved_capabilities=@([pscustomobject]@{capability_id='adaptive_runtime_internal_forced_mode';state='available'})
    }
    execution_order=@($manifestValidation.expanded_planned_cells | Where-Object executable | Sort-Object cell_order | ForEach-Object cell_id)
    execution_order_policy='deterministic'
    executable_cells=@($manifestValidation.expanded_planned_cells | Where-Object executable | Sort-Object cell_order | ForEach-Object {
        [pscustomobject]@{cell_id=$_.cell_id;cell_order=$_.cell_order;axis_ids=$_.axis_ids;treatment_ids=$_.treatment_ids;execution_state='executable'}
    })
    capability_ineligible_cells=@()
    excluded_cells=@()
    output_roots=@('fixture/output')
    retention_rules=@('retain_plan_validation_manifest_and_failures')
    expected_result_schemas=@('adaptive-runtime-policy-local-result-v1')
    post_build_refs=@((New-DocumentRef $manifestPlan),(New-DocumentRef $manifestValidation))
    build_status='compiled'
    notes=@('Static shape fixture only.')
}
Write-AdaptiveRuntimeCanonicalDocument $manifest (Join-Path $validRoot 'compiled-manifest.fixture.json')

$invalidManifestExpectations = [ordered]@{}
function Add-InvalidManifest([string] $Name, [object] $Document, [string[]] $Codes, [switch] $PreserveBadHash) {
    if (-not $PreserveBadHash) { [void](Set-AdaptiveRuntimeDocumentHash $Document) }
    [System.IO.File]::WriteAllText(
        (Join-Path $invalidRoot "$Name.manifest.json"),
        (ConvertTo-AdaptiveRuntimeCanonicalJson -Value $Document -IncludeRootContentSha256),
        [System.Text.UTF8Encoding]::new($false))
    $invalidManifestExpectations["$Name.manifest.json"] = $Codes
}
$clone = Copy-JsonValue $manifest
$clone.content_sha256 = ('d' * 64)
Add-InvalidManifest 'manifest-hash-mismatch' $clone @('hash_mismatch') -PreserveBadHash
$clone = Copy-JsonValue $manifest
$clone.source_plan_ref.document_version = 2
Add-InvalidManifest 'plan-manifest-version-mismatch' $clone @('stale_contract_reference')
$clone = Copy-JsonValue $manifest
$clone | Add-Member -NotePropertyName unknown_field -NotePropertyValue $true
Add-InvalidManifest 'manifest-unknown-field' $clone @('unknown_field')
$clone = Copy-JsonValue $manifest
$clone.active_behavior_authorization = $true
Add-InvalidManifest 'manifest-active-authorization' $clone @('active_behavior_unauthorized')
$clone = Copy-JsonValue $manifest
$clone.performance_acceptance_authorization = $true
Add-InvalidManifest 'manifest-performance-authorization' $clone @('performance_acceptance_unauthorized')

$invalidValidation = Copy-JsonValue $manifestValidation
$invalidValidation.content_sha256 = ('e' * 64)
[System.IO.File]::WriteAllText(
    (Join-Path $invalidRoot 'validation-hash-mismatch.validation.json'),
    (ConvertTo-AdaptiveRuntimeCanonicalJson -Value $invalidValidation -IncludeRootContentSha256),
    [System.Text.UTF8Encoding]::new($false))
$invalidManifestExpectations['validation-hash-mismatch.validation.json'] = @('hash_mismatch','stale_contract_reference')
$invalidManifestExpectationText = [pscustomobject]$invalidManifestExpectations | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText(
    (Join-Path $invalidRoot 'manifest-expectations.json'),
    $invalidManifestExpectationText,
    [System.Text.UTF8Encoding]::new($false))

[pscustomobject][ordered]@{
    valid_plan_count = $validKeys.Count
    warning_plan_count = $warningKeys.Count
    invalid_plan_count = $invalidPlans.Count
    invalid_manifest_or_validation_count = $invalidManifestExpectations.Count
}
