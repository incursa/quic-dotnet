# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [string] $CatalogRoot,
    [string] $OutputPath,
    [string] $RepositoryRoot,
    [ValidateSet('v1','v2','v3')][string] $CatalogContractVersion = 'v1',
    [switch] $PassThru,
    [switch] $AllowInvalid
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
}
if ([string]::IsNullOrWhiteSpace($CatalogRoot)) {
    $CatalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
}

Import-Module (Join-Path $scriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$planSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-experiment-plan-v1.schema.json'
$validationSchemaPath = Join-Path $RepositoryRoot (
    "schemas\adaptive-runtime-experiment-plan-validation-$CatalogContractVersion.schema.json")
$catalogFiles = if ($CatalogContractVersion -eq 'v3') {
    [ordered]@{
        axis = 'adaptive-runtime-policy-axis-contracts-v2.json'
        behavior = 'adaptive-runtime-effective-behavior-catalog-v3.json'
        relationship = 'adaptive-runtime-policy-relationship-graph-v3.json'
        constraint = 'adaptive-runtime-combination-constraint-catalog-v2.json'
        family = 'adaptive-runtime-experiment-family-catalog-v3.json'
    }
}
else {
    [ordered]@{
        axis = 'adaptive-runtime-policy-axis-contracts-v1.json'
        behavior =
            "adaptive-runtime-effective-behavior-catalog-$CatalogContractVersion.json"
        relationship =
            "adaptive-runtime-policy-relationship-graph-$CatalogContractVersion.json"
        constraint = 'adaptive-runtime-combination-constraint-catalog-v1.json'
        family =
            "adaptive-runtime-experiment-family-catalog-$CatalogContractVersion.json"
    }
}

$errors = [System.Collections.Generic.List[object]]::new()
$warnings = [System.Collections.Generic.List[object]]::new()

function Add-PlanError {
    param([string] $Code, [string] $Message, [string] $Target = '')

    if (-not ($errors | Where-Object {
        $_.error_code -eq $Code -and
        [string](Get-AdaptiveRuntimeJsonProperty -Value $_ -Name 'target_ref') -eq $Target
    })) {
        $entry = [ordered]@{ error_code = $Code; message = $Message }
        if (-not [string]::IsNullOrWhiteSpace($Target)) { $entry.target_ref = $Target }
        $errors.Add([pscustomobject]$entry)
    }
}

function Add-PlanWarning {
    param([string] $Code, [string] $Message, [string] $Target = '')

    if (-not ($warnings | Where-Object {
        $_.warning_code -eq $Code -and
        [string](Get-AdaptiveRuntimeJsonProperty -Value $_ -Name 'target_ref') -eq $Target
    })) {
        $entry = [ordered]@{ warning_code = $Code; message = $Message }
        if (-not [string]::IsNullOrWhiteSpace($Target)) { $entry.target_ref = $Target }
        $warnings.Add([pscustomobject]$entry)
    }
}

function Get-StringArray {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { [string]$_ })
}

function Test-SameStringSet {
    param([string[]] $Left, [string[]] $Right)
    $leftKey = (@($Left | Sort-Object -Unique) -join '|')
    $rightKey = (@($Right | Sort-Object -Unique) -join '|')
    return [string]::Equals($leftKey, $rightKey, [StringComparison]::Ordinal)
}

function Get-AxisContract {
    param([string] $AxisId)
    return @($axisCatalog.axis_contracts | Where-Object axis_id -eq $AxisId) | Select-Object -First 1
}

function Get-ExpectedBehaviorSet {
    param([string] $AxisId, [string] $Value)

    if ($behaviorCatalog.schema_version -in @(
        'adaptive-runtime-effective-behavior-catalog-v2',
        'adaptive-runtime-effective-behavior-catalog-v3')) {
        $valueSet = @($behaviorCatalog.value_behavior_sets | Where-Object {
            $_.axis_id -eq $AxisId -and $_.policy_value -eq $Value
        })
        if ($valueSet.Count -ne 1) {
            return $null
        }
        return [pscustomobject][ordered]@{
            primary_expected_behavior_ids = @(
                Get-StringArray $valueSet[0].primary_expected_behavior_ids |
                    Sort-Object -Unique
            )
            possible_effective_behavior_ids = @(
                Get-StringArray $valueSet[0].possible_effective_behavior_ids |
                    Sort-Object -Unique
            )
            non_behavior_outcome_ids = @(
                Get-StringArray $valueSet[0].non_behavior_outcome_ids |
                    Sort-Object -Unique
            )
            activation_signature_id = [string]$valueSet[0].activation_signature_id
        }
    }

    $primary = @($behaviorCatalog.effective_behaviors | Where-Object {
        $_.axis_id -eq $AxisId -and
        (Get-StringArray $_.source_policy_values) -contains $Value
    } | ForEach-Object { [string]$_.effective_behavior_id } | Sort-Object -Unique)
    $possible = @($behaviorCatalog.effective_behaviors | Where-Object {
        $_.axis_id -eq $AxisId -and
        (Get-StringArray $_.candidate_values) -contains $Value
    } | ForEach-Object { [string]$_.effective_behavior_id } | Sort-Object -Unique)
    if ($primary.Count -eq 0) {
        return $null
    }
    $contract = Get-AxisContract -AxisId $AxisId
    $activationSignature = if ($null -ne $contract) {
        "activation.$AxisId.$(@(
            $contract.readiness.behavior_distinctness_predicate_refs |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        ) -join '+')"
    }
    else {
        "activation.$AxisId"
    }
    return [pscustomobject][ordered]@{
        primary_expected_behavior_ids = $primary
        possible_effective_behavior_ids = $possible
        non_behavior_outcome_ids = @()
        activation_signature_id = $activationSignature
    }
}

function Get-DocumentReferences {
    param(
        [AllowNull()][object] $Value,
        [int] $Depth = 0
    )

    $references = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        return @()
    }
    if ($Value -is [System.Collections.IEnumerable] -and
        -not ($Value -is [System.Collections.IDictionary])) {
        foreach ($item in @($Value)) {
            foreach ($reference in @(Get-DocumentReferences $item ($Depth + 1))) { $references.Add($reference) }
        }
        return @($references)
    }

    $names = @($Value.PSObject.Properties.Name)
    if ($Depth -gt 0 -and @('document_id','schema_version','document_version','content_sha256' |
        Where-Object { $names -notcontains $_ }).Count -eq 0) {
        $references.Add($Value)
        return @($references)
    }
    foreach ($property in $Value.PSObject.Properties) {
        foreach ($reference in @(Get-DocumentReferences $property.Value ($Depth + 1))) { $references.Add($reference) }
    }
    return @($references)
}

$plan = Read-AdaptiveRuntimeJsonDocument -Path $PlanPath
$catalogs = [ordered]@{}
$documentMap = @{}
foreach ($catalogName in $catalogFiles.Keys) {
    $path = Join-Path $CatalogRoot $catalogFiles[$catalogName]
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required experiment-control catalog '$path' does not exist."
    }
    $document = Read-AdaptiveRuntimeJsonDocument -Path $path
    $catalogs[$catalogName] = $document
    $documentMap[[string]$document.document_id] = $document
    if (-not (Test-AdaptiveRuntimeDocumentHash -Document $document)) {
        Add-PlanError 'hash_mismatch' "Catalog '$($document.document_id)' has a content hash mismatch." $document.document_id
    }
}
if ($CatalogContractVersion -in @('v2','v3')) {
    $reviewedProofRoot = Join-Path $CatalogRoot 'reviewed-proofs'
    foreach ($proofPath in @(Get-ChildItem -LiteralPath $reviewedProofRoot `
        -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object FullName)) {
        $proofDocument = Read-AdaptiveRuntimeJsonDocument $proofPath
        $documentMap[[string]$proofDocument.document_id] = $proofDocument
        if (-not (Test-AdaptiveRuntimeDocumentHash $proofDocument)) {
            Add-PlanError 'hash_mismatch' (
                "Reviewed proof '$($proofDocument.document_id)' has a " +
                'content hash mismatch.') $proofDocument.document_id
        }
    }
    foreach ($compatibilityFile in @(
        'adaptive-runtime-effective-behavior-catalog-v1.json',
        'adaptive-runtime-policy-relationship-graph-v1.json',
        'adaptive-runtime-experiment-family-catalog-v1.json'
    )) {
        $compatibilityPath = Join-Path $CatalogRoot $compatibilityFile
        $compatibilityDocument = Read-AdaptiveRuntimeJsonDocument -Path $compatibilityPath
        $documentMap[[string]$compatibilityDocument.document_id] = $compatibilityDocument
        if (-not (Test-AdaptiveRuntimeDocumentHash -Document $compatibilityDocument)) {
            Add-PlanError 'hash_mismatch' "Compatibility catalog '$($compatibilityDocument.document_id)' has a content hash mismatch." $compatibilityDocument.document_id
        }
    }
}

$axisCatalog = $catalogs.axis
$behaviorCatalog = $catalogs.behavior
$constraintCatalog = $catalogs.constraint
$familyCatalog = $catalogs.family

foreach ($catalog in $catalogs.Values) {
    foreach ($reference in @(Get-DocumentReferences $catalog)) {
        $referenceId = [string]$reference.document_id
        if (-not $documentMap.ContainsKey($referenceId)) {
            Add-PlanError 'unknown_contract_reference' "Catalog reference '$referenceId' is unknown." $referenceId
            continue
        }
        $target = $documentMap[$referenceId]
        if ($reference.schema_version -ne $target.schema_version -or
            [int]$reference.document_version -ne [int]$target.document_version -or
            $reference.content_sha256 -ne $target.content_sha256) {
            Add-PlanError 'stale_contract_reference' "Catalog reference '$referenceId' is stale." $referenceId
        }
    }
}

$knownTopLevelFields = @(
    'schema_version','document_id','document_version','content_sha256','trace_references',
    'active_behavior_authorization','performance_acceptance_authorization','experiment_plan_id',
    'family_id','experiment_type','fixed_axis_ids','fixed_axis_values','varied_axis_ids',
    'treatment_order','treatments','planned_cells','execution_status','expected_capabilities',
    'preserve_equivalent_cells_for_verification','required_predicate_refs','history_controls',
    'profile_definition','execution_order_policy','randomization_seed','source_document_refs','notes',
    'execution_purpose','reviewed_actuation_proof_refs'
)
foreach ($property in $plan.PSObject.Properties.Name) {
    if ($knownTopLevelFields -notcontains $property) {
        if ($property -in @('runtime_controller_inputs','workload_identity_controller_input')) {
            Add-PlanError 'prohibited_runtime_controller_input' "Runtime-controller input '$property' is prohibited." $property
        }
        else {
            Add-PlanError 'unknown_field' "Unknown source-plan field '$property'." $property
        }
    }
}

$closedExperimentTypes = @(
    'actuation_validation',
    'isolated_counterfactual',
    'interaction_screen',
    'feedback_loop',
    'profile_validation'
)
if ($closedExperimentTypes -notcontains [string]$plan.experiment_type) {
    Add-PlanError 'unsupported_experiment_type' "Experiment type '$($plan.experiment_type)' is not supported." 'experiment_type'
}

try {
    if (-not (Test-AdaptiveRuntimeJsonSchema -Document $plan -SchemaPath $planSchemaPath) -and
        -not ($errors | Where-Object error_code -in @('unknown_field','prohibited_runtime_controller_input','unsupported_experiment_type'))) {
        Add-PlanError 'schema_validation_failed' 'The source plan does not satisfy adaptive-runtime-experiment-plan-v1.' $plan.document_id
    }
}
catch {
    if (-not ($errors | Where-Object error_code -in @('unknown_field','prohibited_runtime_controller_input','unsupported_experiment_type'))) {
        Add-PlanError 'schema_validation_failed' "Source-plan schema validation failed: $($_.Exception.Message)" $plan.document_id
    }
}

if (-not (Test-AdaptiveRuntimeDocumentHash -Document $plan)) {
    Add-PlanError 'hash_mismatch' 'The source-plan content hash does not match its canonical JSON.' $plan.document_id
}
if ($plan.active_behavior_authorization -ne $false) {
    Add-PlanError 'active_behavior_unauthorized' 'Active behavior authorization must remain false.' 'active_behavior_authorization'
}
if ($plan.performance_acceptance_authorization -ne $false) {
    Add-PlanError 'performance_acceptance_unauthorized' 'Performance acceptance authorization must remain false.' 'performance_acceptance_authorization'
}

foreach ($reference in @($plan.source_document_refs)) {
    $referenceId = [string]$reference.document_id
    if (-not $documentMap.ContainsKey($referenceId)) {
        Add-PlanError 'unknown_contract_reference' "Document reference '$referenceId' is unknown." $referenceId
        continue
    }
    $target = $documentMap[$referenceId]
    if ($reference.schema_version -ne $target.schema_version -or
        [int]$reference.document_version -ne [int]$target.document_version -or
        $reference.content_sha256 -ne $target.content_sha256) {
        Add-PlanError 'stale_contract_reference' "Document reference '$referenceId' does not identify the loaded version and hash." $referenceId
    }
}

$fixedAxisIds = @(Get-StringArray $plan.fixed_axis_ids)
$variedAxisIds = @(Get-StringArray $plan.varied_axis_ids)
if (@($fixedAxisIds | Group-Object | Where-Object Count -gt 1).Count -gt 0 -or
    @($variedAxisIds | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
    Add-PlanError 'duplicate_axis_reference' 'Fixed and varied axis arrays must not contain duplicate axis references.'
}
if (@($fixedAxisIds | Where-Object { $variedAxisIds -contains $_ }).Count -gt 0) {
    Add-PlanError 'fixed_varied_axis_overlap' 'Fixed and varied axes must not overlap.'
}

$fixedValueAxisIds = @(Get-StringArray @($plan.fixed_axis_values | ForEach-Object axis_id))
if (-not (Test-SameStringSet $fixedAxisIds $fixedValueAxisIds)) {
    Add-PlanError 'duplicate_axis_reference' 'fixed_axis_values must identify each fixed axis exactly once.' 'fixed_axis_values'
}
foreach ($fixedValue in @($plan.fixed_axis_values)) {
    if ($fixedValue.configured_value -ne 'legacy_current') {
        Add-PlanError 'fixed_axis_not_legacy_current' "Fixed axis '$($fixedValue.axis_id)' must remain legacy_current." $fixedValue.axis_id
    }
}

$interactionProofMissing = $false
$interactionCorrectnessAuthorized = $false
$family = @($familyCatalog.experiment_families | Where-Object family_id -eq $plan.family_id) | Select-Object -First 1
if ($null -eq $family) {
    Add-PlanError 'unsupported_experiment_family' "Experiment family '$($plan.family_id)' is unknown." $plan.family_id
}
else {
    $familyAxisIds = @(if ($familyCatalog.schema_version -in @(
        'adaptive-runtime-experiment-family-catalog-v2',
        'adaptive-runtime-experiment-family-catalog-v3')) {
        Get-StringArray $family.included_axis_ids
    }
    else {
        Get-StringArray $family.contexts
    })
    $familyFixedAxisIds = @(if ($familyCatalog.schema_version -in @(
        'adaptive-runtime-experiment-family-catalog-v2',
        'adaptive-runtime-experiment-family-catalog-v3')) {
        Get-StringArray @($family.fixed_axis_requirements | ForEach-Object axis_id)
    }
    else {
        @()
    })
    foreach ($axisId in @($fixedAxisIds + $variedAxisIds)) {
        $isFamilyAxis = $familyAxisIds -contains $axisId -or
            $familyFixedAxisIds -contains $axisId
        if (-not $isFamilyAxis) {
            Add-PlanError 'axis_outside_experiment_family' "Axis '$axisId' is outside family '$($plan.family_id)'." $axisId
        }
    }
    if ($familyFixedAxisIds.Count -gt 0 -and
        -not (Test-SameStringSet $familyFixedAxisIds $fixedAxisIds)) {
        Add-PlanError 'axis_outside_experiment_family' "Plan fixed axes do not match family '$($plan.family_id)' fixed-axis requirements." 'fixed_axis_ids'
    }
    if ((Get-StringArray $family.supported_experiment_types) -notcontains $plan.experiment_type -and
        (Get-StringArray $family.blocked_experiment_types) -notcontains $plan.experiment_type) {
        Add-PlanError 'unsupported_experiment_type' "Family '$($plan.family_id)' does not support '$($plan.experiment_type)'." $plan.experiment_type
    }
    if ($familyCatalog.schema_version -in @(
        'adaptive-runtime-experiment-family-catalog-v2',
        'adaptive-runtime-experiment-family-catalog-v3') -and
        $plan.experiment_type -eq 'interaction_screen') {
        $familyProofIds = @(Get-StringArray $family.actuation_proof_refs)
        $reviewedProofs = @($familyCatalog.reviewed_actuation_proofs)
        $forcedVariedTreatments = @($plan.treatments | Where-Object {
            $variedAxisIds -contains [string]$_.axis_id -and
            -not [string]::IsNullOrWhiteSpace(
                [string](Get-AdaptiveRuntimeJsonProperty $_ 'forced_value'))
        })
        foreach ($treatment in $forcedVariedTreatments) {
            $proofs = @($reviewedProofs | Where-Object {
                $familyProofIds -contains [string]$_.proof_id -and
                [string]$_.axis_id -ceq [string]$treatment.axis_id -and
                [string]$_.policy_value -ceq [string]$treatment.forced_value -and
                [int]$_.proof_version -eq 1 -and
                [string]$_.review_outcome -ceq 'passed'
            })
            if ($proofs.Count -ne 1) {
                $interactionProofMissing = $true
                $target = "$($treatment.axis_id)=$($treatment.forced_value)"
                Add-PlanWarning 'interaction_actuation_proof_missing' (
                    "Interaction correctness compilation retained '$target', " +
                    'but reviewed v1 actuation proof is absent; measurement ' +
                    'execution remains blocked.') $target
            }
        }
        $declaredProofValue = Get-AdaptiveRuntimeJsonProperty $plan `
            'reviewed_actuation_proof_refs'
        $declaredProofRefs = if ($null -eq $declaredProofValue) {
            @()
        }
        else {
            @($declaredProofValue)
        }
        $exactProofRefs = @($forcedVariedTreatments | ForEach-Object {
            $treatment = $_
            @($reviewedProofs | Where-Object {
                $familyProofIds -contains [string]$_.proof_id -and
                [string]$_.axis_id -ceq [string]$treatment.axis_id -and
                [string]$_.policy_value -ceq [string]$treatment.forced_value -and
                [string]$_.review_outcome -ceq 'passed'
            } | ForEach-Object evidence_ref)
        })
        $declaredKeys = @($declaredProofRefs | ForEach-Object {
            "$($_.document_id)|$($_.schema_version)|$($_.document_version)|$($_.content_sha256)"
        } | Sort-Object -CaseSensitive)
        $exactKeys = @($exactProofRefs | ForEach-Object {
            "$($_.document_id)|$($_.schema_version)|$($_.document_version)|$($_.content_sha256)"
        } | Sort-Object -CaseSensitive)
        $interactionCorrectnessAuthorized =
            (Get-AdaptiveRuntimeJsonProperty $plan 'execution_purpose') `
                -ceq 'correctness_only' -and
            $forcedVariedTreatments.Count -eq 2 -and
            $exactProofRefs.Count -eq 2 -and
            (ConvertTo-Json $declaredKeys -Compress) -ceq
                (ConvertTo-Json $exactKeys -Compress)
        if (-not $interactionCorrectnessAuthorized) {
            $interactionProofMissing = $true
            foreach ($treatment in $forcedVariedTreatments) {
                $target =
                    "$($treatment.axis_id)=$($treatment.forced_value)"
                Add-PlanWarning 'interaction_actuation_proof_missing' (
                    "Interaction execution requires the exact reviewed " +
                    "proof reference for '$target'.") $target
            }
        }
    }
}

switch ([string]$plan.experiment_type) {
    'actuation_validation' {
        if ($variedAxisIds.Count -ne 1) {
            Add-PlanError 'experiment_type_axis_count_invalid' 'Actuation validation requires exactly one varied axis.'
        }
    }
    'isolated_counterfactual' {
        if ($variedAxisIds.Count -ne 1) {
            Add-PlanError 'experiment_type_axis_count_invalid' 'Isolated counterfactual requires exactly one varied axis.'
        }
    }
    'interaction_screen' {
        if ($variedAxisIds.Count -lt 2) {
            Add-PlanError 'experiment_type_axis_count_invalid' 'Interaction screen requires at least two varied axes.'
        }
    }
    'feedback_loop' {
        if ($null -eq (Get-AdaptiveRuntimeJsonProperty $plan 'history_controls')) {
            Add-PlanError 'feedback_loop_history_missing' 'Feedback-loop plans require the complete history-controls contract.' 'history_controls'
        }
    }
    'profile_validation' {
        $profile = Get-AdaptiveRuntimeJsonProperty $plan 'profile_definition'
        if ($null -eq $profile -or $profile.transparent -ne $true -or @($profile.profile_treatment_ids).Count -eq 0) {
            Add-PlanError 'opaque_profile_definition' 'Profile validation requires transparent per-axis treatment evidence.' 'profile_definition'
        }
    }
}

$canonicalPredicateIds = @(
    $axisCatalog.axis_contracts.canonical_predicates.predicate_id
    $familyCatalog.experiment_families.predicate_refs
    $constraintCatalog.combination_constraints.predicate_refs
) | ForEach-Object { [string]$_ } | Sort-Object -Unique
$declaredPlanPredicateIds = @(Get-StringArray $plan.required_predicate_refs)
$declaredCapabilityIds = @(Get-StringArray @($plan.expected_capabilities | ForEach-Object capability_id))
$allAxisIds = @($fixedAxisIds + $variedAxisIds | Sort-Object -Unique)
$axisById = @{}
foreach ($axisId in $allAxisIds) {
    $contract = Get-AxisContract -AxisId $axisId
    if ($null -eq $contract) {
        Add-PlanError 'unknown_axis' "Axis '$axisId' has no loaded contract." $axisId
        continue
    }
    $axisById[$axisId] = $contract
    if ($contract.status -eq 'blocked') {
        Add-PlanError 'blocked_axis' "Axis '$axisId' is blocked." $axisId
    }
    elseif ($contract.status -eq 'preparation_only') {
        Add-PlanError 'preparation_only_axis' "Axis '$axisId' is preparation-only." $axisId
    }
    elseif ($contract.status -ne 'implemented' -or $contract.executable -ne $true) {
        Add-PlanError 'axis_not_implemented' "Axis '$axisId' is not implemented and executable." $axisId
    }

    $readiness = Get-AdaptiveRuntimeJsonProperty $contract 'readiness'
    if ($variedAxisIds -contains $axisId) {
        if ($null -eq $readiness -or $readiness.forceable -ne $true) {
            Add-PlanError 'axis_not_forceable' "Axis '$axisId' is not forceable." $axisId
        }
        if ($null -eq $readiness -or $readiness.rollback_proof_status -ne 'represented') {
            Add-PlanError 'rollback_proof_missing' "Axis '$axisId' lacks represented rollback proof." $axisId
        }
        if ($plan.experiment_type -eq 'isolated_counterfactual' -and
            ($null -eq $readiness -or $readiness.actuation_validation_status -ne 'passed')) {
            Add-PlanError 'actuation_proof_missing' "Axis '$axisId' has not passed actuation validation." $axisId
        }
        foreach ($capabilityId in @($readiness.required_capability_ids)) {
            if ($declaredCapabilityIds -notcontains $capabilityId) {
                Add-PlanError 'expected_capability_missing' "Axis '$axisId' requires expected capability '$capabilityId'." $axisId
            }
        }
        foreach ($predicateRef in @(
            $readiness.activation_predicate_refs
            $readiness.behavior_distinctness_predicate_refs
        )) {
            if ($canonicalPredicateIds -notcontains [string]$predicateRef -or
                $declaredPlanPredicateIds -notcontains [string]$predicateRef) {
                Add-PlanError 'missing_canonical_predicate_reference' "Axis '$axisId' requires predicate '$predicateRef'." $axisId
            }
        }
    }
}

foreach ($predicateRef in @($plan.required_predicate_refs)) {
    if ($canonicalPredicateIds -notcontains [string]$predicateRef) {
        Add-PlanError 'missing_canonical_predicate_reference' "Predicate '$predicateRef' is not owned by the loaded catalogs." $predicateRef
    }
}

$treatmentMap = @{}
$forcedAxisIds = [System.Collections.Generic.List[string]]::new()
foreach ($treatment in @($plan.treatments)) {
    $treatmentId = [string]$treatment.treatment_id
    if ($treatmentMap.ContainsKey($treatmentId)) {
        Add-PlanError 'duplicate_axis_reference' "Treatment '$treatmentId' is duplicated." $treatmentId
        continue
    }
    $treatmentMap[$treatmentId] = $treatment
    $axisId = [string]$treatment.axis_id
    if (-not $axisById.ContainsKey($axisId)) { continue }
    $contract = $axisById[$axisId]
    $forcedValue = Get-AdaptiveRuntimeJsonProperty $treatment 'forced_value'
    if ($null -ne $forcedValue) { $forcedAxisIds.Add($axisId) }
    foreach ($valueName in @('configured_value','candidate_value','forced_value')) {
        $value = Get-AdaptiveRuntimeJsonProperty $treatment $valueName
        if ($null -ne $value -and (Get-StringArray $contract.policy_values) -notcontains [string]$value) {
            Add-PlanError 'unknown_policy_value' "Value '$value' is not legal for axis '$axisId'." $treatmentId
        }
    }
    if ($treatment.configured_value -ne 'legacy_current' -and
        ($null -eq $forcedValue -or $forcedValue -ne $treatment.candidate_value)) {
        Add-PlanError 'axis_not_forceable' "Non-legacy treatment '$treatmentId' must declare its exact forced candidate." $treatmentId
    }
}
$forcedAxisIds = @($forcedAxisIds | Sort-Object -Unique)
if ($plan.experiment_type -eq 'actuation_validation' -and
    ($forcedAxisIds.Count -ne 1 -or $forcedAxisIds[0] -ne $variedAxisIds[0])) {
    Add-PlanError 'experiment_type_axis_count_invalid' 'Actuation validation requires forced values on exactly its one varied axis.'
}
foreach ($forcedAxisId in $forcedAxisIds) {
    if ($variedAxisIds -notcontains $forcedAxisId) {
        Add-PlanError 'fixed_axis_not_legacy_current' "Forced axis '$forcedAxisId' is not declared varied." $forcedAxisId
    }
}

$matchingConstraint = @($constraintCatalog.combination_constraints | Where-Object {
    $_.family_id -eq $plan.family_id -and
    (Get-StringArray $_.experiment_types) -contains $plan.experiment_type -and
    (Test-SameStringSet (Get-StringArray $_.varied_axis_ids) $variedAxisIds) -and
    (Test-SameStringSet (Get-StringArray $_.fixed_axis_ids) $fixedAxisIds)
}) | Select-Object -First 1
if ($plan.experiment_type -eq 'interaction_screen') {
    if ($null -eq $matchingConstraint -or $matchingConstraint.legality -ne 'legal') {
        Add-PlanError 'cross_axis_constraint_violation' 'No legal cross-axis constraint permits this interaction.'
    }
}

$expandedCells = [System.Collections.Generic.List[object]]::new()
$behaviorKeyByCellId = @{}
$cellById = @{}
$capabilityPendingPlan = $plan.execution_status -eq 'blocked_by_capability' -or
    @($plan.expected_capabilities | Where-Object resolution -eq 'pending').Count -gt 0 -or
    (($null -ne $matchingConstraint -and
        $matchingConstraint.capability_state -in @('blocked','capability_blocked','deferred')) -and
        -not $interactionCorrectnessAuthorized)

foreach ($cell in @($plan.planned_cells | Sort-Object cell_order, cell_id)) {
    $behaviorIds = [System.Collections.Generic.List[string]]::new()
    $possibleBehaviorIds = [System.Collections.Generic.List[string]]::new()
    $outcomeIds = [System.Collections.Generic.List[string]]::new()
    $activationSignatureIds = [System.Collections.Generic.List[string]]::new()
    $missingTreatment = $false
    foreach ($treatmentId in @($cell.treatment_ids)) {
        if (-not $treatmentMap.ContainsKey([string]$treatmentId)) {
            Add-PlanError 'duplicate_axis_reference' "Cell '$($cell.cell_id)' references unknown treatment '$treatmentId'." $cell.cell_id
            $missingTreatment = $true
            continue
        }
        $treatment = $treatmentMap[[string]$treatmentId]
        $behaviorSet = Get-ExpectedBehaviorSet -AxisId $treatment.axis_id -Value $treatment.candidate_value
        if ($null -eq $behaviorSet) {
            $behaviorIds.Add("unknown.$($treatment.axis_id).$($treatment.candidate_value)")
            $activationSignatureIds.Add("activation.unknown.$($treatment.axis_id)")
        }
        else {
            foreach ($behaviorId in @($behaviorSet.primary_expected_behavior_ids)) {
                $behaviorIds.Add([string]$behaviorId)
            }
            foreach ($behaviorId in @($behaviorSet.possible_effective_behavior_ids)) {
                $possibleBehaviorIds.Add([string]$behaviorId)
            }
            foreach ($outcomeId in @($behaviorSet.non_behavior_outcome_ids)) {
                $outcomeIds.Add([string]$outcomeId)
            }
            $activationSignatureIds.Add([string]$behaviorSet.activation_signature_id)
        }
    }
    $behaviorIds = @($behaviorIds | Sort-Object -Unique)
    $possibleBehaviorIds = @($possibleBehaviorIds | Sort-Object -Unique)
    $outcomeIds = @($outcomeIds | Sort-Object -Unique)
    $activationSignatureIds = @($activationSignatureIds | Sort-Object -Unique)
    $behaviorKey = "$($behaviorIds -join '|')::$($activationSignatureIds -join '|')"
    $behaviorKeyByCellId[[string]$cell.cell_id] = $behaviorKey
    $cellById[[string]$cell.cell_id] = $cell

    $state = 'executable'
    $reasonCodes = [System.Collections.Generic.List[string]]::new()
    $activationExpectation = [string](Get-AdaptiveRuntimeJsonProperty $cell 'activation_expectation')
    if ($activationExpectation -eq 'unreachable') {
        Add-PlanError 'activation_predicate_unreachable' "Cell '$($cell.cell_id)' declares unreachable activation." $cell.cell_id
        $state = 'rejected'
        $reasonCodes.Add('activation_predicate_unreachable')
    }
    elseif ($activationExpectation -eq 'structurally_inactive') {
        $state = 'structurally_inactive'
        $reasonCodes.Add('structurally_inactive')
        Add-PlanWarning 'structurally_inactive_cell' "Cell '$($cell.cell_id)' is retained as structurally inactive." $cell.cell_id
    }
    elseif ($activationExpectation -eq 'unknown') {
        $state = 'behavior_distinctness_unknown'
        $reasonCodes.Add('activation_unknown')
        Add-PlanWarning 'behavior_distinctness_unproven' "Cell '$($cell.cell_id)' has unproven activation/behavior distinctness." $cell.cell_id
    }
    elseif ($capabilityPendingPlan) {
        $state = 'capability_pending'
        $reasonCodes.Add('capability_resolution_required')
        Add-PlanWarning 'capability_resolution_required' "Cell '$($cell.cell_id)' requires capability resolution." $cell.cell_id
    }
    elseif ($plan.experiment_type -in @('feedback_loop','profile_validation')) {
        $state = 'structurally_inactive'
        $reasonCodes.Add('first_slice_execution_deferred')
        Add-PlanWarning 'structurally_inactive_cell' "Cell '$($cell.cell_id)' is structurally valid but not executable in the first slice." $cell.cell_id
    }
    if ($missingTreatment) {
        $state = 'rejected'
    }

    $expanded = [ordered]@{
        cell_id = [string]$cell.cell_id
        cell_order = [int]$cell.cell_order
        axis_ids = @(Get-StringArray $cell.axis_ids | Sort-Object -Unique)
        treatment_ids = @(Get-StringArray $cell.treatment_ids)
        executable = $state -in @('executable','retained_for_verification')
        execution_state = $state
        expected_behavior_class_ids = @($behaviorIds)
        equivalence_group_id = 'pending'
        reason_codes = @($reasonCodes | Sort-Object -Unique)
    }
    if ($CatalogContractVersion -in @('v2','v3')) {
        $expanded.primary_expected_behavior_ids = @($behaviorIds)
        $expanded.possible_effective_behavior_ids = @($possibleBehaviorIds)
        $expanded.non_behavior_outcome_ids = @($outcomeIds)
        $expanded.activation_signature_ids = @($activationSignatureIds)
    }
    $expandedCells.Add([pscustomobject]$expanded)
}

$equivalenceGroups = [System.Collections.Generic.List[object]]::new()
foreach ($group in @($expandedCells | Group-Object { $behaviorKeyByCellId[[string]$_.cell_id] } | Sort-Object Name)) {
    $memberIds = @($group.Group.cell_id | Sort-Object)
    $groupHash = Get-AdaptiveRuntimeSha256 -Text ([string]$group.Name)
    $groupId = "equivalence.$($groupHash.Substring(0,16))"
    $state = if ($memberIds.Count -gt 1) { 'equivalent' } else { 'distinct' }
    foreach ($expanded in $group.Group) {
        $expanded.equivalence_group_id = $groupId
    }
    $equivalenceGroups.Add([pscustomobject][ordered]@{
        equivalence_group_id = $groupId
        member_cell_ids = $memberIds
        equivalence_state = $state
        expected_behavior_key = [string]$group.Name
    })

    if ($memberIds.Count -gt 1) {
        if (@($group.Group | Where-Object {
            $source = $cellById[[string]$_.cell_id]
            (Get-AdaptiveRuntimeJsonProperty $source 'performance_comparable') -eq $true
        }).Count -gt 0) {
            Add-PlanError 'equivalent_cells_performance_comparable' 'Expected-equivalent cells cannot be performance-comparable.' $groupId
        }

        Add-PlanWarning 'all_configured_values_collapse_to_one_expected_behavior' "Configured cells in '$groupId' collapse to one expected behavior." $groupId
        $preserve = (Get-AdaptiveRuntimeJsonProperty $plan 'preserve_equivalent_cells_for_verification') -eq $true -or
            $plan.experiment_type -eq 'actuation_validation'
        $orderedMembers = @($group.Group | Sort-Object cell_order, cell_id)
        if ($preserve) {
            foreach ($expanded in $orderedMembers) {
                if ($expanded.execution_state -eq 'executable') {
                    $expanded.execution_state = 'retained_for_verification'
                    $expanded.executable = $true
                    $expanded.reason_codes = @($expanded.reason_codes + 'verification_cell_preserved' | Sort-Object -Unique)
                }
            }
            Add-PlanWarning 'verification_cell_preserved' "Equivalent cells in '$groupId' are preserved for verification." $groupId
        }
        else {
            foreach ($expanded in @($orderedMembers | Select-Object -Skip 1)) {
                if ($expanded.execution_state -eq 'executable') {
                    $expanded.execution_state = 'deduplicated'
                    $expanded.executable = $false
                    $expanded.reason_codes = @($expanded.reason_codes + 'equivalent_cells_deduplicated' | Sort-Object -Unique)
                }
            }
            Add-PlanWarning 'equivalent_cells_deduplicated' "Equivalent cells in '$groupId' were deterministically deduplicated." $groupId
        }
    }
}

Add-PlanWarning 'measurement_freeze_active' 'Performance measurement and performance acceptance remain unauthorized.'
if ($plan.experiment_type -eq 'profile_validation') {
    Add-PlanWarning 'profile_execution_deferred' 'Profile validation remains non-executable in the first vertical slice.'
}

$classification = 'invalid'
if ($errors.Count -eq 0) {
    if ($plan.experiment_type -eq 'profile_validation') {
        $classification = 'valid_profile_validation'
    }
    elseif ($plan.experiment_type -eq 'feedback_loop') {
        $classification = 'valid_feedback_loop'
    }
    elseif ($interactionProofMissing) {
        $classification = 'blocked_for_measurement'
    }
    elseif (@($expandedCells | Where-Object execution_state -eq 'capability_pending').Count -gt 0) {
        $classification = 'capability_pending'
    }
    elseif ($equivalenceGroups.Count -eq 1 -and $expandedCells.Count -gt 1 -and
        $equivalenceGroups[0].member_cell_ids.Count -eq $expandedCells.Count) {
        $classification = 'verification_only'
        $equivalenceGroups[0].equivalence_state = 'verification_only'
    }
    else {
        $classification = switch ($plan.experiment_type) {
            'actuation_validation' { 'valid_actuation' }
            'isolated_counterfactual' { 'valid_isolated_counterfactual' }
            'interaction_screen' { 'valid_interaction_screen' }
            default { 'invalid' }
        }
    }
}

$count = {
    param([string]$State)
    return @($expandedCells | Where-Object execution_state -eq $State).Count
}
$expectedEffectiveCount = @($behaviorKeyByCellId.Values | Sort-Object -Unique).Count
$potentialExecutionCount = @($expandedCells | Where-Object execution_state -in @(
    'executable','capability_pending','retained_for_verification','behavior_distinctness_unknown'
)).Count

$result = [pscustomobject][ordered]@{
    schema_version = "adaptive-runtime-experiment-plan-validation-$CatalogContractVersion"
    document_id = "validation.$($plan.experiment_plan_id)"
    document_version = switch ($CatalogContractVersion) {
        'v3' { 3 }
        'v2' { 2 }
        default { 1 }
    }
    content_sha256 = ('0' * 64)
    trace_references = New-AdaptiveRuntimeTraceReferences
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    validation_id = "validation.$($plan.experiment_plan_id).$CatalogContractVersion"
    validated_plan_ref = [ordered]@{
        document_id = [string]$plan.document_id
        schema_version = [string]$plan.schema_version
        document_version = [int]$plan.document_version
        content_sha256 = [string]$plan.content_sha256
    }
    validation_classification = $classification
    validation_errors = @($errors | Sort-Object error_code, target_ref)
    validation_warnings = @($warnings | Sort-Object warning_code, target_ref)
    cell_counts = [ordered]@{
        configured = $expandedCells.Count
        expected_effective = $expectedEffectiveCount
        potential_execution = $potentialExecutionCount
        structurally_inactive = (& $count 'structurally_inactive')
        capability_pending = (& $count 'capability_pending')
        rejected = (& $count 'rejected')
        deduplicated = (& $count 'deduplicated')
        retained_for_verification = (& $count 'retained_for_verification')
        behavior_distinctness_unknown = (& $count 'behavior_distinctness_unknown')
    }
    equivalence_groups = @($equivalenceGroups)
    expanded_planned_cells = @($expandedCells)
    notes = @(
        'Plan eligibility is distinct from runtime operation eligibility.',
        'No runtime policy behavior or performance measurement is authorized by this result.'
    )
}
[void](Set-AdaptiveRuntimeDocumentHash -Document $result)

try {
    if (-not (Test-AdaptiveRuntimeJsonSchema -Document $result -SchemaPath $validationSchemaPath)) {
        throw "Generated validation result failed adaptive-runtime-experiment-plan-validation-$CatalogContractVersion."
    }
}
catch {
    throw "Compiler defect: $($_.Exception.Message)"
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-AdaptiveRuntimeCanonicalDocument -Document $result -Path $OutputPath
}

if ($PassThru) {
    $result
}
else {
    ConvertTo-AdaptiveRuntimeCanonicalJson -Value $result -IncludeRootContentSha256
}

if ($classification -eq 'invalid' -and -not $AllowInvalid) {
    exit 1
}
