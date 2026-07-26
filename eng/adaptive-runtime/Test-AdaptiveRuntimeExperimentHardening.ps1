# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1')

$fixtureRoot = Join-Path $RepositoryRoot 'tests\fixtures\adaptive-runtime-experiment-hardening'
$catalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
$schemaRoot = Join-Path $RepositoryRoot 'schemas'
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v2.json')
$interactionValidation = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'linked\interaction.validation.v2.json')
$verificationValidation = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'linked\send-verification.validation.v2.json')
$expectations = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'expectations.json')

$operationSchemaPath = Join-Path $schemaRoot 'adaptive-runtime-operation-evidence-v2.schema.json'
$behaviorSchemaPath = Join-Path $schemaRoot 'adaptive-runtime-effective-behavior-materialization-v2.schema.json'
$outcomeSchemaPath = Join-Path $schemaRoot 'adaptive-runtime-operation-outcome-materialization-v1.schema.json'
$validationSchemaPath = Join-Path $schemaRoot 'adaptive-runtime-experiment-plan-validation-v2.schema.json'

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Test-DocumentSchema {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $SchemaPath,
        [Parameter(Mandatory = $true)][string] $Label
    )
    $json = $Document | ConvertTo-Json -Depth 100 -Compress
    $schema = Get-Content -LiteralPath $SchemaPath -Raw
    try {
        $valid = Test-Json -Json $json -Schema $schema -ErrorAction Stop
    }
    catch {
        throw "$Label failed schema validation: $($_.Exception.Message)"
    }
    Assert-Condition $valid "$Label failed schema validation."
}

$schemaFiles = @(
    'adaptive-runtime-effective-behavior-catalog-v2.schema.json',
    'adaptive-runtime-policy-relationship-graph-v2.schema.json',
    'adaptive-runtime-experiment-family-catalog-v2.schema.json',
    'adaptive-runtime-experiment-plan-validation-v2.schema.json',
    'adaptive-runtime-operation-evidence-v2.schema.json',
    'adaptive-runtime-effective-behavior-materialization-v2.schema.json',
    'adaptive-runtime-operation-outcome-materialization-v1.schema.json',
    'adaptive-runtime-experiment-evidence-projection-v2.schema.json'
)
foreach ($schemaFile in $schemaFiles) {
    try {
        Get-Content -LiteralPath (Join-Path $schemaRoot $schemaFile) -Raw |
            ConvertFrom-Json -Depth 100 | Out-Null
    }
    catch {
        throw "Schema '$schemaFile' is not valid JSON: $($_.Exception.Message)"
    }
}

$catalogPairs = @(
    @(
        'adaptive-runtime-effective-behavior-catalog-v2.json',
        'adaptive-runtime-effective-behavior-catalog-v2.schema.json'
    ),
    @(
        'adaptive-runtime-policy-relationship-graph-v2.json',
        'adaptive-runtime-policy-relationship-graph-v2.schema.json'
    ),
    @(
        'adaptive-runtime-experiment-family-catalog-v2.json',
        'adaptive-runtime-experiment-family-catalog-v2.schema.json'
    )
)
foreach ($pair in $catalogPairs) {
    $document = Read-AdaptiveRuntimeJsonDocument (Join-Path $catalogRoot $pair[0])
    Test-DocumentSchema $document (Join-Path $schemaRoot $pair[1]) $pair[0]
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $document) (
        "$($pair[0]) has a stale content hash.")
}
foreach ($entry in @(
    @($interactionValidation, 'interaction.validation.v2.json'),
    @($verificationValidation, 'send-verification.validation.v2.json')
)) {
    Test-DocumentSchema $entry[0] $validationSchemaPath $entry[1]
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $entry[0]) (
        "$($entry[1]) has a stale content hash.")
}

$validCount = 0
$warningCount = 0
$invalidCount = 0
$deterministicMaterializations = 0

function Get-LinkedValidation {
    param([object] $Evidence)
    if ([string]$Evidence.plan_validation_ref.document_id -eq
        [string]$verificationValidation.document_id) {
        return $verificationValidation
    }
    return $interactionValidation
}

function Test-ValidEvidence {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][bool] $CheckWarnings
    )
    $name = Split-Path -Leaf $Path
    $evidence = Read-AdaptiveRuntimeJsonDocument $Path
    $linkedValidation = Get-LinkedValidation $evidence
    Test-DocumentSchema $evidence $operationSchemaPath $name
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $evidence) (
        "$name has a stale content hash.")

    $errors = @(Get-AdaptiveRuntimeEvidenceV2Errors -Evidence $evidence `
        -Catalog $catalog -PlanValidation $linkedValidation)
    Assert-Condition ($errors.Count -eq 0) (
        "$name unexpectedly failed semantic validation: $($errors -join ', ')")

    $behavior1 = New-AdaptiveRuntimeBehaviorMaterializationV2 `
        -Evidence $evidence -Catalog $catalog
    $behavior2 = New-AdaptiveRuntimeBehaviorMaterializationV2 `
        -Evidence $evidence -Catalog $catalog
    $outcome1 = New-AdaptiveRuntimeOutcomeMaterializationV1 `
        -Evidence $evidence -Catalog $catalog
    $outcome2 = New-AdaptiveRuntimeOutcomeMaterializationV1 `
        -Evidence $evidence -Catalog $catalog
    Test-DocumentSchema $behavior1 $behaviorSchemaPath "$name behavior materialization"
    Test-DocumentSchema $outcome1 $outcomeSchemaPath "$name outcome materialization"
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $behavior1) (
        "$name behavior materialization hash failed.")
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $outcome1) (
        "$name outcome materialization hash failed.")

    $behaviorBytes1 = ConvertTo-AdaptiveRuntimeCanonicalJson $behavior1
    $behaviorBytes2 = ConvertTo-AdaptiveRuntimeCanonicalJson $behavior2
    $outcomeBytes1 = ConvertTo-AdaptiveRuntimeCanonicalJson $outcome1
    $outcomeBytes2 = ConvertTo-AdaptiveRuntimeCanonicalJson $outcome2
    Assert-Condition ($behaviorBytes1 -ceq $behaviorBytes2) (
        "$name behavior materialization is not byte deterministic.")
    Assert-Condition ($outcomeBytes1 -ceq $outcomeBytes2) (
        "$name outcome materialization is not byte deterministic.")

    $matchedOperationIds = @($behavior1.derivations |
        Where-Object derivation_status -eq 'matched' |
        ForEach-Object { [string]$_.operation_id } | Sort-Object -Unique)
    $outcomeOperationIds = @($evidence.operations | Where-Object {
        -not [string]::IsNullOrWhiteSpace(
            (Get-AdaptiveRuntimeOperationOutcomeId $_))
    } | ForEach-Object { [string]$_.operation_id } | Sort-Object -Unique)
    $allOperationIds = @($evidence.operations |
        ForEach-Object { [string]$_.operation_id } | Sort-Object -Unique)
    $accountedOperationIds = @($matchedOperationIds + $outcomeOperationIds |
        Sort-Object -Unique)
    Assert-Condition ($accountedOperationIds.Count -eq $allOperationIds.Count) (
        "$name operation accounting omitted an operation.")

    if ($CheckWarnings) {
        $actualWarnings = @(Get-AdaptiveRuntimeEvidenceV2WarningCodes `
            -Evidence $evidence -BehaviorMaterialization $behavior1 `
            -PlanValidation $linkedValidation)
        $expectedWarnings = @($expectations.warning.$name | Sort-Object)
        Assert-Condition (
            (($actualWarnings | ConvertTo-Json -Compress) -ceq
             ($expectedWarnings | ConvertTo-Json -Compress))) (
            "$name warning mismatch. Expected [$($expectedWarnings -join ', ')]; " +
            "actual [$($actualWarnings -join ', ')].")
    }

    return [pscustomobject]@{
        Evidence = $evidence
        Behavior = $behavior1
        Outcome = $outcome1
    }
}

foreach ($name in @($expectations.valid)) {
    $null = Test-ValidEvidence (
        Join-Path $fixtureRoot "valid\$name") $false
    $validCount++
    $deterministicMaterializations++
}
foreach ($property in @($expectations.warning.PSObject.Properties |
    Sort-Object Name)) {
    $null = Test-ValidEvidence (
        Join-Path $fixtureRoot "warning\$($property.Name)") $true
    $warningCount++
    $deterministicMaterializations++
}
foreach ($property in @($expectations.invalid.PSObject.Properties |
    Sort-Object Name)) {
    $name = $property.Name
    $evidence = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $fixtureRoot "invalid\$name")
    Test-DocumentSchema $evidence $operationSchemaPath $name
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $evidence) (
        "$name has a stale content hash.")
    $errors = @(Get-AdaptiveRuntimeEvidenceV2Errors -Evidence $evidence `
        -Catalog $catalog -PlanValidation $interactionValidation)
    Assert-Condition ($errors -ccontains [string]$property.Value) (
        "$name did not produce expected error '$($property.Value)'; " +
        "actual [$($errors -join ', ')].")
    $invalidCount++
}

$inactiveWarnings = @(Get-AdaptiveRuntimeEvidenceV2WarningCodes `
    -Evidence (Read-AdaptiveRuntimeJsonDocument (
        Join-Path $fixtureRoot 'warning\inactive-derived-from-content.json')) `
    -BehaviorMaterialization (
        New-AdaptiveRuntimeBehaviorMaterializationV2 -Evidence (
            Read-AdaptiveRuntimeJsonDocument (
                Join-Path $fixtureRoot 'warning\inactive-derived-from-content.json')) `
            -Catalog $catalog) `
    -PlanValidation $interactionValidation)
$renamedWarnings = @(Get-AdaptiveRuntimeEvidenceV2WarningCodes `
    -Evidence (Read-AdaptiveRuntimeJsonDocument (
        Join-Path $fixtureRoot 'warning\renamed-inactive-content-copy.json')) `
    -BehaviorMaterialization (
        New-AdaptiveRuntimeBehaviorMaterializationV2 -Evidence (
            Read-AdaptiveRuntimeJsonDocument (
                Join-Path $fixtureRoot 'warning\renamed-inactive-content-copy.json')) `
            -Catalog $catalog) `
    -PlanValidation $interactionValidation)
Assert-Condition (
    (($inactiveWarnings | ConvertTo-Json -Compress) -ceq
     ($renamedWarnings | ConvertTo-Json -Compress))) (
    'Renaming equivalent evidence changed warning derivation.')

$catalogProofEvidence = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'valid\catalog.batch-single.json')
$sourceBehavior = Resolve-AdaptiveRuntimeEffectiveBehavior `
    -Operation $catalogProofEvidence.operations[0] -Catalog $catalog
$changedCatalog = $catalog | ConvertTo-Json -Depth 100 |
    ConvertFrom-Json -Depth 100
$changedBehavior = @($changedCatalog.effective_behaviors | Where-Object {
    $_.effective_behavior_id -eq $sourceBehavior.effective_behavior_ids[0]
})[0]
$changedBehavior.effective_behavior_id =
    'batch_formation.catalog_mapping_change_proof'
[void](Set-AdaptiveRuntimeDocumentHash $changedCatalog)
$changedResult = Resolve-AdaptiveRuntimeEffectiveBehavior `
    -Operation $catalogProofEvidence.operations[0] -Catalog $changedCatalog
Assert-Condition (
    [string]$changedResult.effective_behavior_ids[0] -ceq
    'batch_formation.catalog_mapping_change_proof') (
    'Changing only the catalog did not change behavior derivation.')

$ambiguousCatalog = $catalog | ConvertTo-Json -Depth 100 |
    ConvertFrom-Json -Depth 100
$duplicateBehavior = $changedBehavior | ConvertTo-Json -Depth 100 |
    ConvertFrom-Json -Depth 100
$duplicateBehavior.effective_behavior_id =
    'batch_formation.catalog_ambiguity_proof'
$ambiguousCatalog.effective_behaviors = @(
    $ambiguousCatalog.effective_behaviors + $duplicateBehavior)
$ambiguousResult = Resolve-AdaptiveRuntimeEffectiveBehavior `
    -Operation $catalogProofEvidence.operations[0] -Catalog $ambiguousCatalog
Assert-Condition ($ambiguousResult.status -eq 'ambiguous') (
    'Conflicting exclusive catalog rules were not rejected as ambiguous.')

$interactionPlanPath = Join-Path $RepositoryRoot (
    'tests\fixtures\adaptive-runtime-experiment-plan-compiler\valid\interaction.plan.json')
$verificationPlanPath = Join-Path $RepositoryRoot (
    'tests\fixtures\adaptive-runtime-experiment-hardening\linked\send-verification.plan.v2-input.json')
$interactionCompile1 = & (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeExperimentPlan.ps1') -PlanPath $interactionPlanPath `
    -RepositoryRoot $RepositoryRoot -CatalogContractVersion v2 -PassThru
$interactionCompile2 = & (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeExperimentPlan.ps1') -PlanPath $interactionPlanPath `
    -RepositoryRoot $RepositoryRoot -CatalogContractVersion v2 -PassThru
$verificationCompile = & (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeExperimentPlan.ps1') -PlanPath $verificationPlanPath `
    -RepositoryRoot $RepositoryRoot -CatalogContractVersion v2 -PassThru
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $interactionCompile1) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $interactionCompile2)) (
    'v2 interaction compilation is not byte deterministic.')
Assert-Condition (
    $interactionCompile1.validation_classification -eq
        'blocked_for_measurement' -and
    @($interactionCompile1.validation_warnings | Where-Object {
        $_.warning_code -eq 'interaction_actuation_proof_missing'
    }).Count -eq 2) (
    'Interaction compilation did not require one reviewed actuation proof ' +
    'for each forced behavior-distinct axis/value pair.')
Assert-Condition (
    $verificationCompile.validation_classification -eq 'verification_only' -and
    $verificationCompile.cell_counts.configured -eq 2 -and
    $verificationCompile.cell_counts.expected_effective -eq 1) (
    'Send-planning expected-equivalence classification regressed.')
$setCell = @($interactionCompile1.expanded_planned_cells | Where-Object {
    @($_.possible_effective_behavior_ids).Count -gt 1
})[0]
Assert-Condition ($null -ne $setCell) (
    'v2 compilation did not preserve one-to-many expected behaviors.')
Assert-Condition (@($setCell.non_behavior_outcome_ids).Count -gt 0) (
    'v2 compilation did not preserve non-behavior outcomes.')

$relationshipSchema = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $schemaRoot 'adaptive-runtime-policy-relationship-graph-v2.schema.json')
$relationshipTypes = @($relationshipSchema.'$defs'.relationshipType.enum)
$requiredRelationshipTypes = @(
    'authority_overlap',
    'structural_constraint',
    'supplies_work',
    'changes_observed_state',
    'feedback_loop',
    'shared_outcome_only',
    'context_effect'
)
Assert-Condition (
    (($relationshipTypes | Sort-Object | ConvertTo-Json -Compress) -ceq
     ($requiredRelationshipTypes | Sort-Object | ConvertTo-Json -Compress))) (
    'Relationship graph v2 does not expose the complete closed taxonomy.')
$familyCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-experiment-family-catalog-v2.json')
$sendFamily = @($familyCatalog.experiment_families | Where-Object {
    $_.family_id -eq 'send_composition'
})[0]
foreach ($propertyName in @(
    'included_axis_ids','fixed_axis_requirements','outer_context_ids',
    'workload_archetype_ids','primary_metric_ids','guardrail_metric_ids',
    'actuation_proof_refs')) {
    Assert-Condition (
        $sendFamily.PSObject.Properties.Name -ccontains $propertyName) (
        "Experiment family v2 is missing '$propertyName'.")
}

$projectionRoot = Join-Path $fixtureRoot 'projection-inputs'
$projectionExpectedPath = Join-Path $fixtureRoot 'expected\projection.json'
$projectionSchemaPath = Join-Path $schemaRoot `
    'adaptive-runtime-experiment-evidence-projection-v2.schema.json'
$projectionParameters = [ordered]@{
    PlanPath = $interactionPlanPath
    PlanValidationPath =
        (Join-Path $fixtureRoot 'linked\interaction.validation.v2.json')
    CompiledManifestPath =
        (Join-Path $projectionRoot 'compiled-manifest.json')
    ExperimentRunPath =
        (Join-Path $projectionRoot 'experiment-run.json')
    HostFingerprintPath =
        (Join-Path $projectionRoot 'host-fingerprint.json')
    BinaryCohortPath =
        (Join-Path $projectionRoot 'binary-cohort.json')
    WorkloadInstancePath =
        (Join-Path $projectionRoot 'workload-instance.json')
    RequestedWorkloadShapePath =
        (Join-Path $projectionRoot 'requested-workload-shape.json')
    EffectiveWorkloadShapePath =
        (Join-Path $projectionRoot 'effective-workload-shape.json')
    OperationEvidencePath =
        (Join-Path $fixtureRoot 'valid\both-axes-distinct.json')
    BehaviorMaterializationPath =
        (Join-Path $fixtureRoot 'expected\behavior-materialization.json')
    OutcomeMaterializationPath =
        (Join-Path $fixtureRoot 'expected\outcome-materialization.json')
    MetricObservationsPath =
        (Join-Path $projectionRoot 'metric-observations.json')
    ArtifactInventoryPath =
        (Join-Path $projectionRoot 'artifact-inventory.json')
    ClassificationsPath =
        (Join-Path $projectionRoot 'classifications.json')
}
function Invoke-Projection {
    param([hashtable] $Overrides)
    $parameters = @{}
    foreach ($entry in $projectionParameters.GetEnumerator()) {
        $parameters[$entry.Key] = $entry.Value
    }
    foreach ($entry in $Overrides.GetEnumerator()) {
        $parameters[$entry.Key] = $entry.Value
    }
    return & (Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeExperimentEvidenceProjection.ps1') `
        @parameters -PassThru
}

$projection1 = Invoke-Projection @{}
$projection2 = Invoke-Projection @{}
$expectedProjection = Read-AdaptiveRuntimeJsonDocument $projectionExpectedPath
Test-DocumentSchema $projection1 $projectionSchemaPath 'projection rebuild'
Assert-Condition (Test-AdaptiveRuntimeDocumentHash $projection1) (
    'Projection rebuild hash failed.')
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection1) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection2)) (
    'Projection rebuild is not byte deterministic.')
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection1) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $expectedProjection)) (
    'Projection rebuild does not match the checked-in expected projection.')

$projectionInvalidRoot = Join-Path $fixtureRoot 'projection-invalid'
foreach ($property in @($expectations.projection_invalid.PSObject.Properties |
    Sort-Object Name)) {
    $override = switch ($property.Name) {
        'experiment-run-missing-hash.json' {
            @{ ExperimentRunPath = Join-Path $projectionInvalidRoot $property.Name }
        }
        'behavior-wrong-source-ref.json' {
            @{ BehaviorMaterializationPath =
                Join-Path $projectionInvalidRoot $property.Name }
        }
        'manifest-plan-mismatch.json' {
            @{ CompiledManifestPath =
                Join-Path $projectionInvalidRoot $property.Name }
        }
        'evidence-duplicate-epoch.json' {
            @{ OperationEvidencePath =
                Join-Path $projectionInvalidRoot $property.Name }
        }
        'classifications-target-missing.json' {
            @{ ClassificationsPath =
                Join-Path $projectionInvalidRoot $property.Name }
        }
    }
    $actualError = $null
    try {
        $null = Invoke-Projection $override
    }
    catch {
        $actualError = $_.Exception.Message
    }
    Assert-Condition (
        -not [string]::IsNullOrWhiteSpace($actualError) -and
        $actualError.Contains([string]$property.Value,
            [StringComparison]::Ordinal)) (
        "$($property.Name) did not fail with '$($property.Value)'; " +
        "actual '$actualError'.")
}

[pscustomobject][ordered]@{
    schemas = $schemaFiles.Count
    canonical_catalogs = $catalogPairs.Count
    valid_fixtures = $validCount
    warning_fixtures = $warningCount
    invalid_fixtures = $invalidCount
    deterministic_materializations = $deterministicMaterializations
    catalog_mapping_change_proof = $true
    ambiguous_catalog_rejected = $true
    filename_independent_warnings = $true
    one_to_many_expected_behaviors = $true
    relationship_types = $relationshipTypes.Count
    interaction_actuation_proof_warnings = 2
    interaction_classification =
        [string]$interactionCompile1.validation_classification
    projection_invalid_fixtures =
        @($expectations.projection_invalid.PSObject.Properties).Count
    projection_byte_deterministic = $true
    projection_hash = [string]$projection1.content_sha256
    verification_only_configured_cells =
        $verificationCompile.cell_counts.configured
    verification_only_expected_effective_cells =
        $verificationCompile.cell_counts.expected_effective
} | ConvertTo-Json -Depth 10
