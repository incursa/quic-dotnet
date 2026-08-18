# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-exp-evidence-closeout'
$schemaRoot = Join-Path $RepositoryRoot 'schemas'
$catalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
$inputRoot = Join-Path $fixtureRoot 'valid\inputs'
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v2.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-classification-compatibility-catalog-v1.json')
$expectations = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'expectations.json')

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) { throw $Message }
}

function Assert-ThrowsCode {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $ExpectedCode,
        [Parameter(Mandatory = $true)][string] $Label
    )
    try {
        & $Action
        throw "$Label did not fail with '$ExpectedCode'."
    }
    catch {
        if ([string]$_.Exception.Message -notlike "*$ExpectedCode*") {
            throw "$Label failed with '$($_.Exception.Message)' instead of '$ExpectedCode'."
        }
    }
}

function Assert-Schema {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $SchemaFile,
        [Parameter(Mandatory = $true)][string] $Label
    )
    try {
        $valid = Test-AdaptiveRuntimeJsonSchema $Document (
            Join-Path $schemaRoot $SchemaFile)
    }
    catch {
        throw "$Label failed schema validation: $($_.Exception.Message)"
    }
    Assert-Condition $valid "$Label failed schema validation."
    Assert-Condition (Test-AdaptiveRuntimeDocumentHash $Document) (
        "$Label has a stale content hash.")
}

function Assert-SchemaInvalid {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $SchemaFile,
        [Parameter(Mandatory = $true)][string] $Label
    )
    $valid = $false
    try {
        $valid = Test-AdaptiveRuntimeJsonSchema $Document (
            Join-Path $schemaRoot $SchemaFile)
    }
    catch {
        $valid = $false
    }
    Assert-Condition (-not $valid) "$Label unexpectedly passed schema validation."
}

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)][object] $Value)
    return $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Read-Input {
    param([Parameter(Mandatory = $true)][string] $Role)
    return Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputRoot "$Role.json")
}

$schemaFiles = @(
    'adaptive-runtime-classification-compatibility-catalog-v1.schema.json',
    'adaptive-runtime-operation-evidence-v3.schema.json',
    'adaptive-runtime-effective-behavior-materialization-v3.schema.json',
    'adaptive-runtime-operation-outcome-materialization-v2.schema.json',
    'adaptive-runtime-projection-immutable-input-v1.schema.json',
    'adaptive-runtime-experiment-evidence-projection-v3.schema.json'
)
foreach ($schemaFile in $schemaFiles) {
    Get-Content (Join-Path $schemaRoot $schemaFile) -Raw |
        ConvertFrom-Json -Depth 100 | Out-Null
}
Assert-Schema $compatibilityCatalog `
    'adaptive-runtime-classification-compatibility-catalog-v1.schema.json' `
    'classification compatibility catalog'
Assert-Schema $catalog `
    'adaptive-runtime-effective-behavior-catalog-v2.schema.json' `
    'effective behavior catalog'

$documents = [ordered]@{
    experiment_plan = Read-Input 'experiment_plan'
    plan_validation = Read-Input 'plan_validation'
    compiled_execution_manifest = Read-Input 'compiled_execution_manifest'
    experiment_run = Read-Input 'experiment_run'
    host_fingerprint = Read-Input 'host_fingerprint'
    binary_cohort = Read-Input 'binary_cohort'
    workload_instance = Read-Input 'workload_instance'
    requested_workload_shape = Read-Input 'requested_workload_shape'
    effective_workload_shape = Read-Input 'effective_workload_shape'
    operation_evidence = Read-Input 'operation_evidence'
    behavior_materialization = Read-Input 'behavior_materialization'
    outcome_materialization = Read-Input 'outcome_materialization'
    metric_observations = Read-Input 'metric_observations'
    artifact_inventory = Read-Input 'artifact_inventory'
    classifications = Read-Input 'classifications'
}
foreach ($entry in $documents.GetEnumerator()) {
    $schemaFile = switch ([string]$entry.Value.schema_version) {
        'adaptive-runtime-experiment-plan-v1' {
            'adaptive-runtime-experiment-plan-v1.schema.json'
        }
        'adaptive-runtime-experiment-plan-validation-v2' {
            'adaptive-runtime-experiment-plan-validation-v2.schema.json'
        }
        'adaptive-runtime-compiled-execution-manifest-v1' {
            'adaptive-runtime-compiled-execution-manifest-v1.schema.json'
        }
        'adaptive-runtime-operation-evidence-v3' {
            'adaptive-runtime-operation-evidence-v3.schema.json'
        }
        'adaptive-runtime-effective-behavior-materialization-v3' {
            'adaptive-runtime-effective-behavior-materialization-v3.schema.json'
        }
        'adaptive-runtime-operation-outcome-materialization-v2' {
            'adaptive-runtime-operation-outcome-materialization-v2.schema.json'
        }
        default {
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        }
    }
    Assert-Schema $entry.Value $schemaFile $entry.Key
}

$evidence = $documents.operation_evidence
$classificationSet = $documents.classifications
$validation = $documents.plan_validation
$evidenceErrors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
    $evidence $catalog $validation $classificationSet $compatibilityCatalog `
    $documents.artifact_inventory)
Assert-Condition ($evidenceErrors.Count -eq 0) (
    "Valid closeout evidence failed: $($evidenceErrors -join ', ')")

$behavior1 = New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$behavior2 = New-AdaptiveRuntimeBehaviorMaterializationV3 $evidence $catalog
$outcome1 = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $catalog $classificationSet
$outcome2 = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $catalog $classificationSet
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior1 -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior2 -IncludeRootContentSha256)
) 'Behavior materialization is not byte deterministic.'
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome1 -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome2 -IncludeRootContentSha256)
) 'Outcome materialization is not byte deterministic.'
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior1 -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson `
        $documents.behavior_materialization -IncludeRootContentSha256)
) 'Checked-in behavior materialization does not recompute.'
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome1 -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson `
        $documents.outcome_materialization -IncludeRootContentSha256)
) 'Checked-in outcome materialization does not recompute.'

$operationIdentities = @($evidence.operations | ForEach-Object {
    New-AdaptiveRuntimeOperationIdentity $_
})
Assert-Condition (
    @($operationIdentities.operation_key | Sort-Object -Unique).Count -eq
        $evidence.operations.Count
) 'Composite operation identity collided.'
Assert-Condition (
    @($evidence.operations | Group-Object operation_id |
        Where-Object Count -gt 1).Count -gt 0
) 'Composite identity fixture does not reuse a numeric operation ID.'
$allAggregateSourceKeys = @(
    $behavior1.aggregates.source_operation_identities.operation_key +
    $outcome1.aggregates.source_operation_identities.operation_key)
Assert-Condition (
    @($allAggregateSourceKeys | Where-Object {
        $operationIdentities.operation_key -cnotcontains $_
    }).Count -eq 0
) 'An aggregate source did not resolve a composite operation identity.'
Assert-Condition (
    @($operationIdentities.operation_key | Where-Object {
        $allAggregateSourceKeys -cnotcontains $_
    }).Count -eq 0
) 'An operation was omitted from both aggregate kinds.'
foreach ($aggregate in @($behavior1.aggregates + $outcome1.aggregates)) {
    Assert-Condition (
        @($aggregate.source_operation_identities.operation_key |
            Sort-Object -Unique).Count -eq
            [int]$aggregate.operation_count
    ) 'An aggregate double-counted or substituted a source operation.'
}

$mappingCases = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'valid\outcome-mapping-cases.json')
Assert-Condition (Test-AdaptiveRuntimeDocumentHash $mappingCases) (
    'Outcome mapping cases have a stale hash.')
$mappingOperation = Copy-JsonObject $evidence.operations[2]
foreach ($case in @($mappingCases.cases)) {
    $mappingOperation.result = [string]$case.result_kind
    $resolved = Resolve-AdaptiveRuntimeOperationOutcome $mappingOperation $catalog
    Assert-Condition (
        $resolved.status -eq 'matched' -and
        [string]$resolved.outcome_id -ceq
            [string]$case.expected_outcome_id -and
        [bool]$resolved.requires_retained_classification -eq
            [bool]$case.requires_retained_classification
    ) "Catalog mapping failed for '$($case.result_kind)'."
}
$changedCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'valid\catalog-mapping-changed.json')
$mappingOperation.result = 'inactive'
$changedResolution =
    Resolve-AdaptiveRuntimeOperationOutcome $mappingOperation $changedCatalog
Assert-Condition (
    [string]$changedResolution.outcome_id -ceq 'outcome.fallback'
) 'Changing only the catalog did not change outcome materialization.'
$changedOutcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
    $evidence $changedCatalog $classificationSet
Assert-Condition (
    [string]$changedOutcome.content_sha256 -cne
        [string]$outcome1.content_sha256
) 'Catalog mapping change did not change the outcome materialization hash.'
$ambiguousCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'invalid\catalog-outcome-ambiguous.json')
$ambiguousResolution =
    Resolve-AdaptiveRuntimeOperationOutcome $mappingOperation $ambiguousCatalog
Assert-Condition (
    $ambiguousResolution.error_code -eq 'outcome_derivation_ambiguous'
) 'Ambiguous catalog outcome mapping was not rejected.'
$retentionFalseCatalog = $catalog | ConvertTo-Json -Depth 100 -Compress |
    ConvertFrom-Json -Depth 100
$retentionFalseCatalog.outcome_definitions[0].requires_retained_classification =
    $false
[void](Set-AdaptiveRuntimeDocumentHash $retentionFalseCatalog)
Assert-SchemaInvalid $retentionFalseCatalog `
    'adaptive-runtime-effective-behavior-catalog-v2.schema.json' `
    'outcome definition without retained classification'

foreach ($property in @($expectations.evidence_invalid.PSObject.Properties)) {
    $invalidEvidence = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $fixtureRoot "invalid\$($property.Name)")
    $errors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
        $invalidEvidence $catalog $validation $classificationSet `
        $compatibilityCatalog $documents.artifact_inventory)
    Assert-Condition ($errors -contains [string]$property.Value) (
        "$($property.Name) did not emit '$($property.Value)': " +
        ($errors -join ', '))
}
foreach ($property in @($expectations.classification_invalid.PSObject.Properties)) {
    $invalidClassification = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $fixtureRoot "invalid\$($property.Name)")
    if ([string]$property.Value -eq 'projection_input_schema_invalid') {
        Assert-SchemaInvalid $invalidClassification `
            'adaptive-runtime-projection-immutable-input-v1.schema.json' `
            $property.Name
        continue
    }
    $errors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
        $evidence $catalog $validation $invalidClassification `
        $compatibilityCatalog $documents.artifact_inventory)
    Assert-Condition ($errors -contains [string]$property.Value) (
        "$($property.Name) did not emit '$($property.Value)': " +
        ($errors -join ', '))
}

$classificationKinds =
    @($compatibilityCatalog.classification_definitions.classification_kind |
        Sort-Object -CaseSensitive)
$compatiblePairs = @($compatibilityCatalog.compatible_pairs | ForEach-Object {
    "$($_.left_kind)|$($_.right_kind)"
})
$pairwiseCases = 0
for ($left = 0; $left -lt $classificationKinds.Count; $left++) {
    for ($right = $left + 1; $right -lt $classificationKinds.Count; $right++) {
        $pairwiseCases++
        $pairSet = $classificationSet | ConvertTo-Json -Depth 100 -Compress |
            ConvertFrom-Json -Depth 100
        $target = $pairSet.payload.classifications[0].target
        $targetKey = Get-AdaptiveRuntimeClassificationTargetKey $target
        $pairSet.payload.classifications = @(
            $pairSet.payload.classifications | Where-Object {
                (Get-AdaptiveRuntimeClassificationTargetKey $_.target) -cne
                    $targetKey
            })
        $pairSet.payload.classifications += @(
            [pscustomobject][ordered]@{
                classification_id = "classification.pair.$left"
                target = $target
                kind = $classificationKinds[$left]
                reason_code = 'reason.pairwise'
                retained = $true
            },
            [pscustomobject][ordered]@{
                classification_id = "classification.pair.$right"
                target = $target
                kind = $classificationKinds[$right]
                reason_code = 'reason.pairwise'
                retained = $true
            })
        [void](Set-AdaptiveRuntimeDocumentHash $pairSet)
        $errors = @(Get-AdaptiveRuntimeEvidenceV3Errors `
            $evidence $catalog $validation $pairSet $compatibilityCatalog `
            $documents.artifact_inventory)
        $pairKey =
            "$($classificationKinds[$left])|$($classificationKinds[$right])"
        $shouldBeCompatible = $compatiblePairs -ccontains $pairKey
        Assert-Condition (
            (($errors -contains 'classification_contradiction') -eq
                (-not $shouldBeCompatible))
        ) "Classification pair '$pairKey' did not follow the catalog matrix."
    }
}

$projectionScript = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1'
$projectionParameters = [ordered]@{
    PlanPath = Join-Path $inputRoot 'experiment_plan.json'
    PlanValidationPath = Join-Path $inputRoot 'plan_validation.json'
    CompiledManifestPath =
        Join-Path $inputRoot 'compiled_execution_manifest.json'
    ExperimentRunPath = Join-Path $inputRoot 'experiment_run.json'
    HostFingerprintPath = Join-Path $inputRoot 'host_fingerprint.json'
    BinaryCohortPath = Join-Path $inputRoot 'binary_cohort.json'
    WorkloadInstancePath = Join-Path $inputRoot 'workload_instance.json'
    RequestedWorkloadShapePath =
        Join-Path $inputRoot 'requested_workload_shape.json'
    EffectiveWorkloadShapePath =
        Join-Path $inputRoot 'effective_workload_shape.json'
    OperationEvidencePath = Join-Path $inputRoot 'operation_evidence.json'
    BehaviorMaterializationPath =
        Join-Path $inputRoot 'behavior_materialization.json'
    OutcomeMaterializationPath =
        Join-Path $inputRoot 'outcome_materialization.json'
    MetricObservationsPath =
        Join-Path $inputRoot 'metric_observations.json'
    ArtifactInventoryPath = Join-Path $inputRoot 'artifact_inventory.json'
    ClassificationsPath = Join-Path $inputRoot 'classifications.json'
    BehaviorCatalogPath =
        Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v2.json'
    ClassificationCompatibilityCatalogPath =
        Join-Path $catalogRoot `
            'adaptive-runtime-classification-compatibility-catalog-v1.json'
    SchemaRoot = $schemaRoot
    PassThru = $true
}
function Invoke-CloseoutProjection {
    param([hashtable] $Overrides)
    $parameters = @{}
    foreach ($entry in $projectionParameters.GetEnumerator()) {
        $parameters[$entry.Key] = $entry.Value
    }
    foreach ($entry in $Overrides.GetEnumerator()) {
        $parameters[$entry.Key] = $entry.Value
    }
    return & $projectionScript @parameters
}
$projection1 = Invoke-CloseoutProjection @{}
$projection2 = Invoke-CloseoutProjection @{}
$expectedProjection = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'valid\expected\projection.json')
Assert-Schema $projection1 `
    'adaptive-runtime-experiment-evidence-projection-v3.schema.json' `
    'projection v3'
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection1 `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection2 `
        -IncludeRootContentSha256)
) 'Repeated projections are not byte-identical.'
Assert-Condition (
    (ConvertTo-AdaptiveRuntimeCanonicalJson $projection1 `
        -IncludeRootContentSha256) -ceq
    (ConvertTo-AdaptiveRuntimeCanonicalJson $expectedProjection `
        -IncludeRootContentSha256)
) 'Projection does not match the checked-in expected output.'
Assert-Condition ($projection1.authority_chain.Count -eq 15) (
    'Projection authority chain does not contain all fifteen inputs.')
Assert-Condition (
    @($projection1.authority_chain.document_id | Sort-Object -Unique).Count -eq 15
) 'Projection authority chain contains duplicate input references.'

$projectionOverrideByName = @{
    'host-unrelated.json' = 'HostFingerprintPath'
    'binary-unrelated.json' = 'BinaryCohortPath'
    'workload-unrelated.json' = 'WorkloadInstancePath'
    'metrics-unrelated.json' = 'MetricObservationsPath'
    'behavior-recompute-mismatch.json' = 'BehaviorMaterializationPath'
    'outcome-recompute-mismatch.json' = 'OutcomeMaterializationPath'
    'artifact-inventory-incomplete.json' = 'ArtifactInventoryPath'
}
foreach ($property in @($expectations.projection_invalid.PSObject.Properties)) {
    $path = Join-Path $fixtureRoot "invalid\projection\$($property.Name)"
    $parameterName = $projectionOverrideByName[$property.Name]
    Assert-ThrowsCode {
        $override = @{}
        $override[$parameterName] = $path
        [void](Invoke-CloseoutProjection $override)
    } ([string]$property.Value) $property.Name
}
Assert-ThrowsCode {
    [void](Invoke-CloseoutProjection @{
        ClassificationsPath =
            Join-Path $fixtureRoot 'invalid\classification-wrong-run.json'
    })
} 'projection_classification_evidence_mismatch' `
    'self-hashed unrelated classifications'

$completeReleaseIdentity = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'valid\release-complete-identity-reuse.json')
$completeReleaseClassifications = Copy-JsonObject $classificationSet
$completeReleaseClassifications.payload.evidence_ref =
    New-AdaptiveRuntimeDocumentRef $completeReleaseIdentity
[void](Set-AdaptiveRuntimeDocumentHash $completeReleaseClassifications)
$completeReleaseErrors = @(
    Get-AdaptiveRuntimeEvidenceV3Errors `
        -Evidence $completeReleaseIdentity `
        -Catalog $catalog `
        -PlanValidation $validation `
        -ClassificationSet $completeReleaseClassifications `
        -CompatibilityCatalog $compatibilityCatalog `
        -ArtifactInventory $documents.artifact_inventory
)
Assert-Condition ($completeReleaseErrors.Count -eq 0) (
    "Complete release identity reuse fixture failed: $($completeReleaseErrors -join ',').")
$reusedOperationIds = @(
    $completeReleaseIdentity.operations |
        Where-Object {
            $_.axis_id -eq 'buffer_copy_coalescing' -and
            [long]$_.operation_id -eq 1
        }
)
Assert-Condition ($reusedOperationIds.Count -eq 2) (
    'Complete release identity fixture did not reuse the numeric operation ID.')
Assert-Condition (
    @($reusedOperationIds.decision_instance_id | Sort-Object -Unique).Count -eq 2
) 'Complete release identity fixture did not use distinct decisions.'

[pscustomobject]@{
    schemas_validated = $schemaFiles.Count
    immutable_inputs_validated = $documents.Count
    outcome_mapping_cases = $mappingCases.cases.Count
    evidence_invalid =
        @($expectations.evidence_invalid.PSObject.Properties).Count
    classification_invalid =
        @($expectations.classification_invalid.PSObject.Properties).Count
    classification_pairwise_cases = $pairwiseCases
    projection_invalid =
        @($expectations.projection_invalid.PSObject.Properties).Count
    behavior_hash = $behavior1.content_sha256
    outcome_hash = $outcome1.content_sha256
    projection_hash = $projection1.content_sha256
    authority_chain_inputs = $projection1.authority_chain.Count
    complete_release_identity_reuse_cases = $reusedOperationIds.Count
    measurement_frozen = $true
    active_behavior_authorized = $false
} | ConvertTo-Json -Depth 10
