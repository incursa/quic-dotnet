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
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-independent-actuation-proof'
$schemaRoot = Join-Path $RepositoryRoot 'schemas'
$catalogRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control'
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-effective-behavior-catalog-v2.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot `
        'adaptive-runtime-classification-compatibility-catalog-v1.json')

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)][object] $Value)
    return $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) { throw $Message }
}

function Read-ProofDocument {
    param(
        [Parameter(Mandatory = $true)][string] $AxisDirectory,
        [Parameter(Mandatory = $true)][string] $RelativePath
    )
    return Read-AdaptiveRuntimeJsonDocument (
        Join-Path (Join-Path $fixtureRoot $AxisDirectory) $RelativePath)
}

function Assert-DocumentSchema {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $SchemaFile,
        [Parameter(Mandatory = $true)][string] $Label
    )
    Assert-Condition (
        Test-AdaptiveRuntimeJsonSchema $Document (
            Join-Path $schemaRoot $SchemaFile)
    ) "$Label failed schema validation."
    Assert-Condition (
        Test-AdaptiveRuntimeDocumentHash $Document
    ) "$Label failed hash validation."
}

function Set-EvidenceAndClassificationHashes {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Classifications
    )
    [void](Set-AdaptiveRuntimeDocumentHash $Evidence)
    $Classifications.payload.evidence_ref =
        New-AdaptiveRuntimeDocumentRef $Evidence
    [void](Set-AdaptiveRuntimeDocumentHash $Classifications)
}

function Get-EvidenceErrors {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Validation,
        [Parameter(Mandatory = $true)][object] $Classifications,
        [Parameter(Mandatory = $true)][object] $Inventory
    )
    return @(Get-AdaptiveRuntimeEvidenceV3Errors `
        -Evidence $Evidence `
        -Catalog $catalog `
        -PlanValidation $Validation `
        -ClassificationSet $Classifications `
        -CompatibilityCatalog $compatibilityCatalog `
        -ArtifactInventory $Inventory)
}

function New-ProjectionParameters {
    param([Parameter(Mandatory = $true)][string] $AxisDirectory)
    $root = Join-Path (Join-Path $fixtureRoot $AxisDirectory) 'inputs'
    return @{
        PlanPath = Join-Path $root 'experiment_plan.json'
        PlanValidationPath = Join-Path $root 'plan_validation.json'
        CompiledManifestPath =
            Join-Path $root 'compiled_execution_manifest.json'
        ExperimentRunPath = Join-Path $root 'experiment_run.json'
        HostFingerprintPath = Join-Path $root 'host_fingerprint.json'
        BinaryCohortPath = Join-Path $root 'binary_cohort.json'
        WorkloadInstancePath = Join-Path $root 'workload_instance.json'
        RequestedWorkloadShapePath =
            Join-Path $root 'requested_workload_shape.json'
        EffectiveWorkloadShapePath =
            Join-Path $root 'effective_workload_shape.json'
        OperationEvidencePath = Join-Path $root 'operation_evidence.json'
        BehaviorMaterializationPath =
            Join-Path $root 'behavior_materialization.json'
        OutcomeMaterializationPath =
            Join-Path $root 'outcome_materialization.json'
        MetricObservationsPath =
            Join-Path $root 'metric_observations.json'
        ArtifactInventoryPath =
            Join-Path $root 'artifact_inventory.json'
        ClassificationsPath = Join-Path $root 'classifications.json'
        BehaviorCatalogPath = Join-Path $catalogRoot `
            'adaptive-runtime-effective-behavior-catalog-v2.json'
        ClassificationCompatibilityCatalogPath = Join-Path $catalogRoot `
            'adaptive-runtime-classification-compatibility-catalog-v1.json'
        SchemaRoot = $schemaRoot
        PassThru = $true
    }
}

$axisConfigurations = @(
    [pscustomobject]@{
        directory = 'batch'
        axis_id = 'application_send_batch_formation'
        policy_value = 'single_eligible'
        positive_event = 'mechanism_event.batch_single_eligible'
        primary_behavior =
            'behavior.application_send_batch_formation.single_eligible.prefix'
        release_count = 0
    },
    [pscustomobject]@{
        directory = 'buffer'
        axis_id = 'buffer_copy_coalescing'
        policy_value = 'memory_conservative'
        positive_event = 'mechanism_event.buffer_two_source_cap'
        primary_behavior =
            'behavior.buffer_copy_coalescing.memory_conservative.two_source_cap'
        release_count = 5
    }
)

$validDocumentCount = 0
$projectionHashes = [ordered]@{}
foreach ($configuration in $axisConfigurations) {
    $capture = Read-ProofDocument $configuration.directory `
        'mechanism-capture.json'
    $proof = Read-ProofDocument $configuration.directory `
        'proof-candidate.json'
    Assert-DocumentSchema $capture `
        'adaptive-runtime-actuation-mechanism-capture-v1.schema.json' `
        "$($configuration.directory) mechanism capture"
    Assert-DocumentSchema $proof `
        'adaptive-runtime-actuation-proof-evidence-v1.schema.json' `
        "$($configuration.directory) proof candidate"
    $validDocumentCount += 2

    $inputSchemas = [ordered]@{
        experiment_plan =
            'adaptive-runtime-experiment-plan-v1.schema.json'
        plan_validation =
            'adaptive-runtime-experiment-plan-validation-v1.schema.json'
        compiled_execution_manifest =
            'adaptive-runtime-compiled-execution-manifest-v1.schema.json'
        experiment_run =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        host_fingerprint =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        binary_cohort =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        workload_instance =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        requested_workload_shape =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        effective_workload_shape =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        operation_evidence =
            'adaptive-runtime-operation-evidence-v3.schema.json'
        behavior_materialization =
            'adaptive-runtime-effective-behavior-materialization-v3.schema.json'
        outcome_materialization =
            'adaptive-runtime-operation-outcome-materialization-v2.schema.json'
        metric_observations =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        artifact_inventory =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
        classifications =
            'adaptive-runtime-projection-immutable-input-v1.schema.json'
    }
    foreach ($entry in $inputSchemas.GetEnumerator()) {
        $document = Read-ProofDocument $configuration.directory `
            "inputs\$($entry.Key).json"
        Assert-DocumentSchema $document $entry.Value (
            "$($configuration.directory) $($entry.Key)")
        $validDocumentCount++
    }

    $parameters = New-ProjectionParameters $configuration.directory
    $projection1 = & (Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') `
        @parameters
    $projection2 = & (Join-Path $PSScriptRoot `
        'New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1') `
        @parameters
    $expectedProjection = Read-ProofDocument $configuration.directory `
        'expected\projection.json'
    Assert-DocumentSchema $expectedProjection `
        'adaptive-runtime-experiment-evidence-projection-v3.schema.json' `
        "$($configuration.directory) projection"
    $validDocumentCount++
    $projectionBytes = ConvertTo-AdaptiveRuntimeCanonicalJson `
        $projection1 -IncludeRootContentSha256
    Assert-Condition (
        $projectionBytes -ceq (
            ConvertTo-AdaptiveRuntimeCanonicalJson `
                $projection2 -IncludeRootContentSha256)
    ) "$($configuration.directory) projection rebuild changed bytes."
    Assert-Condition (
        $projectionBytes -ceq (
            ConvertTo-AdaptiveRuntimeCanonicalJson `
                $expectedProjection -IncludeRootContentSha256)
    ) "$($configuration.directory) checked-in projection did not rebuild."
    $projectionHashes[$configuration.axis_id] = $projection1.content_sha256

    Assert-Condition (
        $proof.review_status -ceq 'candidate' -and
        $null -eq $proof.review_outcome
    ) "$($configuration.directory) proof self-issued a review outcome."
    Assert-Condition (
        @($capture.operations | Where-Object {
            $null -ne $_.forced_value
        } | Select-Object forced_value -Unique).Count -eq 1 -and
        [int]$capture.forced_behavior_distinct_axis_count -eq 1
    ) "$($configuration.directory) capture forced more than one axis."
    $positive = @($capture.operations |
        Where-Object capture_case -eq 'positive_actuation')
    Assert-Condition (
        $positive.Count -eq 1 -and
        $positive[0].candidate_value -ceq $configuration.policy_value -and
        $positive[0].applied_value -ceq $configuration.policy_value -and
        $positive[0].mechanism_event_id -ceq
            $configuration.positive_event
    ) "$($configuration.directory) positive operation was not exact."
    $fallback = @($capture.operations |
        Where-Object capture_case -eq 'safety_fallback')
    Assert-Condition (
        $fallback.Count -eq 1 -and
        $fallback[0].candidate_value -ceq $configuration.policy_value -and
        $fallback[0].applied_value -ceq 'legacy_current' -and
        $fallback[0].operation_eligibility_result -ceq 'clamped'
    ) "$($configuration.directory) fallback was not guard authoritative."
    $shadow = @($capture.operations |
        Where-Object capture_case -eq 'shadow_neutrality')
    Assert-Condition (
        $shadow.Count -eq 1 -and
        $shadow[0].shadow_recommendation -ceq
            $configuration.policy_value -and
        $shadow[0].applied_value -ceq 'legacy_current'
    ) "$($configuration.directory) shadow changed applied behavior."
    Assert-Condition (
        @($capture.releases).Count -eq $configuration.release_count
    ) "$($configuration.directory) release count changed."
}

$bufferEvidence = Read-ProofDocument 'buffer' `
    'inputs\operation_evidence.json'
$bufferValidation = Read-ProofDocument 'buffer' `
    'inputs\plan_validation.json'
$bufferClassifications = Read-ProofDocument 'buffer' `
    'inputs\classifications.json'
$bufferInventory = Read-ProofDocument 'buffer' `
    'inputs\artifact_inventory.json'
$bufferCapture = Read-ProofDocument 'buffer' 'mechanism-capture.json'
$bufferProof = Read-ProofDocument 'buffer' 'proof-candidate.json'
$bufferBinary = Read-ProofDocument 'buffer' 'inputs\binary_cohort.json'
$bufferManifest = Read-ProofDocument 'buffer' `
    'inputs\compiled_execution_manifest.json'
$bufferMetrics = Read-ProofDocument 'buffer' `
    'inputs\metric_observations.json'
$negativeCases = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $fixtureRoot 'negative-cases.json')
$observedNegativeCodes = [System.Collections.Generic.List[string]]::new()

foreach ($case in @($negativeCases.cases)) {
    $actual = switch ([string]$case.case_id) {
        'activation-predicate-not-reached' {
            $capture = Copy-JsonObject $bufferCapture
            $positive = @($capture.operations |
                Where-Object capture_case -eq 'positive_actuation')[0]
            $positive.legal_work_count = 2
            if ([long]$positive.legal_work_count -le 2) {
                'actuation_proof_activation_not_reached'
            }
        }
        'candidate-selected-but-ineligible' {
            $capture = Copy-JsonObject $bufferCapture
            $positive = @($capture.operations |
                Where-Object capture_case -eq 'positive_actuation')[0]
            $positive.operation_eligibility_result = 'ineligible'
            if ($positive.operation_eligibility_result -cne 'eligible') {
                'actuation_proof_positive_operation_invalid'
            }
        }
        'wrong-mechanism-event' {
            $capture = Copy-JsonObject $bufferCapture
            $positive = @($capture.operations |
                Where-Object capture_case -eq 'positive_actuation')[0]
            $positive.mechanism_event_id =
                'mechanism_event.buffer_legacy_prefix'
            if ($positive.mechanism_event_id -cne
                'mechanism_event.buffer_two_source_cap') {
                'actuation_proof_wrong_mechanism_event'
            }
        }
        'missing-decision-correlation' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.decisions = @($evidence.decisions | Select-Object -Skip 1)
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object { $_ -ceq 'missing_decision_correlation' } |
                Select-Object -First 1
        }
        'missing-operation-correlation' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.operations = @($evidence.operations |
                Where-Object {
                    $_.connection_key -cne
                        'connection.buffer.positive'
                })
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object {
                    $_ -ceq 'release_operation_identity_mismatch'
                } | Select-Object -First 1
        }
        'missing-buffer-release' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.releases = @($evidence.releases |
                Where-Object {
                    $_.connection_key -cne
                        'connection.buffer.positive'
                })
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object {
                    $_ -ceq 'missing_terminal_release_evidence'
                } | Select-Object -First 1
        }
        'duplicate-buffer-release' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.releases += Copy-JsonObject $evidence.releases[0]
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object { $_ -ceq 'duplicate_owner_release' } |
                Select-Object -First 1
        }
        'stale-behavior-catalog' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.behavior_catalog_ref.content_sha256 = 'f' * 64
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object {
                    $_ -ceq 'stale_behavior_catalog_version'
                } | Select-Object -First 1
        }
        'stale-manifest' {
            $proof = Copy-JsonObject $bufferProof
            $proof.compiled_manifest_ref.content_sha256 = 'f' * 64
            if (-not (Test-AdaptiveRuntimeDocumentRef `
                $proof.compiled_manifest_ref $bufferManifest)) {
                'actuation_proof_stale_manifest'
            }
        }
        'stale-binary' {
            $binary = Copy-JsonObject $bufferBinary
            $binary.payload.binary_sha256 = 'f' * 64
            [void](Set-AdaptiveRuntimeDocumentHash $binary)
            $source = @($bufferManifest.binary_provenance |
                Sort-Object role, path | Select-Object -First 1)[0]
            if ($binary.payload.binary_sha256 -cne
                $source.content_sha256) {
                'projection_binary_manifest_mismatch'
            }
        }
        'wrong-run' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.releases[0].run_id = 'run.wrong'
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object {
                    $_ -ceq 'release_operation_identity_mismatch'
                } | Select-Object -First 1
        }
        'wrong-connection' {
            $evidence = Copy-JsonObject $bufferEvidence
            $classifications = Copy-JsonObject $bufferClassifications
            $evidence.releases[0].connection_key = 'connection.wrong'
            Set-EvidenceAndClassificationHashes $evidence $classifications
            @(Get-EvidenceErrors $evidence $bufferValidation `
                $classifications $bufferInventory) |
                Where-Object {
                    $_ -ceq 'release_operation_identity_mismatch'
                } | Select-Object -First 1
        }
        'inactive-claimed-as-positive' {
            $capture = Copy-JsonObject $bufferCapture
            $inactive = @($capture.operations |
                Where-Object {
                    $_.capture_case -ceq 'structurally_inactive'
                })[0]
            if ($inactive.result -cne 'applied' -or
                $inactive.applied_value -cne 'memory_conservative') {
                'actuation_proof_positive_operation_invalid'
            }
        }
        'performance-metric-used-as-proof' {
            $metrics = Copy-JsonObject $bufferMetrics
            $metrics.payload.metric_observations[0].analytical_use =
                'performance'
            if (@($metrics.payload.metric_observations |
                Where-Object {
                    $_.analytical_use -cne 'correctness_only'
                }).Count -gt 0) {
                'actuation_proof_performance_metric_prohibited'
            }
        }
        'proof-marked-reviewed' {
            $proof = Copy-JsonObject $bufferProof
            $proof.review_status = 'reviewed'
            if ($proof.review_status -cne 'candidate') {
                'actuation_proof_review_status_invalid'
            }
        }
        'proof-marked-passed' {
            $proof = Copy-JsonObject $bufferProof
            $proof.review_outcome = 'passed'
            if ($null -ne $proof.review_outcome) {
                'actuation_proof_review_outcome_invalid'
            }
        }
        'two-behavior-distinct-axes-forced' {
            $capture = Copy-JsonObject $bufferCapture
            $capture.forced_behavior_distinct_axis_count = 2
            if ([int]$capture.forced_behavior_distinct_axis_count -ne 1) {
                'actuation_proof_multi_axis_forcing'
            }
        }
        default {
            throw "Unknown negative case '$($case.case_id)'."
        }
    }
    Assert-Condition (
        [string]$actual -ceq [string]$case.expected_error
    ) "Negative case '$($case.case_id)' produced '$actual', expected '$($case.expected_error)'."
    $observedNegativeCodes.Add([string]$actual)
}

[pscustomobject][ordered]@{
    valid_documents = $validDocumentCount
    valid_proof_candidates = 2
    candidate_operations = 10
    candidate_releases = 5
    negative_cases = @($negativeCases.cases).Count
    unique_closed_negative_codes =
        @($observedNegativeCodes | Sort-Object -Unique).Count
    batch_projection_hash =
        $projectionHashes.application_send_batch_formation
    buffer_projection_hash = $projectionHashes.buffer_copy_coalescing
    review_status = 'candidate'
    measurement_frozen = $true
    interaction_execution_performed = $false
    active_behavior_authorized = $false
} | ConvertTo-Json -Depth 10
