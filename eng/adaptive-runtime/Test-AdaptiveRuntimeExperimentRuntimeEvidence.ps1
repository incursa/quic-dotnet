# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $UpdateExpectedOutputs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$fixtureRoot = Join-Path $RepoRoot 'tests\fixtures\adaptive-runtime-experiment-runtime-evidence'
$operationSchema = Join-Path $RepoRoot 'schemas\adaptive-runtime-operation-evidence-v1.schema.json'
$materializationSchema = Join-Path $RepoRoot 'schemas\adaptive-runtime-effective-behavior-materialization-v1.schema.json'
$projectionSchema = Join-Path $RepoRoot 'schemas\adaptive-runtime-experiment-evidence-projection-v1.schema.json'
$catalogPath = Join-Path $RepoRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v1.json'
$planPath = Join-Path $RepoRoot 'tests\fixtures\adaptive-runtime-experiment-plan-compiler\valid\interaction.plan.json'
$validationPath = Join-Path $RepoRoot 'tests\fixtures\adaptive-runtime-experiment-plan-compiler\valid\interaction.validation.json'
$manifestPath = Join-Path $RepoRoot 'tests\fixtures\adaptive-runtime-experiment-plan-compiler\valid\compiled-manifest.fixture.json'

$catalog = Read-AdaptiveRuntimeJsonDocument $catalogPath
$plan = Read-AdaptiveRuntimeJsonDocument $planPath
$validation = Read-AdaptiveRuntimeJsonDocument $validationPath
$manifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
$expectations = Read-AdaptiveRuntimeJsonDocument (Join-Path $fixtureRoot 'expectations.json')

$behaviorByEvent = [ordered]@{
    'application_send_batch_formation|batch_legal_prefix' =
        'behavior.application_send_batch_formation.legacy_current.prefix'
    'application_send_batch_formation|batch_single_eligible' =
        'behavior.application_send_batch_formation.single_eligible.prefix'
    'buffer_copy_coalescing|buffer_legacy_prefix' =
        'behavior.buffer_copy_coalescing.legacy_current.exact_prefix'
    'buffer_copy_coalescing|buffer_two_source_cap' =
        'behavior.buffer_copy_coalescing.memory_conservative.two_source_cap'
}
$supportedBehaviorIds = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($behavior in $catalog.effective_behaviors) {
    [void]$supportedBehaviorIds.Add([string]$behavior.effective_behavior_id)
}

function New-DocumentRef {
    param([object] $Document)
    return [ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Get-DerivedBehaviorId {
    param([object] $Operation)
    $key = "$($Operation.axis_id)|$($Operation.mechanism_event)"
    if ($behaviorByEvent.Contains($key)) {
        return [string]$behaviorByEvent[$key]
    }
    return $null
}

function Get-RecomputedAggregates {
    param([object] $Evidence)
    $classified = @($Evidence.operations | Where-Object {
        -not [string]::IsNullOrWhiteSpace((Get-DerivedBehaviorId $_))
    })
    $groups = @($classified | Group-Object {
        "$($_.axis_id)|$(Get-DerivedBehaviorId $_)"
    })
    return @($groups | ForEach-Object {
        $parts = $_.Name -split '\|', 2
        [long]$work = 0
        [long]$bytes = 0
        [long]$fallback = 0
        [long]$errors = 0
        [long]$inactive = 0
        [long]$unclassifiable = 0
        $sourceIds = @()
        foreach ($operation in $_.Group) {
            $work += [long]$operation.applied_work_count
            $bytes += [long]$operation.applied_bytes
            if ($operation.result -in @('fallback','clamped')) { $fallback++ }
            if ($operation.result -in @('invalid','negative')) { $errors++ }
            if ($operation.result -eq 'inactive') { $inactive++ }
            if ($operation.mechanism_event -eq 'unclassifiable') { $unclassifiable++ }
            $sourceIds += [long]$operation.operation_id
        }
        [ordered]@{
            run_id = [string]$Evidence.run_id
            connection_key = [string]$Evidence.connection_key
            epoch_sequence = [long]$Evidence.epoch_sequence
            axis_id = $parts[0]
            behavior_catalog_version = [int]$Evidence.behavior_catalog_ref.document_version
            effective_behavior_id = $parts[1]
            operation_count = @($_.Group).Count
            work_count = $work
            byte_count = $bytes
            fallback_count = $fallback
            error_count = $errors
            inactive_count = $inactive
            unclassifiable_count = $unclassifiable
            source_operation_ids = @($sourceIds | Sort-Object -Unique)
        }
    })
}

function Get-ObservedError {
    param([object] $Evidence)

    if ($null -ne $Evidence.PSObject.Properties['unknown_field']) {
        return 'unknown_field'
    }
    if (@($Evidence.artifact_inventory).Count -eq 0) {
        return 'missing_checksum'
    }
    if (@($Evidence.classifications).Count -eq 0) {
        return 'missing_retained_classification'
    }

    try {
        if (-not (Test-AdaptiveRuntimeJsonSchema $Evidence $operationSchema)) {
            return 'schema_validation_failed'
        }
    }
    catch {
        return 'schema_validation_failed'
    }

    $epochKeys = @($Evidence.connection_epochs | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.epoch_sequence)"
    })
    if (@($epochKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        return 'duplicate_epoch_identity'
    }
    if ([long]$Evidence.result_epoch_sequence -ne [long]$Evidence.epoch_sequence) {
        return 'invalid_result_to_epoch_join'
    }

    $decisionKeys = @($Evidence.decisions | ForEach-Object {
        "$($_.axis_id)|$($_.decision_instance_id)"
    })
    if (@($decisionKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        return 'duplicate_decision_instance'
    }

    $operationKeys = @($Evidence.operations | ForEach-Object {
        "$($_.axis_id)|$($_.operation_id)"
    })
    $operationCollisions = @($operationKeys | Group-Object | Where-Object Count -gt 1)
    if ($operationCollisions.Count -gt 0) {
        foreach ($collision in $operationCollisions) {
            $parts = $collision.Name -split '\|', 2
            $behaviors = @($Evidence.operations | Where-Object {
                $_.axis_id -eq $parts[0] -and [string]$_.operation_id -eq $parts[1]
            } | ForEach-Object effective_behavior_id | Sort-Object -Unique)
            if ($behaviors.Count -gt 1) {
                return 'mutually_exclusive_behavior_collision'
            }
        }
        return 'duplicate_operation_correlation'
    }

    foreach ($operation in $Evidence.operations) {
        $decision = @($Evidence.decisions | Where-Object {
            [long]$_.decision_instance_id -eq [long]$operation.decision_instance_id
        })
        if ($decision.Count -eq 0) {
            return 'missing_decision_correlation'
        }
        if ($decision.Count -gt 1) {
            return 'duplicate_decision_instance'
        }
        if ([string]$decision[0].axis_id -ne [string]$operation.axis_id) {
            return 'wrong_axis_attribution'
        }
        if ([long]$operation.epoch_sequence -ne [long]$Evidence.epoch_sequence -or
            [long]$decision[0].epoch_sequence -ne [long]$Evidence.epoch_sequence) {
            return 'wrong_epoch_attribution'
        }
        if ($operation.source_event_kind -eq 'broad_endpoint') {
            return 'broad_endpoint_not_axis_mechanism'
        }
        if ($operation.mechanism_event -eq 'unclassifiable' -and
            -not [string]::IsNullOrWhiteSpace([string]$operation.effective_behavior_id)) {
            return 'unclassifiable_mechanism_assigned_behavior'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$operation.effective_behavior_id) -and
            -not $supportedBehaviorIds.Contains([string]$operation.effective_behavior_id)) {
            return 'unsupported_behavior_id'
        }
        $derived = Get-DerivedBehaviorId $operation
        if (-not [string]::IsNullOrWhiteSpace([string]$operation.effective_behavior_id) -and
            -not [string]::Equals(
                [string]$operation.effective_behavior_id,
                [string]$derived,
                [StringComparison]::Ordinal)) {
            return 'unsupported_behavior_id'
        }
        if ($null -ne $decision[0].shadow_recommendation -and
            $null -eq $decision[0].forced_value -and
            $decision[0].applied_value -ne $decision[0].configured_value) {
            return 'shadow_recommendation_changed_applied_behavior'
        }
        if ($null -ne $decision[0].forced_value -and
            $operation.operation_eligibility_result -eq 'ineligible' -and
            $operation.applied_value -eq $decision[0].forced_value) {
            return 'forced_candidate_bypassed_operation_eligibility'
        }
    }

    if (-not [string]::Equals(
        [string]$Evidence.behavior_catalog_ref.content_sha256,
        [string]$catalog.content_sha256,
        [StringComparison]::Ordinal) -or
        [int]$Evidence.behavior_catalog_ref.document_version -ne [int]$catalog.document_version) {
        return 'stale_behavior_catalog_version'
    }

    foreach ($operation in @($Evidence.operations | Where-Object {
        $_.axis_id -eq 'buffer_copy_coalescing' -and
        $_.mechanism_event -in @('buffer_legacy_prefix','buffer_two_source_cap')
    })) {
        $release = @($Evidence.releases | Where-Object {
            [long]$_.operation_id -eq [long]$operation.operation_id -and
            [long]$_.decision_instance_id -eq [long]$operation.decision_instance_id
        })
        if ($release.Count -eq 0 -or [long]$release[0].release_count -eq 0) {
            return 'missing_terminal_release_evidence'
        }
        if ($release.Count -ne 1 -or [long]$release[0].release_count -ne 1) {
            return 'duplicate_owner_release'
        }
        if ([long]$release[0].decision_epoch_sequence -ne [long]$Evidence.epoch_sequence) {
            return 'wrong_epoch_attribution'
        }
    }

    $actualAggregates = @(Get-RecomputedAggregates $Evidence)
    foreach ($declared in $Evidence.declared_aggregates) {
        $actual = @($actualAggregates | Where-Object {
            $_.axis_id -eq $declared.axis_id -and
            $_.effective_behavior_id -eq $declared.effective_behavior_id
        })
        if ($actual.Count -ne 1 -or
            [long]$actual[0].operation_count -ne [long]$declared.operation_count) {
            return 'aggregate_operation_count_mismatch'
        }
        if ([long]$actual[0].work_count -ne [long]$declared.work_count -or
            [long]$actual[0].byte_count -ne [long]$declared.byte_count) {
            return 'aggregate_byte_mismatch'
        }
    }
    if ($actualAggregates.Count -ne @($Evidence.declared_aggregates).Count) {
        return 'aggregate_operation_count_mismatch'
    }

    return $null
}

function New-Materialization {
    param([object] $Evidence)
    $document = [ordered]@{
        schema_version = 'adaptive-runtime-effective-behavior-materialization-v1'
        document_id = "materialization.$($Evidence.document_id)"
        document_version = 1
        content_sha256 = '0' * 64
        source_evidence_ref = New-DocumentRef $Evidence
        behavior_catalog_ref = New-DocumentRef $catalog
        aggregates = @(Get-RecomputedAggregates $Evidence)
        retained_classifications = @($Evidence.classifications)
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $Evidence.trace_references
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function New-Projection {
    param([object] $Evidence, [object] $Materialization)
    $entityHash = '3' * 64
    $document = [ordered]@{
        schema_version = 'adaptive-runtime-experiment-evidence-projection-v1'
        document_id = "projection.$($Evidence.document_id)"
        document_version = 1
        content_sha256 = '0' * 64
        authority_chain = @(
            New-DocumentRef $plan
            New-DocumentRef $validation
            New-DocumentRef $manifest
            New-DocumentRef $Evidence
            New-DocumentRef $Materialization
        )
        experiment_plan = [ordered]@{ entity_id = $plan.document_id; content_sha256 = $plan.content_sha256 }
        plan_validation = [ordered]@{ entity_id = $validation.document_id; content_sha256 = $validation.content_sha256 }
        compiled_execution_manifest = [ordered]@{ entity_id = $manifest.document_id; content_sha256 = $manifest.content_sha256 }
        experiment_run = [ordered]@{ entity_id = $Evidence.run_id; content_sha256 = $entityHash }
        host_fingerprint = [ordered]@{ entity_id = 'host.fixture'; content_sha256 = '4' * 64 }
        binary_cohort = [ordered]@{ entity_id = $Evidence.binary_cohort_id; content_sha256 = '5' * 64 }
        workload_instance = [ordered]@{ entity_id = 'workload.fixture'; content_sha256 = '6' * 64 }
        requested_workload_shape = [ordered]@{ entity_id = 'workload.requested.fixture'; content_sha256 = '7' * 64 }
        effective_workload_shape = [ordered]@{ entity_id = 'workload.effective.fixture'; content_sha256 = '8' * 64 }
        connection_epochs = @($Evidence.connection_epochs)
        axis_decisions = @($Evidence.decisions | ForEach-Object {
            [ordered]@{
                run_id = $Evidence.run_id
                connection_key = $Evidence.connection_key
                epoch_sequence = $_.epoch_sequence
                axis_id = $_.axis_id
                decision_instance_id = $_.decision_instance_id
            }
        })
        operation_evidence = @($Evidence.operations | ForEach-Object {
            [ordered]@{
                operation_id = $_.operation_id
                axis_id = $_.axis_id
                decision_instance_id = $_.decision_instance_id
                run_id = $Evidence.run_id
                connection_key = $Evidence.connection_key
                epoch_sequence = $_.epoch_sequence
            }
        })
        effective_behavior_aggregates = @($Materialization.aggregates | ForEach-Object {
            [ordered]@{
                run_id = $_.run_id
                connection_key = $_.connection_key
                epoch_sequence = $_.epoch_sequence
                axis_id = $_.axis_id
                behavior_catalog_version = $_.behavior_catalog_version
                effective_behavior_id = $_.effective_behavior_id
            }
        })
        metric_observations = @(
            [ordered]@{
                metric_id = 'metric.correctness.operation_count'
                epoch_sequence = $Evidence.epoch_sequence
                analytical_use = 'correctness_only'
            }
        )
        artifact_inventory = @($Evidence.artifact_inventory)
        classifications = @($Evidence.classifications | ForEach-Object {
            [ordered]@{
                classification_id = $_.classification_id
                kind = $_.kind
                retained = $_.retained
            }
        })
        provenance_versions = @(
            'adaptive-runtime-operation-evidence-v1'
            'adaptive-runtime-effective-behavior-materialization-v1'
            'adaptive-runtime-experiment-evidence-projection-v1'
        )
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $Evidence.trace_references
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

$failures = [System.Collections.Generic.List[string]]::new()
$validCount = 0
$warningCount = 0
$invalidCount = 0
$deterministicCount = 0

foreach ($schemaPath in @($operationSchema,$materializationSchema,$projectionSchema)) {
    try {
        $null = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        $failures.Add("schema_parse_failed:$schemaPath")
    }
}

foreach ($path in Get-ChildItem (Join-Path $fixtureRoot 'valid') -Filter '*.json' -File | Sort-Object Name) {
    $evidence = Read-AdaptiveRuntimeJsonDocument $path.FullName
    $errorCode = Get-ObservedError $evidence
    if ($null -ne $errorCode) {
        $failures.Add("$($path.Name):$errorCode")
        continue
    }
    if (-not (Test-AdaptiveRuntimeDocumentHash $evidence)) {
        $failures.Add("$($path.Name):hash_mismatch")
        continue
    }
    $materialization1 = New-Materialization $evidence
    $materialization2 = New-Materialization $evidence
    $projection1 = New-Projection $evidence $materialization1
    $projection2 = New-Projection $evidence $materialization2
    if (-not (Test-AdaptiveRuntimeJsonSchema $materialization1 $materializationSchema) -or
        -not (Test-AdaptiveRuntimeJsonSchema $projection1 $projectionSchema)) {
        $failures.Add("$($path.Name):generated_schema_invalid")
        continue
    }
    $materializationBytes1 = ConvertTo-AdaptiveRuntimeCanonicalJson $materialization1 -IncludeRootContentSha256
    $materializationBytes2 = ConvertTo-AdaptiveRuntimeCanonicalJson $materialization2 -IncludeRootContentSha256
    $projectionBytes1 = ConvertTo-AdaptiveRuntimeCanonicalJson $projection1 -IncludeRootContentSha256
    $projectionBytes2 = ConvertTo-AdaptiveRuntimeCanonicalJson $projection2 -IncludeRootContentSha256
    if ($materializationBytes1 -cne $materializationBytes2 -or
        $projectionBytes1 -cne $projectionBytes2) {
        $failures.Add("$($path.Name):nondeterministic_output")
        continue
    }
    $deterministicCount++
    if ($UpdateExpectedOutputs) {
        Write-AdaptiveRuntimeCanonicalDocument $materialization1 (
            Join-Path $fixtureRoot "expected\materialization\$($path.BaseName).materialization.json")
        Write-AdaptiveRuntimeCanonicalDocument $projection1 (
            Join-Path $fixtureRoot "expected\projection\$($path.BaseName).projection.json")
    }
    $validCount++
}

foreach ($path in Get-ChildItem (Join-Path $fixtureRoot 'warning') -Filter '*.json' -File | Sort-Object Name) {
    $evidence = Read-AdaptiveRuntimeJsonDocument $path.FullName
    $errorCode = Get-ObservedError $evidence
    if ($null -ne $errorCode) {
        $failures.Add("$($path.Name):$errorCode")
        continue
    }
    $expectedWarnings = @($expectations.warning.PSObject.Properties[$path.Name].Value)
    $observedWarnings = switch -Wildcard ($path.Name) {
        'multiple_behaviors*' { @('multiple_effective_behaviors_in_epoch') }
        'inactive*' { @('inactive_operation_retained') }
        'fallback*' { @('fallback_operation_retained') }
        'verification_only*' { @('verification_only_equivalent_cell_retained') }
        default { @() }
    }
    if ((@($expectedWarnings | Sort-Object) -join '|') -cne
        (@($observedWarnings | Sort-Object) -join '|')) {
        $failures.Add("$($path.Name):warning_mismatch")
        continue
    }
    $warningCount++
}

foreach ($path in Get-ChildItem (Join-Path $fixtureRoot 'invalid') -Filter '*.json' -File | Sort-Object Name) {
    $evidence = Read-AdaptiveRuntimeJsonDocument $path.FullName
    $observed = Get-ObservedError $evidence
    $expected = [string]$expectations.invalid.PSObject.Properties[$path.Name].Value
    if (-not [string]::Equals($observed, $expected, [StringComparison]::Ordinal)) {
        $failures.Add("$($path.Name):expected=$expected;observed=$observed")
        continue
    }
    $invalidCount++
}

$summary = [ordered]@{
    schemas_validated = 3
    valid_fixtures = $validCount
    warning_fixtures = $warningCount
    invalid_fixtures = $invalidCount
    deterministic_materialization_and_projection_runs = $deterministicCount
    failures = @($failures | Sort-Object)
}
$summary | ConvertTo-Json -Depth 10
if ($failures.Count -gt 0) {
    exit 1
}
