# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1')

function New-AdaptiveRuntimeDocumentRef {
    param([Parameter(Mandatory = $true)][object] $Document)

    return [ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Test-AdaptiveRuntimeDocumentRef {
    param(
        [Parameter(Mandatory = $true)][object] $Reference,
        [Parameter(Mandatory = $true)][object] $Document
    )

    return [string]$Reference.document_id -ceq [string]$Document.document_id -and
        [string]$Reference.schema_version -ceq [string]$Document.schema_version -and
        [int]$Reference.document_version -eq [int]$Document.document_version -and
        [string]$Reference.content_sha256 -ceq [string]$Document.content_sha256 -and
        (Test-AdaptiveRuntimeDocumentHash -Document $Document)
}

function Resolve-AdaptiveRuntimeEffectiveBehavior {
    param(
        [Parameter(Mandatory = $true)][object] $Operation,
        [Parameter(Mandatory = $true)][object] $Catalog
    )

    $matches = @($Catalog.effective_behaviors | Where-Object {
        [string]$_.axis_id -ceq [string]$Operation.axis_id -and
        @($_.mechanism_event_ids | ForEach-Object { [string]$_ }) -ccontains
            [string]$Operation.mechanism_event_id -and
        [string]$_.operation_scope.operation_kind -ceq
            [string]$Operation.operation_kind -and
        [int]$_.operation_scope.scope_version -eq [int]$Operation.scope_version
    } | Sort-Object effective_behavior_id)

    if ($matches.Count -eq 0) {
        return [pscustomobject][ordered]@{
            status = 'no_match'
            effective_behavior_ids = @()
            error_code = 'behavior_derivation_no_match'
        }
    }

    if ($matches.Count -gt 1 -and
        @($matches | Where-Object derivation_mode -ne 'composable').Count -gt 0) {
        return [pscustomobject][ordered]@{
            status = 'ambiguous'
            effective_behavior_ids = @($matches.effective_behavior_id)
            error_code = 'behavior_derivation_ambiguous'
        }
    }

    return [pscustomobject][ordered]@{
        status = 'matched'
        effective_behavior_ids = @($matches.effective_behavior_id)
        error_code = $null
    }
}

function Resolve-AdaptiveRuntimeOperationOutcome {
    param(
        [Parameter(Mandatory = $true)][object] $Operation,
        [Parameter(Mandatory = $true)][object] $Catalog
    )

    if ([string]$Operation.result -in @('applied','succeeded')) {
        return [pscustomobject][ordered]@{
            status = 'behavior_only'
            outcome_id = $null
            requires_retained_classification = $null
            error_code = $null
        }
    }

    $matches = @($Catalog.outcome_definitions | Where-Object {
        @($_.result_kinds | ForEach-Object { [string]$_ }) -ccontains
            [string]$Operation.result
    } | Sort-Object outcome_id)
    if ($matches.Count -eq 0) {
        return [pscustomobject][ordered]@{
            status = 'no_match'
            outcome_id = $null
            requires_retained_classification = $null
            error_code = 'outcome_derivation_no_match'
        }
    }
    if ($matches.Count -gt 1) {
        return [pscustomobject][ordered]@{
            status = 'ambiguous'
            outcome_id = $null
            requires_retained_classification = $null
            error_code = 'outcome_derivation_ambiguous'
        }
    }
    return [pscustomobject][ordered]@{
        status = 'matched'
        outcome_id = [string]$matches[0].outcome_id
        requires_retained_classification =
            [bool]$matches[0].requires_retained_classification
        error_code = $null
    }
}

function Get-AdaptiveRuntimeOperationOutcomeId {
    param(
        [Parameter(Mandatory = $true)][object] $Operation,
        [Parameter(Mandatory = $true)][object] $Catalog
    )

    $resolved = Resolve-AdaptiveRuntimeOperationOutcome $Operation $Catalog
    if ($resolved.status -eq 'matched') {
        return [string]$resolved.outcome_id
    }
    return $null
}

function New-AdaptiveRuntimeOperationIdentity {
    param([Parameter(Mandatory = $true)][object] $Operation)

    $components = [ordered]@{
        identity_version = 1
        run_id = [string]$Operation.run_id
        connection_key = [string]$Operation.connection_key
        epoch_sequence = [long]$Operation.epoch_sequence
        axis_id = [string]$Operation.axis_id
        decision_instance_id = [long]$Operation.decision_instance_id
        operation_id = [long]$Operation.operation_id
    }
    $hash = Get-AdaptiveRuntimeSha256 (
        ConvertTo-AdaptiveRuntimeCanonicalJson $components)
    return [pscustomobject][ordered]@{
        identity_version = 1
        operation_key = "operation_identity_v1:$hash"
        run_id = $components.run_id
        connection_key = $components.connection_key
        epoch_sequence = $components.epoch_sequence
        axis_id = $components.axis_id
        decision_instance_id = $components.decision_instance_id
        operation_id = $components.operation_id
    }
}

function Get-AdaptiveRuntimeClassificationTargetKey {
    param([Parameter(Mandatory = $true)][object] $Target)

    return ConvertTo-AdaptiveRuntimeCanonicalJson $Target
}

function Get-AdaptiveRuntimeClassificationDefinitionForOutcome {
    param(
        [Parameter(Mandatory = $true)][string] $OutcomeId,
        [Parameter(Mandatory = $true)][object] $CompatibilityCatalog
    )

    return @($CompatibilityCatalog.classification_definitions | Where-Object {
        [string]$_.role -ceq 'primary' -and
        @($_.outcome_ids | ForEach-Object { [string]$_ }) -ccontains $OutcomeId
    } | Sort-Object classification_kind)
}

function Get-AdaptiveRuntimeEvidenceV2Errors {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Catalog,
        [Parameter(Mandatory = $true)][object] $PlanValidation
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $add = {
        param([string]$Code)
        if (-not $errors.Contains($Code)) { $errors.Add($Code) }
    }

    if (-not (Test-AdaptiveRuntimeDocumentRef $Evidence.behavior_catalog_ref $Catalog)) {
        & $add 'stale_behavior_catalog_version'
    }
    if (-not (Test-AdaptiveRuntimeDocumentRef $Evidence.plan_validation_ref $PlanValidation)) {
        & $add 'stale_plan_validation_reference'
    }
    if ($Evidence.active_behavior_authorization -ne $false) {
        & $add 'active_behavior_unauthorized'
    }
    if ($Evidence.performance_acceptance_authorization -ne $false) {
        & $add 'performance_acceptance_unauthorized'
    }

    $epochKeys = @($Evidence.connection_epochs | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.epoch_sequence)"
    })
    if (@($epochKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'top_epoch_not_unique'
    }
    $topEpochKey =
        "$($Evidence.run_id)|$($Evidence.connection_key)|$($Evidence.epoch_sequence)"
    if (@($epochKeys | Where-Object { $_ -ceq $topEpochKey }).Count -ne 1) {
        & $add 'top_epoch_missing'
    }
    $resultEpochKey =
        "$($Evidence.run_id)|$($Evidence.connection_key)|$($Evidence.result_epoch_sequence)"
    if ($epochKeys -cnotcontains $resultEpochKey) {
        & $add 'result_epoch_missing'
    }

    $decisionKeys = @($Evidence.decisions | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.axis_id)|$($_.decision_instance_id)"
    })
    if (@($decisionKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'duplicate_decision_instance'
    }
    foreach ($decision in @($Evidence.decisions)) {
        $key = "$($decision.run_id)|$($decision.connection_key)|$($decision.epoch_sequence)"
        if ($epochKeys -cnotcontains $key) { & $add 'decision_epoch_missing' }
    }

    $operationKeys = @($Evidence.operations | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.axis_id)|$($_.operation_id)"
    })
    if (@($operationKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'duplicate_operation_correlation'
    }

    foreach ($operation in @($Evidence.operations)) {
        $operationEpochKey =
            "$($operation.run_id)|$($operation.connection_key)|$($operation.epoch_sequence)"
        if ($epochKeys -cnotcontains $operationEpochKey) {
            & $add 'operation_epoch_missing'
        }

        $identityMatches = @($Evidence.decisions | Where-Object {
            [string]$_.axis_id -ceq [string]$operation.axis_id -and
            [long]$_.decision_instance_id -eq [long]$operation.decision_instance_id
        })
        if ($identityMatches.Count -eq 0) {
            & $add 'missing_decision_correlation'
            continue
        }
        $runMatches = @($identityMatches | Where-Object {
            [string]$_.run_id -ceq [string]$operation.run_id
        })
        if ($runMatches.Count -eq 0) {
            & $add 'run_correlation_mismatch'
            continue
        }
        $connectionMatches = @($runMatches | Where-Object {
            [string]$_.connection_key -ceq [string]$operation.connection_key
        })
        if ($connectionMatches.Count -eq 0) {
            & $add 'connection_correlation_mismatch'
            continue
        }
        $decision = @($connectionMatches | Where-Object {
            [long]$_.epoch_sequence -eq [long]$operation.epoch_sequence
        })
        if ($decision.Count -ne 1) {
            & $add 'wrong_epoch_attribution'
            continue
        }
        $decision = $decision[0]
        foreach ($comparison in @(
            @('configured_value','configured_value_mismatch'),
            @('forced_value','forced_value_mismatch'),
            @('shadow_recommendation','shadow_recommendation_mismatch'),
            @('candidate_value','candidate_value_mismatch'),
            @('applied_value','applied_value_mismatch')
        )) {
            $name = $comparison[0]
            $decisionValue = Get-AdaptiveRuntimeJsonProperty $decision $name
            $operationValue = Get-AdaptiveRuntimeJsonProperty $operation $name
            if (-not [object]::Equals($decisionValue, $operationValue)) {
                & $add $comparison[1]
            }
        }

        $eligibility = [string]$operation.operation_eligibility_result
        $reason = [string]$operation.operation_eligibility_reason
        if (($eligibility -eq 'eligible' -and
                $reason -notin @('eligible','structurally_inactive')) -or
            ($eligibility -eq 'ineligible' -and $reason -eq 'eligible') -or
            ($eligibility -eq 'clamped' -and
                $reason -notin @('lifecycle_guard','resource_guard','safety_override'))) {
            & $add 'eligibility_reason_mismatch'
        }
        if ($null -ne $decision.shadow_recommendation -and
            $null -eq $decision.forced_value -and
            [string]$decision.applied_value -cne [string]$decision.configured_value) {
            & $add 'shadow_recommendation_changed_applied_behavior'
        }
        if ($null -ne $decision.forced_value -and
            $eligibility -eq 'ineligible' -and
            [string]$operation.applied_value -ceq [string]$decision.forced_value) {
            & $add 'forced_candidate_bypassed_operation_eligibility'
        }

        $derivation = Resolve-AdaptiveRuntimeEffectiveBehavior $operation $Catalog
        if ($derivation.status -eq 'no_match' -and
            [string]$operation.result -ne 'unclassifiable') {
            & $add 'behavior_derivation_no_match'
        }
        elseif ($derivation.status -eq 'ambiguous') {
            & $add 'behavior_derivation_ambiguous'
        }
    }

    $releaseKeys = @($Evidence.releases | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.axis_id)|$($_.operation_id)"
    })
    if (@($releaseKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'duplicate_owner_release'
    }
    foreach ($release in @($Evidence.releases)) {
        $operation = @($Evidence.operations | Where-Object {
            [long]$_.operation_id -eq [long]$release.operation_id -and
            [string]$_.axis_id -ceq [string]$release.axis_id
        })
        if ($operation.Count -ne 1) {
            & $add 'release_operation_missing'
            continue
        }
        $operation = $operation[0]
        if ([string]$release.run_id -cne [string]$operation.run_id) {
            & $add 'run_correlation_mismatch'
        }
        if ([string]$release.connection_key -cne [string]$operation.connection_key) {
            & $add 'connection_correlation_mismatch'
        }
        if ([long]$release.decision_instance_id -ne
            [long]$operation.decision_instance_id) {
            & $add 'release_decision_mismatch'
        }
        $releaseEpochKey =
            "$($release.run_id)|$($release.connection_key)|$($release.release_epoch_sequence)"
        if ($epochKeys -cnotcontains $releaseEpochKey) {
            & $add 'release_epoch_missing'
        }
        if ([long]$release.release_epoch_sequence -lt
            [long]$release.decision_epoch_sequence) {
            & $add 'release_precedes_decision'
        }
        if ([long]$release.release_count -ne 1) {
            & $add 'duplicate_owner_release'
        }
    }
    foreach ($operation in @($Evidence.operations | Where-Object {
        $_.axis_id -eq 'buffer_copy_coalescing' -and
        $_.mechanism_event_id -in @(
            'mechanism_event.buffer_legacy_prefix',
            'mechanism_event.buffer_two_source_cap')
    })) {
        if (@($Evidence.releases | Where-Object {
            [long]$_.operation_id -eq [long]$operation.operation_id -and
            [string]$_.run_id -ceq [string]$operation.run_id -and
            [string]$_.connection_key -ceq [string]$operation.connection_key
        }).Count -ne 1) {
            & $add 'missing_terminal_release_evidence'
        }
    }

    $classificationIds = @($Evidence.classifications.classification_id)
    if (@($classificationIds | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'classification_id_duplicate'
    }
    foreach ($classification in @($Evidence.classifications)) {
        $targetExists = switch ([string]$classification.target_kind) {
            'operation' {
                @($Evidence.operations | Where-Object {
                    [string]$_.operation_id -ceq [string]$classification.target_id
                }).Count -eq 1
            }
            'epoch' {
                @($Evidence.connection_epochs | Where-Object {
                    [string]$_.epoch_sequence -ceq [string]$classification.target_id
                }).Count -eq 1
            }
            'release' {
                @($Evidence.releases | Where-Object {
                    [string]$_.operation_id -ceq [string]$classification.target_id
                }).Count -eq 1
            }
            'artifact' {
                @($Evidence.artifact_inventory | Where-Object {
                    [string]$_.artifact_id -ceq [string]$classification.target_id
                }).Count -eq 1
            }
            default { $false }
        }
        if (-not $targetExists) { & $add 'classification_target_missing' }
    }
    foreach ($group in @($Evidence.classifications | Group-Object {
        "$($_.target_kind)|$($_.target_id)"
    })) {
        $kinds = @($group.Group.kind | Sort-Object -Unique)
        if ($kinds -contains 'analytically_eligible' -and
            @($kinds | Where-Object {
                $_ -in @('invalid','negative','unclassifiable','excluded')
            }).Count -gt 0) {
            & $add 'classification_contradiction'
        }
    }
    foreach ($operation in @($Evidence.operations)) {
        $outcome = Resolve-AdaptiveRuntimeOperationOutcome $operation $Catalog
        $requiredKind = if ($outcome.status -eq 'matched') {
            ([string]$outcome.outcome_id -split '\.', 2)[1]
        }
        else { $null }
        if ($outcome.requires_retained_classification -eq $true -and
            @($Evidence.classifications | Where-Object {
                $_.target_kind -eq 'operation' -and
                [string]$_.target_id -ceq [string]$operation.operation_id -and
                $_.kind -eq $requiredKind -and $_.retained -eq $true
            }).Count -ne 1) {
            & $add 'required_retained_classification_missing'
        }
    }

    return @($errors | Sort-Object)
}

function New-AdaptiveRuntimeBehaviorMaterializationV2 {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Catalog
    )

    $derivations = @($Evidence.operations | Sort-Object operation_id | ForEach-Object {
        $resolved = Resolve-AdaptiveRuntimeEffectiveBehavior $_ $Catalog
        [ordered]@{
            operation_id = [long]$_.operation_id
            axis_id = [string]$_.axis_id
            mechanism_event_id = [string]$_.mechanism_event_id
            derivation_status = [string]$resolved.status
            effective_behavior_ids = @($resolved.effective_behavior_ids)
            error_code = $resolved.error_code
        }
    })
    $matchedRows = @()
    foreach ($operation in @($Evidence.operations)) {
        $resolved = Resolve-AdaptiveRuntimeEffectiveBehavior $operation $Catalog
        if ($resolved.status -eq 'matched') {
            foreach ($behaviorId in @($resolved.effective_behavior_ids)) {
                $matchedRows += [pscustomobject]@{
                    operation = $operation
                    behavior_id = [string]$behaviorId
                }
            }
        }
    }
    $aggregates = @($matchedRows | Group-Object {
        "$($_.operation.run_id)|$($_.operation.connection_key)|$($_.operation.epoch_sequence)|$($_.operation.axis_id)|$($_.behavior_id)"
    } | Sort-Object Name | ForEach-Object {
        $parts = $_.Name -split '\|', 5
        [ordered]@{
            run_id = $parts[0]
            connection_key = $parts[1]
            epoch_sequence = [long]$parts[2]
            axis_id = $parts[3]
            behavior_catalog_version = 2
            effective_behavior_id = $parts[4]
            operation_count = @($_.Group).Count
            work_count = [long](($_.Group.operation.applied_work_count |
                Measure-Object -Sum).Sum)
            byte_count = [long](($_.Group.operation.applied_bytes |
                Measure-Object -Sum).Sum)
            source_operation_ids = @($_.Group.operation.operation_id |
                Sort-Object -Unique)
        }
    })
    $document = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-effective-behavior-materialization-v2'
        document_id = "materialization.behavior.$($Evidence.document_id)"
        document_version = 2
        content_sha256 = '0' * 64
        source_evidence_ref = New-AdaptiveRuntimeDocumentRef $Evidence
        behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $Catalog
        aggregates = $aggregates
        derivations = $derivations
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $Evidence.trace_references
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function New-AdaptiveRuntimeOutcomeMaterializationV1 {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Catalog
    )

    $rows = @($Evidence.operations | ForEach-Object {
        $resolved = Resolve-AdaptiveRuntimeOperationOutcome $_ $Catalog
        if ($resolved.status -in @('no_match','ambiguous')) {
            throw [string]$resolved.error_code
        }
        if ($resolved.status -eq 'matched') {
            [pscustomobject]@{
                operation = $_
                outcome_id = [string]$resolved.outcome_id
            }
        }
    })
    $aggregates = @($rows | Group-Object {
        "$($_.operation.run_id)|$($_.operation.connection_key)|$($_.operation.epoch_sequence)|$($_.operation.axis_id)|$($_.outcome_id)"
    } | Sort-Object Name | ForEach-Object {
        $parts = $_.Name -split '\|', 5
        [ordered]@{
            run_id = $parts[0]
            connection_key = $parts[1]
            epoch_sequence = [long]$parts[2]
            axis_id = $parts[3]
            outcome_contract_version = 1
            outcome_id = $parts[4]
            operation_count = @($_.Group).Count
            work_count = [long](($_.Group.operation.applied_work_count |
                Measure-Object -Sum).Sum)
            byte_count = [long](($_.Group.operation.applied_bytes |
                Measure-Object -Sum).Sum)
            source_operation_ids = @($_.Group.operation.operation_id |
                Sort-Object -Unique)
        }
    })
    $document = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-operation-outcome-materialization-v1'
        document_id = "materialization.outcome.$($Evidence.document_id)"
        document_version = 1
        content_sha256 = '0' * 64
        source_evidence_ref = New-AdaptiveRuntimeDocumentRef $Evidence
        behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $Catalog
        aggregates = $aggregates
        retained_classifications = @($Evidence.classifications)
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $Evidence.trace_references
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function Test-AdaptiveRuntimeExactOperationTarget {
    param(
        [Parameter(Mandatory = $true)][object] $Target,
        [Parameter(Mandatory = $true)][object] $Operation
    )

    return [string]$Target.target_kind -ceq 'operation' -and
        [string]$Target.run_id -ceq [string]$Operation.run_id -and
        [string]$Target.connection_key -ceq [string]$Operation.connection_key -and
        [long]$Target.epoch_sequence -eq [long]$Operation.epoch_sequence -and
        [string]$Target.axis_id -ceq [string]$Operation.axis_id -and
        [long]$Target.decision_instance_id -eq
            [long]$Operation.decision_instance_id -and
        [long]$Target.operation_id -eq [long]$Operation.operation_id
}

function Get-AdaptiveRuntimeClassificationTargetMatchCount {
    param(
        [Parameter(Mandatory = $true)][object] $Target,
        [Parameter(Mandatory = $true)][object] $Evidence,
        [object] $ArtifactInventory
    )

    switch ([string]$Target.target_kind) {
        'operation' {
            return @($Evidence.operations | Where-Object {
                Test-AdaptiveRuntimeExactOperationTarget $Target $_
            }).Count
        }
        'release' {
            return @($Evidence.releases | Where-Object {
                [string]$Target.run_id -ceq [string]$_.run_id -and
                [string]$Target.connection_key -ceq [string]$_.connection_key -and
                [long]$Target.epoch_sequence -eq
                    [long]$_.operation_epoch_sequence -and
                [string]$Target.axis_id -ceq [string]$_.axis_id -and
                [long]$Target.decision_instance_id -eq
                    [long]$_.decision_instance_id -and
                [long]$Target.operation_id -eq [long]$_.operation_id -and
                [long]$Target.release_epoch_sequence -eq
                    [long]$_.release_epoch_sequence
            }).Count
        }
        'epoch' {
            return @($Evidence.connection_epochs | Where-Object {
                [string]$Target.run_id -ceq [string]$_.run_id -and
                [string]$Target.connection_key -ceq [string]$_.connection_key -and
                [long]$Target.epoch_sequence -eq [long]$_.epoch_sequence
            }).Count
        }
        'artifact' {
            if ($null -eq $ArtifactInventory) { return 0 }
            return @($ArtifactInventory.payload.artifacts | Where-Object {
                [string]$_.document_ref.document_id -ceq
                    [string]$Target.artifact_id
            }).Count
        }
        default { return 0 }
    }
}

function Get-AdaptiveRuntimeEvidenceV3Errors {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Catalog,
        [Parameter(Mandatory = $true)][object] $PlanValidation,
        [Parameter(Mandatory = $true)][object] $ClassificationSet,
        [Parameter(Mandatory = $true)][object] $CompatibilityCatalog,
        [object] $ArtifactInventory
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $add = {
        param([string]$Code)
        if (-not $errors.Contains($Code)) { $errors.Add($Code) }
    }
    if (-not (Test-AdaptiveRuntimeDocumentRef $Evidence.behavior_catalog_ref $Catalog)) {
        & $add 'stale_behavior_catalog_version'
    }
    if (-not (Test-AdaptiveRuntimeDocumentRef $Evidence.plan_validation_ref $PlanValidation)) {
        & $add 'stale_plan_validation_reference'
    }
    if (-not (Test-AdaptiveRuntimeDocumentRef `
        $ClassificationSet.payload.evidence_ref $Evidence)) {
        & $add 'classification_evidence_mismatch'
    }
    if (-not (Test-AdaptiveRuntimeDocumentRef `
        $ClassificationSet.payload.compatibility_catalog_ref $CompatibilityCatalog)) {
        & $add 'stale_classification_catalog_version'
    }
    foreach ($document in @($Evidence, $Catalog, $ClassificationSet,
        $CompatibilityCatalog)) {
        if ($document.active_behavior_authorization -ne $false) {
            & $add 'active_behavior_unauthorized'
        }
        if ($document.performance_acceptance_authorization -ne $false) {
            & $add 'performance_acceptance_unauthorized'
        }
    }

    $epochKeys = @($Evidence.connection_epochs | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.epoch_sequence)"
    })
    if (@($epochKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'top_epoch_not_unique'
    }
    $topEpochKey =
        "$($Evidence.run_id)|$($Evidence.connection_key)|$($Evidence.epoch_sequence)"
    if (@($epochKeys | Where-Object { $_ -ceq $topEpochKey }).Count -ne 1) {
        & $add 'top_epoch_missing'
    }
    $resultEpochKey =
        "$($Evidence.run_id)|$($Evidence.connection_key)|$($Evidence.result_epoch_sequence)"
    if ($epochKeys -cnotcontains $resultEpochKey) {
        & $add 'result_epoch_missing'
    }

    $decisionKeys = @($Evidence.decisions | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.epoch_sequence)|$($_.axis_id)|$($_.decision_instance_id)"
    })
    if (@($decisionKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'duplicate_decision_instance'
    }
    foreach ($decision in @($Evidence.decisions)) {
        $epochKey =
            "$($decision.run_id)|$($decision.connection_key)|$($decision.epoch_sequence)"
        if ($epochKeys -cnotcontains $epochKey) {
            & $add 'decision_epoch_missing'
        }
    }

    $operationIdentities = @($Evidence.operations | ForEach-Object {
        New-AdaptiveRuntimeOperationIdentity $_
    })
    if (@($operationIdentities.operation_key | Group-Object |
        Where-Object Count -gt 1).Count -gt 0) {
        & $add 'duplicate_operation_correlation'
    }
    foreach ($operation in @($Evidence.operations)) {
        $operationEpochKey =
            "$($operation.run_id)|$($operation.connection_key)|$($operation.epoch_sequence)"
        if ($epochKeys -cnotcontains $operationEpochKey) {
            & $add 'operation_epoch_missing'
        }
        $decisionMatches = @($Evidence.decisions | Where-Object {
            [string]$_.run_id -ceq [string]$operation.run_id -and
            [string]$_.connection_key -ceq [string]$operation.connection_key -and
            [long]$_.epoch_sequence -eq [long]$operation.epoch_sequence -and
            [string]$_.axis_id -ceq [string]$operation.axis_id -and
            [long]$_.decision_instance_id -eq
                [long]$operation.decision_instance_id
        })
        if ($decisionMatches.Count -ne 1) {
            & $add 'missing_decision_correlation'
            continue
        }
        $decision = $decisionMatches[0]
        foreach ($comparison in @(
            @('configured_value','configured_value_mismatch'),
            @('forced_value','forced_value_mismatch'),
            @('shadow_recommendation','shadow_recommendation_mismatch'),
            @('candidate_value','candidate_value_mismatch'),
            @('operation_eligibility_result','eligibility_result_mismatch'),
            @('operation_eligibility_reason','eligibility_reason_mismatch'),
            @('applied_value','applied_value_mismatch')
        )) {
            if (-not [object]::Equals(
                (Get-AdaptiveRuntimeJsonProperty $decision $comparison[0]),
                (Get-AdaptiveRuntimeJsonProperty $operation $comparison[0]))) {
                & $add $comparison[1]
            }
        }
        if ($null -ne $decision.shadow_recommendation -and
            $null -eq $decision.forced_value -and
            [string]$decision.applied_value -cne
                [string]$decision.configured_value) {
            & $add 'shadow_recommendation_changed_applied_behavior'
        }
        if ($null -ne $decision.forced_value -and
            [string]$operation.operation_eligibility_result -ceq 'ineligible' -and
            [string]$operation.applied_value -ceq
                [string]$decision.forced_value) {
            & $add 'forced_candidate_bypassed_operation_eligibility'
        }
        $behavior = Resolve-AdaptiveRuntimeEffectiveBehavior $operation $Catalog
        if ($behavior.status -eq 'no_match' -and
            [string]$operation.result -cne 'unclassifiable') {
            & $add 'behavior_derivation_no_match'
        }
        elseif ($behavior.status -eq 'ambiguous') {
            & $add 'behavior_derivation_ambiguous'
        }
        $outcome = Resolve-AdaptiveRuntimeOperationOutcome $operation $Catalog
        if ($outcome.status -in @('no_match','ambiguous')) {
            & $add ([string]$outcome.error_code)
        }
    }

    $releaseKeys = @($Evidence.releases | ForEach-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.operation_epoch_sequence)|$($_.axis_id)|$($_.decision_instance_id)|$($_.operation_id)"
    })
    if (@($releaseKeys | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        & $add 'duplicate_owner_release'
    }
    foreach ($release in @($Evidence.releases)) {
        $operationMatches = @($Evidence.operations | Where-Object {
            [string]$_.run_id -ceq [string]$release.run_id -and
            [string]$_.connection_key -ceq [string]$release.connection_key -and
            [long]$_.epoch_sequence -eq
                [long]$release.operation_epoch_sequence -and
            [string]$_.axis_id -ceq [string]$release.axis_id -and
            [long]$_.decision_instance_id -eq
                [long]$release.decision_instance_id -and
            [long]$_.operation_id -eq [long]$release.operation_id
        })
        if ($operationMatches.Count -ne 1) {
            & $add 'release_operation_identity_mismatch'
            continue
        }
        $operation = $operationMatches[0]
        $decisionMatches = @($Evidence.decisions | Where-Object {
            [string]$_.run_id -ceq [string]$operation.run_id -and
            [string]$_.connection_key -ceq [string]$operation.connection_key -and
            [long]$_.epoch_sequence -eq [long]$operation.epoch_sequence -and
            [string]$_.axis_id -ceq [string]$operation.axis_id -and
            [long]$_.decision_instance_id -eq
                [long]$operation.decision_instance_id
        })
        if ($decisionMatches.Count -ne 1) {
            & $add 'release_decision_identity_mismatch'
            continue
        }
        $decision = $decisionMatches[0]
        if ([long]$release.decision_epoch_sequence -ne
            [long]$decision.epoch_sequence) {
            & $add 'release_decision_epoch_mismatch'
        }
        $releaseEpochKey =
            "$($release.run_id)|$($release.connection_key)|$($release.release_epoch_sequence)"
        if ($epochKeys -cnotcontains $releaseEpochKey) {
            & $add 'release_epoch_missing'
        }
        if ([long]$release.release_epoch_sequence -lt
            [long]$decision.epoch_sequence) {
            & $add 'release_precedes_decision'
        }
        if ([long]$release.release_count -ne 1) {
            & $add 'duplicate_owner_release'
        }
    }
    foreach ($operation in @($Evidence.operations | Where-Object {
        $_.axis_id -eq 'buffer_copy_coalescing' -and
        $_.mechanism_event_id -in @(
            'mechanism_event.buffer_legacy_prefix',
            'mechanism_event.buffer_two_source_cap')
    })) {
        if (@($Evidence.releases | Where-Object {
            [string]$_.run_id -ceq [string]$operation.run_id -and
            [string]$_.connection_key -ceq [string]$operation.connection_key -and
            [long]$_.operation_epoch_sequence -eq
                [long]$operation.epoch_sequence -and
            [string]$_.axis_id -ceq [string]$operation.axis_id -and
            [long]$_.decision_instance_id -eq
                [long]$operation.decision_instance_id -and
            [long]$_.operation_id -eq [long]$operation.operation_id
        }).Count -ne 1) {
            & $add 'missing_terminal_release_evidence'
        }
    }

    $classifications = @($ClassificationSet.payload.classifications)
    if (@($classifications.classification_id | Group-Object |
        Where-Object Count -gt 1).Count -gt 0) {
        & $add 'classification_id_duplicate'
    }
    foreach ($classification in $classifications) {
        $matchCount = Get-AdaptiveRuntimeClassificationTargetMatchCount `
            $classification.target $Evidence $ArtifactInventory
        if ($matchCount -eq 0) {
            & $add 'classification_target_missing'
        }
        elseif ($matchCount -gt 1) {
            & $add 'classification_target_ambiguous'
        }
    }

    $definitions = @($CompatibilityCatalog.classification_definitions)
    if (@($definitions.classification_kind | Group-Object |
        Where-Object Count -gt 1).Count -gt 0) {
        & $add 'classification_catalog_duplicate_definition'
    }
    $compatiblePairs = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($pair in @($CompatibilityCatalog.compatible_pairs)) {
        $parts = @([string]$pair.left_kind, [string]$pair.right_kind) |
            Sort-Object -CaseSensitive
        [void]$compatiblePairs.Add("$($parts[0])|$($parts[1])")
    }
    foreach ($group in @($classifications | Group-Object {
        Get-AdaptiveRuntimeClassificationTargetKey $_.target
    })) {
        $kinds = @($group.Group.kind | Sort-Object -CaseSensitive)
        if (@($kinds | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
            & $add 'classification_contradiction'
        }
        for ($left = 0; $left -lt $kinds.Count; $left++) {
            for ($right = $left + 1; $right -lt $kinds.Count; $right++) {
                $pairKey = "$($kinds[$left])|$($kinds[$right])"
                if (-not $compatiblePairs.Contains($pairKey)) {
                    & $add 'classification_contradiction'
                }
            }
        }
    }
    foreach ($operation in @($Evidence.operations)) {
        $outcome = Resolve-AdaptiveRuntimeOperationOutcome $operation $Catalog
        if ($outcome.status -ne 'matched' -or
            $outcome.requires_retained_classification -ne $true) {
            continue
        }
        $definition = @(
            Get-AdaptiveRuntimeClassificationDefinitionForOutcome `
                $outcome.outcome_id $CompatibilityCatalog)
        if ($definition.Count -ne 1) {
            & $add 'classification_outcome_mapping_invalid'
            continue
        }
        $target = [pscustomobject][ordered]@{
            target_kind = 'operation'
            run_id = [string]$operation.run_id
            connection_key = [string]$operation.connection_key
            epoch_sequence = [long]$operation.epoch_sequence
            axis_id = [string]$operation.axis_id
            decision_instance_id = [long]$operation.decision_instance_id
            operation_id = [long]$operation.operation_id
        }
        $targetKey = Get-AdaptiveRuntimeClassificationTargetKey $target
        $matching = @($classifications | Where-Object {
            (Get-AdaptiveRuntimeClassificationTargetKey $_.target) -ceq
                $targetKey -and
            [string]$_.kind -ceq
                [string]$definition[0].classification_kind -and
            $_.retained -eq $true
        })
        if ($matching.Count -ne 1) {
            & $add 'required_retained_classification_missing'
        }
    }
    return @($errors | Sort-Object -CaseSensitive)
}

function New-AdaptiveRuntimeBehaviorMaterializationV3 {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Catalog
    )

    $derivations = @($Evidence.operations | ForEach-Object {
        $identity = New-AdaptiveRuntimeOperationIdentity $_
        $resolved = Resolve-AdaptiveRuntimeEffectiveBehavior $_ $Catalog
        [pscustomobject][ordered]@{
            operation_identity = $identity
            mechanism_event_id = [string]$_.mechanism_event_id
            derivation_status = [string]$resolved.status
            effective_behavior_ids =
                @($resolved.effective_behavior_ids | Sort-Object -CaseSensitive)
            error_code = $resolved.error_code
        }
    } | Sort-Object { $_.operation_identity.operation_key })
    $rows = @()
    foreach ($operation in @($Evidence.operations)) {
        $resolved = Resolve-AdaptiveRuntimeEffectiveBehavior $operation $Catalog
        if ($resolved.status -ne 'matched') { continue }
        foreach ($behaviorId in @($resolved.effective_behavior_ids)) {
            $rows += [pscustomobject]@{
                operation = $operation
                identity = New-AdaptiveRuntimeOperationIdentity $operation
                behavior_id = [string]$behaviorId
            }
        }
    }
    $aggregates = @($rows | Group-Object {
        "$($_.operation.run_id)|$($_.operation.connection_key)|$($_.operation.epoch_sequence)|$($_.operation.axis_id)|$($_.behavior_id)"
    } | Sort-Object Name | ForEach-Object {
        $parts = $_.Name -split '\|', 5
        [pscustomobject][ordered]@{
            run_id = $parts[0]
            connection_key = $parts[1]
            epoch_sequence = [long]$parts[2]
            axis_id = $parts[3]
            behavior_catalog_version = 2
            effective_behavior_id = $parts[4]
            operation_count = @($_.Group).Count
            work_count = [long](($_.Group.operation.applied_work_count |
                Measure-Object -Sum).Sum)
            byte_count = [long](($_.Group.operation.applied_bytes |
                Measure-Object -Sum).Sum)
            source_operation_identities = @($_.Group.identity |
                Sort-Object operation_key)
        }
    })
    $document = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-effective-behavior-materialization-v3'
        document_id = "materialization.behavior.v3.$($Evidence.document_id)"
        document_version = 3
        content_sha256 = '0' * 64
        source_evidence_ref = New-AdaptiveRuntimeDocumentRef $Evidence
        behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $Catalog
        aggregates = $aggregates
        derivations = $derivations
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $Evidence.trace_references
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function New-AdaptiveRuntimeOutcomeMaterializationV2 {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $Catalog,
        [Parameter(Mandatory = $true)][object] $ClassificationSet
    )

    $rows = @()
    $derivations = @()
    foreach ($operation in @($Evidence.operations)) {
        $identity = New-AdaptiveRuntimeOperationIdentity $operation
        $resolved = Resolve-AdaptiveRuntimeOperationOutcome $operation $Catalog
        $derivations += [pscustomobject][ordered]@{
            operation_identity = $identity
            result_kind = [string]$operation.result
            derivation_status = [string]$resolved.status
            outcome_id = $resolved.outcome_id
            requires_retained_classification =
                $resolved.requires_retained_classification
            error_code = $resolved.error_code
        }
        if ($resolved.status -in @('no_match','ambiguous')) {
            throw [string]$resolved.error_code
        }
        if ($resolved.status -eq 'matched') {
            $rows += [pscustomobject]@{
                operation = $operation
                identity = $identity
                outcome_id = [string]$resolved.outcome_id
            }
        }
    }
    $aggregates = @($rows | Group-Object {
        "$($_.operation.run_id)|$($_.operation.connection_key)|$($_.operation.epoch_sequence)|$($_.operation.axis_id)|$($_.outcome_id)"
    } | Sort-Object Name | ForEach-Object {
        $parts = $_.Name -split '\|', 5
        [pscustomobject][ordered]@{
            run_id = $parts[0]
            connection_key = $parts[1]
            epoch_sequence = [long]$parts[2]
            axis_id = $parts[3]
            outcome_contract_version = 2
            outcome_id = $parts[4]
            operation_count = @($_.Group).Count
            work_count = [long](($_.Group.operation.applied_work_count |
                Measure-Object -Sum).Sum)
            byte_count = [long](($_.Group.operation.applied_bytes |
                Measure-Object -Sum).Sum)
            source_operation_identities = @($_.Group.identity |
                Sort-Object operation_key)
        }
    })
    $document = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-operation-outcome-materialization-v2'
        document_id = "materialization.outcome.v2.$($Evidence.document_id)"
        document_version = 2
        content_sha256 = '0' * 64
        source_evidence_ref = New-AdaptiveRuntimeDocumentRef $Evidence
        behavior_catalog_ref = New-AdaptiveRuntimeDocumentRef $Catalog
        classification_set_ref = New-AdaptiveRuntimeDocumentRef $ClassificationSet
        aggregates = $aggregates
        derivations = @($derivations | Sort-Object {
            $_.operation_identity.operation_key
        })
        retained_classifications =
            @($ClassificationSet.payload.classifications |
                Sort-Object classification_id)
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        trace_references = $Evidence.trace_references
    }
    [void](Set-AdaptiveRuntimeDocumentHash $document)
    return $document
}

function Get-AdaptiveRuntimeEvidenceV2WarningCodes {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [Parameter(Mandatory = $true)][object] $BehaviorMaterialization,
        [Parameter(Mandatory = $true)][object] $PlanValidation
    )

    $warnings = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($group in @($BehaviorMaterialization.aggregates | Group-Object {
        "$($_.run_id)|$($_.connection_key)|$($_.epoch_sequence)|$($_.axis_id)"
    })) {
        if (@($group.Group.effective_behavior_id | Sort-Object -Unique).Count -gt 1) {
            [void]$warnings.Add('multiple_effective_behaviors_in_epoch')
        }
    }
    foreach ($operation in @($Evidence.operations)) {
        $retained = @($Evidence.classifications | Where-Object {
            $_.target_kind -eq 'operation' -and
            [string]$_.target_id -ceq [string]$operation.operation_id -and
            $_.retained -eq $true
        })
        if ($operation.result -eq 'inactive' -and
            @($retained | Where-Object kind -eq 'inactive').Count -eq 1) {
            [void]$warnings.Add('inactive_operation_retained')
        }
        if ($operation.result -in @('fallback','clamped') -and
            @($retained | Where-Object {
                $_.kind -in @('fallback','clamped')
            }).Count -eq 1) {
            [void]$warnings.Add('fallback_operation_retained')
        }
    }
    if ($PlanValidation.validation_classification -eq 'verification_only' -and
        @($PlanValidation.expanded_planned_cells | Where-Object {
            $_.execution_state -eq 'retained_for_verification'
        }).Count -gt 0) {
        [void]$warnings.Add(
            'verification_only_equivalent_cell_retained')
    }
    [void]$warnings.Add('measurement_freeze_active')
    return @($warnings | Sort-Object)
}

Export-ModuleMember -Function @(
    'Get-AdaptiveRuntimeClassificationTargetKey',
    'Get-AdaptiveRuntimeEvidenceV3Errors',
    'Get-AdaptiveRuntimeEvidenceV2Errors',
    'Get-AdaptiveRuntimeEvidenceV2WarningCodes',
    'Get-AdaptiveRuntimeOperationOutcomeId',
    'New-AdaptiveRuntimeBehaviorMaterializationV3',
    'New-AdaptiveRuntimeBehaviorMaterializationV2',
    'New-AdaptiveRuntimeDocumentRef',
    'New-AdaptiveRuntimeOperationIdentity',
    'New-AdaptiveRuntimeOutcomeMaterializationV2',
    'New-AdaptiveRuntimeOutcomeMaterializationV1',
    'Resolve-AdaptiveRuntimeEffectiveBehavior',
    'Resolve-AdaptiveRuntimeOperationOutcome',
    'Test-AdaptiveRuntimeDocumentRef'
)
