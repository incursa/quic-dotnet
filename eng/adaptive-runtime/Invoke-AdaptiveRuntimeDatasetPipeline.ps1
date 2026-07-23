# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $LocalResultPath,

    [Parameter(Mandatory = $true)]
    [string[]] $EpochDatasetPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputRoot,

    [string] $CatalogPath,

    [string] $DatasetId = 'adaptive-runtime-normalized-fixture',

    [string] $DatasetVersion = '2026-07-22-v1',

    [int] $SplitSeed = 17
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object] $InputObject,

        [Parameter(Mandatory = $true)]
        [string] $PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-DefaultCurationState {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Row,

        [Parameter(Mandatory = $true)]
        [object] $Result
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    $flags = @($Row.analysisExclusionFlags)
    if ($flags.Count -ne 1 -or $flags[0] -ne 'none') {
        $reasons.Add('analysis_exclusion_flag')
    }

    switch ([string] $Result.classification) {
        'invalid_environment' { $reasons.Add('invalid_environment_classification') }
        'invalid_contract' { $reasons.Add('invalid_contract_classification') }
        'failed_correctness' { $reasons.Add('failed_correctness_classification') }
        'stress_only' { $reasons.Add('stress_only_classification') }
    }

    if ($reasons.Count -eq 0) {
        return [pscustomobject]@{
            Decision = 'include'
            Reasons = @('none')
        }
    }

    return [pscustomobject]@{
        Decision = 'exclude'
        Reasons = @($reasons)
    }
}

function Get-HoldoutAssignments {
    param(
        [AllowEmptyCollection()]
        [object[]] $IncludedDecisions,

        [Parameter(Mandatory = $true)]
        [int] $Seed
    )

    $distinctWorkloads = @($IncludedDecisions | Select-Object -ExpandProperty HoldoutGroupWorkload -Unique)
    $distinctHosts = @($IncludedDecisions | Select-Object -ExpandProperty HoldoutGroupHost -Unique)
    if ($IncludedDecisions.Count -eq 0) {
        return [pscustomobject]@{
            Status = 'insufficient_group_diversity'
            BlockedReason = 'No curated rows remained eligible for splitting.'
            MapByRowId = @{}
        }
    }

    if ($distinctWorkloads.Count -lt 3 -or $distinctHosts.Count -lt 3) {
        return [pscustomobject]@{
            Status = 'insufficient_group_diversity'
            BlockedReason = 'At least three workload families and three host fingerprints are required before host and workload holdouts can populate train, validation, and test without crossing dimensions.'
            MapByRowId = @{}
        }
    }

    $splitNames = @('train', 'validation', 'test')
    $workloadBuckets = @{}
    $orderedWorkloads = @(
        $distinctWorkloads |
            ForEach-Object {
                [pscustomobject]@{
                    Group = $_
                    SortKey = Get-StringSha256Hex -Value "$Seed|workload|$_"
                }
            } |
            Sort-Object SortKey, Group
    )
    for ($index = 0; $index -lt $orderedWorkloads.Count; $index++) {
        $workloadBuckets[$orderedWorkloads[$index].Group] = $splitNames[$index % $splitNames.Count]
    }

    $hostBuckets = @{}
    $orderedHosts = @(
        $distinctHosts |
            ForEach-Object {
                [pscustomobject]@{
                    Group = $_
                    SortKey = Get-StringSha256Hex -Value "$Seed|host|$_"
                }
            } |
            Sort-Object SortKey, Group
    )
    for ($index = 0; $index -lt $orderedHosts.Count; $index++) {
        $hostBuckets[$orderedHosts[$index].Group] = $splitNames[$index % $splitNames.Count]
    }

    $assignments = @{}
    $counts = @{
        train = 0
        validation = 0
        test = 0
    }
    foreach ($decision in $IncludedDecisions) {
        $workloadSplit = [string] $workloadBuckets[$decision.HoldoutGroupWorkload]
        $hostSplit = [string] $hostBuckets[$decision.HoldoutGroupHost]
        if ($workloadSplit -ne $hostSplit) {
            return [pscustomobject]@{
                Status = 'insufficient_group_diversity'
                BlockedReason = 'The included rows cannot satisfy complete workload-family and host holdouts simultaneously without crossing dimensions.'
                MapByRowId = @{}
            }
        }

        $assignments[$decision.RowId] = $workloadSplit
        $counts[$workloadSplit] += 1
    }

    if ($counts.train -eq 0 -or $counts.validation -eq 0 -or $counts.test -eq 0) {
        return [pscustomobject]@{
            Status = 'insufficient_group_diversity'
            BlockedReason = 'The included rows cannot populate train, validation, and test while keeping workload-family and host holdouts complete.'
            MapByRowId = @{}
        }
    }

    return [pscustomobject]@{
        Status = 'ready'
        BlockedReason = $null
        MapByRowId = $assignments
    }
}

$repositoryRoot = Get-AdaptiveRuntimeRepositoryRoot
$catalogSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-catalog-v1.schema.json'
$normalizedSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-normalized-dataset-v1.schema.json'
$curatedSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-curated-manifest-v1.schema.json'
$splitSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-split-manifest-v1.schema.json'
$validatorPath = Join-Path $repositoryRoot 'eng\adaptive-runtime\Test-AdaptiveRuntimePolicyEvidence.ps1'
$catalogWriterPath = Join-Path $repositoryRoot 'eng\adaptive-runtime\New-AdaptiveRuntimePolicyCatalog.ps1'
$codeCommit = Get-GitCommitHash -RepositoryRoot $repositoryRoot
$resolvedOutputRoot = Resolve-AdaptiveRuntimePath -Path $OutputRoot
if (Test-Path -LiteralPath $resolvedOutputRoot) {
    throw "Append-only output root already exists: $resolvedOutputRoot"
}

$catalogDocument = if ([string]::IsNullOrWhiteSpace($CatalogPath)) {
    $null
}
else {
    Read-ValidatedJsonDocument -Path $CatalogPath -SchemaPath $catalogSchemaPath
}

$validationSummary = (& $validatorPath `
        -LocalResultPath $LocalResultPath `
        -EpochDatasetPath $EpochDatasetPath `
        -AllowUnmatchedEpochRows `
        -AllowLegacyResultLevelEnvironmentExclusions `
        -RepositoryRoot $repositoryRoot | ConvertFrom-Json -Depth 50)
if (-not $validationSummary.valid) {
    $failurePreview = @($validationSummary.failures | Select-Object -First 20) -join ' | '
    throw "Adaptive-runtime evidence validation failed before dataset materialization with $(@($validationSummary.failures).Count) failure(s): $failurePreview"
}

$localResults = @(
    $LocalResultPath |
        ForEach-Object {
            Read-ValidatedJsonDocument -Path $_ -SchemaPath (Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-local-result-v1.schema.json')
        }
)
$epochRows = @(
    $EpochDatasetPath |
        ForEach-Object {
            Read-ValidatedJsonDocument -Path $_ -SchemaPath (Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-epoch-dataset-v1.schema.json')
        }
)

New-Item -ItemType Directory -Force -Path $resolvedOutputRoot | Out-Null
if ($null -eq $catalogDocument) {
    $catalogOutputPath = Join-Path $resolvedOutputRoot 'catalog\policy-catalog.json'
    $null = & $catalogWriterPath -OutputPath $catalogOutputPath
    $catalogDocument = Read-ValidatedJsonDocument -Path $catalogOutputPath -SchemaPath $catalogSchemaPath
}

$resultByCompositeKey = @{}
foreach ($resultItem in $localResults) {
    foreach ($sample in @($resultItem.Document.samples)) {
        $compositeKey = '{0}|{1}|{2}|{3}' -f $resultItem.Document.campaignId, $resultItem.Document.runId, $resultItem.Document.cellId, $sample.sampleId
        $resultByCompositeKey[$compositeKey] = [pscustomobject]@{
            ResultItem = $resultItem
            Result = $resultItem.Document
            Sample = $sample
        }
    }
}

$usedResultKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$normalizedRows = [System.Collections.Generic.List[object]]::new()
$unmatchedEpochRows = [System.Collections.Generic.List[object]]::new()

foreach ($epochItem in ($epochRows | Sort-Object { $_.Document.campaignId }, { $_.Document.runId }, { $_.Document.cellId }, { $_.Document.sampleId }, { $_.Document.rowId })) {
    $row = $epochItem.Document
    $compositeKey = '{0}|{1}|{2}|{3}' -f $row.campaignId, $row.runId, $row.cellId, $row.sampleId
    if (-not $resultByCompositeKey.ContainsKey($compositeKey)) {
        $unmatchedEpochRows.Add([ordered]@{
            rowId = [string] $row.rowId
            runId = [string] $row.runId
            reasonCode = 'unmatched_epoch_row'
            artifact = [ordered]@{
                path = $epochItem.Path
                sha256 = $epochItem.Sha256
            }
        })
        continue
    }

    $match = $resultByCompositeKey[$compositeKey]
    $null = $usedResultKeys.Add($compositeKey)
    $result = $match.Result
    $sample = $match.Sample
    $defaultCuration = Get-DefaultCurationState -Row $row -Result $result
    $binaryCohortKey = '{0}|{1}' -f $row.provenance.benchmarkSha256, $row.provenance.runtimeSha256
    $workloadFamilyKey = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
        $row.workloadAnalysisOnly.scenarioId,
        $row.workloadAnalysisOnly.trafficShape,
        $row.workloadAnalysisOnly.accountingMode,
        $row.workloadAnalysisOnly.payloadBytes,
        $row.workloadAnalysisOnly.effectiveConnections,
        $row.workloadAnalysisOnly.effectiveStreamsPerConnection,
        $row.workloadAnalysisOnly.effectiveConcurrency,
        $row.workloadAnalysisOnly.arrivalPattern
    $hostFingerprintKey = [string] $row.provenance.hostFingerprint
    $runConnectionKey = '{0}|{1}' -f $row.runId, $row.connectionKey
    $repetitionProtocolKey = [string] $result.sequenceProtocol
    $preDecisionRegimeMaterial = @(
        $row.preDecisionObservations.PSObject.Properties |
            Sort-Object Name |
            ForEach-Object { '{0}={1}' -f $_.Name, ($_.Value | ConvertTo-Json -Compress -Depth 10) }
    ) -join '|'
    $preDecisionRegimeKey = Get-StringSha256Hex -Value $preDecisionRegimeMaterial
    $counterfactualGroupKey = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $row.campaignId, $workloadFamilyKey, $binaryCohortKey, $hostFingerprintKey, $result.policyAxis, $repetitionProtocolKey, $preDecisionRegimeKey
    $flowBlockedMicros = @($row.preDecisionObservations.connectionFlowBlockedMicrosEpoch, $row.preDecisionObservations.streamFlowBlockedMicrosEpoch) |
        Where-Object { $null -ne $_ } |
        Measure-Object -Sum
    $resultArtifact = @($result.artifacts | Where-Object { $_.kind -eq 'result' } | Select-Object -First 1)
    $resultArtifactPath = if ($resultArtifact.Count -gt 0) { [string] $resultArtifact[0].path } else { $match.ResultItem.Path }
    $resultArtifactSha = if ($resultArtifact.Count -gt 0) { [string] $resultArtifact[0].sha256 } else { $match.ResultItem.Sha256 }
    $normalizedRowId = '{0}|{1}|{2}' -f $row.campaignId, $row.runId, $row.rowId

    $normalizedRows.Add([ordered]@{
        rowId = $normalizedRowId
        sourceRowId = [string] $row.rowId
        joinKey = $compositeKey
        campaignId = [string] $row.campaignId
        runId = [string] $row.runId
        cellId = [string] $row.cellId
        sampleId = [string] $row.sampleId
        connectionKey = [string] $row.connectionKey
        epochIndex = [int] $row.epochIndex
        policyAxis = [string] $result.policyAxis
        classification = [string] $result.classification
        mode = [string] $result.mode
        selectedPolicy = [string] $row.candidatePolicySelection.selectedPolicy
        appliedPolicy = [string] $row.currentPolicyState.appliedPolicy
        forcedPolicy = $result.policyConfiguration.forcedPolicy
        shadowRecommendation = $row.candidatePolicySelection.shadowRecommendation
        selectionSource = [string] $row.candidatePolicySelection.selectionSource
        reasonCode = [string] $row.candidatePolicySelection.reasonCode
        sourceExclusionFlags = @($row.analysisExclusionFlags)
        defaultCurationDecision = $defaultCuration.Decision
        defaultCurationReasons = @($defaultCuration.Reasons)
        workloadShape = [ordered]@{
            scenarioId = [string] $row.workloadAnalysisOnly.scenarioId
            trafficShape = [string] $row.workloadAnalysisOnly.trafficShape
            accountingMode = [string] $row.workloadAnalysisOnly.accountingMode
            payloadBytes = [int] $row.workloadAnalysisOnly.payloadBytes
            effectiveConnections = [int] $row.workloadAnalysisOnly.effectiveConnections
            effectiveStreamsPerConnection = [int] $row.workloadAnalysisOnly.effectiveStreamsPerConnection
            effectiveConcurrency = [int] $row.workloadAnalysisOnly.effectiveConcurrency
            arrivalPattern = [string] $row.workloadAnalysisOnly.arrivalPattern
        }
        groupKeys = [ordered]@{
            binaryCohortKey = $binaryCohortKey
            workloadFamilyKey = $workloadFamilyKey
            hostFingerprintKey = $hostFingerprintKey
            runConnectionKey = $runConnectionKey
            repetitionProtocolKey = $repetitionProtocolKey
            preDecisionRegimeKey = $preDecisionRegimeKey
            counterfactualGroupKey = $counterfactualGroupKey
        }
        normalizedMetrics = [ordered]@{
            throughputMiBPerSecond = Convert-BytesToMiB -Value $row.postEpochOutcomes.throughputBytesPerSecond
            latencyP95Ms = Convert-MicrosToMilliseconds -Value $row.postEpochOutcomes.latencyP95Micros
            allocatedKiB = Convert-BytesToKiB -Value $row.postEpochOutcomes.allocatedBytes
            peakRetainedKiB = Convert-BytesToKiB -Value $row.postEpochOutcomes.peakRetainedBytes
            queueToServiceRatio = Convert-Q16ToRatio -Value $row.preDecisionObservations.queueToServiceRatioQ16
            flowBlockedMs = if ($flowBlockedMicros.Count -gt 0 -and $flowBlockedMicros.Sum -ne $null) { Convert-MicrosToMilliseconds -Value $flowBlockedMicros.Sum } else { $null }
            missingSignalCount = Get-BitCount -Value ([int] $row.preDecisionObservations.missingSignalMask)
            staleSignalCount = Get-BitCount -Value ([int] $row.preDecisionObservations.staleSignalMask)
        }
        sampleScopedOutcomes = [ordered]@{
            scope = 'sample'
            throughputMiBPerSecond = Convert-BytesToMiB -Value $sample.outcomes.throughputBytesPerSecond
            latencyP95Ms = $sample.outcomes.latencyP95Ms
            bufferPoolRentedKiB = Convert-BytesToKiB -Value (Get-OptionalPropertyValue -InputObject $sample.outcomes -PropertyName 'bufferPoolRentedBytes')
            bufferPoolOutstandingPeakKiB = Convert-BytesToKiB -Value (Get-OptionalPropertyValue -InputObject $sample.outcomes -PropertyName 'bufferPoolOutstandingPeakBytes')
            managedAllocatedKiB = Convert-BytesToKiB -Value $sample.outcomes.allocatedBytes
            peakRetainedKiB = Convert-BytesToKiB -Value $sample.outcomes.peakRetainedBytes
            fairnessAssessed = [bool] $result.fairnessOutcomes.assessed
        }
        provenance = [ordered]@{
            resultArtifactPath = $resultArtifactPath
            resultArtifactSha256 = $resultArtifactSha
            repositoryCommit = [string] $row.provenance.repositoryCommit
            benchmarkSha256 = [string] $row.provenance.benchmarkSha256
            runtimeSha256 = [string] $row.provenance.runtimeSha256
            hostFingerprint = [string] $row.provenance.hostFingerprint
        }
    })
}

$unmatchedResults = [System.Collections.Generic.List[object]]::new()
foreach ($resultItem in $localResults) {
    foreach ($sample in @($resultItem.Document.samples)) {
        $compositeKey = '{0}|{1}|{2}|{3}' -f $resultItem.Document.campaignId, $resultItem.Document.runId, $resultItem.Document.cellId, $sample.sampleId
        if ($usedResultKeys.Contains($compositeKey)) {
            continue
        }

        $unmatchedResults.Add([ordered]@{
            runId = [string] $resultItem.Document.runId
            campaignId = [string] $resultItem.Document.campaignId
            cellId = [string] $resultItem.Document.cellId
            reasonCode = 'unmatched_source_result'
            artifact = [ordered]@{
                path = $resultItem.Path
                sha256 = $resultItem.Sha256
            }
        })
    }
}

$normalizedDocument = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-normalized-dataset-v1'
    normalizedDatasetId = $DatasetId
    datasetVersion = $DatasetVersion
    createdUtc = [DateTime]::UtcNow.ToString('O')
    catalog = [ordered]@{
        path = $catalogDocument.Path
        sha256 = $catalogDocument.Sha256
    }
    rawInputs = [ordered]@{
        localResults = @($localResults | ForEach-Object {
                [ordered]@{
                    path = $_.Path
                    sha256 = $_.Sha256
                }
            })
        epochRows = @($epochRows | ForEach-Object {
                [ordered]@{
                    path = $_.Path
                    sha256 = $_.Sha256
                }
            })
        evidenceValidation = [ordered]@{
            schemaVersion = [string] $validationSummary.schemaVersion
            valid = [bool] $validationSummary.valid
            localResultCount = [int] $validationSummary.localResultCount
            epochRowCount = [int] $validationSummary.epochRowCount
            uniqueArtifactHashCount = [int] $validationSummary.uniqueArtifactHashCount
            legacyResultLevelEnvironmentExclusionsAllowed = [bool] $validationSummary.legacyResultLevelEnvironmentExclusionsAllowed
            legacyResultLevelEnvironmentExclusionRowCount = [int] $validationSummary.legacyResultLevelEnvironmentExclusionRowCount
            failures = @($validationSummary.failures)
        }
    }
    transformation = [ordered]@{
        name = 'adaptive-runtime-raw-to-normalized'
        version = $DatasetVersion
        codeCommit = $codeCommit
    }
    joinContract = [ordered]@{
        joinKeys = @('campaignId', 'runId', 'cellId', 'sampleId')
        unmatchedResultPolicy = 'retained'
        unmatchedEpochPolicy = 'retained'
        missingValueSemantics = 'Null numeric values remain null; missing and stale masks retain the raw bit counts for later curation.'
    }
    rows = @($normalizedRows)
    unmatchedResults = @($unmatchedResults)
    unmatchedEpochRows = @($unmatchedEpochRows)
    summary = [ordered]@{
        joinedRowCount = $normalizedRows.Count
        defaultIncludedRowCount = @($normalizedRows | Where-Object { $_.defaultCurationDecision -eq 'include' }).Count
        defaultExcludedRowCount = @($normalizedRows | Where-Object { $_.defaultCurationDecision -eq 'exclude' }).Count
        unmatchedResultCount = $unmatchedResults.Count
        unmatchedEpochRowCount = $unmatchedEpochRows.Count
    }
}

$normalizedOutputPath = Join-Path $resolvedOutputRoot 'normalized\normalized-dataset.json'
$normalizedWritten = Write-ValidatedJsonDocument -Document $normalizedDocument -SchemaPath $normalizedSchemaPath -OutputPath $normalizedOutputPath

$curatedDecisions = [System.Collections.Generic.List[object]]::new()
foreach ($row in @($normalizedDocument.rows)) {
    $decision = if ($row.defaultCurationDecision -eq 'include') { 'included' } else { 'excluded' }
    $reasonCodes = if ($decision -eq 'included') {
        if ($row.classification -eq 'negative_retained') {
            @('retained_negative_evidence')
        }
        else {
            @('none')
        }
    }
    else {
        @($row.defaultCurationReasons | Where-Object { $_ -ne 'none' })
    }

    $qualityBucket = if ($decision -eq 'excluded') {
        'excluded'
    }
    elseif ($row.classification -eq 'negative_retained') {
        'retained_negative'
    }
    else {
        'eligible_measurement'
    }

    $outcomeTier = if ($decision -eq 'excluded') {
        'excluded'
    }
    elseif ($row.classification -eq 'negative_retained') {
        'retained_negative'
    }
    else {
        'counterfactual_candidate'
    }

    $curatedDecisions.Add([pscustomobject]@{
        RowId = [string] $row.rowId
        Decision = $decision
        ReasonCodes = $reasonCodes
        CounterfactualGroupKey = [string] $row.groupKeys.counterfactualGroupKey
        HoldoutGroupKey = ('{0}|{1}' -f $row.groupKeys.workloadFamilyKey, $row.groupKeys.hostFingerprintKey)
        HoldoutGroupWorkload = [string] $row.groupKeys.workloadFamilyKey
        HoldoutGroupHost = [string] $row.groupKeys.hostFingerprintKey
        LabelSet = [ordered]@{
            classification = [string] $row.classification
            qualityBucket = $qualityBucket
            outcomeTier = $outcomeTier
        }
    })
}

$curatedDocument = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-curated-manifest-v1'
    curatedManifestId = "$DatasetId-curated"
    createdUtc = [DateTime]::UtcNow.ToString('O')
    normalizedDataset = [ordered]@{
        path = $normalizedWritten.Path
        sha256 = $normalizedWritten.Sha256
        normalizedDatasetId = $normalizedDocument.normalizedDatasetId
    }
    transformation = [ordered]@{
        name = 'adaptive-runtime-normalized-to-curated'
        version = $DatasetVersion
        codeCommit = $codeCommit
    }
    curationPolicy = [ordered]@{
        appendOnly = $true
        includedClassifications = @('accepted_local', 'neutral_local', 'negative_retained')
        excludedClassifications = @('invalid_environment', 'invalid_contract', 'failed_correctness', 'stress_only')
        excludedAnalysisFlags = @(
            'correctness_failed',
            'requested_effective_mismatch',
            'binary_identity_missing',
            'binary_changed',
            'target_health_invalid',
            'generator_health_invalid',
            'observation_missing',
            'observation_stale',
            'observation_saturated',
            'out_of_domain',
            'instrumentation_mismatch',
            'warmup',
            'cooldown',
            'terminal_partial_epoch',
            'policy_mismatch',
            'source_join_failed'
        )
    }
    rowDecisions = @($curatedDecisions | ForEach-Object {
            [ordered]@{
                rowId = $_.RowId
                decision = $_.Decision
                reasonCodes = @($_.ReasonCodes)
                counterfactualGroupKey = $_.CounterfactualGroupKey
                holdoutGroupKey = $_.HoldoutGroupKey
                labelSet = $_.LabelSet
            }
        })
    summary = [ordered]@{
        includedRowCount = @($curatedDecisions | Where-Object { $_.Decision -eq 'included' }).Count
        excludedRowCount = @($curatedDecisions | Where-Object { $_.Decision -eq 'excluded' }).Count
        retainedNegativeRowCount = @($curatedDecisions | Where-Object { $_.LabelSet.outcomeTier -eq 'retained_negative' }).Count
    }
}

$curatedOutputPath = Join-Path $resolvedOutputRoot 'curated\curated-manifest.json'
$curatedWritten = Write-ValidatedJsonDocument -Document $curatedDocument -SchemaPath $curatedSchemaPath -OutputPath $curatedOutputPath

$includedForSplit = @($curatedDecisions | Where-Object { $_.Decision -eq 'included' })
$splitPlan = Get-HoldoutAssignments -IncludedDecisions $includedForSplit -Seed $SplitSeed
$splitAssignments = [System.Collections.Generic.List[object]]::new()
foreach ($decision in $curatedDecisions) {
    $splitName = if ($splitPlan.Status -eq 'ready' -and $decision.Decision -eq 'included') {
        [string] $splitPlan.MapByRowId[$decision.RowId]
    }
    else {
        'holdout_blocked'
    }

    $splitAssignments.Add([ordered]@{
        rowId = $decision.RowId
        split = $splitName
        counterfactualGroupKey = $decision.CounterfactualGroupKey
        holdoutGroupKey = $decision.HoldoutGroupKey
    })
}

$splitDocument = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-split-manifest-v1'
    splitManifestId = "$DatasetId-split"
    createdUtc = [DateTime]::UtcNow.ToString('O')
    curatedManifest = [ordered]@{
        path = $curatedWritten.Path
        sha256 = $curatedWritten.Sha256
        curatedManifestId = $curatedDocument.curatedManifestId
    }
    transformation = [ordered]@{
        name = 'adaptive-runtime-curated-to-split'
        version = $DatasetVersion
        codeCommit = $codeCommit
    }
    strategy = [ordered]@{
        appendOnly = $true
        groupingDimensions = @(
            'workloadFamilyKey',
            'hostFingerprintKey',
            'runConnectionKey',
            'counterfactualGroupKey'
        )
        deterministicSort = 'sha256(seed|dimension) ascending with host and workload buckets checked for agreement'
        seed = $SplitSeed
        insufficientDiversityAction = 'blocked_manifest'
    }
    status = $splitPlan.Status
    blockedReason = $splitPlan.BlockedReason
    assignments = @($splitAssignments)
    summary = [ordered]@{
        trainRowCount = @($splitAssignments | Where-Object { $_.split -eq 'train' }).Count
        validationRowCount = @($splitAssignments | Where-Object { $_.split -eq 'validation' }).Count
        testRowCount = @($splitAssignments | Where-Object { $_.split -eq 'test' }).Count
        blockedRowCount = @($splitAssignments | Where-Object { $_.split -eq 'holdout_blocked' }).Count
    }
}

$splitOutputPath = Join-Path $resolvedOutputRoot 'split\split-manifest.json'
$splitWritten = Write-ValidatedJsonDocument -Document $splitDocument -SchemaPath $splitSchemaPath -OutputPath $splitOutputPath

[ordered]@{
    schemaVersion = 'adaptive-runtime-policy-dataset-pipeline-output-v1'
    catalogPath = $catalogDocument.Path
    catalogSha256 = $catalogDocument.Sha256
    normalizedDatasetPath = $normalizedWritten.Path
    normalizedDatasetSha256 = $normalizedWritten.Sha256
    curatedManifestPath = $curatedWritten.Path
    curatedManifestSha256 = $curatedWritten.Sha256
    splitManifestPath = $splitWritten.Path
    splitManifestSha256 = $splitWritten.Sha256
    splitStatus = $splitDocument.status
} | ConvertTo-Json -Depth 30
