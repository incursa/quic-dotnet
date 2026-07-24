# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $NormalizedDatasetPath,

    [Parameter(Mandatory = $true)]
    [string] $CuratedManifestPath,

    [Parameter(Mandatory = $true)]
    [string] $SplitManifestPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [string] $AnalysisId = 'application-send-turn-analysis-v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

function Get-CountMap {
    param(
        [AllowEmptyCollection()]
        [object[]] $Values
    )

    $counts = [ordered]@{}
    foreach ($value in @($Values | ForEach-Object { [string] $_ } | Sort-Object)) {
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = 'null'
        }
        if (-not $counts.Contains($value)) {
            $counts[$value] = 0
        }
        $counts[$value]++
    }
    return $counts
}

function Get-NearestRankValue {
    param(
        [AllowEmptyCollection()]
        [long[]] $SortedValues,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0.0, 1.0)]
        [double] $Percentile
    )

    if ($SortedValues.Count -eq 0) {
        return $null
    }

    $index = [int] [Math]::Ceiling($Percentile * $SortedValues.Count) - 1
    $index = [Math]::Max(0, [Math]::Min($SortedValues.Count - 1, $index))
    return [long] $SortedValues[$index]
}

function Get-FeatureDistribution {
    param(
        [AllowEmptyCollection()]
        [object[]] $Rows,

        [Parameter(Mandatory = $true)]
        [string] $FeatureName
    )

    $values = [System.Collections.Generic.List[long]]::new()
    foreach ($row in $Rows) {
        $property = $row.modelFeatures.PSObject.Properties[$FeatureName]
        if ($null -ne $property -and $null -ne $property.Value) {
            $values.Add([long] $property.Value)
        }
    }

    [long[]] $sorted = @($values | Sort-Object)
    return [ordered]@{
        count = $sorted.Count
        missingCount = $Rows.Count - $sorted.Count
        minimum = if ($sorted.Count -eq 0) { $null } else { [long] $sorted[0] }
        p50 = Get-NearestRankValue -SortedValues $sorted -Percentile 0.50
        p95 = Get-NearestRankValue -SortedValues $sorted -Percentile 0.95
        maximum = if ($sorted.Count -eq 0) { $null } else { [long] $sorted[-1] }
    }
}

function Assert-EqualStringSet {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [AllowEmptyCollection()]
        [string[]] $Expected,

        [AllowEmptyCollection()]
        [string[]] $Actual
    )

    [string[]] $expectedSorted = @($Expected | Sort-Object -Unique)
    [string[]] $actualSorted = @($Actual | Sort-Object -Unique)
    if ($expectedSorted.Count -ne $actualSorted.Count -or
        @(Compare-Object -ReferenceObject $expectedSorted -DifferenceObject $actualSorted).Count -ne 0) {
        throw "$Name does not contain the exact normalized row-ID set."
    }
}

$repositoryRoot = Get-AdaptiveRuntimeRepositoryRoot
$normalizedSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-normalized-dataset-v1.schema.json'
$curatedSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-curated-manifest-v1.schema.json'
$splitSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-split-manifest-v1.schema.json'
$analysisSchemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-application-send-turn-analysis-v1.schema.json'

$normalized = Read-ValidatedJsonDocument -Path $NormalizedDatasetPath -SchemaPath $normalizedSchemaPath
$curated = Read-ValidatedJsonDocument -Path $CuratedManifestPath -SchemaPath $curatedSchemaPath
$split = Read-ValidatedJsonDocument -Path $SplitManifestPath -SchemaPath $splitSchemaPath

$rows = @($normalized.Document.rows)
$rowIds = @($rows | ForEach-Object { [string] $_.rowId })
if (@($rowIds | Sort-Object -Unique).Count -ne $rowIds.Count) {
    throw 'Normalized dataset contains duplicate row IDs.'
}

$wrongAxisRows = @($rows | Where-Object { [string] $_.policyAxis -ne 'application_send_turn_planning' })
if ($wrongAxisRows.Count -ne 0) {
    throw "Application-send turn analysis cannot mix $($wrongAxisRows.Count) row(s) from another policy axis."
}
$closedPolicyValues = @('legacy_current', 'conservative')
foreach ($propertyName in @('selectedPolicy', 'appliedPolicy', 'forcedPolicy', 'shadowRecommendation')) {
    $invalidPolicyRows = @($rows | Where-Object {
        $value = $_.PSObject.Properties[$propertyName].Value
        $null -ne $value -and $closedPolicyValues -notcontains [string] $value
    })
    if ($invalidPolicyRows.Count -ne 0) {
        throw "Application-send turn analysis found $($invalidPolicyRows.Count) row(s) with an invalid $propertyName value."
    }
}
if ([int] $normalized.Document.summary.joinedRowCount -ne $rows.Count) {
    throw 'Normalized dataset summary does not match its row count.'
}

$normalizedDatasetId = [string] $normalized.Document.normalizedDatasetId
if ([string] $curated.Document.normalizedDataset.normalizedDatasetId -ne $normalizedDatasetId -or
    [string] $curated.Document.normalizedDataset.sha256 -ne $normalized.Sha256) {
    throw 'Curated manifest does not identify the supplied normalized dataset and checksum.'
}
if ([string] $split.Document.curatedManifest.curatedManifestId -ne
        [string] $curated.Document.curatedManifestId -or
    [string] $split.Document.curatedManifest.sha256 -ne $curated.Sha256) {
    throw 'Split manifest does not identify the supplied curated manifest and checksum.'
}

$curatedDecisions = @($curated.Document.rowDecisions)
$curatedRowIds = @($curatedDecisions | ForEach-Object { [string] $_.rowId })
if (@($curatedRowIds | Sort-Object -Unique).Count -ne $curatedRowIds.Count) {
    throw 'Curated manifest contains duplicate row IDs.'
}
Assert-EqualStringSet -Name 'Curated manifest' -Expected $rowIds -Actual $curatedRowIds

$splitAssignments = @($split.Document.assignments)
$splitRowIds = @($splitAssignments | ForEach-Object { [string] $_.rowId })
if (@($splitRowIds | Sort-Object -Unique).Count -ne $splitRowIds.Count) {
    throw 'Split manifest contains duplicate row IDs.'
}
Assert-EqualStringSet -Name 'Split manifest' -Expected $rowIds -Actual $splitRowIds

$curatedDecisionByRowId = @{}
foreach ($decision in $curatedDecisions) {
    $curatedDecisionByRowId[[string] $decision.rowId] = [string] $decision.decision
}

$includedRows = @($rows | Where-Object {
    $curatedDecisionByRowId.ContainsKey([string] $_.rowId) -and
    $curatedDecisionByRowId[[string] $_.rowId] -eq 'included'
})
$excludedRows = @($rows | Where-Object {
    -not $curatedDecisionByRowId.ContainsKey([string] $_.rowId) -or
    $curatedDecisionByRowId[[string] $_.rowId] -ne 'included'
})
if ([int] $curated.Document.summary.includedRowCount -ne $includedRows.Count -or
    [int] $curated.Document.summary.excludedRowCount -ne $excludedRows.Count) {
    throw 'Curated manifest summary does not match its row decisions.'
}
$splitSummaryRowCount =
    [int] $split.Document.summary.trainRowCount +
    [int] $split.Document.summary.validationRowCount +
    [int] $split.Document.summary.testRowCount +
    [int] $split.Document.summary.blockedRowCount
if ($splitSummaryRowCount -ne $splitAssignments.Count) {
    throw 'Split manifest summary does not match its row assignments.'
}

$numericFeatures = @(
    'queuedApplicationWrites',
    'outboundBacklogBytes',
    'distinctQueuedSendStreams',
    'oldestQueuedSendAgeMicros',
    'queueDelayEwmaMicros',
    'actorServiceTimeEwmaMicros',
    'queueToServiceRatioQ16',
    'burstLimitHitsEpoch',
    'congestionWindowBytes',
    'bytesInFlight',
    'retainedSendBuffers',
    'retainedSendBytes',
    'missingSignalMask',
    'staleSignalMask',
    'lifecycleFlags'
)
$featureDistributions = [ordered]@{}
foreach ($featureName in $numericFeatures) {
    $featureDistributions[$featureName] =
        Get-FeatureDistribution -Rows $includedRows -FeatureName $featureName
}

$includedSamples = @(
    $includedRows |
        Group-Object -Property joinKey |
        ForEach-Object { $_.Group[0] }
)
$sampleOutcomeProperties = [ordered]@{
    throughputMiBPerSecond = 'throughputMiBPerSecond'
    latencyP95Ms = 'latencyP95Ms'
    bufferPoolRentedKiB = 'bufferPoolRentedKiB'
    bufferPoolOutstandingPeakKiB = 'bufferPoolOutstandingPeakKiB'
    managedAllocatedKiB = 'managedAllocatedKiB'
    peakRetainedKiB = 'peakRetainedKiB'
}
$sampleOutcomeDistributions = [ordered]@{}
foreach ($outcomeName in $sampleOutcomeProperties.Keys) {
    $values = @(
        $includedSamples |
            ForEach-Object { $_.sampleScopedOutcomes.PSObject.Properties[$outcomeName].Value } |
            Where-Object { $null -ne $_ } |
            ForEach-Object { [double] $_ } |
            Sort-Object
    )
    $sampleOutcomeDistributions[$outcomeName] = [ordered]@{
        sampleCount = $values.Count
        missingSampleCount = $includedSamples.Count - $values.Count
        minimum = if ($values.Count -eq 0) { $null } else { [double] $values[0] }
        maximum = if ($values.Count -eq 0) { $null } else { [double] $values[-1] }
    }
}

$forbiddenFields = @(
    'scenarioId',
    'payloadBytes',
    'requestedConcurrency',
    'peerIdentity',
    'url',
    'applicationIdentity'
)
$modelFeatureNames = @(
    $rows |
        ForEach-Object { $_.modelFeatures.PSObject.Properties.Name } |
        Select-Object -Unique
)
$forbiddenFieldsFound = @($forbiddenFields | Where-Object { $modelFeatureNames -contains $_ })
$workloadIdentitySeparated = @($rows | Where-Object {
    $null -eq $_.workloadShape -or $null -eq $_.modelFeatures
}).Count -eq 0

$splitStatus = [string] $split.Document.status
$distinctAppliedPolicies = @($includedRows.appliedPolicy | Select-Object -Unique)
$ruleStatus = if ($splitStatus -ne 'ready') {
    'holdout_blocked'
}
elseif ($distinctAppliedPolicies.Count -lt 2) {
    'insufficient_counterfactual_coverage'
}
else {
    'review_required'
}
$ruleReason = switch ($ruleStatus) {
    'holdout_blocked' {
        "Split status is '$splitStatus'; complete host and workload holdouts are unavailable."
    }
    'insufficient_counterfactual_coverage' {
        'Fewer than two applied policy values are represented; shadow recommendations are not counterfactual outcomes.'
    }
    default {
        'Eligible counterfactual coverage exists, but any deterministic rule proposal still requires human review.'
    }
}

$report = [ordered]@{
    schemaVersion = 'adaptive-runtime-application-send-turn-analysis-v1'
    analysisId = $AnalysisId
    createdUtc = [DateTime]::UtcNow.ToString('O')
    codeCommit = Get-GitCommitHash -RepositoryRoot $repositoryRoot
    source = [ordered]@{
        normalizedDataset = [ordered]@{
            path = $normalized.Path
            sha256 = $normalized.Sha256
        }
        curatedManifest = [ordered]@{
            path = $curated.Path
            sha256 = $curated.Sha256
        }
        splitManifest = [ordered]@{
            path = $split.Path
            sha256 = $split.Sha256
        }
    }
    scope = [ordered]@{
        policyAxis = 'application_send_turn_planning'
        rowCount = $rows.Count
        includedRowCount = $includedRows.Count
        excludedRowCount = $excludedRows.Count
        includedSampleCount = $includedSamples.Count
        hostFingerprintCount = @($rows.groupKeys.hostFingerprintKey | Select-Object -Unique).Count
        workloadFamilyCount = @($rows.groupKeys.workloadFamilyKey | Select-Object -Unique).Count
        splitStatus = $splitStatus
    }
    quality = [ordered]@{
        classificationCounts = Get-CountMap -Values @($rows.classification)
        modeCounts = Get-CountMap -Values @($rows.mode)
        appliedPolicyCounts = Get-CountMap -Values @($rows.appliedPolicy)
        reasonCounts = Get-CountMap -Values @($rows.reasonCode)
        recommendationCounts = Get-CountMap -Values @($rows.shadowRecommendation)
        exclusionFlagCounts = Get-CountMap -Values @(
            $rows | ForEach-Object { @($_.sourceExclusionFlags) }
        )
        outOfDomainRowCount = @($rows | Where-Object { [bool] $_.modelFeatures.outOfDomain }).Count
    }
    featureDistributions = $featureDistributions
    sampleScopedOutcomes = [ordered]@{
        scope = 'descriptive_only_not_epoch_independent'
        distributions = $sampleOutcomeDistributions
    }
    leakageAudit = [ordered]@{
        workloadIdentitySeparated = $workloadIdentitySeparated
        forbiddenFieldsChecked = $forbiddenFields
        forbiddenFieldsFound = $forbiddenFieldsFound
        passed = $workloadIdentitySeparated -and $forbiddenFieldsFound.Count -eq 0
    }
    ruleProposal = [ordered]@{
        status = $ruleStatus
        reason = $ruleReason
        candidateRule = $null
        activeInternalAuthorized = $false
    }
}

$written = Write-ValidatedJsonDocument `
    -Document $report `
    -SchemaPath $analysisSchemaPath `
    -OutputPath $OutputPath

[ordered]@{
    schemaVersion = 'adaptive-runtime-application-send-turn-analysis-output-v1'
    reportPath = $written.Path
    reportSha256 = $written.Sha256
    rowCount = $rows.Count
    includedRowCount = $includedRows.Count
    excludedRowCount = $excludedRows.Count
    ruleProposalStatus = $ruleStatus
} | ConvertTo-Json -Depth 10
