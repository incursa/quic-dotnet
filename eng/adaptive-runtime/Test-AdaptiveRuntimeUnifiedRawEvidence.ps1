# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RawEpochPath,

    [Parameter(Mandatory = $true)]
    [string] $ActorObservationPath,

    [int[]] $SourceRowCount,

    [int[]] $SourceActorObservationRowCount,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-epoch-raw-v3.schema.json'
$actorSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-actor-service-raw-v1.schema.json'
$resolvedRawEpochPath = (Resolve-Path -LiteralPath $RawEpochPath).Path
$resolvedActorObservationPath = (Resolve-Path -LiteralPath $ActorObservationPath).Path
$seenKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$expectedActorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenActorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$lastSequenceByConnection = @{}
$lastActorSequenceByConnection = @{}
$joinFailures = [System.Collections.Generic.List[string]]::new()
$duplicateKeys = [System.Collections.Generic.List[string]]::new()
$outOfOrderKeys = [System.Collections.Generic.List[string]]::new()
$duplicateActorKeys = [System.Collections.Generic.List[string]]::new()
$outOfOrderActorKeys = [System.Collections.Generic.List[string]]::new()
$orphanActorKeys = [System.Collections.Generic.List[string]]::new()
$multiAxisRows = [System.Collections.Generic.List[string]]::new()
$rowCount = 0
$axisRecordCount = 0
$actorEpochRowCount = 0
$actorObservationRowCount = 0
$bufferObservationRowCount = 0
$sourceIndex = 0
$sourceRowOffset = 0

function Resolve-SourceKey {
    param(
        [int[]] $Counts,
        [ref] $Index,
        [ref] $Offset
    )

    while ($null -ne $Counts -and
        $Index.Value -lt $Counts.Count -and
        $Offset.Value -ge $Counts[$Index.Value]) {
        $Index.Value++
        $Offset.Value = 0
    }

    if ($null -ne $Counts -and $Index.Value -ge $Counts.Count) {
        throw 'Retained rows exceed the supplied per-source row counts.'
    }

    if ($null -eq $Counts) {
        return 'source-0'
    }

    return "source-$($Index.Value)"
}

foreach ($line in [System.IO.File]::ReadLines($resolvedRawEpochPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    if (-not ($line | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw "Unified adaptive-runtime raw epoch failed schema validation at row $($rowCount + 1)."
    }

    $record = $line | ConvertFrom-Json -Depth 100
    $epoch = $record.epoch
    $connectionKey = [string] $record.connectionKey
    $sequence = [uint64] $epoch.connectionEpochSequence
    $sourceKey = Resolve-SourceKey `
        -Counts $SourceRowCount `
        -Index ([ref] $sourceIndex) `
        -Offset ([ref] $sourceRowOffset)
    $scopedConnectionKey = "$sourceKey|$connectionKey"
    $rowKey = "$scopedConnectionKey|$sequence"
    $rowCount++
    $sourceRowOffset++

    if (-not $seenKeys.Add($rowKey)) {
        [void] $duplicateKeys.Add($rowKey)
    }

    if ($lastSequenceByConnection.ContainsKey($scopedConnectionKey) -and
        $sequence -le [uint64] $lastSequenceByConnection[$scopedConnectionKey]) {
        [void] $outOfOrderKeys.Add($rowKey)
    }
    $lastSequenceByConnection[$scopedConnectionKey] = $sequence

    $observationSequence = [uint64] $epoch.connectionObservation.connectionEpochSequence
    $snapshotSequence = [uint64] $epoch.receiveCreditSnapshot.epochSequence
    $boundarySequence = [uint64] $epoch.postServiceBoundary.connectionEpochSequence
    $stage1Sequence = [uint64] $epoch.stage1.epochIndex
    $observationEndTicks = [long] $epoch.connectionObservation.epochEndTicks
    $boundaryEndTicks = [long] $epoch.postServiceBoundary.epochEndTicks
    if ($sequence -ne $observationSequence -or
        $sequence -ne $snapshotSequence -or
        $sequence -ne $boundarySequence -or
        $sequence -ne $stage1Sequence -or
        $observationEndTicks -ne $boundaryEndTicks) {
        [void] $joinFailures.Add($rowKey)
    }

    $stage1Records = @(
        $epoch.stage1.applicationSendTurnPlanning,
        $epoch.stage1.applicationSendBatchFormation,
        $epoch.stage1.queuedSendBurstBudget,
        $epoch.stage1.oversizedWriteAdmissionQuantum
    )
    $axisRecordCount += $stage1Records.Count
    $nonLegacyApplied = @($stage1Records | Where-Object {
        [string] $_.decision.appliedValue -ne 'LegacyCurrent'
    }).Count
    if ([string] $epoch.receiveCreditSnapshot.appliedPolicy -notin
        @('LegacyCurrent', 'legacy_current')) {
        $nonLegacyApplied++
    }
    if ($nonLegacyApplied -gt 1) {
        [void] $multiAxisRows.Add($rowKey)
    }

    $actorSummary = $epoch.actorService
    if ([bool] $actorSummary.hasObservation) {
        $actorEpochRowCount++
        $first = [uint64] $actorSummary.firstServiceSequence
        $last = [uint64] $actorSummary.lastServiceSequence
        $turnCount = [uint64] $actorSummary.actorTurnCount
        if ($first -eq 0 -or $last -lt $first -or
            $turnCount -ne (($last - $first) + 1)) {
            [void] $joinFailures.Add("$rowKey|actor-range")
        }
        else {
            for ($actorSequence = $first;
                $actorSequence -le $last;
                $actorSequence++) {
                [void] $expectedActorKeys.Add(
                    "$scopedConnectionKey|$actorSequence")
                if ($actorSequence -eq [uint64]::MaxValue) {
                    break
                }
            }
        }
    }
    elseif ([uint64] $actorSummary.firstServiceSequence -ne 0 -or
        [uint64] $actorSummary.lastServiceSequence -ne 0 -or
        [uint64] $actorSummary.actorTurnCount -ne 0) {
        [void] $joinFailures.Add("$rowKey|actor-empty")
    }

    if ([uint64] $actorSummary.interServiceGapObservationCount -gt
        [uint64] $actorSummary.actorTurnCount) {
        [void] $joinFailures.Add("$rowKey|actor-inter-service-gap")
    }
    if ([uint64] $actorSummary.deadlineLatenessObservationCount -gt
        [uint64] $actorSummary.timerCount) {
        [void] $joinFailures.Add("$rowKey|actor-deadline-lateness")
    }
    if ([bool] $epoch.bufferCopy.hasObservation) {
        $bufferObservationRowCount++
    }

    if ([bool] $epoch.postServiceBoundary.actorObservationPublished -and
        -not [bool] $actorSummary.hasObservation) {
        [void] $joinFailures.Add("$rowKey|actor")
    }
}

if ($rowCount -eq 0) {
    throw 'No unified adaptive-runtime raw epoch rows were found.'
}
if ($null -ne $SourceRowCount -and
    ($SourceRowCount | Measure-Object -Sum).Sum -ne $rowCount) {
    throw (
        "Unified adaptive-runtime source row counts do not match retained rows: " +
        "sources=$(($SourceRowCount | Measure-Object -Sum).Sum), rows=$rowCount.")
}

$actorSourceIndex = 0
$actorSourceRowOffset = 0
foreach ($line in [System.IO.File]::ReadLines($resolvedActorObservationPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    if (-not ($line | Test-Json -SchemaFile $actorSchemaPath -ErrorAction Stop)) {
        throw "Actor-service raw observation failed schema validation at row $($actorObservationRowCount + 1)."
    }

    $record = $line | ConvertFrom-Json -Depth 100
    $sourceKey = Resolve-SourceKey `
        -Counts $SourceActorObservationRowCount `
        -Index ([ref] $actorSourceIndex) `
        -Offset ([ref] $actorSourceRowOffset)
    $scopedConnectionKey = "$sourceKey|$([string] $record.connectionKey)"
    $sequence = [uint64] $record.observation.serviceSequence
    $rowKey = "$scopedConnectionKey|$sequence"
    $actorObservationRowCount++
    $actorSourceRowOffset++

    if (-not $seenActorKeys.Add($rowKey)) {
        [void] $duplicateActorKeys.Add($rowKey)
    }
    if ($lastActorSequenceByConnection.ContainsKey($scopedConnectionKey) -and
        $sequence -le
            [uint64] $lastActorSequenceByConnection[$scopedConnectionKey]) {
        [void] $outOfOrderActorKeys.Add($rowKey)
    }
    $lastActorSequenceByConnection[$scopedConnectionKey] = $sequence

    if (-not $expectedActorKeys.Remove($rowKey)) {
        [void] $orphanActorKeys.Add($rowKey)
    }
}

if ($null -ne $SourceActorObservationRowCount -and
    ($SourceActorObservationRowCount | Measure-Object -Sum).Sum -ne
        $actorObservationRowCount) {
    throw (
        "Actor-service source row counts do not match retained rows: " +
        "sources=$(($SourceActorObservationRowCount | Measure-Object -Sum).Sum), " +
        "rows=$actorObservationRowCount.")
}

$valid =
    $duplicateKeys.Count -eq 0 -and
    $outOfOrderKeys.Count -eq 0 -and
    $duplicateActorKeys.Count -eq 0 -and
    $outOfOrderActorKeys.Count -eq 0 -and
    $orphanActorKeys.Count -eq 0 -and
    $expectedActorKeys.Count -eq 0 -and
    $joinFailures.Count -eq 0 -and
    $multiAxisRows.Count -eq 0 -and
    $axisRecordCount -eq ($rowCount * 4)
if (-not $valid) {
    throw (
        "Unified adaptive-runtime raw evidence failed semantic validation: " +
        "duplicates=$($duplicateKeys.Count), outOfOrder=$($outOfOrderKeys.Count), " +
        "actorDuplicates=$($duplicateActorKeys.Count), " +
        "actorOutOfOrder=$($outOfOrderActorKeys.Count), " +
        "actorOrphans=$($orphanActorKeys.Count), " +
        "actorMissing=$($expectedActorKeys.Count), " +
        "joinFailures=$($joinFailures.Count), multiAxis=$($multiAxisRows.Count), " +
        "axisRecords=$axisRecordCount, expectedAxisRecords=$($rowCount * 4).")
}

[ordered]@{
    schemaVersion = 'adaptive-runtime-unified-raw-validation-v4'
    valid = $true
    rawEpochRowCount = $rowCount
    axisRecordCount = $axisRecordCount
    connectionCount = $lastSequenceByConnection.Count
    actorEpochRowCount = $actorEpochRowCount
    actorObservationRowCount = $actorObservationRowCount
    bufferObservationRowCount = $bufferObservationRowCount
    duplicateKeyCount = $duplicateKeys.Count
    outOfOrderKeyCount = $outOfOrderKeys.Count
    duplicateActorKeyCount = $duplicateActorKeys.Count
    outOfOrderActorKeyCount = $outOfOrderActorKeys.Count
    orphanActorKeyCount = $orphanActorKeys.Count
    missingActorKeyCount = $expectedActorKeys.Count
    joinFailureCount = $joinFailures.Count
    multiAxisVariationCount = $multiAxisRows.Count
} | ConvertTo-Json -Depth 20
