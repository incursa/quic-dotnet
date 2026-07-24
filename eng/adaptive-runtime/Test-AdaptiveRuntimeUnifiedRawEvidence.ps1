# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RawEpochPath,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-epoch-raw-v1.schema.json'
$resolvedRawEpochPath = (Resolve-Path -LiteralPath $RawEpochPath).Path
$seenKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$lastSequenceByConnection = @{}
$joinFailures = [System.Collections.Generic.List[string]]::new()
$duplicateKeys = [System.Collections.Generic.List[string]]::new()
$outOfOrderKeys = [System.Collections.Generic.List[string]]::new()
$multiAxisRows = [System.Collections.Generic.List[string]]::new()
$rowCount = 0
$axisRecordCount = 0
$actorObservationRowCount = 0
$bufferObservationRowCount = 0

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
    $rowKey = "$connectionKey|$sequence"
    $rowCount++

    if (-not $seenKeys.Add($rowKey)) {
        [void] $duplicateKeys.Add($rowKey)
    }

    if ($lastSequenceByConnection.ContainsKey($connectionKey) -and
        $sequence -le [uint64] $lastSequenceByConnection[$connectionKey]) {
        [void] $outOfOrderKeys.Add($rowKey)
    }
    $lastSequenceByConnection[$connectionKey] = $sequence

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

    if ([bool] $epoch.actorService.hasObservation) {
        $actorObservationRowCount++
    }
    if ([bool] $epoch.bufferCopy.hasObservation) {
        $bufferObservationRowCount++
    }

    if ([bool] $epoch.postServiceBoundary.actorObservationPublished -and
        -not [bool] $epoch.actorService.hasObservation) {
        [void] $joinFailures.Add("$rowKey|actor")
    }
}

if ($rowCount -eq 0) {
    throw 'No unified adaptive-runtime raw epoch rows were found.'
}

$valid =
    $duplicateKeys.Count -eq 0 -and
    $outOfOrderKeys.Count -eq 0 -and
    $joinFailures.Count -eq 0 -and
    $multiAxisRows.Count -eq 0 -and
    $axisRecordCount -eq ($rowCount * 4)
if (-not $valid) {
    throw (
        "Unified adaptive-runtime raw evidence failed semantic validation: " +
        "duplicates=$($duplicateKeys.Count), outOfOrder=$($outOfOrderKeys.Count), " +
        "joinFailures=$($joinFailures.Count), multiAxis=$($multiAxisRows.Count), " +
        "axisRecords=$axisRecordCount, expectedAxisRecords=$($rowCount * 4).")
}

[ordered]@{
    schemaVersion = 'adaptive-runtime-unified-raw-validation-v1'
    valid = $true
    rawEpochRowCount = $rowCount
    axisRecordCount = $axisRecordCount
    connectionCount = $lastSequenceByConnection.Count
    actorObservationRowCount = $actorObservationRowCount
    bufferObservationRowCount = $bufferObservationRowCount
    duplicateKeyCount = $duplicateKeys.Count
    outOfOrderKeyCount = $outOfOrderKeys.Count
    joinFailureCount = $joinFailures.Count
    multiAxisVariationCount = $multiAxisRows.Count
} | ConvertTo-Json -Depth 20
