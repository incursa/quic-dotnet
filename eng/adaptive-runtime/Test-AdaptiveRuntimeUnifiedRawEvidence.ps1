# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RawEpochPath,

    [Parameter(Mandatory = $true)]
    [string] $ActorObservationPath,

    [Parameter(Mandatory = $true)]
    [string] $AdaptiveBackpressureObservationPath,

    [Parameter(Mandatory = $true)]
    [string] $PacketFlushCadenceObservationPath,

    [int[]] $SourceRowCount,

    [int[]] $SourceActorObservationRowCount,

    [int[]] $SourceAdaptiveBackpressureObservationRowCount,

    [int[]] $SourcePacketFlushCadenceObservationRowCount,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-epoch-raw-v9.schema.json'
$actorSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-actor-service-raw-v4.schema.json'
$adaptiveBackpressureSchemaPath =
    Join-Path $RepositoryRoot 'schemas\adaptive-runtime-backpressure-raw-v1.schema.json'
$packetFlushCadenceSchemaPath =
    Join-Path $RepositoryRoot 'schemas\adaptive-runtime-packet-flush-cadence-raw-v1.schema.json'
$resolvedRawEpochPath = (Resolve-Path -LiteralPath $RawEpochPath).Path
$resolvedActorObservationPath = (Resolve-Path -LiteralPath $ActorObservationPath).Path
$resolvedAdaptiveBackpressureObservationPath =
    (Resolve-Path -LiteralPath $AdaptiveBackpressureObservationPath).Path
$resolvedPacketFlushCadenceObservationPath =
    (Resolve-Path -LiteralPath $PacketFlushCadenceObservationPath).Path
$seenKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$expectedActorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenActorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$expectedAdaptiveBackpressureKeys =
    [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$seenAdaptiveBackpressureKeys =
    [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$expectedPacketFlushCadenceKeys =
    [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$seenPacketFlushCadenceKeys =
    [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$lastSequenceByConnection = @{}
$lastActorSequenceByConnection = @{}
$lastAdaptiveBackpressureSequenceByConnection = @{}
$lastPacketFlushCadenceSequenceByConnection = @{}
$actorEpochSummaryByRowKey = @{}
$actorEpochRowByActorKey = @{}
$actorContenderCountByEpoch = @{}
$actorContenderMaximumByEpoch = @{}
$actorContendedTurnCountByEpoch = @{}
$actorAcceptedWorkCountByEpoch = @{}
$actorAcceptedWorkTotalByEpoch = @{}
$actorAcceptedWorkMaximumByEpoch = @{}
$actorAcceptedWorkRemainingTurnsByEpoch = @{}
$actorContinuationByEpoch = @{}
$adaptiveBackpressureEpochByOperationKey = @{}
$adaptiveBackpressureSummaryByEpoch = @{}
$adaptiveBackpressureAggregateByEpoch = @{}
$packetFlushCadenceEpochByOperationKey = @{}
$packetFlushCadenceSummaryByEpoch = @{}
$packetFlushCadenceAggregateByEpoch = @{}
$joinFailures = [System.Collections.Generic.List[string]]::new()
$duplicateKeys = [System.Collections.Generic.List[string]]::new()
$outOfOrderKeys = [System.Collections.Generic.List[string]]::new()
$duplicateActorKeys = [System.Collections.Generic.List[string]]::new()
$outOfOrderActorKeys = [System.Collections.Generic.List[string]]::new()
$orphanActorKeys = [System.Collections.Generic.List[string]]::new()
$duplicateAdaptiveBackpressureKeys =
    [System.Collections.Generic.List[string]]::new()
$outOfOrderAdaptiveBackpressureKeys =
    [System.Collections.Generic.List[string]]::new()
$orphanAdaptiveBackpressureKeys =
    [System.Collections.Generic.List[string]]::new()
$duplicatePacketFlushCadenceKeys =
    [System.Collections.Generic.List[string]]::new()
$outOfOrderPacketFlushCadenceKeys =
    [System.Collections.Generic.List[string]]::new()
$orphanPacketFlushCadenceKeys =
    [System.Collections.Generic.List[string]]::new()
$multiAxisRows = [System.Collections.Generic.List[string]]::new()
$rowCount = 0
$axisRecordCount = 0
$actorEpochRowCount = 0
$actorObservationRowCount = 0
$bufferObservationRowCount = 0
$adaptiveBackpressureEpochRowCount = 0
$adaptiveBackpressureObservationRowCount = 0
$packetFlushCadenceEpochRowCount = 0
$packetFlushCadenceObservationRowCount = 0
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

function Test-ActorValidityFlag {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Value,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [uint64] $Mask
    )

    if ($Value -is [string]) {
        return ([string] $Value) -match `
            "(^|, )$([regex]::Escape($Name))($|, )"
    }

    return (([uint64] $Value -band $Mask) -ne 0)
}

function Add-ActorUInt64Saturating {
    param(
        [uint64] $Current,
        [uint64] $Value
    )

    if ([uint64]::MaxValue - $Current -lt $Value) {
        return [uint64]::MaxValue
    }

    return [uint64] ($Current + $Value)
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
    $axisRecordCount += $stage1Records.Count + 3
    $nonLegacyApplied = @($stage1Records | Where-Object {
        [string] $_.decision.appliedValue -ne 'LegacyCurrent'
    }).Count
    if ([string] $epoch.receiveCreditSnapshot.appliedPolicy -notin
        @('LegacyCurrent', 'legacy_current')) {
        $nonLegacyApplied++
    }
    $bufferSummary = $epoch.bufferCopy
    $bufferSnapshot = $bufferSummary.policySnapshot
    if ([string] $bufferSnapshot.appliedValue -ne 'LegacyCurrent') {
        $nonLegacyApplied++
    }
    $backpressureSummary = $epoch.adaptiveBackpressure
    $backpressureSnapshot = $backpressureSummary.policySnapshot
    if ([string] $backpressureSnapshot.appliedValue -ne 'LegacyCurrent') {
        $nonLegacyApplied++
    }
    $packetFlushSummary = $epoch.packetFlushCadence
    $packetFlushSnapshot = $packetFlushSummary.policySnapshot
    if ([string] $packetFlushSnapshot.appliedValue -ne 'LegacyCurrent') {
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
            $actorEpochSummaryByRowKey[$rowKey] = [ordered]@{
                observationCount =
                    [uint64] $actorSummary.serviceContenderObservationCount
                maximum =
                    [uint64] $actorSummary.maximumServiceContenderCount
                contendedTurnCount =
                    [uint64] $actorSummary.contendedTurnCount
                acceptedWorkObservationCount =
                    [uint64] $actorSummary.acceptedConnectionWorkObservationCount
                acceptedWorkTotal =
                    [uint64] $actorSummary.totalAcceptedConnectionWorkItemsAfterCurrent
                acceptedWorkMaximum =
                    [uint64] $actorSummary.maximumAcceptedConnectionWorkItemsAfterCurrent
                acceptedWorkRemainingTurns =
                    [uint64] $actorSummary.turnsWithAcceptedConnectionWorkRemaining
                completeContinuationAssessmentTurnCount =
                    [uint64] $actorSummary.completeContinuationAssessmentTurnCount
                applicationSendContinuation = [ordered]@{
                    Observation = [uint64] $actorSummary.applicationSendContinuationObservationCount
                    Drained = [uint64] $actorSummary.applicationSendContinuationDrainedTurnCount
                    Scheduled = [uint64] $actorSummary.applicationSendContinuationScheduledTurnCount
                    Blocked = [uint64] $actorSummary.applicationSendContinuationBlockedTurnCount
                    Ready = [uint64] $actorSummary.applicationSendContinuationReadyTurnCount
                    Maximum = [uint64] $actorSummary.maximumApplicationSendContinuationRemainingCount
                }
                flowControlContinuation = [ordered]@{
                    Observation = [uint64] $actorSummary.flowControlContinuationObservationCount
                    Drained = [uint64] $actorSummary.flowControlContinuationDrainedTurnCount
                    Scheduled = [uint64] $actorSummary.flowControlContinuationScheduledTurnCount
                    Blocked = [uint64] $actorSummary.flowControlContinuationBlockedTurnCount
                    Ready = [uint64] $actorSummary.flowControlContinuationReadyTurnCount
                    Maximum = [uint64] $actorSummary.maximumFlowControlContinuationRemainingCount
                }
                streamCapacityContinuation = [ordered]@{
                    Observation = [uint64] $actorSummary.streamCapacityContinuationObservationCount
                    Drained = [uint64] $actorSummary.streamCapacityContinuationDrainedTurnCount
                    Scheduled = [uint64] $actorSummary.streamCapacityContinuationScheduledTurnCount
                    Blocked = [uint64] $actorSummary.streamCapacityContinuationBlockedTurnCount
                    Ready = [uint64] $actorSummary.streamCapacityContinuationReadyTurnCount
                    Maximum = [uint64] $actorSummary.maximumStreamCapacityContinuationRemainingCount
                }
            }
            for ($actorSequence = $first;
                $actorSequence -le $last;
                $actorSequence++) {
                $actorKey = "$scopedConnectionKey|$actorSequence"
                [void] $expectedActorKeys.Add($actorKey)
                if ($actorEpochRowByActorKey.ContainsKey($actorKey)) {
                    [void] $joinFailures.Add(
                        "$rowKey|actor-range-overlap")
                }
                else {
                    $actorEpochRowByActorKey[$actorKey] = $rowKey
                }
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
    if ([uint64] $actorSummary.serviceContenderObservationCount -gt
        [uint64] $actorSummary.actorTurnCount -or
        [uint64] $actorSummary.contendedTurnCount -gt
        [uint64] $actorSummary.serviceContenderObservationCount) {
        [void] $joinFailures.Add("$rowKey|actor-service-contender-count")
    }
    if ([uint64] $actorSummary.acceptedConnectionWorkObservationCount -gt
        [uint64] $actorSummary.actorTurnCount -or
        [uint64] $actorSummary.turnsWithAcceptedConnectionWorkRemaining -gt
        [uint64] $actorSummary.acceptedConnectionWorkObservationCount -or
        [uint64] $actorSummary.maximumAcceptedConnectionWorkItemsAfterCurrent -gt
        [uint64] $actorSummary.totalAcceptedConnectionWorkItemsAfterCurrent) {
        [void] $joinFailures.Add(
            "$rowKey|actor-accepted-connection-work-count")
    }
    if ([bool] $bufferSummary.hasObservation) {
        $bufferObservationRowCount++
    }
    $bufferOperationCount = [uint64] $bufferSummary.operationCount
    $bufferPathCount =
        [uint64] $bufferSummary.applicationWriteRequestCount +
        [uint64] $bufferSummary.oversizedRawQueueCount +
        [uint64] $bufferSummary.formattedStreamPayloadCount +
        [uint64] $bufferSummary.combinedApplicationSendCount +
        [uint64] $bufferSummary.sentPacketPlaintextRetentionCount +
        [uint64] $bufferSummary.retransmissionCloneCount +
        [uint64] $bufferSummary.receiveSegmentCount +
        [uint64] $bufferSummary.outboundPacketProtectionCount
    $bufferKindCount =
        [uint64] $bufferSummary.copyCount +
        [uint64] $bufferSummary.reuseAndCopyCount +
        [uint64] $bufferSummary.formatCount +
        [uint64] $bufferSummary.combineCount +
        [uint64] $bufferSummary.retainCount +
        [uint64] $bufferSummary.cloneCount +
        [uint64] $bufferSummary.protectCount
    if ($bufferPathCount -ne $bufferOperationCount -or
        $bufferKindCount -ne $bufferOperationCount -or
        [uint64] $bufferSummary.totalAppliedSourceSegments -gt
            [uint64] $bufferSummary.totalLegalSourceSegments -or
        [uint64] $bufferSummary.totalLogicalBytes -gt
            [uint64] $bufferSummary.totalLegalLogicalBytes -or
        [uint64] $bufferSummary.memoryConservativeOperationCount -gt
            $bufferOperationCount -or
        [uint64] $bufferSummary.safetyOverrideOperationCount -gt
            $bufferOperationCount -or
        [uint64] $bufferSummary.fallbackOperationCount -gt
            $bufferOperationCount) {
        [void] $joinFailures.Add("$rowKey|buffer-aggregate")
    }
    if ([bool] $bufferSummary.hasObservation) {
        if ($bufferOperationCount -eq 0 -or
            [uint64] $bufferSummary.firstOperationSequence -eq 0 -or
            [uint64] $bufferSummary.lastOperationSequence -lt
                [uint64] $bufferSummary.firstOperationSequence) {
            [void] $joinFailures.Add("$rowKey|buffer-range")
        }
    }
    elseif ($bufferOperationCount -ne 0 -or
        [uint64] $bufferSummary.firstOperationSequence -ne 0 -or
        [uint64] $bufferSummary.lastOperationSequence -ne 0) {
        [void] $joinFailures.Add("$rowKey|buffer-empty")
    }
    if ([bool] $bufferSnapshot.hasForcedValue) {
        if ([string] $bufferSnapshot.selectionSource -ne 'Forced' -or
            [string] $bufferSnapshot.selectedValue -ne
                [string] $bufferSnapshot.forcedValue -or
            [string] $bufferSnapshot.appliedValue -ne
                [string] $bufferSnapshot.forcedValue) {
            [void] $joinFailures.Add("$rowKey|buffer-forced-identity")
        }
    }
    elseif ([string] $bufferSnapshot.mode -eq 'Shadow') {
        if (-not [bool] $bufferSnapshot.hasShadowRecommendation -or
            [string] $bufferSnapshot.selectedValue -ne
                [string] $bufferSnapshot.shadowRecommendation -or
            [string] $bufferSnapshot.appliedValue -ne 'LegacyCurrent') {
            [void] $joinFailures.Add("$rowKey|buffer-shadow-identity")
        }
    }
    elseif ([string] $bufferSnapshot.selectedValue -ne 'LegacyCurrent' -or
        [string] $bufferSnapshot.appliedValue -ne 'LegacyCurrent') {
        [void] $joinFailures.Add("$rowKey|buffer-legacy-identity")
    }

    if ([bool] $backpressureSummary.hasObservation) {
        $adaptiveBackpressureEpochRowCount++
        $backpressureFirst =
            [uint64] $backpressureSummary.firstOperationSequence
        $backpressureLast =
            [uint64] $backpressureSummary.lastOperationSequence
        $backpressureCount =
            [uint64] $backpressureSummary.operationCount
        if ($backpressureCount -eq 0 -or
            $backpressureFirst -eq 0 -or
            $backpressureLast -lt $backpressureFirst -or
            $backpressureCount -ne
                (($backpressureLast - $backpressureFirst) + 1)) {
            [void] $joinFailures.Add("$rowKey|backpressure-range")
        }
        else {
            $adaptiveBackpressureSummaryByEpoch[$rowKey] =
                [ordered]@{
                    OperationCount = $backpressureCount
                    DelayAppliedCount =
                        [uint64] $backpressureSummary.delayAppliedCount
                    SafetyOverrideCount =
                        [uint64] $backpressureSummary.safetyOverrideCount
                    FallbackCount =
                        [uint64] $backpressureSummary.fallbackCount
                    MaximumQueuedOperationCount =
                        [uint64] $backpressureSummary.maximumQueuedOperationCount
                    MaximumRetainedCapacityBytes =
                        [uint64] $backpressureSummary.maximumRetainedCapacityBytes
                }
            for ($backpressureSequence = $backpressureFirst;
                $backpressureSequence -le $backpressureLast;
                $backpressureSequence++) {
                $backpressureKey =
                    "$scopedConnectionKey|$backpressureSequence"
                [void] $expectedAdaptiveBackpressureKeys.Add(
                    $backpressureKey)
                if ($adaptiveBackpressureEpochByOperationKey.ContainsKey(
                        $backpressureKey)) {
                    [void] $joinFailures.Add(
                        "$rowKey|backpressure-range-overlap")
                }
                else {
                    $adaptiveBackpressureEpochByOperationKey[
                        $backpressureKey] = $rowKey
                }
                if ($backpressureSequence -eq [uint64]::MaxValue) {
                    break
                }
            }
        }
    }
    elseif ([uint64] $backpressureSummary.operationCount -ne 0 -or
        [uint64] $backpressureSummary.firstOperationSequence -ne 0 -or
        [uint64] $backpressureSummary.lastOperationSequence -ne 0) {
        [void] $joinFailures.Add("$rowKey|backpressure-empty")
    }
    if ([uint64] $backpressureSummary.delayAppliedCount -gt
            [uint64] $backpressureSummary.operationCount -or
        [uint64] $backpressureSummary.safetyOverrideCount -gt
            [uint64] $backpressureSummary.operationCount -or
        [uint64] $backpressureSummary.fallbackCount -gt
            [uint64] $backpressureSummary.operationCount) {
        [void] $joinFailures.Add("$rowKey|backpressure-counts")
    }
    if ([bool] $backpressureSnapshot.hasForcedValue) {
        if ([string] $backpressureSnapshot.selectionSource -ne 'Forced' -or
            [string] $backpressureSnapshot.selectedValue -ne
                [string] $backpressureSnapshot.forcedValue -or
            [string] $backpressureSnapshot.appliedValue -ne
                [string] $backpressureSnapshot.forcedValue) {
            [void] $joinFailures.Add(
                "$rowKey|backpressure-forced-identity")
        }
    }
    elseif ([string] $backpressureSnapshot.mode -eq 'Shadow') {
        if (-not [bool] $backpressureSnapshot.hasShadowRecommendation -or
            [string] $backpressureSnapshot.selectedValue -ne
                [string] $backpressureSnapshot.shadowRecommendation -or
            [string] $backpressureSnapshot.appliedValue -ne
                'LegacyCurrent') {
            [void] $joinFailures.Add(
                "$rowKey|backpressure-shadow-identity")
        }
    }
    elseif ([string] $backpressureSnapshot.selectedValue -ne
            'LegacyCurrent' -or
        [string] $backpressureSnapshot.appliedValue -ne
            'LegacyCurrent') {
        [void] $joinFailures.Add(
            "$rowKey|backpressure-legacy-identity")
    }

    if ([bool] $packetFlushSummary.hasObservation) {
        $packetFlushCadenceEpochRowCount++
        $packetFlushFirst =
            [uint64] $packetFlushSummary.firstOperationSequence
        $packetFlushLast =
            [uint64] $packetFlushSummary.lastOperationSequence
        $packetFlushCount =
            [uint64] $packetFlushSummary.operationCount
        if ($packetFlushCount -eq 0 -or
            $packetFlushFirst -eq 0 -or
            $packetFlushLast -lt $packetFlushFirst -or
            $packetFlushCount -ne
                (($packetFlushLast - $packetFlushFirst) + 1)) {
            [void] $joinFailures.Add("$rowKey|packet-flush-range")
        }
        else {
            $packetFlushCadenceSummaryByEpoch[$rowKey] =
                [ordered]@{
                    OperationCount = $packetFlushCount
                    EligibleCount =
                        [uint64] $packetFlushSummary.eligibleCount
                    DelayAppliedCount =
                        [uint64] $packetFlushSummary.delayAppliedCount
                    PromptFlushAppliedCount =
                        [uint64] $packetFlushSummary.promptFlushAppliedCount
                    SafetyOverrideCount =
                        [uint64] $packetFlushSummary.safetyOverrideCount
                    FallbackCount =
                        [uint64] $packetFlushSummary.fallbackCount
                    MaximumStreamPayloadLength =
                        [uint64] $packetFlushSummary.maximumStreamPayloadLength
                    MaximumQueuedWriteCount =
                        [uint64] $packetFlushSummary.maximumQueuedWriteCount
                }
            for ($packetFlushSequence = $packetFlushFirst;
                $packetFlushSequence -le $packetFlushLast;
                $packetFlushSequence++) {
                $packetFlushKey =
                    "$scopedConnectionKey|$packetFlushSequence"
                [void] $expectedPacketFlushCadenceKeys.Add(
                    $packetFlushKey)
                if ($packetFlushCadenceEpochByOperationKey.ContainsKey(
                        $packetFlushKey)) {
                    [void] $joinFailures.Add(
                        "$rowKey|packet-flush-range-overlap")
                }
                else {
                    $packetFlushCadenceEpochByOperationKey[
                        $packetFlushKey] = $rowKey
                }
                if ($packetFlushSequence -eq [uint64]::MaxValue) {
                    break
                }
            }
        }
    }
    elseif ([uint64] $packetFlushSummary.operationCount -ne 0 -or
        [uint64] $packetFlushSummary.firstOperationSequence -ne 0 -or
        [uint64] $packetFlushSummary.lastOperationSequence -ne 0) {
        [void] $joinFailures.Add("$rowKey|packet-flush-empty")
    }
    if ([uint64] $packetFlushSummary.eligibleCount -gt
            [uint64] $packetFlushSummary.operationCount -or
        [uint64] $packetFlushSummary.delayAppliedCount -gt
            [uint64] $packetFlushSummary.eligibleCount -or
        [uint64] $packetFlushSummary.promptFlushAppliedCount -gt
            [uint64] $packetFlushSummary.eligibleCount -or
        [uint64] $packetFlushSummary.safetyOverrideCount -gt
            [uint64] $packetFlushSummary.operationCount -or
        [uint64] $packetFlushSummary.fallbackCount -gt
            [uint64] $packetFlushSummary.operationCount) {
        [void] $joinFailures.Add("$rowKey|packet-flush-counts")
    }
    if ([bool] $packetFlushSnapshot.hasForcedValue) {
        if ([string] $packetFlushSnapshot.selectionSource -ne 'Forced' -or
            [string] $packetFlushSnapshot.selectedValue -ne
                [string] $packetFlushSnapshot.forcedValue -or
            [string] $packetFlushSnapshot.appliedValue -ne
                [string] $packetFlushSnapshot.forcedValue) {
            [void] $joinFailures.Add(
                "$rowKey|packet-flush-forced-identity")
        }
    }
    elseif ([string] $packetFlushSnapshot.mode -eq 'Shadow') {
        if (-not [bool] $packetFlushSnapshot.hasShadowRecommendation -or
            [string] $packetFlushSnapshot.selectedValue -ne
                [string] $packetFlushSnapshot.shadowRecommendation -or
            [string] $packetFlushSnapshot.appliedValue -ne
                'LegacyCurrent') {
            [void] $joinFailures.Add(
                "$rowKey|packet-flush-shadow-identity")
        }
    }
    elseif ([string] $packetFlushSnapshot.selectedValue -ne
            'LegacyCurrent' -or
        [string] $packetFlushSnapshot.appliedValue -ne
            'LegacyCurrent') {
        [void] $joinFailures.Add(
            "$rowKey|packet-flush-legacy-identity")
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

    $contenderMissing = Test-ActorValidityFlag `
        -Value $record.observation.validity `
        -Name 'MissingServiceContenderCount' `
        -Mask (1L -shl 8)
    $contenderInvalid = Test-ActorValidityFlag `
        -Value $record.observation.validity `
        -Name 'ServiceContenderStateInvalid' `
        -Mask (1L -shl 9)
    $hasContenderCount =
        $null -ne $record.observation.serviceContenderCountAtStart
    if ($hasContenderCount -eq $contenderMissing -or
        ($hasContenderCount -and $contenderInvalid) -or
        ($contenderInvalid -and -not $contenderMissing)) {
        [void] $joinFailures.Add(
            "$rowKey|actor-service-contender-validity")
    }

    if ($actorEpochRowByActorKey.ContainsKey($rowKey) -and
        $hasContenderCount) {
        $actorEpochRowKey = [string] $actorEpochRowByActorKey[$rowKey]
        $contenderCount =
            [uint64] $record.observation.serviceContenderCountAtStart
        if (-not $actorContenderCountByEpoch.ContainsKey(
                $actorEpochRowKey)) {
            $actorContenderCountByEpoch[$actorEpochRowKey] = [uint64]0
            $actorContenderMaximumByEpoch[$actorEpochRowKey] = [uint64]0
            $actorContendedTurnCountByEpoch[$actorEpochRowKey] = [uint64]0
        }

        $actorContenderCountByEpoch[$actorEpochRowKey] =
            [uint64] $actorContenderCountByEpoch[$actorEpochRowKey] + 1
        if ($contenderCount -gt
            [uint64] $actorContenderMaximumByEpoch[$actorEpochRowKey]) {
            $actorContenderMaximumByEpoch[$actorEpochRowKey] =
                $contenderCount
        }
        if ($contenderCount -gt 1) {
            $actorContendedTurnCountByEpoch[$actorEpochRowKey] =
                [uint64] $actorContendedTurnCountByEpoch[
                    $actorEpochRowKey] + 1
        }
    }

    $acceptedWorkMissing = Test-ActorValidityFlag `
        -Value $record.observation.validity `
        -Name 'MissingAcceptedConnectionWorkItemsAfterCurrent' `
        -Mask (1L -shl 10)
    $hasAcceptedWork =
        $null -ne
            $record.observation.acceptedConnectionWorkItemsAfterCurrent
    if ($hasAcceptedWork -eq $acceptedWorkMissing -or
        ($hasAcceptedWork -and $contenderInvalid)) {
        [void] $joinFailures.Add(
            "$rowKey|actor-accepted-connection-work-validity")
    }
    if ($actorEpochRowByActorKey.ContainsKey($rowKey) -and
        $hasAcceptedWork) {
        $actorEpochRowKey = [string] $actorEpochRowByActorKey[$rowKey]
        $acceptedWork = [uint64] (
            $record.observation.acceptedConnectionWorkItemsAfterCurrent)
        if (-not $actorAcceptedWorkCountByEpoch.ContainsKey(
                $actorEpochRowKey)) {
            $actorAcceptedWorkCountByEpoch[$actorEpochRowKey] = [uint64]0
            $actorAcceptedWorkTotalByEpoch[$actorEpochRowKey] = [uint64]0
            $actorAcceptedWorkMaximumByEpoch[$actorEpochRowKey] = [uint64]0
            $actorAcceptedWorkRemainingTurnsByEpoch[
                $actorEpochRowKey] = [uint64]0
        }

        $actorAcceptedWorkCountByEpoch[$actorEpochRowKey] =
            [uint64] $actorAcceptedWorkCountByEpoch[$actorEpochRowKey] + 1
        $actorAcceptedWorkTotalByEpoch[$actorEpochRowKey] =
            Add-ActorUInt64Saturating `
                -Current ([uint64] $actorAcceptedWorkTotalByEpoch[
                    $actorEpochRowKey]) `
                -Value $acceptedWork
        if ($acceptedWork -gt
            [uint64] $actorAcceptedWorkMaximumByEpoch[$actorEpochRowKey]) {
            $actorAcceptedWorkMaximumByEpoch[$actorEpochRowKey] =
                $acceptedWork
        }
        if ($acceptedWork -gt 0) {
            $actorAcceptedWorkRemainingTurnsByEpoch[$actorEpochRowKey] =
                [uint64] $actorAcceptedWorkRemainingTurnsByEpoch[
                    $actorEpochRowKey] + 1
        }
    }

    $continuation = $record.observation.continuationAssessment
    $continuationDescriptors = @(
        [ordered]@{
            Name = 'ApplicationSend'
            State = [string] $continuation.applicationSendState
            Count = $continuation.applicationSendRemainingCount
        },
        [ordered]@{
            Name = 'FlowControl'
            State = [string] $continuation.flowControlState
            Count = $continuation.flowControlRemainingCount
        },
        [ordered]@{
            Name = 'StreamCapacity'
            State = [string] $continuation.streamCapacityState
            Count = $continuation.streamCapacityRemainingCount
        }
    )
    $completeContinuationAssessment = $true
    $hasInvalidContinuationAssessment = $false
    $actorEpochRowKey = if (
        $actorEpochRowByActorKey.ContainsKey($rowKey)) {
        [string] $actorEpochRowByActorKey[$rowKey]
    }
    else {
        $null
    }
    if ($null -ne $actorEpochRowKey -and
        -not $actorContinuationByEpoch.ContainsKey(
            $actorEpochRowKey)) {
        $actorContinuationByEpoch[$actorEpochRowKey] =
            [ordered]@{
                Complete = [uint64]0
                ApplicationSend = [ordered]@{
                    Observation = [uint64]0
                    Drained = [uint64]0
                    Scheduled = [uint64]0
                    Blocked = [uint64]0
                    Ready = [uint64]0
                    Maximum = [uint64]0
                }
                FlowControl = [ordered]@{
                    Observation = [uint64]0
                    Drained = [uint64]0
                    Scheduled = [uint64]0
                    Blocked = [uint64]0
                    Ready = [uint64]0
                    Maximum = [uint64]0
                }
                StreamCapacity = [ordered]@{
                    Observation = [uint64]0
                    Drained = [uint64]0
                    Scheduled = [uint64]0
                    Blocked = [uint64]0
                    Ready = [uint64]0
                    Maximum = [uint64]0
                }
            }
    }
    foreach ($descriptor in $continuationDescriptors) {
        $state = [string] $descriptor.State
        $hasCount = $null -ne $descriptor.Count
        $remainingCount = if ($hasCount) {
            [uint64] $descriptor.Count
        }
        else {
            [uint64]0
        }
        $consistent = switch ($state) {
            'NotAssessed' { -not $hasCount }
            'Invalid' { -not $hasCount }
            'Drained' { $hasCount -and $remainingCount -eq 0 }
            'Scheduled' { $hasCount -and $remainingCount -gt 0 }
            'Blocked' { $hasCount -and $remainingCount -gt 0 }
            'ReadyAfterCooperativeYield' {
                $hasCount -and $remainingCount -gt 0
            }
            default { $false }
        }
        if (-not $consistent) {
            [void] $joinFailures.Add(
                "$rowKey|actor-$($descriptor.Name)-continuation-validity")
        }

        if ($state -in @('NotAssessed', 'Invalid')) {
            $completeContinuationAssessment = $false
            if ($state -eq 'Invalid') {
                $hasInvalidContinuationAssessment = $true
            }
            continue
        }
        if (-not $consistent -or $null -eq $actorEpochRowKey) {
            continue
        }

        $aggregate =
            $actorContinuationByEpoch[$actorEpochRowKey][
                $descriptor.Name]
        $aggregate.Observation =
            [uint64] $aggregate.Observation + 1
        if ($remainingCount -gt [uint64] $aggregate.Maximum) {
            $aggregate.Maximum = $remainingCount
        }
        switch ($state) {
            'Drained' {
                $aggregate.Drained = [uint64] $aggregate.Drained + 1
            }
            'Scheduled' {
                $aggregate.Scheduled =
                    [uint64] $aggregate.Scheduled + 1
            }
            'Blocked' {
                $aggregate.Blocked = [uint64] $aggregate.Blocked + 1
            }
            'ReadyAfterCooperativeYield' {
                $aggregate.Ready = [uint64] $aggregate.Ready + 1
            }
        }
    }
    if ($completeContinuationAssessment -and
        $null -ne $actorEpochRowKey) {
        $actorContinuationByEpoch[$actorEpochRowKey].Complete =
            [uint64] $actorContinuationByEpoch[
                $actorEpochRowKey].Complete + 1
    }
    $incompleteContinuationFlag = Test-ActorValidityFlag `
        -Value $record.observation.validity `
        -Name 'IncompleteContinuationAssessment' `
        -Mask (1L -shl 11)
    $invalidContinuationFlag = Test-ActorValidityFlag `
        -Value $record.observation.validity `
        -Name 'ContinuationAssessmentInvalid' `
        -Mask (1L -shl 12)
    if ($incompleteContinuationFlag -eq
            $completeContinuationAssessment -or
        $invalidContinuationFlag -ne
            $hasInvalidContinuationAssessment) {
        [void] $joinFailures.Add(
            "$rowKey|actor-continuation-validity")
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

$adaptiveBackpressureSourceIndex = 0
$adaptiveBackpressureSourceRowOffset = 0
foreach ($line in [System.IO.File]::ReadLines(
        $resolvedAdaptiveBackpressureObservationPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    if (-not (
            $line |
                Test-Json `
                    -SchemaFile $adaptiveBackpressureSchemaPath `
                    -ErrorAction Stop)) {
        throw (
            "Adaptive-backpressure raw observation failed schema " +
            "validation at row " +
            "$($adaptiveBackpressureObservationRowCount + 1).")
    }

    $record = $line | ConvertFrom-Json -Depth 100
    $sourceKey = Resolve-SourceKey `
        -Counts $SourceAdaptiveBackpressureObservationRowCount `
        -Index ([ref] $adaptiveBackpressureSourceIndex) `
        -Offset ([ref] $adaptiveBackpressureSourceRowOffset)
    $scopedConnectionKey =
        "$sourceKey|$([string] $record.connectionKey)"
    $sequence = [uint64] $record.observation.operationSequence
    $operationKey = "$scopedConnectionKey|$sequence"
    $adaptiveBackpressureObservationRowCount++
    $adaptiveBackpressureSourceRowOffset++

    if (-not $seenAdaptiveBackpressureKeys.Add($operationKey)) {
        [void] $duplicateAdaptiveBackpressureKeys.Add($operationKey)
    }
    if ($lastAdaptiveBackpressureSequenceByConnection.ContainsKey(
            $scopedConnectionKey) -and
        $sequence -le [uint64] (
            $lastAdaptiveBackpressureSequenceByConnection[
                $scopedConnectionKey])) {
        [void] $outOfOrderAdaptiveBackpressureKeys.Add($operationKey)
    }
    $lastAdaptiveBackpressureSequenceByConnection[
        $scopedConnectionKey] = $sequence

    if (-not $expectedAdaptiveBackpressureKeys.Remove($operationKey)) {
        [void] $orphanAdaptiveBackpressureKeys.Add($operationKey)
        continue
    }

    $epochRowKey =
        [string] $adaptiveBackpressureEpochByOperationKey[$operationKey]
    if (-not $adaptiveBackpressureAggregateByEpoch.ContainsKey(
            $epochRowKey)) {
        $adaptiveBackpressureAggregateByEpoch[$epochRowKey] =
            [ordered]@{
                OperationCount = [uint64]0
                DelayAppliedCount = [uint64]0
                SafetyOverrideCount = [uint64]0
                FallbackCount = [uint64]0
                MaximumQueuedOperationCount = [uint64]0
                MaximumRetainedCapacityBytes = [uint64]0
            }
    }

    $aggregate =
        $adaptiveBackpressureAggregateByEpoch[$epochRowKey]
    $aggregate.OperationCount =
        [uint64] $aggregate.OperationCount + 1
    if ([bool] $record.observation.delayApplied) {
        $aggregate.DelayAppliedCount =
            [uint64] $aggregate.DelayAppliedCount + 1
    }
    if ([string] $record.observation.safetyOverride -ne 'None') {
        $aggregate.SafetyOverrideCount =
            [uint64] $aggregate.SafetyOverrideCount + 1
    }
    if ([bool] $record.observation.fallbackApplied) {
        $aggregate.FallbackCount =
            [uint64] $aggregate.FallbackCount + 1
    }
    $queuedOperationCount =
        [uint64] $record.observation.queuedOperationCount
    if ($queuedOperationCount -gt
        [uint64] $aggregate.MaximumQueuedOperationCount) {
        $aggregate.MaximumQueuedOperationCount = $queuedOperationCount
    }
    $retainedCapacityBytes =
        [uint64] $record.observation.retainedCapacityBytes
    if ($retainedCapacityBytes -gt
        [uint64] $aggregate.MaximumRetainedCapacityBytes) {
        $aggregate.MaximumRetainedCapacityBytes =
            $retainedCapacityBytes
    }
}

if ($null -ne $SourceAdaptiveBackpressureObservationRowCount -and
    ($SourceAdaptiveBackpressureObservationRowCount |
        Measure-Object -Sum).Sum -ne
        $adaptiveBackpressureObservationRowCount) {
    throw (
        "Adaptive-backpressure source row counts do not match retained " +
        "rows: sources=$((
            $SourceAdaptiveBackpressureObservationRowCount |
                Measure-Object -Sum).Sum), " +
        "rows=$adaptiveBackpressureObservationRowCount.")
}

foreach ($epochRowKey in $adaptiveBackpressureSummaryByEpoch.Keys) {
    $expected = $adaptiveBackpressureSummaryByEpoch[$epochRowKey]
    $actual = if ($adaptiveBackpressureAggregateByEpoch.ContainsKey(
            $epochRowKey)) {
        $adaptiveBackpressureAggregateByEpoch[$epochRowKey]
    }
    else {
        [ordered]@{
            OperationCount = [uint64]0
            DelayAppliedCount = [uint64]0
            SafetyOverrideCount = [uint64]0
            FallbackCount = [uint64]0
            MaximumQueuedOperationCount = [uint64]0
            MaximumRetainedCapacityBytes = [uint64]0
        }
    }
    if ([uint64] $expected.OperationCount -ne
            [uint64] $actual.OperationCount -or
        [uint64] $expected.DelayAppliedCount -ne
            [uint64] $actual.DelayAppliedCount -or
        [uint64] $expected.SafetyOverrideCount -ne
            [uint64] $actual.SafetyOverrideCount -or
        [uint64] $expected.FallbackCount -ne
            [uint64] $actual.FallbackCount -or
        [uint64] $expected.MaximumQueuedOperationCount -ne
            [uint64] $actual.MaximumQueuedOperationCount -or
        [uint64] $expected.MaximumRetainedCapacityBytes -ne
            [uint64] $actual.MaximumRetainedCapacityBytes) {
        [void] $joinFailures.Add(
            "$epochRowKey|backpressure-raw-aggregate")
    }
}

$packetFlushSourceIndex = 0
$packetFlushSourceRowOffset = 0
foreach ($line in [System.IO.File]::ReadLines(
        $resolvedPacketFlushCadenceObservationPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    if (-not (
            $line |
                Test-Json `
                    -SchemaFile $packetFlushCadenceSchemaPath `
                    -ErrorAction Stop)) {
        throw (
            "Packet-flush cadence raw observation failed schema " +
            "validation at row " +
            "$($packetFlushCadenceObservationRowCount + 1).")
    }

    $record = $line | ConvertFrom-Json -Depth 100
    $sourceKey = Resolve-SourceKey `
        -Counts $SourcePacketFlushCadenceObservationRowCount `
        -Index ([ref] $packetFlushSourceIndex) `
        -Offset ([ref] $packetFlushSourceRowOffset)
    $scopedConnectionKey =
        "$sourceKey|$([string] $record.connectionKey)"
    $sequence = [uint64] $record.observation.operationSequence
    $operationKey = "$scopedConnectionKey|$sequence"
    $packetFlushCadenceObservationRowCount++
    $packetFlushSourceRowOffset++

    if (-not $seenPacketFlushCadenceKeys.Add($operationKey)) {
        [void] $duplicatePacketFlushCadenceKeys.Add($operationKey)
    }
    if ($lastPacketFlushCadenceSequenceByConnection.ContainsKey(
            $scopedConnectionKey) -and
        $sequence -le [uint64] (
            $lastPacketFlushCadenceSequenceByConnection[
                $scopedConnectionKey])) {
        [void] $outOfOrderPacketFlushCadenceKeys.Add($operationKey)
    }
    $lastPacketFlushCadenceSequenceByConnection[
        $scopedConnectionKey] = $sequence

    if (-not $expectedPacketFlushCadenceKeys.Remove($operationKey)) {
        [void] $orphanPacketFlushCadenceKeys.Add($operationKey)
        continue
    }

    $epochRowKey =
        [string] $packetFlushCadenceEpochByOperationKey[$operationKey]
    if (-not $packetFlushCadenceAggregateByEpoch.ContainsKey(
            $epochRowKey)) {
        $packetFlushCadenceAggregateByEpoch[$epochRowKey] =
            [ordered]@{
                OperationCount = [uint64]0
                EligibleCount = [uint64]0
                DelayAppliedCount = [uint64]0
                PromptFlushAppliedCount = [uint64]0
                SafetyOverrideCount = [uint64]0
                FallbackCount = [uint64]0
                MaximumStreamPayloadLength = [uint64]0
                MaximumQueuedWriteCount = [uint64]0
            }
    }

    $aggregate = $packetFlushCadenceAggregateByEpoch[$epochRowKey]
    $aggregate.OperationCount =
        [uint64] $aggregate.OperationCount + 1
    if ([bool] $record.observation.legacyDelayEligible) {
        $aggregate.EligibleCount =
            [uint64] $aggregate.EligibleCount + 1
    }
    if ([bool] $record.observation.delayApplied) {
        $aggregate.DelayAppliedCount =
            [uint64] $aggregate.DelayAppliedCount + 1
    }
    if ([bool] $record.observation.promptFlushApplied) {
        $aggregate.PromptFlushAppliedCount =
            [uint64] $aggregate.PromptFlushAppliedCount + 1
    }
    if ([string] $record.observation.safetyOverride -ne 'None') {
        $aggregate.SafetyOverrideCount =
            [uint64] $aggregate.SafetyOverrideCount + 1
    }
    if ([bool] $record.observation.fallbackApplied) {
        $aggregate.FallbackCount =
            [uint64] $aggregate.FallbackCount + 1
    }
    $payloadLength =
        [uint64] $record.observation.streamPayloadLength
    if ($payloadLength -gt
        [uint64] $aggregate.MaximumStreamPayloadLength) {
        $aggregate.MaximumStreamPayloadLength = $payloadLength
    }
    $queuedWriteCount =
        [uint64] $record.observation.queuedWriteCount
    if ($queuedWriteCount -gt
        [uint64] $aggregate.MaximumQueuedWriteCount) {
        $aggregate.MaximumQueuedWriteCount = $queuedWriteCount
    }
}

$sourcePacketFlushCadenceObservationRowTotal =
    ($SourcePacketFlushCadenceObservationRowCount |
        Measure-Object -Sum).Sum
if ($null -ne $SourcePacketFlushCadenceObservationRowCount -and
    $sourcePacketFlushCadenceObservationRowTotal -ne
        $packetFlushCadenceObservationRowCount) {
    throw (
        "Packet-flush cadence source row counts do not match retained " +
        "rows: sources=$sourcePacketFlushCadenceObservationRowTotal, " +
        "rows=$packetFlushCadenceObservationRowCount.")
}

foreach ($epochRowKey in $packetFlushCadenceSummaryByEpoch.Keys) {
    $expected = $packetFlushCadenceSummaryByEpoch[$epochRowKey]
    $actual = if ($packetFlushCadenceAggregateByEpoch.ContainsKey(
            $epochRowKey)) {
        $packetFlushCadenceAggregateByEpoch[$epochRowKey]
    }
    else {
        [ordered]@{
            OperationCount = [uint64]0
            EligibleCount = [uint64]0
            DelayAppliedCount = [uint64]0
            PromptFlushAppliedCount = [uint64]0
            SafetyOverrideCount = [uint64]0
            FallbackCount = [uint64]0
            MaximumStreamPayloadLength = [uint64]0
            MaximumQueuedWriteCount = [uint64]0
        }
    }
    if ([uint64] $expected.OperationCount -ne
            [uint64] $actual.OperationCount -or
        [uint64] $expected.EligibleCount -ne
            [uint64] $actual.EligibleCount -or
        [uint64] $expected.DelayAppliedCount -ne
            [uint64] $actual.DelayAppliedCount -or
        [uint64] $expected.PromptFlushAppliedCount -ne
            [uint64] $actual.PromptFlushAppliedCount -or
        [uint64] $expected.SafetyOverrideCount -ne
            [uint64] $actual.SafetyOverrideCount -or
        [uint64] $expected.FallbackCount -ne
            [uint64] $actual.FallbackCount -or
        [uint64] $expected.MaximumStreamPayloadLength -ne
            [uint64] $actual.MaximumStreamPayloadLength -or
        [uint64] $expected.MaximumQueuedWriteCount -ne
            [uint64] $actual.MaximumQueuedWriteCount) {
        [void] $joinFailures.Add(
            "$epochRowKey|packet-flush-raw-aggregate")
    }
}

foreach ($actorEpochRowKey in $actorEpochSummaryByRowKey.Keys) {
    $summary = $actorEpochSummaryByRowKey[$actorEpochRowKey]
    $actualObservationCount = if (
        $actorContenderCountByEpoch.ContainsKey($actorEpochRowKey)) {
        [uint64] $actorContenderCountByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    $actualMaximum = if (
        $actorContenderMaximumByEpoch.ContainsKey($actorEpochRowKey)) {
        [uint64] $actorContenderMaximumByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    $actualContendedTurnCount = if (
        $actorContendedTurnCountByEpoch.ContainsKey($actorEpochRowKey)) {
        [uint64] $actorContendedTurnCountByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    if ([uint64] $summary.observationCount -ne
            $actualObservationCount -or
        [uint64] $summary.maximum -ne $actualMaximum -or
        [uint64] $summary.contendedTurnCount -ne
            $actualContendedTurnCount) {
        [void] $joinFailures.Add(
            "$actorEpochRowKey|actor-service-contender-aggregate")
    }

    $actualAcceptedWorkCount = if (
        $actorAcceptedWorkCountByEpoch.ContainsKey($actorEpochRowKey)) {
        [uint64] $actorAcceptedWorkCountByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    $actualAcceptedWorkTotal = if (
        $actorAcceptedWorkTotalByEpoch.ContainsKey($actorEpochRowKey)) {
        [uint64] $actorAcceptedWorkTotalByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    $actualAcceptedWorkMaximum = if (
        $actorAcceptedWorkMaximumByEpoch.ContainsKey($actorEpochRowKey)) {
        [uint64] $actorAcceptedWorkMaximumByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    $actualAcceptedWorkRemainingTurns = if (
        $actorAcceptedWorkRemainingTurnsByEpoch.ContainsKey(
            $actorEpochRowKey)) {
        [uint64] $actorAcceptedWorkRemainingTurnsByEpoch[$actorEpochRowKey]
    }
    else {
        [uint64]0
    }
    if ([uint64] $summary.acceptedWorkObservationCount -ne
            $actualAcceptedWorkCount -or
        [uint64] $summary.acceptedWorkTotal -ne
            $actualAcceptedWorkTotal -or
        [uint64] $summary.acceptedWorkMaximum -ne
            $actualAcceptedWorkMaximum -or
        [uint64] $summary.acceptedWorkRemainingTurns -ne
            $actualAcceptedWorkRemainingTurns) {
        [void] $joinFailures.Add(
            "$actorEpochRowKey|actor-accepted-connection-work-aggregate")
    }

    $actualContinuation = if (
        $actorContinuationByEpoch.ContainsKey($actorEpochRowKey)) {
        $actorContinuationByEpoch[$actorEpochRowKey]
    }
    else {
        [ordered]@{
            Complete = [uint64]0
            ApplicationSend = [ordered]@{
                Observation = [uint64]0
                Drained = [uint64]0
                Scheduled = [uint64]0
                Blocked = [uint64]0
                Ready = [uint64]0
                Maximum = [uint64]0
            }
            FlowControl = [ordered]@{
                Observation = [uint64]0
                Drained = [uint64]0
                Scheduled = [uint64]0
                Blocked = [uint64]0
                Ready = [uint64]0
                Maximum = [uint64]0
            }
            StreamCapacity = [ordered]@{
                Observation = [uint64]0
                Drained = [uint64]0
                Scheduled = [uint64]0
                Blocked = [uint64]0
                Ready = [uint64]0
                Maximum = [uint64]0
            }
        }
    }
    if ([uint64] $summary.completeContinuationAssessmentTurnCount -ne
        [uint64] $actualContinuation.Complete) {
        [void] $joinFailures.Add(
            "$actorEpochRowKey|actor-continuation-complete-aggregate")
    }
    foreach ($name in @(
            'ApplicationSend',
            'FlowControl',
            'StreamCapacity')) {
        $expectedProperty =
            "$($name.Substring(0, 1).ToLowerInvariant())$($name.Substring(1))Continuation"
        $expected = $summary.$expectedProperty
        $actual = $actualContinuation[$name]
        if ([uint64] $expected.Observation -ne
                [uint64] $actual.Observation -or
            [uint64] $expected.Drained -ne
                [uint64] $actual.Drained -or
            [uint64] $expected.Scheduled -ne
                [uint64] $actual.Scheduled -or
            [uint64] $expected.Blocked -ne
                [uint64] $actual.Blocked -or
            [uint64] $expected.Ready -ne
                [uint64] $actual.Ready -or
            [uint64] $expected.Maximum -ne
                [uint64] $actual.Maximum) {
            [void] $joinFailures.Add(
                "$actorEpochRowKey|actor-$name-continuation-aggregate")
        }
    }
}

$valid =
    $duplicateKeys.Count -eq 0 -and
    $outOfOrderKeys.Count -eq 0 -and
    $duplicateActorKeys.Count -eq 0 -and
    $outOfOrderActorKeys.Count -eq 0 -and
    $orphanActorKeys.Count -eq 0 -and
    $expectedActorKeys.Count -eq 0 -and
    $duplicateAdaptiveBackpressureKeys.Count -eq 0 -and
    $outOfOrderAdaptiveBackpressureKeys.Count -eq 0 -and
    $orphanAdaptiveBackpressureKeys.Count -eq 0 -and
    $expectedAdaptiveBackpressureKeys.Count -eq 0 -and
    $duplicatePacketFlushCadenceKeys.Count -eq 0 -and
    $outOfOrderPacketFlushCadenceKeys.Count -eq 0 -and
    $orphanPacketFlushCadenceKeys.Count -eq 0 -and
    $expectedPacketFlushCadenceKeys.Count -eq 0 -and
    $joinFailures.Count -eq 0 -and
    $multiAxisRows.Count -eq 0 -and
    $axisRecordCount -eq ($rowCount * 7)
if (-not $valid) {
    throw (
        "Unified adaptive-runtime raw evidence failed semantic validation: " +
        "duplicates=$($duplicateKeys.Count), outOfOrder=$($outOfOrderKeys.Count), " +
        "actorDuplicates=$($duplicateActorKeys.Count), " +
        "actorOutOfOrder=$($outOfOrderActorKeys.Count), " +
        "actorOrphans=$($orphanActorKeys.Count), " +
        "actorMissing=$($expectedActorKeys.Count), " +
        "backpressureDuplicates=$(
            $duplicateAdaptiveBackpressureKeys.Count), " +
        "backpressureOutOfOrder=$(
            $outOfOrderAdaptiveBackpressureKeys.Count), " +
        "backpressureOrphans=$(
            $orphanAdaptiveBackpressureKeys.Count), " +
        "backpressureMissing=$(
            $expectedAdaptiveBackpressureKeys.Count), " +
        "packetFlushDuplicates=$(
            $duplicatePacketFlushCadenceKeys.Count), " +
        "packetFlushOutOfOrder=$(
            $outOfOrderPacketFlushCadenceKeys.Count), " +
        "packetFlushOrphans=$(
            $orphanPacketFlushCadenceKeys.Count), " +
        "packetFlushMissing=$(
            $expectedPacketFlushCadenceKeys.Count), " +
        "joinFailures=$($joinFailures.Count), multiAxis=$($multiAxisRows.Count), " +
        "axisRecords=$axisRecordCount, expectedAxisRecords=$($rowCount * 7).")
}

[ordered]@{
    schemaVersion = 'adaptive-runtime-unified-raw-validation-v10'
    valid = $true
    rawEpochRowCount = $rowCount
    axisRecordCount = $axisRecordCount
    connectionCount = $lastSequenceByConnection.Count
    actorEpochRowCount = $actorEpochRowCount
    actorObservationRowCount = $actorObservationRowCount
    bufferObservationRowCount = $bufferObservationRowCount
    adaptiveBackpressureEpochRowCount =
        $adaptiveBackpressureEpochRowCount
    adaptiveBackpressureObservationRowCount =
        $adaptiveBackpressureObservationRowCount
    packetFlushCadenceEpochRowCount =
        $packetFlushCadenceEpochRowCount
    packetFlushCadenceObservationRowCount =
        $packetFlushCadenceObservationRowCount
    duplicateKeyCount = $duplicateKeys.Count
    outOfOrderKeyCount = $outOfOrderKeys.Count
    duplicateActorKeyCount = $duplicateActorKeys.Count
    outOfOrderActorKeyCount = $outOfOrderActorKeys.Count
    orphanActorKeyCount = $orphanActorKeys.Count
    missingActorKeyCount = $expectedActorKeys.Count
    duplicateAdaptiveBackpressureKeyCount =
        $duplicateAdaptiveBackpressureKeys.Count
    outOfOrderAdaptiveBackpressureKeyCount =
        $outOfOrderAdaptiveBackpressureKeys.Count
    orphanAdaptiveBackpressureKeyCount =
        $orphanAdaptiveBackpressureKeys.Count
    missingAdaptiveBackpressureKeyCount =
        $expectedAdaptiveBackpressureKeys.Count
    duplicatePacketFlushCadenceKeyCount =
        $duplicatePacketFlushCadenceKeys.Count
    outOfOrderPacketFlushCadenceKeyCount =
        $outOfOrderPacketFlushCadenceKeys.Count
    orphanPacketFlushCadenceKeyCount =
        $orphanPacketFlushCadenceKeys.Count
    missingPacketFlushCadenceKeyCount =
        $expectedPacketFlushCadenceKeys.Count
    joinFailureCount = $joinFailures.Count
    multiAxisVariationCount = $multiAxisRows.Count
} | ConvertTo-Json -Depth 20
