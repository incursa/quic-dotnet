# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ObservationPath,

    [Parameter(Mandatory = $true)]
    [string] $EpochSummaryPath,

    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$observationSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actor-service-observation-v5.schema.json'
$epochSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actor-service-epoch-v5.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$observations = [System.Collections.Generic.List[object]]::new()

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
        return ([string] $Value) -match "(^|, )$([regex]::Escape($Name))($|, )"
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

foreach ($line in Get-Content -LiteralPath $ObservationPath) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    if (-not ($line |
            Test-Json -SchemaFile $observationSchemaPath -ErrorAction Stop)) {
        $failures.Add('An actor service observation failed schema validation.')
        continue
    }

    [void] $observations.Add(
        ($line | ConvertFrom-Json -Depth 100))
}

if ($observations.Count -eq 0) {
    $failures.Add('No actor service observations were supplied.')
}

$lastServiceSequence = [ulong]0
$lastWakeSequence = [ulong]0
$lastWakePosition = [ulong]0
$observedServiceContenderCount = [ulong]0
$maximumObservedServiceContenderCount = [ulong]0
$observedContendedTurnCount = [ulong]0
$acceptedWorkObservationCount = [ulong]0
$totalAcceptedWorkItemsAfterCurrent = [ulong]0
$maximumAcceptedWorkItemsAfterCurrent = [ulong]0
$turnsWithAcceptedWorkRemaining = [ulong]0
$completeContinuationAssessmentTurnCount = [ulong]0
$continuationAggregates = [ordered]@{
    ApplicationSend = [ordered]@{
        Observation = [ulong]0
        Drained = [ulong]0
        Scheduled = [ulong]0
        Blocked = [ulong]0
        Ready = [ulong]0
        Maximum = [ulong]0
    }
    FlowControl = [ordered]@{
        Observation = [ulong]0
        Drained = [ulong]0
        Scheduled = [ulong]0
        Blocked = [ulong]0
        Ready = [ulong]0
        Maximum = [ulong]0
    }
    StreamCapacity = [ordered]@{
        Observation = [ulong]0
        Drained = [ulong]0
        Scheduled = [ulong]0
        Blocked = [ulong]0
        Ready = [ulong]0
        Maximum = [ulong]0
    }
}
foreach ($observation in $observations) {
    $serviceSequence = [ulong] $observation.serviceSequence
    $wakeSequence = [ulong] $observation.wakeSequence
    $wakePosition = [ulong] $observation.wakePosition
    if ($serviceSequence -le $lastServiceSequence) {
        $failures.Add(
            "Actor service sequence '$serviceSequence' is not increasing.")
    }

    if ($wakeSequence -lt $lastWakeSequence) {
        $failures.Add(
            "Actor wake sequence '$wakeSequence' moved backwards.")
    }
    elseif ($wakeSequence -eq $lastWakeSequence -and
        $wakePosition -le $lastWakePosition) {
        $failures.Add(
            "Actor wake position '$wakePosition' is not increasing.")
    }

    $lastServiceSequence = $serviceSequence
    if ($wakeSequence -ne $lastWakeSequence) {
        $lastWakePosition = 0
    }

    $lastWakeSequence = $wakeSequence
    $lastWakePosition = $wakePosition

    $deadlineMissing = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'MissingDeadlineLateness' `
        -Mask (1L -shl 3)
    $hasDeadlineLateness =
        $null -ne $observation.deadlineLatenessMicros
    if ([string] $observation.workKind -eq 'Timer') {
        if ($hasDeadlineLateness -eq $deadlineMissing) {
            $failures.Add(
                "Timer observation '$serviceSequence' has contradictory deadline-lateness validity.")
        }
    }
    elseif ($hasDeadlineLateness -or $deadlineMissing) {
        $failures.Add(
            "Non-timer observation '$serviceSequence' contains deadline-lateness state.")
    }

    $gapMissing = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'MissingInterServiceGap' `
        -Mask (1L -shl 6)
    $hasGap = $null -ne $observation.interServiceGapMicros
    if ($hasGap -eq $gapMissing) {
        $failures.Add(
            "Actor observation '$serviceSequence' has contradictory inter-service-gap validity.")
    }

    $contenderMissing = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'MissingServiceContenderCount' `
        -Mask (1L -shl 8)
    $contenderInvalid = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'ServiceContenderStateInvalid' `
        -Mask (1L -shl 9)
    $hasServiceContenderCount =
        $null -ne $observation.serviceContenderCountAtStart
    if ($hasServiceContenderCount -eq $contenderMissing) {
        $failures.Add(
            "Actor observation '$serviceSequence' has contradictory service-contender validity.")
    }
    if ($hasServiceContenderCount -and $contenderInvalid) {
        $failures.Add(
            "Actor observation '$serviceSequence' exposes an invalid service-contender count.")
    }
    if ($contenderInvalid -and -not $contenderMissing) {
        $failures.Add(
            "Actor observation '$serviceSequence' marks invalid service-contender state without marking the count missing.")
    }
    if ($hasServiceContenderCount) {
        $serviceContenderCount =
            [ulong] $observation.serviceContenderCountAtStart
        $observedServiceContenderCount++
        $maximumObservedServiceContenderCount = [Math]::Max(
            $maximumObservedServiceContenderCount,
            $serviceContenderCount)
        if ($serviceContenderCount -gt 1) {
            $observedContendedTurnCount++
        }
    }

    $acceptedWorkMissing = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'MissingAcceptedConnectionWorkItemsAfterCurrent' `
        -Mask (1L -shl 10)
    $hasAcceptedWork =
        $null -ne $observation.acceptedConnectionWorkItemsAfterCurrent
    if ($hasAcceptedWork -eq $acceptedWorkMissing) {
        $failures.Add(
            "Actor observation '$serviceSequence' has contradictory accepted-connection-work validity.")
    }
    if ($hasAcceptedWork -and $contenderInvalid) {
        $failures.Add(
            "Actor observation '$serviceSequence' exposes accepted connection work from invalid accounting.")
    }
    if ($hasAcceptedWork) {
        $acceptedWork =
            [ulong] $observation.acceptedConnectionWorkItemsAfterCurrent
        $acceptedWorkObservationCount++
        $totalAcceptedWorkItemsAfterCurrent =
            Add-ActorUInt64Saturating `
                -Current $totalAcceptedWorkItemsAfterCurrent `
                -Value $acceptedWork
        if ($acceptedWork -gt $maximumAcceptedWorkItemsAfterCurrent) {
            $maximumAcceptedWorkItemsAfterCurrent = $acceptedWork
        }
        if ($acceptedWork -gt 0) {
            $turnsWithAcceptedWorkRemaining++
        }
    }

    $continuation = $observation.continuationAssessment
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
    foreach ($descriptor in $continuationDescriptors) {
        $state = [string] $descriptor.State
        $hasCount = $null -ne $descriptor.Count
        $remainingCount = if ($hasCount) {
            [ulong] $descriptor.Count
        }
        else {
            [ulong]0
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
            $failures.Add(
                "Actor observation '$serviceSequence' has contradictory $($descriptor.Name) continuation state.")
        }

        if ($state -in @('NotAssessed', 'Invalid')) {
            $completeContinuationAssessment = $false
            if ($state -eq 'Invalid') {
                $hasInvalidContinuationAssessment = $true
            }
            continue
        }

        if (-not $consistent) {
            continue
        }

        $aggregate = $continuationAggregates[$descriptor.Name]
        $aggregate.Observation =
            [ulong] $aggregate.Observation + 1
        $aggregate.Maximum = [Math]::Max(
            [ulong] $aggregate.Maximum,
            $remainingCount)
        switch ($state) {
            'Drained' { $aggregate.Drained = [ulong] $aggregate.Drained + 1 }
            'Scheduled' { $aggregate.Scheduled = [ulong] $aggregate.Scheduled + 1 }
            'Blocked' { $aggregate.Blocked = [ulong] $aggregate.Blocked + 1 }
            'ReadyAfterCooperativeYield' {
                $aggregate.Ready = [ulong] $aggregate.Ready + 1
            }
        }
    }
    if ($completeContinuationAssessment) {
        $completeContinuationAssessmentTurnCount++
    }

    $incompleteContinuationFlag = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'IncompleteContinuationAssessment' `
        -Mask (1L -shl 11)
    $invalidContinuationFlag = Test-ActorValidityFlag `
        -Value $observation.validity `
        -Name 'ContinuationAssessmentInvalid' `
        -Mask (1L -shl 12)
    if ($incompleteContinuationFlag -eq
        $completeContinuationAssessment) {
        $failures.Add(
            "Actor observation '$serviceSequence' has contradictory continuation completeness validity.")
    }
    if ($invalidContinuationFlag -ne
        $hasInvalidContinuationAssessment) {
        $failures.Add(
            "Actor observation '$serviceSequence' has contradictory invalid continuation validity.")
    }
}

$epochJson = Get-Content -LiteralPath $EpochSummaryPath -Raw
if (-not ($epochJson |
        Test-Json -SchemaFile $epochSchemaPath -ErrorAction Stop)) {
    $failures.Add('The actor service epoch summary failed schema validation.')
}

$epoch = $epochJson | ConvertFrom-Json -Depth 100
$turnCount = [ulong] $epoch.actorTurnCount
$firstServiceSequence = [ulong] $epoch.firstServiceSequence
$epochLastServiceSequence = [ulong] $epoch.lastServiceSequence
$queueDelayObservationCount =
    [ulong] $epoch.queueDelayObservationCount
$maximumServiceTimeMicros =
    [ulong] $epoch.maximumServiceTimeMicros
$totalServiceTimeMicros =
    [ulong] $epoch.totalServiceTimeMicros
$interServiceGapObservationCount =
    [ulong] $epoch.interServiceGapObservationCount
$totalInterServiceGapMicros =
    [ulong] $epoch.totalInterServiceGapMicros
$maximumInterServiceGapMicros =
    [ulong] $epoch.maximumInterServiceGapMicros
$deadlineLatenessObservationCount =
    [ulong] $epoch.deadlineLatenessObservationCount
$totalDeadlineLatenessMicros =
    [ulong] $epoch.totalDeadlineLatenessMicros
$maximumDeadlineLatenessMicros =
    [ulong] $epoch.maximumDeadlineLatenessMicros
$serviceContenderObservationCount =
    [ulong] $epoch.serviceContenderObservationCount
$maximumServiceContenderCount =
    [ulong] $epoch.maximumServiceContenderCount
$contendedTurnCount =
    [ulong] $epoch.contendedTurnCount
$epochAcceptedWorkObservationCount =
    [ulong] $epoch.acceptedConnectionWorkObservationCount
$epochTotalAcceptedWorkItemsAfterCurrent =
    [ulong] $epoch.totalAcceptedConnectionWorkItemsAfterCurrent
$epochMaximumAcceptedWorkItemsAfterCurrent =
    [ulong] $epoch.maximumAcceptedConnectionWorkItemsAfterCurrent
$epochTurnsWithAcceptedWorkRemaining =
    [ulong] $epoch.turnsWithAcceptedConnectionWorkRemaining
$dispositionCount =
    [ulong] $epoch.completedTurnCount +
    [ulong] $epoch.skippedTurnCount +
    [ulong] $epoch.faultedTurnCount
$kindCount =
    [ulong] $epoch.connectionEventCount +
    [ulong] $epoch.timerCount +
    [ulong] $epoch.packetReceivedCount +
    [ulong] $epoch.streamCapacityReleaseCount +
    [ulong] $epoch.flowControlCreditUpdateCount +
    [ulong] $epoch.streamOpenCount +
    [ulong] $epoch.streamWriteCount
if ($dispositionCount -ne $turnCount) {
    $failures.Add(
        "Disposition count '$dispositionCount' does not equal actor turns '$turnCount'.")
}

if ($kindCount -ne $turnCount) {
    $failures.Add(
        "Work-kind count '$kindCount' does not equal actor turns '$turnCount'.")
}

if ([bool] $epoch.hasObservation) {
    if ($turnCount -eq 0 -or
        $firstServiceSequence -eq 0 -or
        $epochLastServiceSequence -lt $firstServiceSequence) {
        $failures.Add(
            'An observed actor epoch has invalid sequence or turn counts.')
    }
}
elseif ($turnCount -ne 0 -or
    $firstServiceSequence -ne 0 -or
    $epochLastServiceSequence -ne 0) {
    $failures.Add(
        'An empty actor epoch contains sequence or turn counts.')
}

if ($queueDelayObservationCount -gt $turnCount) {
    $failures.Add(
        'Queue-delay observation count exceeds actor turn count.')
}

if ($maximumServiceTimeMicros -gt $totalServiceTimeMicros) {
    $failures.Add(
        'Maximum service time exceeds total service time.')
}
if ($interServiceGapObservationCount -gt $turnCount) {
    $failures.Add(
        'Inter-service-gap observation count exceeds actor turn count.')
}
if ($maximumInterServiceGapMicros -gt $totalInterServiceGapMicros) {
    $failures.Add(
        'Maximum inter-service gap exceeds total inter-service gap.')
}
if ($deadlineLatenessObservationCount -gt [ulong] $epoch.timerCount) {
    $failures.Add(
        'Deadline-lateness observation count exceeds timer turn count.')
}
if ($maximumDeadlineLatenessMicros -gt $totalDeadlineLatenessMicros) {
    $failures.Add(
        'Maximum deadline lateness exceeds total deadline lateness.')
}
if ($serviceContenderObservationCount -gt $turnCount) {
    $failures.Add(
        'Service-contender observation count exceeds actor turn count.')
}
if ($contendedTurnCount -gt $serviceContenderObservationCount) {
    $failures.Add(
        'Contended turn count exceeds service-contender observation count.')
}
if ($serviceContenderObservationCount -ne
    $observedServiceContenderCount) {
    $failures.Add(
        'Service-contender observation count does not match raw observations.')
}
if ($maximumServiceContenderCount -ne
    $maximumObservedServiceContenderCount) {
    $failures.Add(
        'Maximum service-contender count does not match raw observations.')
}
if ($contendedTurnCount -ne $observedContendedTurnCount) {
    $failures.Add(
        'Contended turn count does not match raw observations.')
}
if ($epochAcceptedWorkObservationCount -gt $turnCount -or
    $epochTurnsWithAcceptedWorkRemaining -gt
        $epochAcceptedWorkObservationCount) {
    $failures.Add(
        'Accepted connection work counts exceed actor observation bounds.')
}
if ($epochMaximumAcceptedWorkItemsAfterCurrent -gt
    $epochTotalAcceptedWorkItemsAfterCurrent) {
    $failures.Add(
        'Maximum accepted connection work exceeds the epoch total.')
}
if ($epochAcceptedWorkObservationCount -ne
        $acceptedWorkObservationCount -or
    $epochTotalAcceptedWorkItemsAfterCurrent -ne
        $totalAcceptedWorkItemsAfterCurrent -or
    $epochMaximumAcceptedWorkItemsAfterCurrent -ne
        $maximumAcceptedWorkItemsAfterCurrent -or
    $epochTurnsWithAcceptedWorkRemaining -ne
        $turnsWithAcceptedWorkRemaining) {
    $failures.Add(
        'Accepted connection work aggregation does not match raw observations.')
}

if ([ulong] $epoch.completeContinuationAssessmentTurnCount -ne
    $completeContinuationAssessmentTurnCount) {
    $failures.Add(
        'Complete continuation-assessment count does not match raw observations.')
}
foreach ($name in $continuationAggregates.Keys) {
    $aggregate = $continuationAggregates[$name]
    $observationProperty = "$($name.Substring(0, 1).ToLowerInvariant())$($name.Substring(1))ContinuationObservationCount"
    $drainedProperty = "$($name.Substring(0, 1).ToLowerInvariant())$($name.Substring(1))ContinuationDrainedTurnCount"
    $scheduledProperty = "$($name.Substring(0, 1).ToLowerInvariant())$($name.Substring(1))ContinuationScheduledTurnCount"
    $blockedProperty = "$($name.Substring(0, 1).ToLowerInvariant())$($name.Substring(1))ContinuationBlockedTurnCount"
    $readyProperty = "$($name.Substring(0, 1).ToLowerInvariant())$($name.Substring(1))ContinuationReadyTurnCount"
    $maximumProperty = "maximum$($name)ContinuationRemainingCount"
    if ([ulong] $epoch.$observationProperty -ne
            [ulong] $aggregate.Observation -or
        [ulong] $epoch.$drainedProperty -ne
            [ulong] $aggregate.Drained -or
        [ulong] $epoch.$scheduledProperty -ne
            [ulong] $aggregate.Scheduled -or
        [ulong] $epoch.$blockedProperty -ne
            [ulong] $aggregate.Blocked -or
        [ulong] $epoch.$readyProperty -ne
            [ulong] $aggregate.Ready -or
        [ulong] $epoch.$maximumProperty -ne
            [ulong] $aggregate.Maximum) {
        $failures.Add(
            "$name continuation aggregation does not match raw observations.")
    }
}

$result = [ordered]@{
    schemaVersion =
        'adaptive-runtime-actor-service-evidence-validation-v5'
    valid = $failures.Count -eq 0
    observationRowCount = $observations.Count
    actorTurnCount = $turnCount
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
