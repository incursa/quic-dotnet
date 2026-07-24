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
    'schemas\adaptive-runtime-actor-service-observation-v2.schema.json'
$epochSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actor-service-epoch-v2.schema.json'
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

$result = [ordered]@{
    schemaVersion =
        'adaptive-runtime-actor-service-evidence-validation-v2'
    valid = $failures.Count -eq 0
    observationRowCount = $observations.Count
    actorTurnCount = $turnCount
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
