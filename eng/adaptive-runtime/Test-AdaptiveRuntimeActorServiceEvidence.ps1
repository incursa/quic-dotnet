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
    'schemas\adaptive-runtime-actor-service-observation-v1.schema.json'
$epochSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-actor-service-epoch-v1.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$observations = [System.Collections.Generic.List[object]]::new()

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

$result = [ordered]@{
    schemaVersion =
        'adaptive-runtime-actor-service-evidence-validation-v1'
    valid = $failures.Count -eq 0
    observationRowCount = $observations.Count
    actorTurnCount = $turnCount
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
