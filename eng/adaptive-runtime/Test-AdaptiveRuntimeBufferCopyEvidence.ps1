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
    'schemas\adaptive-runtime-buffer-copy-observation-v2.schema.json'
$epochSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-buffer-copy-epoch-v2.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$observations = [System.Collections.Generic.List[object]]::new()

foreach ($line in Get-Content -LiteralPath $ObservationPath) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    if (-not ($line |
            Test-Json -SchemaFile $observationSchemaPath -ErrorAction Stop)) {
        $failures.Add('A buffer-copy observation failed schema validation.')
        continue
    }

    [void] $observations.Add(
        ($line | ConvertFrom-Json -Depth 100))
}

if ($observations.Count -eq 0) {
    $failures.Add('No buffer-copy observations were supplied.')
}

$lastOperationSequence = [ulong]0
foreach ($observation in $observations) {
    $operationSequence = [ulong] $observation.operationSequence
    $logicalBytes = [ulong] $observation.logicalBytes
    $copiedBytes = [ulong] $observation.copiedBytes
    $requestedCapacityBytes =
        [ulong] $observation.requestedCapacityBytes
    $retainedCapacityBytes =
        [ulong] $observation.retainedCapacityBytes
    $sourceSegmentCount = [ulong] $observation.sourceSegmentCount

    if ($operationSequence -le $lastOperationSequence) {
        $failures.Add(
            "Buffer-copy operation sequence '$operationSequence' is not increasing.")
    }

    if ($copiedBytes -gt $retainedCapacityBytes) {
        $failures.Add(
            "Copied bytes '$copiedBytes' exceed retained capacity '$retainedCapacityBytes'.")
    }

    if ($requestedCapacityBytes -gt $retainedCapacityBytes) {
        $failures.Add(
            "Requested capacity '$requestedCapacityBytes' exceeds retained capacity '$retainedCapacityBytes'.")
    }

    if ($logicalBytes -gt 0 -and $sourceSegmentCount -eq 0) {
        $failures.Add(
            'A non-empty buffer-copy observation has no source segment.')
    }

    if ([string] $observation.selectedValue -ne 'LegacyCurrent' -or
        [string] $observation.appliedValue -ne 'LegacyCurrent' -or
        $null -ne $observation.forcedValue -or
        $null -ne $observation.shadowRecommendation -or
        [bool] $observation.fallbackApplied) {
        $failures.Add(
            'Observe-only buffer-copy evidence changed or forced policy identity.')
    }

    $lastOperationSequence = $operationSequence
}

$epochJson = Get-Content -LiteralPath $EpochSummaryPath -Raw
if (-not ($epochJson |
        Test-Json -SchemaFile $epochSchemaPath -ErrorAction Stop)) {
    $failures.Add(
        'The buffer-copy epoch summary failed schema validation.')
}

$epoch = $epochJson | ConvertFrom-Json -Depth 100
$operationCount = [ulong] $epoch.operationCount
$pathCount =
    [ulong] $epoch.applicationWriteRequestCount +
    [ulong] $epoch.oversizedRawQueueCount +
    [ulong] $epoch.formattedStreamPayloadCount +
    [ulong] $epoch.combinedApplicationSendCount +
    [ulong] $epoch.sentPacketPlaintextRetentionCount +
    [ulong] $epoch.retransmissionCloneCount +
    [ulong] $epoch.receiveSegmentCount
$operationKindCount =
    [ulong] $epoch.copyCount +
    [ulong] $epoch.reuseAndCopyCount +
    [ulong] $epoch.formatCount +
    [ulong] $epoch.combineCount +
    [ulong] $epoch.retainCount +
    [ulong] $epoch.cloneCount

if ($pathCount -ne $operationCount) {
    $failures.Add(
        "Path count '$pathCount' does not equal operation count '$operationCount'.")
}

if ($operationKindCount -ne $operationCount) {
    $failures.Add(
        "Operation-kind count '$operationKindCount' does not equal operation count '$operationCount'.")
}

if ([ulong] $epoch.maximumCopiedBytes -gt
    [ulong] $epoch.totalCopiedBytes) {
    $failures.Add(
        'Maximum copied bytes exceed total copied bytes.')
}

if ([ulong] $epoch.maximumRetainedCapacityBytes -gt
    [ulong] $epoch.totalRetainedCapacityBytes) {
    $failures.Add(
        'Maximum retained capacity exceeds total retained capacity.')
}

if ([bool] $epoch.hasObservation) {
    if ($operationCount -eq 0 -or
        [ulong] $epoch.firstOperationSequence -eq 0 -or
        [ulong] $epoch.lastOperationSequence -lt
            [ulong] $epoch.firstOperationSequence) {
        $failures.Add(
            'An observed buffer-copy epoch has invalid sequence or operation counts.')
    }
}
elseif ($operationCount -ne 0 -or
    [ulong] $epoch.firstOperationSequence -ne 0 -or
    [ulong] $epoch.lastOperationSequence -ne 0) {
    $failures.Add(
        'An empty buffer-copy epoch contains sequence or operation counts.')
}

$result = [ordered]@{
    schemaVersion =
        'adaptive-runtime-buffer-copy-evidence-validation-v2'
    valid = $failures.Count -eq 0
    observationRowCount = $observations.Count
    operationCount = $operationCount
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
