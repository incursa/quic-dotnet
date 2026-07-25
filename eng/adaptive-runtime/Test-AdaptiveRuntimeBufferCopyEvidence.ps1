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
    'schemas\adaptive-runtime-buffer-copy-observation-v4.schema.json'
$epochSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-buffer-copy-epoch-v4.schema.json'
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
$memoryConservativeOperationCount = [ulong]0
$safetyOverrideOperationCount = [ulong]0
$fallbackOperationCount = [ulong]0
$totalLegalLogicalBytes = [ulong]0
$totalLogicalBytes = [ulong]0
$totalCopiedBytes = [ulong]0
$totalLegalSourceSegments = [ulong]0
$totalAppliedSourceSegments = [ulong]0
foreach ($observation in $observations) {
    $operationSequence = [ulong] $observation.operationSequence
    $legalLogicalBytes = [ulong] $observation.legalLogicalBytes
    $logicalBytes = [ulong] $observation.logicalBytes
    $copiedBytes = [ulong] $observation.copiedBytes
    $requestedCapacityBytes =
        [ulong] $observation.requestedCapacityBytes
    $retainedCapacityBytes =
        [ulong] $observation.retainedCapacityBytes
    $legalSourceSegmentCount =
        [ulong] $observation.legalSourceSegmentCount
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

    if ($logicalBytes -gt $legalLogicalBytes -or
        $sourceSegmentCount -gt $legalSourceSegmentCount) {
        $failures.Add(
            'Applied buffer-copy work exceeds the legal Stage 1 prefix.')
    }

    $mode = [string] $observation.mode
    $forcedValue = if ($null -eq $observation.forcedValue) {
        $null
    }
    else {
        [string] $observation.forcedValue
    }
    $shadowRecommendation =
        if ($null -eq $observation.shadowRecommendation) {
            $null
        }
        else {
            [string] $observation.shadowRecommendation
        }
    $selectedValue = [string] $observation.selectedValue
    $appliedValue = [string] $observation.appliedValue
    $selectionSource = [string] $observation.selectionSource
    $reasonCode = [string] $observation.reasonCode
    $safetyOverride = [string] $observation.safetyOverride
    $fallbackApplied = [bool] $observation.fallbackApplied

    if ($reasonCode -eq 'NotApplicable') {
        if ($selectedValue -ne 'LegacyCurrent' -or
            $appliedValue -ne 'LegacyCurrent') {
            $failures.Add(
                'A non-policy buffer-copy operation changed applied behavior.')
        }
    }
    elseif ($fallbackApplied) {
        if ($safetyOverride -eq 'None' -or
            $selectionSource -ne 'SafetyOverride' -or
            $appliedValue -ne 'LegacyCurrent') {
            $failures.Add(
                'A buffer-copy fallback did not restore guarded legacy behavior.')
        }
    }
    elseif ($null -ne $forcedValue) {
        if ($selectionSource -ne 'Forced' -or
            $selectedValue -ne $forcedValue -or
            $appliedValue -ne $forcedValue) {
            $failures.Add(
                'Forced buffer-copy identity does not match selected and applied behavior.')
        }
    }
    elseif ($mode -eq 'Shadow') {
        if ($null -eq $shadowRecommendation -or
            $selectedValue -ne $shadowRecommendation -or
            $appliedValue -ne 'LegacyCurrent' -or
            $selectionSource -ne 'ShadowRule') {
            $failures.Add(
                'Shadow buffer-copy selection changed applied behavior or lost its recommendation.')
        }
    }
    elseif ($selectedValue -ne 'LegacyCurrent' -or
        $appliedValue -ne 'LegacyCurrent') {
        $failures.Add(
            'Disabled or observe-only buffer-copy evidence changed behavior.')
    }

    if ($appliedValue -eq 'MemoryConservative') {
        $memoryConservativeOperationCount++
        if ($reasonCode -ne 'NotApplicable' -and
            $sourceSegmentCount -gt 2) {
            $failures.Add(
                'Memory-conservative buffer-copy evidence exceeds its two-segment cap.')
        }
    }
    if ($safetyOverride -ne 'None') {
        $safetyOverrideOperationCount++
    }
    if ($fallbackApplied) {
        $fallbackOperationCount++
    }

    $totalLegalLogicalBytes += $legalLogicalBytes
    $totalLogicalBytes += $logicalBytes
    $totalCopiedBytes += $copiedBytes
    $totalLegalSourceSegments += $legalSourceSegmentCount
    $totalAppliedSourceSegments += $sourceSegmentCount
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
    [ulong] $epoch.receiveSegmentCount +
    [ulong] $epoch.outboundPacketProtectionCount
$operationKindCount =
    [ulong] $epoch.copyCount +
    [ulong] $epoch.reuseAndCopyCount +
    [ulong] $epoch.formatCount +
    [ulong] $epoch.combineCount +
    [ulong] $epoch.retainCount +
    [ulong] $epoch.cloneCount +
    [ulong] $epoch.protectCount

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

if ([ulong] $epoch.memoryConservativeOperationCount -ne
        $memoryConservativeOperationCount -or
    [ulong] $epoch.safetyOverrideOperationCount -ne
        $safetyOverrideOperationCount -or
    [ulong] $epoch.fallbackOperationCount -ne
        $fallbackOperationCount -or
    [ulong] $epoch.totalLegalLogicalBytes -ne
        $totalLegalLogicalBytes -or
    [ulong] $epoch.totalLogicalBytes -ne $totalLogicalBytes -or
    [ulong] $epoch.totalCopiedBytes -ne $totalCopiedBytes -or
    [ulong] $epoch.totalLegalSourceSegments -ne
        $totalLegalSourceSegments -or
    [ulong] $epoch.totalAppliedSourceSegments -ne
        $totalAppliedSourceSegments) {
    $failures.Add(
        'The buffer-copy epoch summary does not match its retained observations.')
}

$snapshot = $epoch.policySnapshot
$snapshotMode = [string] $snapshot.mode
$snapshotSelected = [string] $snapshot.selectedValue
$snapshotApplied = [string] $snapshot.appliedValue
if ([bool] $snapshot.hasForcedValue) {
    if ([string] $snapshot.selectionSource -ne 'Forced' -or
        $snapshotSelected -ne [string] $snapshot.forcedValue -or
        $snapshotApplied -ne [string] $snapshot.forcedValue) {
        $failures.Add(
            'The configured buffer-copy snapshot has inconsistent forced identity.')
    }
}
elseif ($snapshotMode -eq 'Shadow') {
    if (-not [bool] $snapshot.hasShadowRecommendation -or
        $snapshotSelected -ne [string] $snapshot.shadowRecommendation -or
        $snapshotApplied -ne 'LegacyCurrent') {
        $failures.Add(
            'The configured buffer-copy snapshot has inconsistent shadow identity.')
    }
}
elseif ($snapshotSelected -ne 'LegacyCurrent' -or
    $snapshotApplied -ne 'LegacyCurrent') {
    $failures.Add(
        'The configured disabled or observe-only snapshot is not legacy.')
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
        'adaptive-runtime-buffer-copy-evidence-validation-v4'
    valid = $failures.Count -eq 0
    observationRowCount = $observations.Count
    operationCount = $operationCount
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
