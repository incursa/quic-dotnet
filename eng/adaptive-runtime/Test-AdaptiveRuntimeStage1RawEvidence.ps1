# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $RawEpochPath,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

$schemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-unified-epoch-raw-v1.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$rows = [System.Collections.Generic.List[object]]::new()
$lastEpochByConnection = [System.Collections.Generic.Dictionary[string,ulong]]::new(
    [StringComparer]::Ordinal)

$axes = @(
    [pscustomobject]@{
        Property = 'applicationSendTurnPlanning'
        Axis = 'ApplicationSendTurnPlanning'
    },
    [pscustomobject]@{
        Property = 'applicationSendBatchFormation'
        Axis = 'ApplicationSendBatchFormation'
    },
    [pscustomobject]@{
        Property = 'queuedSendBurstBudget'
        Axis = 'QueuedSendBurstBudget'
    },
    [pscustomobject]@{
        Property = 'oversizedWriteAdmissionQuantum'
        Axis = 'OversizedWriteAdmissionQuantum'
    }
)

foreach ($path in $RawEpochPath) {
    $resolvedPath = (Resolve-Path -LiteralPath $path).Path
    $content = Get-Content -LiteralPath $resolvedPath -Raw
    try {
        $document = $content | ConvertFrom-Json -Depth 100
        $documents = if ($document -is [Array]) { @($document) } else { @($document) }
    }
    catch {
        $documents = [System.Collections.Generic.List[object]]::new()
        $lineNumber = 0
        foreach ($line in ($content -split '\r?\n')) {
            $lineNumber++
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            try {
                [void] $documents.Add(($line | ConvertFrom-Json -Depth 100))
            }
            catch {
                $failures.Add(
                    "Raw epoch '$resolvedPath' line $lineNumber is not valid JSON: $($_.Exception.Message)")
            }
        }
    }

    foreach ($record in $documents) {
        $json = $record | ConvertTo-Json -Depth 100 -Compress
        try {
            if (-not ($json | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
                $failures.Add("Raw epoch '$resolvedPath' failed schema validation.")
                continue
            }
        }
        catch {
            $failures.Add(
                "Raw epoch '$resolvedPath' failed schema validation: $($_.Exception.Message)")
            continue
        }

        [void] $rows.Add($record)
    }
}

$axisRecordCount = 0
$missingEventAxisCount = 0
foreach ($row in $rows) {
    $connectionKey = [string] $row.connectionKey
    $epochIndex = [ulong] $row.epoch.epochIndex
    if ($lastEpochByConnection.ContainsKey($connectionKey)) {
        $previousEpoch = $lastEpochByConnection[$connectionKey]
        if ($epochIndex -le $previousEpoch) {
            $failures.Add(
                "Connection '$connectionKey' has non-increasing epoch index '$epochIndex' after '$previousEpoch'.")
        }
    }

    $lastEpochByConnection[$connectionKey] = $epochIndex
    $forcedCount = 0
    foreach ($axis in $axes) {
        $axisRecord = $row.epoch.($axis.Property)
        $snapshotDecision = $row.epoch.policySnapshot.($axis.Property)
        $decision = $axisRecord.decision
        $axisRecordCount++

        if (-not [bool] $axisRecord.hasEvent) {
            $missingEventAxisCount++
        }

        if ([string] $decision.axis -ne $axis.Axis) {
            $failures.Add(
                "Connection '$connectionKey' epoch '$epochIndex' property '$($axis.Property)' reported axis '$($decision.axis)'.")
        }

        foreach ($propertyName in @(
            'axis',
            'decisionSequence',
            'hasForcedValue',
            'forcedValue',
            'hasShadowRecommendation',
            'shadowRecommendation',
            'selectedValue',
            'appliedValue',
            'selectionSource',
            'reasonCode',
            'safetyOverrideReason',
            'decisionBoundary',
            'latchLifetime',
            'latchState',
            'fallbackState',
            'latchSequence')) {
            if ([string] $decision.$propertyName -ne
                [string] $snapshotDecision.$propertyName) {
                $failures.Add(
                    "Connection '$connectionKey' epoch '$epochIndex' axis '$($axis.Axis)' common decision '$propertyName' does not match its policy snapshot.")
            }
        }

        if ([bool] $decision.hasForcedValue) {
            $forcedCount++
            if ([string] $decision.safetyOverrideReason -eq 'None' -and
                [string] $decision.appliedValue -ne [string] $decision.forcedValue) {
                $failures.Add(
                    "Connection '$connectionKey' epoch '$epochIndex' forced axis '$($axis.Axis)' did not apply its forced value.")
            }
        }
        elseif ([string] $decision.appliedValue -ne 'LegacyCurrent') {
            $failures.Add(
                "Connection '$connectionKey' epoch '$epochIndex' adjacent axis '$($axis.Axis)' applied '$($decision.appliedValue)' instead of LegacyCurrent.")
        }
    }

    if ($forcedCount -gt 1) {
        $failures.Add(
            "Connection '$connectionKey' epoch '$epochIndex' forced $forcedCount Stage 1 axes.")
    }
}

$summary = [ordered]@{
    schemaVersion = 'adaptive-runtime-stage1-raw-evidence-validation-v1'
    valid = $failures.Count -eq 0
    rawEpochRowCount = $rows.Count
    axisRecordCount = $axisRecordCount
    missingEventAxisCount = $missingEventAxisCount
    failures = @($failures)
}

$summary | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
