# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CopyPath,

    [Parameter(Mandatory = $true)]
    [string] $ReleasePath,

    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$copyRawSchemaPaths = @{
    'quic-buffer-copy-raw-v2' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-copy-raw-v2.schema.json'
    'quic-buffer-copy-raw-v3' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-copy-raw-v3.schema.json'
}
$copyObservationSchemaPaths = @{
    'quic-buffer-copy-observation-v2' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-copy-observation-v2.schema.json'
    'quic-buffer-copy-observation-v3' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-copy-observation-v3.schema.json'
}
$releaseRawSchemaPaths = @{
    'quic-buffer-release-raw-v1' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v1.schema.json'
    'quic-buffer-release-raw-v2' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v2.schema.json'
    'quic-buffer-release-raw-v3' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v3.schema.json'
    'quic-buffer-release-raw-v4' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v4.schema.json'
    'quic-buffer-release-raw-v5' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v5.schema.json'
    'quic-buffer-release-raw-v6' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v6.schema.json'
    'quic-buffer-release-raw-v7' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-raw-v7.schema.json'
}
$releaseObservationSchemaPaths = @{
    'quic-buffer-release-observation-v1' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v1.schema.json'
    'quic-buffer-release-observation-v2' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v2.schema.json'
    'quic-buffer-release-observation-v3' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v3.schema.json'
    'quic-buffer-release-observation-v4' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v4.schema.json'
    'quic-buffer-release-observation-v5' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v5.schema.json'
    'quic-buffer-release-observation-v6' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v6.schema.json'
    'quic-buffer-release-observation-v7' = Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-buffer-release-observation-v7.schema.json'
}
$failures = [System.Collections.Generic.List[string]]::new()
$copiesByKey = @{}
$trackedCopyKeys = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
$releasesByKey = @{}
$lastCopySequenceByConnection = @{}
$lastReleaseSequenceByConnection = @{}
$copyCount = 0
$trackedCopyCount = 0
$releaseCount = 0

foreach ($line in Get-Content -LiteralPath $CopyPath) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    try {
        $record = $line | ConvertFrom-Json -Depth 100
    }
    catch {
        $failures.Add('A buffer-copy raw record was not valid JSON.')
        continue
    }

    $rawSchemaVersion = [string] $record.schemaVersion
    if (-not $copyRawSchemaPaths.ContainsKey($rawSchemaVersion)) {
        $failures.Add(
            "Unsupported buffer-copy raw schema '$rawSchemaVersion'.")
        continue
    }
    if (-not ($line |
            Test-Json -SchemaFile `
                $copyRawSchemaPaths[$rawSchemaVersion] `
                -ErrorAction Stop)) {
        $failures.Add('A buffer-copy raw record failed schema validation.')
        continue
    }

    $observationSchemaVersion =
        [string] $record.observation.observationContractVersion
    if (-not $copyObservationSchemaPaths.ContainsKey(
            $observationSchemaVersion)) {
        $failures.Add(
            "Unsupported buffer-copy observation schema '$observationSchemaVersion'.")
        continue
    }
    $observationJson = $record.observation |
        ConvertTo-Json -Depth 100 -Compress
    if (-not ($observationJson |
            Test-Json -SchemaFile `
                $copyObservationSchemaPaths[$observationSchemaVersion] `
                -ErrorAction Stop)) {
        $failures.Add(
            'A buffer-copy raw observation failed schema validation.')
        continue
    }

    $connectionKey = [string] $record.connectionKey
    $operationSequence = [ulong] $record.observation.operationSequence
    $key = "$connectionKey|$operationSequence"
    if ($copiesByKey.ContainsKey($key)) {
        $failures.Add(
            "Duplicate buffer-copy join key '$key'.")
        continue
    }

    if ($lastCopySequenceByConnection.ContainsKey($connectionKey) -and
        $operationSequence -le
            [ulong] $lastCopySequenceByConnection[$connectionKey]) {
        $failures.Add(
            "Buffer-copy sequence '$operationSequence' is not increasing for '$connectionKey'.")
    }
    $lastCopySequenceByConnection[$connectionKey] = $operationSequence
    $copiesByKey[$key] = $record
    $copyCount++

    $validityText = [string] $record.observation.validity
    if (-not $validityText.Contains(
            'MissingTerminalReleaseCorrelation',
            [StringComparison]::Ordinal)) {
        [void] $trackedCopyKeys.Add($key)
        $trackedCopyCount++
    }
}

foreach ($line in Get-Content -LiteralPath $ReleasePath) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    try {
        $record = $line | ConvertFrom-Json -Depth 100
    }
    catch {
        $failures.Add('A buffer-release raw record was not valid JSON.')
        continue
    }

    $rawSchemaVersion = [string] $record.schemaVersion
    if (-not $releaseRawSchemaPaths.ContainsKey($rawSchemaVersion)) {
        $failures.Add(
            "Unsupported buffer-release raw schema '$rawSchemaVersion'.")
        continue
    }
    if (-not ($line |
            Test-Json -SchemaFile `
                $releaseRawSchemaPaths[$rawSchemaVersion] `
                -ErrorAction Stop)) {
        $failures.Add('A buffer-release raw record failed schema validation.')
        continue
    }

    $observationSchemaVersion =
        [string] $record.observation.observationContractVersion
    if (-not $releaseObservationSchemaPaths.ContainsKey(
            $observationSchemaVersion)) {
        $failures.Add(
            "Unsupported buffer-release observation schema '$observationSchemaVersion'.")
        continue
    }
    $observationJson = $record.observation |
        ConvertTo-Json -Depth 100 -Compress
    if (-not ($observationJson |
            Test-Json -SchemaFile `
                $releaseObservationSchemaPaths[$observationSchemaVersion] `
                -ErrorAction Stop)) {
        $failures.Add(
            'A buffer-release raw observation failed schema validation.')
        continue
    }

    $connectionKey = [string] $record.connectionKey
    $releaseSequence = [ulong] $record.observation.releaseSequence
    $operationSequence = [ulong] $record.observation.operationSequence
    $key = "$connectionKey|$operationSequence"
    if ($releasesByKey.ContainsKey($key)) {
        $failures.Add(
            "Duplicate terminal release for buffer-copy join key '$key'.")
        continue
    }

    if ($lastReleaseSequenceByConnection.ContainsKey($connectionKey) -and
        $releaseSequence -le
            [ulong] $lastReleaseSequenceByConnection[$connectionKey]) {
        $failures.Add(
            "Buffer-release sequence '$releaseSequence' is not increasing for '$connectionKey'.")
    }
    $lastReleaseSequenceByConnection[$connectionKey] = $releaseSequence
    $releasesByKey[$key] = $record
    $releaseCount++

    if (-not $copiesByKey.ContainsKey($key)) {
        $failures.Add(
            "Buffer release '$key' has no exact construction record.")
        continue
    }

    $copy = $copiesByKey[$key]
    if ([string] $copy.observation.path -ne
        [string] $record.observation.path) {
        $failures.Add(
            "Buffer release '$key' changed the construction path.")
    }
    if ([ulong] $copy.observation.retainedCapacityBytes -ne
        [ulong] $record.observation.releasedCapacityBytes) {
        $failures.Add(
            "Buffer release '$key' changed retained capacity.")
    }
    $releaseValidity = [string] $record.observation.validity
    if ($releaseValidity -ne 'None' -and
        $releaseValidity -ne '0') {
        $failures.Add(
            "Buffer release '$key' retained invalid validity state.")
    }
}

foreach ($key in $trackedCopyKeys) {
    if (-not $releasesByKey.ContainsKey($key)) {
        $failures.Add(
            "Tracked buffer construction '$key' has no terminal release.")
    }
}

$result = [ordered]@{
    schemaVersion =
        'adaptive-runtime-buffer-lifetime-evidence-validation-v1'
    valid = $failures.Count -eq 0
    copyRowCount = $copyCount
    trackedCopyRowCount = $trackedCopyCount
    releaseRowCount = $releaseCount
    exactJoinCount = @(
        $releasesByKey.Keys |
            Where-Object { $copiesByKey.ContainsKey($_) }
    ).Count
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 100
if ($failures.Count -ne 0) {
    exit 1
}
