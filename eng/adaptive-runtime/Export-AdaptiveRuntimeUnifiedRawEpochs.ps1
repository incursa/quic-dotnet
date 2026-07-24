# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $HostLogPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

$prefix = 'QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON='
$failurePrefix = 'QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_FAILURE_JSON='
$rawSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-epoch-raw-v1.schema.json'
$manifestSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-raw-export-manifest-v1.schema.json'
$validatorPath = Join-Path $RepositoryRoot 'eng\adaptive-runtime\Test-AdaptiveRuntimeUnifiedRawEvidence.ps1'
$resolvedOutputDirectory = Resolve-AdaptiveRuntimePath -Path $OutputDirectory
$rawEpochPath = Join-Path $resolvedOutputDirectory 'adaptive-runtime-unified-raw-epochs.jsonl'
$validationPath = Join-Path $resolvedOutputDirectory 'raw-validation-summary.json'
$manifestPath = Join-Path $resolvedOutputDirectory 'raw-export-manifest.json'
$failurePath = Join-Path $resolvedOutputDirectory 'raw-export-failures.jsonl'

foreach ($path in @($rawEpochPath, $validationPath, $manifestPath, $failurePath)) {
    if (Test-Path -LiteralPath $path) {
        throw "Append-only output path already exists: $path"
    }
}

$records = [System.Collections.Generic.List[string]]::new()
$failures = [System.Collections.Generic.List[string]]::new()
$sources = [System.Collections.Generic.List[object]]::new()
foreach ($sourcePath in @($HostLogPath | Sort-Object)) {
    $resolvedSourcePath = (Resolve-Path -LiteralPath $sourcePath).Path
    $sourceRowCount = 0
    $sourceFailureCount = 0
    foreach ($line in [System.IO.File]::ReadLines($resolvedSourcePath)) {
        if ($line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            $json = $line.Substring($prefix.Length)
            if (-not ($json | Test-Json -SchemaFile $rawSchemaPath -ErrorAction Stop)) {
                throw "Unified adaptive-runtime raw epoch from '$resolvedSourcePath' failed schema validation."
            }

            [void] $records.Add($json)
            $sourceRowCount++
        }
        elseif ($line.StartsWith($failurePrefix, [StringComparison]::Ordinal)) {
            [void] $failures.Add($line.Substring($failurePrefix.Length))
            $sourceFailureCount++
        }
    }

    [void] $sources.Add([ordered]@{
        path = $resolvedSourcePath
        sha256 = Get-FileSha256Hex -Path $resolvedSourcePath
        rowCount = $sourceRowCount
        exportFailureCount = $sourceFailureCount
    })
}

if ($records.Count -eq 0) {
    throw 'No unified adaptive-runtime raw epoch records were found in the supplied host logs.'
}

New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
[System.IO.File]::WriteAllLines(
    $rawEpochPath,
    $records,
    [System.Text.UTF8Encoding]::new($false))
if ($failures.Count -ne 0) {
    [System.IO.File]::WriteAllLines(
        $failurePath,
        $failures,
        [System.Text.UTF8Encoding]::new($false))
}

$validationJson = & $validatorPath `
    -RawEpochPath $rawEpochPath `
    -SourceRowCount @($sources | ForEach-Object { [int] $_.rowCount }) `
    -RepositoryRoot $RepositoryRoot
if (-not $?) {
    throw "Unified adaptive-runtime raw evidence validation failed.`n$validationJson"
}

$validationDocument = $validationJson | ConvertFrom-Json -Depth 100
[System.IO.File]::WriteAllText(
    $validationPath,
    ($validationDocument | ConvertTo-Json -Depth 100) + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false))

$artifactRecords = [System.Collections.Generic.List[object]]::new()
[void] $artifactRecords.Add([ordered]@{
    role = 'raw_epochs'
    path = $rawEpochPath
    sha256 = Get-FileSha256Hex -Path $rawEpochPath
    bytes = (Get-Item -LiteralPath $rawEpochPath).Length
})
[void] $artifactRecords.Add([ordered]@{
    role = 'validation_summary'
    path = $validationPath
    sha256 = Get-FileSha256Hex -Path $validationPath
    bytes = (Get-Item -LiteralPath $validationPath).Length
})
if ($failures.Count -ne 0) {
    [void] $artifactRecords.Add([ordered]@{
        role = 'export_failures'
        path = $failurePath
        sha256 = Get-FileSha256Hex -Path $failurePath
        bytes = (Get-Item -LiteralPath $failurePath).Length
    })
}

$manifest = [ordered]@{
    schemaVersion = 'adaptive-runtime-unified-raw-export-manifest-v1'
    createdUtc = (Get-Date).ToUniversalTime().ToString('o')
    rawEpochSchemaVersion = 'adaptive-runtime-unified-epoch-raw-v1'
    classification = if ($failures.Count -eq 0) {
        'accepted'
    }
    else {
        'invalid_contract'
    }
    rowCount = [int] $validationDocument.rawEpochRowCount
    axisRecordCount = [int] $validationDocument.axisRecordCount
    connectionCount = [int] $validationDocument.connectionCount
    actorObservationRowCount =
        [int] $validationDocument.actorObservationRowCount
    bufferObservationRowCount =
        [int] $validationDocument.bufferObservationRowCount
    exportFailureCount = $failures.Count
    sources = @($sources)
    artifacts = @($artifactRecords)
}

[void] (Write-ValidatedJsonDocument `
    -Document $manifest `
    -SchemaPath $manifestSchemaPath `
    -OutputPath $manifestPath)

[ordered]@{
    schemaVersion = 'adaptive-runtime-unified-raw-export-result-v1'
    rowCount = $manifest.rowCount
    axisRecordCount = $manifest.axisRecordCount
    connectionCount = $manifest.connectionCount
    actorObservationRowCount = $manifest.actorObservationRowCount
    bufferObservationRowCount = $manifest.bufferObservationRowCount
    exportFailureCount = $manifest.exportFailureCount
    classification = $manifest.classification
    rawEpochPath = $rawEpochPath
    validationPath = $validationPath
    manifestPath = $manifestPath
} | ConvertTo-Json -Depth 100

if ($failures.Count -ne 0) {
    exit 1
}
