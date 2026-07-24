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

$prefix = 'QUIC_ADAPTIVE_RUNTIME_STAGE1_UNIFIED_EPOCH_JSON='
$rawSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-unified-epoch-raw-v1.schema.json'
$manifestSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-raw-export-manifest-v1.schema.json'
$validatorPath = Join-Path $RepositoryRoot 'eng\adaptive-runtime\Test-AdaptiveRuntimeStage1RawEvidence.ps1'
$resolvedOutputDirectory = Resolve-AdaptiveRuntimePath -Path $OutputDirectory
$rawEpochPath = Join-Path $resolvedOutputDirectory 'stage1-unified-raw-epochs.jsonl'
$validationPath = Join-Path $resolvedOutputDirectory 'raw-validation-summary.json'
$manifestPath = Join-Path $resolvedOutputDirectory 'raw-export-manifest.json'

foreach ($path in @($rawEpochPath, $validationPath, $manifestPath)) {
    if (Test-Path -LiteralPath $path) {
        throw "Append-only output path already exists: $path"
    }
}

$records = [System.Collections.Generic.List[string]]::new()
$sources = [System.Collections.Generic.List[object]]::new()
foreach ($sourcePath in @($HostLogPath | Sort-Object)) {
    $resolvedSourcePath = (Resolve-Path -LiteralPath $sourcePath).Path
    $sourceRowCount = 0
    foreach ($line in [System.IO.File]::ReadLines($resolvedSourcePath)) {
        if (-not $line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            continue
        }

        $json = $line.Substring($prefix.Length)
        if (-not ($json | Test-Json -SchemaFile $rawSchemaPath -ErrorAction Stop)) {
            throw "Stage 1 raw epoch from '$resolvedSourcePath' failed schema validation."
        }

        [void] $records.Add($json)
        $sourceRowCount++
    }

    [void] $sources.Add([ordered]@{
        path = $resolvedSourcePath
        sha256 = Get-FileSha256Hex -Path $resolvedSourcePath
        rowCount = $sourceRowCount
    })
}

if ($records.Count -eq 0) {
    throw 'No Stage 1 unified raw epoch records were found in the supplied host logs.'
}

New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
[System.IO.File]::WriteAllLines(
    $rawEpochPath,
    $records,
    [System.Text.UTF8Encoding]::new($false))

$validationJson = & $validatorPath `
    -RawEpochPath $rawEpochPath `
    -RepositoryRoot $RepositoryRoot
if (-not $?) {
    throw "Stage 1 raw evidence validation failed.`n$validationJson"
}

$validationDocument = $validationJson | ConvertFrom-Json -Depth 100
[System.IO.File]::WriteAllText(
    $validationPath,
    ($validationDocument | ConvertTo-Json -Depth 100) + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false))

$manifest = [ordered]@{
    schemaVersion = 'adaptive-runtime-stage1-raw-export-manifest-v1'
    createdUtc = (Get-Date).ToUniversalTime().ToString('o')
    rawEpochSchemaVersion = 'adaptive-runtime-stage1-unified-epoch-raw-v1'
    rowCount = [int] $validationDocument.rawEpochRowCount
    axisRecordCount = [int] $validationDocument.axisRecordCount
    missingEventAxisCount = [int] $validationDocument.missingEventAxisCount
    sources = @($sources)
    artifacts = @(
        [ordered]@{
            role = 'raw_epochs'
            path = $rawEpochPath
            sha256 = Get-FileSha256Hex -Path $rawEpochPath
            bytes = (Get-Item -LiteralPath $rawEpochPath).Length
        },
        [ordered]@{
            role = 'validation_summary'
            path = $validationPath
            sha256 = Get-FileSha256Hex -Path $validationPath
            bytes = (Get-Item -LiteralPath $validationPath).Length
        }
    )
}

[void] (Write-ValidatedJsonDocument `
    -Document $manifest `
    -SchemaPath $manifestSchemaPath `
    -OutputPath $manifestPath)

[ordered]@{
    schemaVersion = 'adaptive-runtime-stage1-raw-export-result-v1'
    rowCount = $manifest.rowCount
    axisRecordCount = $manifest.axisRecordCount
    missingEventAxisCount = $manifest.missingEventAxisCount
    rawEpochPath = $rawEpochPath
    validationPath = $validationPath
    manifestPath = $manifestPath
} | ConvertTo-Json -Depth 100
