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
$actorPrefix = 'QUIC_ACTOR_SERVICE_OBSERVATION_JSON='
$actorFailurePrefix = 'QUIC_ACTOR_SERVICE_OBSERVATION_FAILURE_JSON='
$adaptiveBackpressurePrefix =
    'QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON='
$packetFlushCadencePrefix =
    'QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON='
$receiveDeliveryQuantumPrefix =
    'QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON='
$rawSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-epoch-raw-v11.schema.json'
$actorSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-actor-service-raw-v4.schema.json'
$actorFailureSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-actor-service-export-failure-v1.schema.json'
$adaptiveBackpressureSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-backpressure-raw-v1.schema.json'
$packetFlushCadenceSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-packet-flush-cadence-raw-v1.schema.json'
$receiveDeliveryQuantumSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-receive-delivery-quantum-raw-v1.schema.json'
$manifestSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-raw-export-manifest-v12.schema.json'
$legacyManifestSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-unified-raw-export-manifest-v11.schema.json'
$validatorPath = Join-Path $RepositoryRoot 'eng\adaptive-runtime\Test-AdaptiveRuntimeUnifiedRawEvidence.ps1'
$resolvedOutputDirectory = Resolve-AdaptiveRuntimePath -Path $OutputDirectory
$rawEpochPath = Join-Path $resolvedOutputDirectory 'adaptive-runtime-unified-raw-epochs.jsonl'
$actorObservationPath = Join-Path $resolvedOutputDirectory 'adaptive-runtime-actor-service-observations.jsonl'
$adaptiveBackpressureObservationPath =
    Join-Path $resolvedOutputDirectory 'adaptive-runtime-backpressure-observations.jsonl'
$packetFlushCadenceObservationPath =
    Join-Path $resolvedOutputDirectory 'adaptive-runtime-packet-flush-cadence-observations.jsonl'
$receiveDeliveryQuantumObservationPath =
    Join-Path $resolvedOutputDirectory 'adaptive-runtime-receive-delivery-quantum-observations.jsonl'
$validationPath = Join-Path $resolvedOutputDirectory 'raw-validation-summary.json'
$manifestPath = Join-Path $resolvedOutputDirectory 'raw-export-manifest.json'
$failurePath = Join-Path $resolvedOutputDirectory 'raw-export-failures.jsonl'

foreach ($path in @(
    $rawEpochPath,
    $actorObservationPath,
    $adaptiveBackpressureObservationPath,
    $packetFlushCadenceObservationPath,
    $receiveDeliveryQuantumObservationPath,
    $validationPath,
    $manifestPath,
    $failurePath
)) {
    if (Test-Path -LiteralPath $path) {
        throw "Append-only output path already exists: $path"
    }
}

$records = [System.Collections.Generic.List[string]]::new()
$actorObservations = [System.Collections.Generic.List[string]]::new()
$adaptiveBackpressureObservations =
    [System.Collections.Generic.List[string]]::new()
$packetFlushCadenceObservations =
    [System.Collections.Generic.List[string]]::new()
$receiveDeliveryQuantumObservations =
    [System.Collections.Generic.List[string]]::new()
$failures = [System.Collections.Generic.List[string]]::new()
$sources = [System.Collections.Generic.List[object]]::new()
foreach ($sourcePath in @($HostLogPath | Sort-Object)) {
    $resolvedSourcePath = (Resolve-Path -LiteralPath $sourcePath).Path
    $sourceRowCount = 0
    $sourceActorObservationCount = 0
    $sourceAdaptiveBackpressureEpochCount = 0
    $sourceAdaptiveBackpressureObservationCount = 0
    $sourcePacketFlushCadenceEpochCount = 0
    $sourcePacketFlushCadenceObservationCount = 0
    $sourceReceiveDeliveryQuantumEpochCount = 0
    $sourceReceiveDeliveryQuantumObservationCount = 0
    $sourceActorFailureCount = 0
    $sourceFailureCount = 0
    foreach ($line in [System.IO.File]::ReadLines($resolvedSourcePath)) {
        if ($line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            $json = $line.Substring($prefix.Length)
            if (-not ($json | Test-Json -SchemaFile $rawSchemaPath -ErrorAction Stop)) {
                throw "Unified adaptive-runtime raw epoch from '$resolvedSourcePath' failed schema validation."
            }

            [void] $records.Add($json)
            $sourceRowCount++
            $parsedRecord = $json | ConvertFrom-Json -Depth 100
            if ([bool] $parsedRecord.epoch.adaptiveBackpressure.hasObservation) {
                $sourceAdaptiveBackpressureEpochCount++
            }
            if ([bool] $parsedRecord.epoch.packetFlushCadence.hasObservation) {
                $sourcePacketFlushCadenceEpochCount++
            }
            if ([bool] $parsedRecord.epoch.receiveDeliveryQuantum.hasObservation) {
                $sourceReceiveDeliveryQuantumEpochCount++
            }
        }
        elseif ($line.StartsWith($actorPrefix, [StringComparison]::Ordinal)) {
            $json = $line.Substring($actorPrefix.Length)
            if (-not ($json | Test-Json -SchemaFile $actorSchemaPath -ErrorAction Stop)) {
                throw "Actor-service raw observation from '$resolvedSourcePath' failed schema validation."
            }

            [void] $actorObservations.Add($json)
            $sourceActorObservationCount++
        }
        elseif ($line.StartsWith(
                $adaptiveBackpressurePrefix,
                [StringComparison]::Ordinal)) {
            $json = $line.Substring($adaptiveBackpressurePrefix.Length)
            if (-not (
                    $json |
                        Test-Json `
                            -SchemaFile $adaptiveBackpressureSchemaPath `
                            -ErrorAction Stop)) {
                throw "Adaptive-backpressure raw observation from '$resolvedSourcePath' failed schema validation."
            }

            [void] $adaptiveBackpressureObservations.Add($json)
            $sourceAdaptiveBackpressureObservationCount++
        }
        elseif ($line.StartsWith(
                $packetFlushCadencePrefix,
                [StringComparison]::Ordinal)) {
            $json = $line.Substring($packetFlushCadencePrefix.Length)
            if (-not (
                    $json |
                        Test-Json `
                            -SchemaFile $packetFlushCadenceSchemaPath `
                            -ErrorAction Stop)) {
                throw "Packet-flush cadence raw observation from '$resolvedSourcePath' failed schema validation."
            }

            [void] $packetFlushCadenceObservations.Add($json)
            $sourcePacketFlushCadenceObservationCount++
        }
        elseif ($line.StartsWith(
                $receiveDeliveryQuantumPrefix,
                [StringComparison]::Ordinal)) {
            $json = $line.Substring($receiveDeliveryQuantumPrefix.Length)
            if (-not (
                    $json |
                        Test-Json `
                            -SchemaFile $receiveDeliveryQuantumSchemaPath `
                            -ErrorAction Stop)) {
                throw "Receive-delivery quantum raw observation from '$resolvedSourcePath' failed schema validation."
            }

            [void] $receiveDeliveryQuantumObservations.Add($json)
            $sourceReceiveDeliveryQuantumObservationCount++
        }
        elseif ($line.StartsWith($actorFailurePrefix, [StringComparison]::Ordinal)) {
            $json = $line.Substring($actorFailurePrefix.Length)
            if (-not ($json | Test-Json -SchemaFile $actorFailureSchemaPath -ErrorAction Stop)) {
                throw "Actor-service export failure from '$resolvedSourcePath' failed schema validation."
            }

            [void] $failures.Add($json)
            $sourceActorFailureCount++
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
        actorObservationRowCount = $sourceActorObservationCount
        adaptiveBackpressureEpochRowCount =
            $sourceAdaptiveBackpressureEpochCount
        adaptiveBackpressureObservationRowCount =
            $sourceAdaptiveBackpressureObservationCount
        packetFlushCadenceEpochRowCount =
            $sourcePacketFlushCadenceEpochCount
        packetFlushCadenceObservationRowCount =
            $sourcePacketFlushCadenceObservationCount
        receiveDeliveryQuantumEpochRowCount =
            $sourceReceiveDeliveryQuantumEpochCount
        receiveDeliveryQuantumObservationRowCount =
            $sourceReceiveDeliveryQuantumObservationCount
        actorExportFailureCount = $sourceActorFailureCount
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
[System.IO.File]::WriteAllLines(
    $actorObservationPath,
    $actorObservations,
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllLines(
    $adaptiveBackpressureObservationPath,
    $adaptiveBackpressureObservations,
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllLines(
    $packetFlushCadenceObservationPath,
    $packetFlushCadenceObservations,
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllLines(
    $receiveDeliveryQuantumObservationPath,
    $receiveDeliveryQuantumObservations,
    [System.Text.UTF8Encoding]::new($false))
if ($failures.Count -ne 0) {
    [System.IO.File]::WriteAllLines(
        $failurePath,
        $failures,
        [System.Text.UTF8Encoding]::new($false))
}

$validationJson = & $validatorPath `
    -RawEpochPath $rawEpochPath `
    -ActorObservationPath $actorObservationPath `
    -AdaptiveBackpressureObservationPath `
        $adaptiveBackpressureObservationPath `
    -PacketFlushCadenceObservationPath `
        $packetFlushCadenceObservationPath `
    -ReceiveDeliveryQuantumObservationPath `
        $receiveDeliveryQuantumObservationPath `
    -SourceRowCount @($sources | ForEach-Object { [int] $_.rowCount }) `
    -SourceActorObservationRowCount @(
        $sources | ForEach-Object { [int] $_.actorObservationRowCount }) `
    -SourceAdaptiveBackpressureObservationRowCount @(
        $sources |
            ForEach-Object {
                [int] $_.adaptiveBackpressureObservationRowCount
            }) `
    -SourcePacketFlushCadenceObservationRowCount @(
        $sources |
            ForEach-Object {
                [int] $_.packetFlushCadenceObservationRowCount
            }) `
    -SourceReceiveDeliveryQuantumObservationRowCount @(
        $sources |
            ForEach-Object {
                [int] $_.receiveDeliveryQuantumObservationRowCount
            }) `
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
    role = 'actor_service_observations'
    path = $actorObservationPath
    sha256 = Get-FileSha256Hex -Path $actorObservationPath
    bytes = (Get-Item -LiteralPath $actorObservationPath).Length
})
[void] $artifactRecords.Add([ordered]@{
    role = 'adaptive_backpressure_observations'
    path = $adaptiveBackpressureObservationPath
    sha256 =
        Get-FileSha256Hex -Path $adaptiveBackpressureObservationPath
    bytes =
        (Get-Item -LiteralPath $adaptiveBackpressureObservationPath).Length
})
[void] $artifactRecords.Add([ordered]@{
    role = 'packet_flush_cadence_observations'
    path = $packetFlushCadenceObservationPath
    sha256 =
        Get-FileSha256Hex -Path $packetFlushCadenceObservationPath
    bytes =
        (Get-Item -LiteralPath $packetFlushCadenceObservationPath).Length
})
[void] $artifactRecords.Add([ordered]@{
    role = 'receive_delivery_quantum_observations'
    path = $receiveDeliveryQuantumObservationPath
    sha256 =
        Get-FileSha256Hex -Path $receiveDeliveryQuantumObservationPath
    bytes =
        (Get-Item -LiteralPath $receiveDeliveryQuantumObservationPath).Length
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
    schemaVersion = 'adaptive-runtime-unified-raw-export-manifest-v12'
    createdUtc = (Get-Date).ToUniversalTime().ToString('o')
    rawEpochSchemaVersion = 'adaptive-runtime-unified-epoch-raw-v11'
    actorRawObservationSchemaVersion =
        'adaptive-runtime-actor-service-raw-v4'
    bufferRawObservationSchemaVersion = 'quic-buffer-copy-raw-v4'
    adaptiveBackpressureRawObservationSchemaVersion =
        'quic-adaptive-backpressure-raw-v1'
    packetFlushCadenceRawObservationSchemaVersion =
        'quic-packet-flush-cadence-raw-v1'
    receiveDeliveryQuantumRawObservationSchemaVersion =
        'quic-receive-delivery-quantum-raw-v1'
    classification = if ($failures.Count -eq 0) {
        'accepted'
    }
    else {
        'invalid_contract'
    }
    rowCount = [int] $validationDocument.rawEpochRowCount
    axisRecordCount = [int] $validationDocument.axisRecordCount
    connectionCount = [int] $validationDocument.connectionCount
    actorEpochRowCount = [int] $validationDocument.actorEpochRowCount
    actorObservationRowCount =
        [int] $validationDocument.actorObservationRowCount
    bufferObservationRowCount =
        [int] $validationDocument.bufferObservationRowCount
    adaptiveBackpressureEpochRowCount =
        [int] $validationDocument.adaptiveBackpressureEpochRowCount
    adaptiveBackpressureObservationRowCount =
        [int] $validationDocument.adaptiveBackpressureObservationRowCount
    packetFlushCadenceEpochRowCount =
        [int] $validationDocument.packetFlushCadenceEpochRowCount
    packetFlushCadenceObservationRowCount =
        [int] $validationDocument.packetFlushCadenceObservationRowCount
    receiveDeliveryQuantumEpochRowCount =
        [int] $validationDocument.receiveDeliveryQuantumEpochRowCount
    receiveDeliveryQuantumObservationRowCount =
        [int] $validationDocument.receiveDeliveryQuantumObservationRowCount
    actorExportFailureCount = [int] (
        @(
            $sources |
                ForEach-Object { [int] $_.actorExportFailureCount }
        ) |
            Measure-Object -Sum
    ).Sum
    exportFailureCount = $failures.Count
    sources = @($sources)
    artifacts = @($artifactRecords)
}

$legacyManifest = [ordered]@{}
foreach ($entry in $manifest.GetEnumerator()) {
    $legacyManifest[$entry.Key] = $entry.Value
}
$legacyManifest.schemaVersion =
    'adaptive-runtime-unified-raw-export-manifest-v11'
$legacyManifest.rawEpochSchemaVersion =
    'adaptive-runtime-unified-epoch-raw-v10'
$legacyManifestJson =
    $legacyManifest | ConvertTo-Json -Depth 100 -Compress
if (-not (
        $legacyManifestJson |
            Test-Json `
                -SchemaFile $legacyManifestSchemaPath `
                -ErrorAction Stop)) {
    throw 'Unified adaptive-runtime v11 manifest base projection failed schema validation.'
}

[void] (Write-ValidatedJsonDocument `
    -Document $manifest `
    -SchemaPath $manifestSchemaPath `
    -OutputPath $manifestPath)

[ordered]@{
    schemaVersion = 'adaptive-runtime-unified-raw-export-result-v12'
    rowCount = $manifest.rowCount
    axisRecordCount = $manifest.axisRecordCount
    connectionCount = $manifest.connectionCount
    actorEpochRowCount = $manifest.actorEpochRowCount
    actorObservationRowCount = $manifest.actorObservationRowCount
    bufferObservationRowCount = $manifest.bufferObservationRowCount
    adaptiveBackpressureEpochRowCount =
        $manifest.adaptiveBackpressureEpochRowCount
    adaptiveBackpressureObservationRowCount =
        $manifest.adaptiveBackpressureObservationRowCount
    packetFlushCadenceEpochRowCount =
        $manifest.packetFlushCadenceEpochRowCount
    packetFlushCadenceObservationRowCount =
        $manifest.packetFlushCadenceObservationRowCount
    receiveDeliveryQuantumEpochRowCount =
        $manifest.receiveDeliveryQuantumEpochRowCount
    receiveDeliveryQuantumObservationRowCount =
        $manifest.receiveDeliveryQuantumObservationRowCount
    actorExportFailureCount = $manifest.actorExportFailureCount
    exportFailureCount = $manifest.exportFailureCount
    classification = $manifest.classification
    rawEpochPath = $rawEpochPath
    actorObservationPath = $actorObservationPath
    adaptiveBackpressureObservationPath =
        $adaptiveBackpressureObservationPath
    packetFlushCadenceObservationPath =
        $packetFlushCadenceObservationPath
    receiveDeliveryQuantumObservationPath =
        $receiveDeliveryQuantumObservationPath
    validationPath = $validationPath
    manifestPath = $manifestPath
} | ConvertTo-Json -Depth 100

if ($failures.Count -ne 0) {
    exit 1
}
