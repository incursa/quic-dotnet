# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RawProvenancePath,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $DatasetId,

    [Parameter(Mandatory = $true)]
    [string] $CampaignId,

    [Parameter(Mandatory = $true)]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [string] $CellId,

    [Parameter(Mandatory = $true)]
    [string] $SampleId,

    [Parameter(Mandatory = $true)]
    [ValidateSet('legacy_current', 'conservative')]
    [string] $ExpectedPolicy,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $BenchmarkSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $RuntimeSha256,

    [Parameter(Mandatory = $true)]
    [string] $HostFingerprint,

    [Parameter(Mandatory = $true)]
    [string] $CorrectnessFlagsJson,

    [Parameter(Mandatory = $true)]
    [string] $ScenarioId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int] $Connections,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int] $StreamsPerConnection,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, [long]::MaxValue)]
    [long] $WarmupMicros,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $MeasurementMicros,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,

    [string] $RepositoryCommit = (git -C (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path rev-parse HEAD).Trim(),

    [switch] $RepositoryDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rawPath = (Resolve-Path -LiteralPath $RawProvenancePath -ErrorAction Stop).Path
$schemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-construction-dataset-v1.schema.json'
if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
    throw "Construction provenance schema was not found: $schemaPath"
}

$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $resolvedOutputDirectory) {
    throw "Construction provenance output target already exists and will not be overwritten: $resolvedOutputDirectory"
}
New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null

$sourceHash = (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant()
try {
    $correctnessFlags = $CorrectnessFlagsJson | ConvertFrom-Json -Depth 8
}
catch {
    throw "CorrectnessFlagsJson is not valid JSON. $($_.Exception.Message)"
}

foreach ($propertyName in @('payloadValid', 'protocolValid', 'timedOut', 'ownershipValid', 'terminalValid', 'violationCodes')) {
    if ($null -eq $correctnessFlags.PSObject.Properties[$propertyName]) {
        throw "CorrectnessFlagsJson is missing required property '$propertyName'."
    }
}

$normalizedCorrectnessFlags = [ordered]@{
    payloadValid = [bool] $correctnessFlags.payloadValid
    protocolValid = [bool] $correctnessFlags.protocolValid
    timedOut = [bool] $correctnessFlags.timedOut
    ownershipValid = [bool] $correctnessFlags.ownershipValid
    terminalValid = [bool] $correctnessFlags.terminalValid
    violationCodes = @($correctnessFlags.violationCodes | ForEach-Object { [string] $_ })
}

$correctnessInvalid = -not $normalizedCorrectnessFlags.payloadValid -or
    -not $normalizedCorrectnessFlags.protocolValid -or
    $normalizedCorrectnessFlags.timedOut -or
    -not $normalizedCorrectnessFlags.ownershipValid -or
    -not $normalizedCorrectnessFlags.terminalValid -or
    $normalizedCorrectnessFlags.violationCodes.Count -ne 0
[string[]] $analysisExclusionFlags = if ($correctnessInvalid) { , 'correctness_failed' } else { , 'none' }

$records = @(
    Get-Content -LiteralPath $rawPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        try { $_ | ConvertFrom-Json -Depth 16 }
        catch { throw "Construction provenance source contains invalid JSON: $rawPath. $($_.Exception.Message)" }
    }
)
if ($records.Count -eq 0) {
    throw "Construction provenance source contains no records: $rawPath"
}

$seenConnections = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$rowPaths = [System.Collections.Generic.List[string]]::new()
foreach ($record in $records) {
    if ([string] $record.schemaVersion -ne 'adaptive-runtime-application-send-turn-provenance-v1') {
        throw "Construction provenance record has an unsupported schemaVersion: $($record.schemaVersion)"
    }
    if ([string] $record.axisId -ne 'application_send_turn_planning') {
        throw "Construction provenance record has an unexpected axisId: $($record.axisId)"
    }
    if ([string] $record.ruleVersion -ne 'application-send-turn-force-v1') {
        throw "Construction provenance record has an unexpected ruleVersion: $($record.ruleVersion)"
    }
    $appliedPolicy = switch ([string] $record.appliedPolicy) {
        'LegacyCurrent' { 'legacy_current'; break }
        'Conservative' { 'conservative'; break }
        default { throw "Construction provenance record has an unsupported appliedPolicy: $($record.appliedPolicy)" }
    }
    if ($appliedPolicy -ne $ExpectedPolicy) {
        throw "Construction provenance record policy mismatch: expected '$ExpectedPolicy', actual '$appliedPolicy'."
    }

    $connectionKey = [string] $record.connectionKey
    if ([string]::IsNullOrWhiteSpace($connectionKey) -or -not $seenConnections.Add($connectionKey)) {
        throw "Construction provenance record has a missing or duplicate connectionKey: '$connectionKey'."
    }

    $row = [ordered]@{
        schemaVersion = 'adaptive-runtime-policy-construction-dataset-v1'
        datasetId = $DatasetId
        rowId = "$SampleId-$connectionKey-construction"
        campaignId = $CampaignId
        runId = $RunId
        cellId = $CellId
        sampleId = $SampleId
        repetition = 0
        connectionKey = $connectionKey
        axisId = 'application_send_turn_planning'
        constructionPolicyState = [ordered]@{
            provenanceContractVersion = [string] $record.schemaVersion
            ruleVersion = [string] $record.ruleVersion
            appliedPolicy = $appliedPolicy
            selectionSource = 'forced'
        }
        correctnessFlags = $normalizedCorrectnessFlags
        provenance = [ordered]@{
            repositoryCommit = $RepositoryCommit
            repositoryDirty = [bool] $RepositoryDirty
            benchmarkSha256 = $BenchmarkSha256.ToLowerInvariant()
            runtimeSha256 = $RuntimeSha256.ToLowerInvariant()
            hostFingerprint = $HostFingerprint
            resultSchemaVersion = 'adaptive-runtime-policy-local-result-v1'
            sourceArtifactPath = $rawPath
            sourceArtifactSha256 = $sourceHash
            transformation = [ordered]@{
                name = 'adaptive-runtime-construction-provenance-export'
                version = '1.0.0'
                codeCommit = $RepositoryCommit
                inputSha256 = $sourceHash
                outputSha256 = ('0' * 64)
            }
        }
        workloadAnalysisOnly = [ordered]@{
            excludedFromProductionFeatures = $true
            scenarioId = $ScenarioId
            requestedConnections = $Connections
            effectiveConnections = $Connections
            requestedStreamsPerConnection = $StreamsPerConnection
            effectiveStreamsPerConnection = $StreamsPerConnection
            requestedConcurrency = $Connections * $StreamsPerConnection
            effectiveConcurrency = $Connections * $StreamsPerConnection
            warmupMicros = $WarmupMicros
            measurementMicros = $MeasurementMicros
        }
        analysisExclusionFlags = $analysisExclusionFlags
    }

    $canonical = $row | ConvertTo-Json -Depth 30 -Compress
    $row.provenance.transformation.outputSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
    $rowFileName = 'construction-row-' + [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($connectionKey))).ToLowerInvariant() + '.json'
    $rowPath = Join-Path $resolvedOutputDirectory $rowFileName
    $row | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $rowPath -Encoding utf8
    if (-not ((Get-Content -LiteralPath $rowPath -Raw) | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw "Generated construction provenance row did not validate: $rowPath"
    }
    $rowPaths.Add($rowPath)
}

$rowChecksums = @(
    $rowPaths | ForEach-Object {
        [ordered]@{
            path = $_
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
)

[ordered]@{
    schemaVersion = 'adaptive-runtime-policy-construction-provenance-export-manifest-v1'
    sourceArtifactPath = $rawPath
    sourceArtifactSha256 = $sourceHash
    rowCount = $rowPaths.Count
    rowPaths = @($rowPaths)
    rowChecksums = $rowChecksums
} | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $resolvedOutputDirectory 'construction-provenance-export-manifest.json') -Encoding utf8

Write-Output (@($rowPaths) | ConvertTo-Json -Depth 4)
