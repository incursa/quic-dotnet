# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $LocalResultPath,

    [string[]] $EpochDatasetPath = @(),

    [string[]] $ConstructionDatasetPath = @(),

    [switch] $AllowUnmatchedEpochRows,

    [switch] $AllowLegacyResultLevelEnvironmentExclusions,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$localResultSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-local-result-v1.schema.json'
$epochDatasetSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-epoch-dataset-v1.schema.json'
$constructionDatasetSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-construction-dataset-v1.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$validatedLocalResults = [System.Collections.Generic.List[object]]::new()
$validatedEpochRows = [System.Collections.Generic.List[object]]::new()
$validatedConstructionRows = [System.Collections.Generic.List[object]]::new()
$verifiedArtifactSha256ByPath = [System.Collections.Generic.Dictionary[string,string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
$sendTurnRawRecordLookupsByPath = [System.Collections.Generic.Dictionary[string,object]]::new(
    [StringComparer]::OrdinalIgnoreCase)
$legacyResultLevelEnvironmentExclusionRows = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)

function Resolve-NormalizedEvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $BasePath,

        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-CollectionCount {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value) {
        return 0
    }

    return @($Value).Count
}

function ConvertTo-NullableLong {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) {
        return $null
    }

    return [long] $Value
}

function ConvertTo-NullableDouble {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) {
        return $null
    }

    return [double] $Value
}

function Get-OptionalObjectProperty {
    param(
        [AllowNull()][object] $Object,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-MetricValueFromSummary {
    param(
        [AllowNull()][object] $Summary,

        [Parameter(Mandatory = $true)]
        [string] $MetricName,

        [Parameter(Mandatory = $true)]
        [string] $PropertyName
    )

    if ($null -eq $Summary) {
        return $null
    }

    $metric = @($Summary.metrics | Where-Object {
        [string] $_.metricName -eq $MetricName
    }) | Select-Object -First 1
    if ($null -eq $metric) {
        return $null
    }

    return Get-OptionalObjectProperty -Object $metric -Name $PropertyName
}

function Get-Median {
    param([AllowNull()][object[]] $Values)

    $numbers = @($Values | Where-Object { $null -ne $_ } | ForEach-Object { [double] $_ } | Sort-Object)
    if ($numbers.Count -eq 0) {
        return $null
    }

    $middle = [int][Math]::Floor($numbers.Count / 2)
    if (($numbers.Count % 2) -eq 1) {
        return $numbers[$middle]
    }

    return ($numbers[$middle - 1] + $numbers[$middle]) / 2.0
}

function Get-RoundedMedianInt64 {
    param([AllowNull()][object[]] $Values)

    $numbers = @($Values | Where-Object { $null -ne $_ } | ForEach-Object { [double] $_ } | Sort-Object)
    if ($numbers.Count -eq 0) {
        return $null
    }

    $middle = [int][Math]::Floor($numbers.Count / 2)
    $median = if (($numbers.Count % 2) -eq 1) {
        $numbers[$middle]
    }
    else {
        ($numbers[$middle - 1] + $numbers[$middle]) / 2.0
    }

    return [long] [Math]::Round($median, 0, [MidpointRounding]::AwayFromZero)
}

function Get-ExpectedFairnessViolations {
    param([int] $StarvationCount)

    if ($StarvationCount -gt 0) {
        return @('stream_completion_incomplete')
    }

    return @()
}

function Get-ChecksumInventoryContext {
    param(
        [Parameter(Mandatory = $true)]
        [object] $ResultItem
    )

    $resultDirectory = Split-Path -Parent $ResultItem.Path
    $checksumArtifacts = @($ResultItem.Document.artifacts | Where-Object { $_.kind -eq 'checksum_inventory' })
    if ($checksumArtifacts.Count -eq 0) {
        $failures.Add("Local result '$($ResultItem.Path)' has no checksum inventory; checksum-backed source joins are required.")
        return $null
    }

    if ($checksumArtifacts.Count -ne 1) {
        $failures.Add("Local result '$($ResultItem.Path)' retained $($checksumArtifacts.Count) checksum inventories; exactly one is required.")
        return $null
    }

    $checksumArtifact = $checksumArtifacts[0]
    $inventoryPath = Resolve-NormalizedEvidencePath -BasePath $resultDirectory -Path ([string] $checksumArtifact.path)
    if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
        $failures.Add("Local result '$($ResultItem.Path)' retained checksum inventory '$inventoryPath', but that file was not found.")
        return $null
    }

    $actualInventorySha256 = (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $declaredInventorySha256 = ([string] $checksumArtifact.sha256).ToLowerInvariant()
    if (-not [string]::Equals($actualInventorySha256, $declaredInventorySha256, [StringComparison]::Ordinal)) {
        $failures.Add("Local result '$($ResultItem.Path)' recorded checksum inventory sha256 '$declaredInventorySha256', but '$inventoryPath' hashed to '$actualInventorySha256'.")
        return $null
    }

    try {
        $inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json -Depth 50
    }
    catch {
        $failures.Add("Checksum inventory '$inventoryPath' could not be parsed: $($_.Exception.Message)")
        return $null
    }

    $entriesByPath = @{}
    foreach ($entry in @($inventory.files)) {
        $declaredPath = [string] $entry.path
        if ([string]::IsNullOrWhiteSpace($declaredPath)) {
            $failures.Add("Checksum inventory '$inventoryPath' contains an entry with an empty path.")
            continue
        }

        $normalizedPath = Resolve-NormalizedEvidencePath -BasePath (Split-Path -Parent $inventoryPath) -Path $declaredPath
        if ($entriesByPath.ContainsKey($normalizedPath)) {
            $failures.Add("Checksum inventory '$inventoryPath' contains duplicate path '$normalizedPath'.")
            continue
        }

        $entriesByPath[$normalizedPath] = [pscustomobject]@{
            Path = $normalizedPath
            Sha256 = [string] $entry.sha256
        }
    }

    return [pscustomobject]@{
        Path = $inventoryPath
        Directory = Split-Path -Parent $inventoryPath
        EntriesByPath = $entriesByPath
    }
}

function Test-InventoryJoin {
    param(
        [AllowNull()][object] $InventoryContext,

        [Parameter(Mandatory = $true)]
        [string] $BasePath,

        [AllowNull()][string] $DeclaredPath,

        [AllowNull()][string] $ExpectedSha256,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    if ($null -eq $InventoryContext -or [string]::IsNullOrWhiteSpace($DeclaredPath)) {
        return $null
    }

    $normalizedPath = Resolve-NormalizedEvidencePath -BasePath $BasePath -Path $DeclaredPath
    if (-not $InventoryContext.EntriesByPath.ContainsKey($normalizedPath)) {
        $failures.Add("$Description is missing from checksum inventory '$($InventoryContext.Path)'.")
        return $normalizedPath
    }

    $entry = $InventoryContext.EntriesByPath[$normalizedPath]
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
        -not [string]::Equals([string] $entry.Sha256, $ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        $failures.Add("$Description expected sha256 '$ExpectedSha256' but checksum inventory '$($InventoryContext.Path)' recorded '$($entry.Sha256)'.")
    }

    if ($verifiedArtifactSha256ByPath.ContainsKey($normalizedPath)) {
        $actualSha256 = $verifiedArtifactSha256ByPath[$normalizedPath]
    }
    else {
        if (-not (Test-Path -LiteralPath $normalizedPath -PathType Leaf)) {
            $failures.Add("$Description points to '$normalizedPath', but that file was not found.")
            return $normalizedPath
        }

        # Evidence artifacts are append-only for one validation invocation.
        # Hash each unique path once while still checking every declared join
        # and every inventory digest against that verified value.
        $actualSha256 = (Get-FileHash -LiteralPath $normalizedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $verifiedArtifactSha256ByPath[$normalizedPath] = $actualSha256
    }

    if (-not [string]::Equals($actualSha256, [string] $entry.Sha256, [StringComparison]::OrdinalIgnoreCase)) {
        $failures.Add("$Description path '$normalizedPath' does not match checksum inventory '$($InventoryContext.Path)'.")
    }

    return $normalizedPath
}

function Add-ExpectedExclusionFlags {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]] $Flags,

        [Parameter(Mandatory = $true)]
        [object] $Row,

        [Parameter(Mandatory = $true)]
        [object] $Result,

        [bool] $IsSendTurnTerminalPartialEpoch = $false
    )

    if ([long] $Row.preDecisionObservations.missingSignalMask -ne 0) {
        [void] $Flags.Add('observation_missing')
    }

    if ([long] $Row.preDecisionObservations.staleSignalMask -ne 0) {
        [void] $Flags.Add('observation_stale')
    }

    if ([string] $Row.candidatePolicySelection.reasonCode -eq 'arithmetic_saturated') {
        [void] $Flags.Add('observation_saturated')
    }

    if ([bool] $Row.preDecisionObservations.outOfDomain -or
        [string] $Row.candidatePolicySelection.reasonCode -eq 'out_of_domain') {
        [void] $Flags.Add('out_of_domain')
    }

    if ([long] $Row.epochStartOffsetMicros -lt [long] $Row.workloadAnalysisOnly.warmupMicros) {
        [void] $Flags.Add('warmup')
    }

    if (([long] $Row.preDecisionObservations.lifecycleFlags -band 96) -ne 0 -or
        $IsSendTurnTerminalPartialEpoch) {
        [void] $Flags.Add('terminal_partial_epoch')
    }

    $correctnessInvalid = -not [bool] $Row.correctnessFlags.payloadValid -or
        -not [bool] $Row.correctnessFlags.protocolValid -or
        [bool] $Row.correctnessFlags.timedOut -or
        -not [bool] $Row.correctnessFlags.ownershipValid -or
        -not [bool] $Row.correctnessFlags.terminalValid -or
        (Get-CollectionCount -Value $Row.correctnessFlags.violationCodes) -ne 0
    if ($correctnessInvalid) {
        [void] $Flags.Add('correctness_failed')
    }

    if (-not [bool] $Result.workload.requestedEffectiveMatch) {
        [void] $Flags.Add('requested_effective_mismatch')
    }

    if ([string] $Result.environment.targetHealth -eq 'invalid') {
        [void] $Flags.Add('target_health_invalid')
    }

    if ([string] $Result.environment.generatorHealth -eq 'invalid') {
        [void] $Flags.Add('generator_health_invalid')
    }
}

function ConvertTo-SendTurnConditionMask {
    param([object] $Value)

    if ($Value -is [byte] -or
        $Value -is [int16] -or
        $Value -is [int32] -or
        $Value -is [int64] -or
        $Value -is [uint16] -or
        $Value -is [uint32] -or
        $Value -is [uint64]) {
        return [long] $Value
    }

    $map = @{
        None = 0L
        ArithmeticSaturated = 1L
        Contradictory = 2L
        OutOfDomain = 4L
        RecoveryUnstable = 8L
        ResourceConstrained = 16L
    }
    $mask = 0L
    foreach ($name in @(([string] $Value) -split '[,\|]')) {
        $trimmed = $name.Trim()
        if (-not $map.ContainsKey($trimmed)) {
            throw "Unknown application-send turn observation condition '$trimmed'."
        }
        $mask = $mask -bor [long] $map[$trimmed]
    }
    return $mask
}

function Get-SendTurnRawRecordLookup {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if ($sendTurnRawRecordLookupsByPath.ContainsKey($Path)) {
        return $sendTurnRawRecordLookupsByPath[$Path]
    }

    $recordsByConnection = @{}
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $record = $line | ConvertFrom-Json -Depth 30
        $connectionKey = [string] $record.connectionKey
        if (-not $recordsByConnection.ContainsKey($connectionKey)) {
            $recordsByConnection[$connectionKey] = [System.Collections.Generic.List[object]]::new()
        }
        $recordsByConnection[$connectionKey].Add($record)
    }

    $lookup = @{}
    foreach ($connectionKey in $recordsByConnection.Keys) {
        $orderedRecords = @(
            $recordsByConnection[$connectionKey] |
                Sort-Object { [uint64] $_.observation.turnSequence }
        )
        for ($index = 0; $index -lt $orderedRecords.Count; $index++) {
            $lookup["$connectionKey|$index"] = $orderedRecords[$index]
        }
    }
    $sendTurnRawRecordLookupsByPath[$Path] = $lookup
    return $lookup
}

function Add-ExpectedConstructionExclusionFlags {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]] $Flags,

        [Parameter(Mandatory = $true)]
        [object] $Row,

        [Parameter(Mandatory = $true)]
        [object] $Result
    )

    $correctnessInvalid = -not [bool] $Row.correctnessFlags.payloadValid -or
        -not [bool] $Row.correctnessFlags.protocolValid -or
        [bool] $Row.correctnessFlags.timedOut -or
        -not [bool] $Row.correctnessFlags.ownershipValid -or
        -not [bool] $Row.correctnessFlags.terminalValid -or
        (Get-CollectionCount -Value $Row.correctnessFlags.violationCodes) -ne 0
    if ($correctnessInvalid) {
        [void] $Flags.Add('correctness_failed')
    }

    if ([long] $Row.workloadAnalysisOnly.requestedConnections -ne [long] $Row.workloadAnalysisOnly.effectiveConnections -or
        [long] $Row.workloadAnalysisOnly.requestedStreamsPerConnection -ne [long] $Row.workloadAnalysisOnly.effectiveStreamsPerConnection -or
        [long] $Row.workloadAnalysisOnly.requestedConcurrency -ne [long] $Row.workloadAnalysisOnly.effectiveConcurrency) {
        [void] $Flags.Add('requested_effective_mismatch')
    }

    if (-not [bool] $Result.binaryProvenance.frozen) {
        [void] $Flags.Add('binary_identity_missing')
    }

    if ([string] $Result.environment.targetHealth -eq 'invalid') {
        [void] $Flags.Add('target_health_invalid')
    }

    if ([string] $Result.environment.generatorHealth -eq 'invalid') {
        [void] $Flags.Add('generator_health_invalid')
    }
}

function Test-SchemaDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Destination
    )

    try {
        $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
        $json = Get-Content -LiteralPath $resolvedPath -Raw
        if (-not ($json | Test-Json -SchemaFile $SchemaPath -ErrorAction Stop)) {
            $failures.Add("Schema validation failed: $resolvedPath")
            return
        }

        $document = $json | ConvertFrom-Json -Depth 100
        $Destination.Add([pscustomobject]@{
            Path = $resolvedPath
            Directory = Split-Path -Parent $resolvedPath
            Document = $document
        })
    }
    catch {
        $failures.Add("$Path`: $($_.Exception.Message)")
    }
}

foreach ($path in $LocalResultPath) {
    Test-SchemaDocument -Path $path -SchemaPath $localResultSchemaPath -Destination $validatedLocalResults
}

foreach ($path in $EpochDatasetPath) {
    Test-SchemaDocument -Path $path -SchemaPath $epochDatasetSchemaPath -Destination $validatedEpochRows
}

foreach ($path in $ConstructionDatasetPath) {
    Test-SchemaDocument -Path $path -SchemaPath $constructionDatasetSchemaPath -Destination $validatedConstructionRows
}

$localResultsByRunId = @{}
$localResultContextsByRunId = @{}
foreach ($item in $validatedLocalResults) {
    $document = $item.Document
    if ($localResultsByRunId.ContainsKey($document.runId)) {
        $failures.Add("Duplicate local-result runId '$($document.runId)'.")
        continue
    }

    $localResultsByRunId[$document.runId] = $document
    $samplesById = @{}
    foreach ($sample in @($document.samples)) {
        if ($samplesById.ContainsKey($sample.sampleId)) {
            $failures.Add("Local result '$($item.Path)' contains duplicate sampleId '$($sample.sampleId)'.")
            continue
        }

        $samplesById[$sample.sampleId] = $sample
    }

    $artifactPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($artifact in @($document.artifacts)) {
        $normalizedArtifactPath = Resolve-NormalizedEvidencePath -BasePath $item.Directory -Path ([string] $artifact.path)
        if (-not $artifactPaths.Add($normalizedArtifactPath)) {
            $failures.Add("Local result '$($item.Path)' contains duplicate artifact path '$normalizedArtifactPath'.")
        }
    }

    $localResultContextsByRunId[$document.runId] = [pscustomobject]@{
        Item = $item
        Document = $document
        SamplesById = $samplesById
        ChecksumInventory = Get-ChecksumInventoryContext -ResultItem $item
    }
}

foreach ($resultContext in $localResultContextsByRunId.Values) {
    $result = $resultContext.Document
    if ($result.mode -eq 'observe_only') {
        if ($result.policyAxis -ne 'application_send_turn_planning' -or
            $result.policyConfiguration.appliedPolicy -ne 'legacy_current' -or
            $null -ne $result.policyConfiguration.forcedPolicy -or
            [bool] $result.policyConfiguration.shadowEnabled) {
            $failures.Add(
                "Observe-only result '$($resultContext.Item.Path)' must keep application_send_turn_planning on unforced legacy_current with shadow disabled.")
        }
    }

    $unsupportedFairnessClaim = [bool] $result.fairnessOutcomes.assessed -or
        $null -ne $result.fairnessOutcomes.streamCompletionP95Ms -or
        $null -ne $result.fairnessOutcomes.streamCompletionP99Ms -or
        [int] $result.fairnessOutcomes.starvationCount -ne 0 -or
        (Get-CollectionCount -Value $result.fairnessOutcomes.violations) -ne 0
    if ($unsupportedFairnessClaim) {
        $failures.Add("Local result '$($resultContext.Item.Path)' claims stream fairness, but the v1 evidence surface has no true stream-completion source; fairness must remain unassessed.")
    }

    $sampleBufferPoolRentedBytes = [System.Collections.Generic.List[long]]::new()
    $sampleBufferPoolOutstandingPeakBytes = [System.Collections.Generic.List[long]]::new()
    $sampleFairnessP95Ms = [System.Collections.Generic.List[double]]::new()
    $sampleFairnessP99Ms = [System.Collections.Generic.List[double]]::new()
    $expectedFairnessAssessable = $true
    $expectedStarvationCount = 0
    $aggregateBufferPoolRentedBytes = Get-OptionalObjectProperty -Object $result.aggregateOutcomes -Name 'bufferPoolRentedBytes'
    $aggregateBufferPoolOutstandingPeakBytes = Get-OptionalObjectProperty -Object $result.aggregateOutcomes -Name 'bufferPoolOutstandingPeakBytes'

    foreach ($sample in @($result.samples)) {
        $sampleArtifactPaths = @($sample.artifactPaths | ForEach-Object {
            Resolve-NormalizedEvidencePath -BasePath $resultContext.Item.Directory -Path ([string] $_)
        })
        $bufferPoolSummaryPaths = @($sampleArtifactPaths | Where-Object {
            [System.IO.Path]::GetFileName($_).StartsWith('quic-buffer-pool-summary', [StringComparison]::OrdinalIgnoreCase)
        })
        $sampleBufferPoolRentedOutcome = Get-OptionalObjectProperty -Object $sample.outcomes -Name 'bufferPoolRentedBytes'
        $sampleBufferPoolOutstandingPeakOutcome = Get-OptionalObjectProperty -Object $sample.outcomes -Name 'bufferPoolOutstandingPeakBytes'
        $sampleHasOutcomeMetrics = $null -ne $sampleBufferPoolRentedOutcome -or $null -ne $sampleBufferPoolOutstandingPeakOutcome

        if ($sampleHasOutcomeMetrics -or
            $null -ne $aggregateBufferPoolRentedBytes -or
            $null -ne $aggregateBufferPoolOutstandingPeakBytes) {
            if ($bufferPoolSummaryPaths.Count -ne 1) {
                $failures.Add("Sample '$($sample.sampleId)' must retain exactly one quic-buffer-pool-summary.json when buffer-pool outcomes are populated.")
            }
            else {
                $declaredBufferPoolSummaryPath = @($sample.artifactPaths | Where-Object {
                    [System.IO.Path]::GetFileName($_).StartsWith('quic-buffer-pool-summary', [StringComparison]::OrdinalIgnoreCase)
                } | Select-Object -First 1)[0]
                $bufferPoolSummaryPath = Test-InventoryJoin `
                    -InventoryContext $resultContext.ChecksumInventory `
                    -BasePath $resultContext.Item.Directory `
                    -DeclaredPath ([string] $declaredBufferPoolSummaryPath) `
                    -ExpectedSha256 $null `
                    -Description "Sample '$($sample.sampleId)' quic-buffer-pool summary"

                if ($null -ne $bufferPoolSummaryPath) {
                    try {
                        $bufferPoolSummary = Get-Content -LiteralPath $bufferPoolSummaryPath -Raw | ConvertFrom-Json -Depth 100
                        $expectedBufferPoolRentedBytes = ConvertTo-NullableLong (Get-MetricValueFromSummary `
                            -Summary $bufferPoolSummary `
                            -MetricName 'incursa.quic.buffer_pool.bytes.rented' `
                            -PropertyName 'total')
                        $expectedBufferPoolOutstandingPeakBytes = ConvertTo-NullableLong (Get-MetricValueFromSummary `
                            -Summary $bufferPoolSummary `
                            -MetricName 'incursa.quic.buffer_pool.outstanding.bytes' `
                            -PropertyName 'max')

                        if ($sampleHasOutcomeMetrics) {
                            if ($null -eq $expectedBufferPoolRentedBytes) {
                                $failures.Add("Sample '$($sample.sampleId)' populated outcomes.bufferPoolRentedBytes, but quic-buffer-pool-summary.json did not retain incursa.quic.buffer_pool.bytes.rented total.")
                            }
                            elseif ([long] $sampleBufferPoolRentedOutcome -ne $expectedBufferPoolRentedBytes) {
                                $failures.Add("Sample '$($sample.sampleId)' outcomes.bufferPoolRentedBytes does not match quic-buffer-pool-summary.json.")
                            }
                            else {
                                $sampleBufferPoolRentedBytes.Add($expectedBufferPoolRentedBytes)
                            }

                            if ($null -eq $expectedBufferPoolOutstandingPeakBytes) {
                                $failures.Add("Sample '$($sample.sampleId)' populated outcomes.bufferPoolOutstandingPeakBytes, but quic-buffer-pool-summary.json did not retain incursa.quic.buffer_pool.outstanding.bytes max.")
                            }
                            elseif ([long] $sampleBufferPoolOutstandingPeakOutcome -ne $expectedBufferPoolOutstandingPeakBytes) {
                                $failures.Add("Sample '$($sample.sampleId)' outcomes.bufferPoolOutstandingPeakBytes does not match quic-buffer-pool-summary.json.")
                            }
                            else {
                                $sampleBufferPoolOutstandingPeakBytes.Add($expectedBufferPoolOutstandingPeakBytes)
                            }
                        }
                    }
                    catch {
                        $failures.Add("Sample '$($sample.sampleId)' quic-buffer-pool summary could not be parsed: $($_.Exception.Message)")
                    }
                }
            }
        }

        $fairnessRequested = [bool] $result.fairnessOutcomes.assessed -or
            $null -ne $result.fairnessOutcomes.streamCompletionP95Ms -or
            $null -ne $result.fairnessOutcomes.streamCompletionP99Ms -or
            [int] $result.fairnessOutcomes.starvationCount -ne 0 -or
            (Get-CollectionCount -Value $result.fairnessOutcomes.violations) -ne 0
        if ($fairnessRequested) {
            $benchmarkResultPath = Test-InventoryJoin `
                -InventoryContext $resultContext.ChecksumInventory `
                -BasePath $resultContext.Item.Directory `
                -DeclaredPath ([string] $sample.targetAttribution.resultArtifactPath) `
                -ExpectedSha256 $null `
                -Description "Sample '$($sample.sampleId)' benchmark result"

            if ($null -eq $benchmarkResultPath) {
                $expectedFairnessAssessable = $false
                continue
            }

            try {
                $benchmarkResult = Get-Content -LiteralPath $benchmarkResultPath -Raw | ConvertFrom-Json -Depth 100
                $metrics = Get-OptionalObjectProperty -Object $benchmarkResult -Name 'metrics'
                $latencyP95Ms = ConvertTo-NullableDouble (Get-OptionalObjectProperty -Object $metrics -Name 'latencyP95Ms')
                $latencyP99Ms = ConvertTo-NullableDouble (Get-OptionalObjectProperty -Object $metrics -Name 'latencyP99Ms')
                $totalRequests = ConvertTo-NullableLong (Get-OptionalObjectProperty -Object $metrics -Name 'totalRequests')
                $successfulRequests = ConvertTo-NullableLong (Get-OptionalObjectProperty -Object $metrics -Name 'successfulRequests')
                if ($latencyP95Ms -eq $null -or $latencyP99Ms -eq $null -or $totalRequests -eq $null -or $successfulRequests -eq $null) {
                    $failures.Add("Sample '$($sample.sampleId)' fairnessOutcomes require retained result.json latency and completion metrics.")
                    $expectedFairnessAssessable = $false
                    continue
                }

                $sampleFairnessP95Ms.Add($latencyP95Ms)
                $sampleFairnessP99Ms.Add($latencyP99Ms)
                $expectedStarvationCount += [int] [Math]::Max(0L, $totalRequests - $successfulRequests)
            }
            catch {
                $failures.Add("Sample '$($sample.sampleId)' retained result.json could not be parsed for fairness evidence: $($_.Exception.Message)")
                $expectedFairnessAssessable = $false
            }
        }
    }

    if ($null -ne $aggregateBufferPoolRentedBytes) {
        $expectedAggregateBufferPoolRentedBytes = Get-RoundedMedianInt64 -Values @($sampleBufferPoolRentedBytes)
        if ($null -eq $expectedAggregateBufferPoolRentedBytes) {
            $failures.Add("Local result '$($resultContext.Item.Path)' populated aggregateOutcomes.bufferPoolRentedBytes without checksum-backed sample buffer-pool evidence.")
        }
        elseif ([long] $aggregateBufferPoolRentedBytes -ne $expectedAggregateBufferPoolRentedBytes) {
            $failures.Add("Local result '$($resultContext.Item.Path)' aggregateOutcomes.bufferPoolRentedBytes does not match the checksum-backed sample median.")
        }
    }

    if ($null -ne $aggregateBufferPoolOutstandingPeakBytes) {
        $expectedAggregateBufferPoolOutstandingPeakBytes = Get-RoundedMedianInt64 -Values @($sampleBufferPoolOutstandingPeakBytes)
        if ($null -eq $expectedAggregateBufferPoolOutstandingPeakBytes) {
            $failures.Add("Local result '$($resultContext.Item.Path)' populated aggregateOutcomes.bufferPoolOutstandingPeakBytes without checksum-backed sample buffer-pool evidence.")
        }
        elseif ([long] $aggregateBufferPoolOutstandingPeakBytes -ne $expectedAggregateBufferPoolOutstandingPeakBytes) {
            $failures.Add("Local result '$($resultContext.Item.Path)' aggregateOutcomes.bufferPoolOutstandingPeakBytes does not match the checksum-backed sample median.")
        }
    }

    $fairnessRequested = [bool] $result.fairnessOutcomes.assessed -or
        $null -ne $result.fairnessOutcomes.streamCompletionP95Ms -or
        $null -ne $result.fairnessOutcomes.streamCompletionP99Ms -or
        [int] $result.fairnessOutcomes.starvationCount -ne 0 -or
        (Get-CollectionCount -Value $result.fairnessOutcomes.violations) -ne 0
    if ($fairnessRequested) {
        if (-not [bool] $result.fairnessOutcomes.assessed) {
            $failures.Add("Local result '$($resultContext.Item.Path)' populated fairness values or violations without fairnessOutcomes.assessed=true.")
        }
        elseif (-not $expectedFairnessAssessable) {
            $failures.Add("Local result '$($resultContext.Item.Path)' marked fairnessOutcomes.assessed=true without complete retained result.json completion metrics.")
        }
        else {
            $expectedFairnessP95Ms = Get-Median -Values @($sampleFairnessP95Ms)
            $expectedFairnessP99Ms = Get-Median -Values @($sampleFairnessP99Ms)
            if ([double] $result.fairnessOutcomes.streamCompletionP95Ms -ne [double] $expectedFairnessP95Ms) {
                $failures.Add("Local result '$($resultContext.Item.Path)' fairnessOutcomes.streamCompletionP95Ms does not match retained result.json metrics.")
            }
            if ([double] $result.fairnessOutcomes.streamCompletionP99Ms -ne [double] $expectedFairnessP99Ms) {
                $failures.Add("Local result '$($resultContext.Item.Path)' fairnessOutcomes.streamCompletionP99Ms does not match retained result.json metrics.")
            }
            if ([int] $result.fairnessOutcomes.starvationCount -ne $expectedStarvationCount) {
                $failures.Add("Local result '$($resultContext.Item.Path)' fairnessOutcomes.starvationCount does not match retained result.json completion counts.")
            }

            $expectedFairnessViolations = Get-ExpectedFairnessViolations -StarvationCount $expectedStarvationCount
            $actualFairnessViolations = @($result.fairnessOutcomes.violations | ForEach-Object { [string] $_ })
            $expectedFairnessKey = (@($expectedFairnessViolations | Sort-Object) -join '|')
            $actualFairnessKey = (@($actualFairnessViolations | Sort-Object) -join '|')
            if ($expectedFairnessKey -ne $actualFairnessKey) {
                $failures.Add("Local result '$($resultContext.Item.Path)' fairnessOutcomes.violations does not match retained result.json completion evidence.")
            }
        }
    }
}

$seenRowIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenEpochKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$sendTurnLastEpochIndexByConnection = @{}
foreach ($item in $validatedEpochRows) {
    $row = $item.Document
    if ([string] $row.provenance.transformation.name -ne 'adaptive-runtime-send-turn-epoch-export' -or
        [string] $row.provenance.transformation.version -ne '1.0.0' -or
        [string] $row.provenance.observationContractVersion -ne 'adaptive-runtime-application-send-turn-observation-v1') {
        continue
    }

    $connectionEpochKey = "$($row.runId)|$($row.sampleId)|$($row.connectionKey)"
    $epochIndex = [long] $row.epochIndex
    if (-not $sendTurnLastEpochIndexByConnection.ContainsKey($connectionEpochKey) -or
        $epochIndex -gt [long] $sendTurnLastEpochIndexByConnection[$connectionEpochKey]) {
        $sendTurnLastEpochIndexByConnection[$connectionEpochKey] = $epochIndex
    }
}
foreach ($item in $validatedEpochRows) {
    $row = $item.Document
    $scopedRowId = "$($row.runId)|$($row.rowId)"
    if (-not $seenRowIds.Add($scopedRowId)) {
        $failures.Add("Duplicate epoch-row rowId '$($row.rowId)' within run '$($row.runId)'.")
    }

    $epochKey = "$($row.runId)|$($row.sampleId)|$($row.connectionKey)|$($row.epochIndex)"
    if (-not $seenEpochKeys.Add($epochKey)) {
        $failures.Add("Duplicate epoch identity '$epochKey'.")
    }

    if (-not $row.workloadAnalysisOnly.excludedFromProductionFeatures) {
        $failures.Add("Epoch row '$($row.rowId)' does not exclude workload identity from production features.")
    }

    if ($row.currentPolicyState.ruleVersion -ne $row.provenance.ruleVersion) {
        $failures.Add("Epoch row '$($row.rowId)' has inconsistent rule versions.")
    }

    if ($row.currentPolicyState.observationContractVersion -ne $row.provenance.observationContractVersion) {
        $failures.Add("Epoch row '$($row.rowId)' has inconsistent observation contract versions.")
    }

    if (-not $localResultContextsByRunId.ContainsKey($row.runId)) {
        if (-not $AllowUnmatchedEpochRows) {
            $failures.Add("Epoch row '$($row.rowId)' cannot be joined to local-result runId '$($row.runId)'.")
        }
        continue
    }

    $resultContext = $localResultContextsByRunId[$row.runId]
    $result = $resultContext.Document
    if ($row.campaignId -ne $result.campaignId -or $row.cellId -ne $result.cellId) {
        $failures.Add("Epoch row '$($row.rowId)' does not match its local-result campaign/cell identity.")
    }

    if ($row.provenance.resultSchemaVersion -ne $result.schemaVersion) {
        $failures.Add("Epoch row '$($row.rowId)' does not name its source result schema version.")
    }

    if ($row.provenance.ruleVersion -ne $result.policyConfiguration.ruleVersion -or
        $row.provenance.observationContractVersion -ne $result.policyConfiguration.observationContractVersion) {
        $failures.Add("Epoch row '$($row.rowId)' does not match its local-result policy contract versions.")
    }

    if ($row.currentPolicyState.appliedPolicy -ne $row.candidatePolicySelection.selectedPolicy) {
        $failures.Add("Epoch row '$($row.rowId)' does not keep the selected policy aligned with the applied policy snapshot.")
    }

    if (-not $resultContext.SamplesById.ContainsKey($row.sampleId)) {
        if (-not $AllowUnmatchedEpochRows) {
            $failures.Add("Epoch row '$($row.rowId)' does not resolve to source sample '$($row.sampleId)'.")
        }
        continue
    }

    $sourceSample = $resultContext.SamplesById[$row.sampleId]
    $treatmentProperty = $result.treatments.PSObject.Properties[[string] $sourceSample.treatment]
    if ($null -eq $treatmentProperty) {
        $failures.Add("Epoch row '$($row.rowId)' source sample names unknown treatment '$($sourceSample.treatment)'.")
    }
    else {
        $expectedSamplePolicy = [string] $treatmentProperty.Value.policy
        if ($row.currentPolicyState.appliedPolicy -ne $expectedSamplePolicy) {
            $failures.Add("Epoch row '$($row.rowId)' applied policy does not match source sample treatment '$($sourceSample.treatment)'.")
        }
    }

    if ([string]::IsNullOrWhiteSpace([string] $row.provenance.sourceArtifactPath)) {
        $failures.Add("Epoch row '$($row.rowId)' did not retain provenance.sourceArtifactPath.")
    }

    if ($row.provenance.transformation.inputSha256 -ne $row.provenance.sourceArtifactSha256) {
        $failures.Add("Epoch row '$($row.rowId)' does not keep transformation.inputSha256 aligned with sourceArtifactSha256.")
    }

    $rowBasePath = $item.Directory
    $normalizedSourceArtifactPath = Test-InventoryJoin `
        -InventoryContext $resultContext.ChecksumInventory `
        -BasePath $rowBasePath `
        -DeclaredPath ([string] $row.provenance.sourceArtifactPath) `
        -ExpectedSha256 ([string] $row.provenance.sourceArtifactSha256) `
        -Description "Epoch row '$($row.rowId)' source artifact"

    if ($null -ne $normalizedSourceArtifactPath) {
        $sampleArtifactPaths = @($sourceSample.artifactPaths | ForEach-Object {
            Resolve-NormalizedEvidencePath -BasePath $resultContext.Item.Directory -Path ([string] $_)
        })
        if ($sampleArtifactPaths -notcontains $normalizedSourceArtifactPath) {
            $failures.Add("Epoch row '$($row.rowId)' source artifact is not retained on source sample '$($row.sampleId)'.")
        }
    }

    foreach ($artifactPath in @($sourceSample.artifactPaths)) {
        [void] (Test-InventoryJoin `
            -InventoryContext $resultContext.ChecksumInventory `
            -BasePath $resultContext.Item.Directory `
            -DeclaredPath ([string] $artifactPath) `
            -ExpectedSha256 $null `
            -Description "Source sample '$($row.sampleId)' artifact '$artifactPath'")
    }

    foreach ($declaredPath in @(
        [string] $sourceSample.targetAttribution.resultArtifactPath,
        [string] $sourceSample.targetAttribution.diagnosticTargetArtifactPath,
        [string] $sourceSample.targetAttribution.counterSummaryArtifactPath,
        [string] $result.diagnosticSignals.summaryArtifactPath
    )) {
        [void] (Test-InventoryJoin `
            -InventoryContext $resultContext.ChecksumInventory `
            -BasePath $resultContext.Item.Directory `
            -DeclaredPath $declaredPath `
            -ExpectedSha256 $null `
            -Description "Result '$($row.runId)' retained artifact '$declaredPath'")
    }

    $expectedExclusionFlags = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $connectionEpochKey = "$($row.runId)|$($row.sampleId)|$($row.connectionKey)"
    $isSendTurnTerminalPartialEpoch =
        $sendTurnLastEpochIndexByConnection.ContainsKey($connectionEpochKey) -and
        [long] $row.epochIndex -eq [long] $sendTurnLastEpochIndexByConnection[$connectionEpochKey]
    Add-ExpectedExclusionFlags `
        -Flags $expectedExclusionFlags `
        -Row $row `
        -Result $result `
        -IsSendTurnTerminalPartialEpoch $isSendTurnTerminalPartialEpoch
    if ([string] $row.provenance.transformation.name -eq 'adaptive-runtime-send-turn-epoch-export' -and
        [string] $row.provenance.transformation.version -eq '1.0.0' -and
        [string] $row.provenance.observationContractVersion -eq
            'adaptive-runtime-application-send-turn-observation-v1' -and
        $null -ne $normalizedSourceArtifactPath) {
        try {
            $rawLookup = Get-SendTurnRawRecordLookup -Path $normalizedSourceArtifactPath
            $rawKey = "$($row.connectionKey)|$([long] $row.epochIndex)"
            $nextRawKey = "$($row.connectionKey)|$([long] $row.epochIndex + 1)"
            if (-not $rawLookup.ContainsKey($rawKey)) {
                $failures.Add(
                    "Epoch row '$($row.rowId)' does not resolve to its send-turn raw record '$rawKey'.")
            }
            elseif ($rawLookup.ContainsKey($nextRawKey) -and
                [long] $rawLookup[$nextRawKey].observation.capturedAtTicks -le
                    [long] $rawLookup[$rawKey].observation.capturedAtTicks) {
                [void] $expectedExclusionFlags.Add('instrumentation_mismatch')
            }
        }
        catch {
            $failures.Add(
                "Epoch row '$($row.rowId)' send-turn raw source could not be replayed: $($_.Exception.Message)")
        }
    }
    if ($result.mode -eq 'observe_only' -and
        [string] $row.provenance.transformation.name -eq 'adaptive-runtime-send-turn-epoch-export' -and
        [string] $row.provenance.transformation.version -eq '1.0.0' -and
        [string] $row.provenance.observationContractVersion -eq
            'adaptive-runtime-application-send-turn-observation-v1' -and
        $null -ne $normalizedSourceArtifactPath) {
        try {
            $rawLookup = Get-SendTurnRawRecordLookup -Path $normalizedSourceArtifactPath
            $rawKey = "$($row.connectionKey)|$([long] $row.epochIndex)"
            if (-not $rawLookup.ContainsKey($rawKey)) {
                $failures.Add(
                    "Epoch row '$($row.rowId)' does not resolve to its observe-only raw record '$rawKey'.")
            }
            else {
                $rawRecord = $rawLookup[$rawKey]
                if ([string] $rawRecord.mode -ne 'ObserveOnly' -or
                    [bool] $rawRecord.hasRecommendation -or
                    $null -ne $rawRecord.snapshot) {
                    $failures.Add(
                        "Epoch row '$($row.rowId)' source record is not recommendation-free observe-only evidence.")
                }
                $conditionMask = ConvertTo-SendTurnConditionMask -Value $rawRecord.observation.conditions
                if (($conditionMask -band 1) -ne 0) {
                    [void] $expectedExclusionFlags.Add('observation_saturated')
                }
                if (($conditionMask -band 4) -ne 0) {
                    [void] $expectedExclusionFlags.Add('out_of_domain')
                }
                if ([bool] $row.preDecisionObservations.outOfDomain -ne (($conditionMask -band 4) -ne 0)) {
                    $failures.Add(
                        "Epoch row '$($row.rowId)' out-of-domain state does not match its observe-only raw record.")
                }
            }
        }
        catch {
            $failures.Add(
                "Epoch row '$($row.rowId)' observe-only raw source could not be replayed: $($_.Exception.Message)")
        }
    }
    $actualFlags = @($row.analysisExclusionFlags | ForEach-Object { [string] $_ })
    $actualFlagsSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($flag in $actualFlags) {
        [void] $actualFlagsSet.Add($flag)
    }
    if ($actualFlagsSet.Contains('terminal_partial_epoch') -and
        -not $expectedExclusionFlags.Contains('terminal_partial_epoch')) {
        $failures.Add("Epoch row '$($row.rowId)' retains terminal_partial_epoch but is not terminal by lifecycle or exporter ordering.")
    }

    $requiredExclusionFlags = [System.Collections.Generic.HashSet[string]]::new(
        $expectedExclusionFlags,
        [StringComparer]::Ordinal)
    if ($AllowLegacyResultLevelEnvironmentExclusions -and
        [string] $result.classification -eq 'invalid_environment') {
        $toleratedLegacyResultFlag = $false
        foreach ($resultLevelFlag in @('target_health_invalid', 'generator_health_invalid')) {
            if ($requiredExclusionFlags.Contains($resultLevelFlag) -and
                -not $actualFlagsSet.Contains($resultLevelFlag)) {
                [void] $requiredExclusionFlags.Remove($resultLevelFlag)
                $toleratedLegacyResultFlag = $true
            }
        }

        if ($toleratedLegacyResultFlag) {
            [void] $legacyResultLevelEnvironmentExclusionRows.Add($scopedRowId)
        }
    }

    if ($requiredExclusionFlags.Count -eq 0) {
        if ($actualFlags.Count -ne 1 -or $actualFlags[0] -ne 'none') {
            $failures.Add("Epoch row '$($row.rowId)' should be analysis-clean and use analysisExclusionFlags=['none'].")
        }
    }
    else {
        if ($actualFlagsSet.Contains('none')) {
            $failures.Add("Epoch row '$($row.rowId)' cannot retain analysisExclusionFlags=['none'] when observed exclusions are present.")
        }

        foreach ($flag in $requiredExclusionFlags) {
            if (-not $actualFlagsSet.Contains($flag)) {
                $failures.Add("Epoch row '$($row.rowId)' is missing required analysis exclusion flag '$flag'.")
            }
        }
    }

    if ($result.mode -eq 'forced') {
        if ($row.candidatePolicySelection.selectionSource -ne 'forced') {
            $failures.Add("Epoch row '$($row.rowId)' from a forced result did not record selectionSource='forced'.")
        }

        if ($result.policyConfiguration.forcedPolicy -ne $null -and
            $row.currentPolicyState.appliedPolicy -ne $result.policyConfiguration.forcedPolicy) {
            $failures.Add("Epoch row '$($row.rowId)' does not match the forced policy recorded on the local result.")
        }
    }
    elseif ($result.mode -eq 'shadow' -and $row.candidatePolicySelection.selectionSource -ne 'shadow_rule') {
        $failures.Add("Epoch row '$($row.rowId)' from a shadow result did not record selectionSource='shadow_rule'.")
    }
    elseif ($result.mode -eq 'observe_only') {
        if ($row.candidatePolicySelection.selectionSource -ne 'legacy' -or
            $null -ne $row.candidatePolicySelection.shadowRecommendation -or
            $row.currentPolicyState.appliedPolicy -ne 'legacy_current') {
            $failures.Add(
                "Epoch row '$($row.rowId)' from an observe-only result must record legacy selection, no recommendation, and legacy_current applied.")
        }
    }
}

$seenConstructionRowIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenConstructionKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($item in $validatedConstructionRows) {
    $row = $item.Document
    $scopedRowId = "$($row.runId)|$($row.rowId)"
    if (-not $seenConstructionRowIds.Add($scopedRowId)) {
        $failures.Add("Duplicate construction-row rowId '$($row.rowId)' within run '$($row.runId)'.")
    }

    $constructionKey = "$($row.runId)|$($row.sampleId)|$($row.connectionKey)"
    if (-not $seenConstructionKeys.Add($constructionKey)) {
        $failures.Add("Duplicate construction identity '$constructionKey'.")
    }

    if (-not $row.workloadAnalysisOnly.excludedFromProductionFeatures) {
        $failures.Add("Construction row '$($row.rowId)' does not exclude workload identity from production features.")
    }

    if (-not $localResultContextsByRunId.ContainsKey($row.runId)) {
        $failures.Add("Construction row '$($row.rowId)' cannot be joined to local-result runId '$($row.runId)'.")
        continue
    }

    $resultContext = $localResultContextsByRunId[$row.runId]
    $result = $resultContext.Document
    if ($result.policyAxis -ne 'application_send_turn_planning') {
        $failures.Add("Construction row '$($row.rowId)' joined a local result for axis '$($result.policyAxis)', not application_send_turn_planning.")
    }

    if ($row.campaignId -ne $result.campaignId -or $row.cellId -ne $result.cellId) {
        $failures.Add("Construction row '$($row.rowId)' does not match its local-result campaign/cell identity.")
    }

    if ($row.provenance.resultSchemaVersion -ne $result.schemaVersion) {
        $failures.Add("Construction row '$($row.rowId)' does not name its source result schema version.")
    }

    if ($result.mode -ne 'forced') {
        $failures.Add("Construction row '$($row.rowId)' requires a forced local result.")
    }
    elseif ($null -ne $result.policyConfiguration.forcedPolicy -and
        ($row.constructionPolicyState.appliedPolicy -ne $result.policyConfiguration.forcedPolicy -or
            $result.policyConfiguration.appliedPolicy -ne $result.policyConfiguration.forcedPolicy)) {
        $failures.Add("Construction row '$($row.rowId)' does not match the singular forced policy recorded on the local result.")
    }

    if ($row.constructionPolicyState.selectionSource -ne 'forced') {
        $failures.Add("Construction row '$($row.rowId)' did not record selectionSource='forced'.")
    }

    if ($row.constructionPolicyState.ruleVersion -ne 'application-send-turn-force-v1' -or
        $row.constructionPolicyState.provenanceContractVersion -ne 'adaptive-runtime-application-send-turn-provenance-v1') {
        $failures.Add("Construction row '$($row.rowId)' does not use the application-send-turn forced-policy contract.")
    }

    if ($row.constructionPolicyState.ruleVersion -ne $result.policyConfiguration.ruleVersion) {
        $failures.Add("Construction row '$($row.rowId)' does not match its local-result ruleVersion.")
    }

    if (-not $resultContext.SamplesById.ContainsKey($row.sampleId)) {
        $failures.Add("Construction row '$($row.rowId)' does not resolve to source sample '$($row.sampleId)'.")
        continue
    }

    $sourceSample = $resultContext.SamplesById[$row.sampleId]
    $treatmentProperty = $result.treatments.PSObject.Properties[[string] $sourceSample.treatment]
    if ($null -eq $treatmentProperty) {
        $failures.Add("Construction row '$($row.rowId)' source sample names unknown treatment '$($sourceSample.treatment)'.")
    }
    elseif ($row.constructionPolicyState.appliedPolicy -ne [string] $treatmentProperty.Value.policy) {
        $failures.Add("Construction row '$($row.rowId)' applied policy does not match source sample treatment '$($sourceSample.treatment)'.")
    }

    $expectedPayloadValid = [bool] $sourceSample.correctness.payloadValidated -and [int] $sourceSample.correctness.failedOperations -eq 0
    $expectedProtocolValid = [int] $sourceSample.correctness.protocolErrors -eq 0
    $expectedTimedOut = [int] $sourceSample.correctness.timedOutOperations -ne 0
    $expectedOwnershipValid = (Get-CollectionCount -Value $sourceSample.correctness.invariantViolations) -eq 0
    $expectedTerminalValid = [int] $sourceSample.exitCode -eq 0 -and
        [int] $sourceSample.correctness.cancellationFailures -eq 0 -and
        [int] $sourceSample.correctness.disposalFailures -eq 0
    if ([bool] $row.correctnessFlags.payloadValid -ne $expectedPayloadValid -or
        [bool] $row.correctnessFlags.protocolValid -ne $expectedProtocolValid -or
        [bool] $row.correctnessFlags.timedOut -ne $expectedTimedOut -or
        [bool] $row.correctnessFlags.ownershipValid -ne $expectedOwnershipValid -or
        [bool] $row.correctnessFlags.terminalValid -ne $expectedTerminalValid) {
        $failures.Add("Construction row '$($row.rowId)' correctness flags do not match its retained source sample outcomes.")
    }

    if ([string]::IsNullOrWhiteSpace([string] $row.provenance.sourceArtifactPath)) {
        $failures.Add("Construction row '$($row.rowId)' did not retain provenance.sourceArtifactPath.")
    }

    if ($row.provenance.transformation.inputSha256 -ne $row.provenance.sourceArtifactSha256) {
        $failures.Add("Construction row '$($row.rowId)' does not keep transformation.inputSha256 aligned with sourceArtifactSha256.")
    }

    $normalizedSourceArtifactPath = Test-InventoryJoin `
        -InventoryContext $resultContext.ChecksumInventory `
        -BasePath $item.Directory `
        -DeclaredPath ([string] $row.provenance.sourceArtifactPath) `
        -ExpectedSha256 ([string] $row.provenance.sourceArtifactSha256) `
        -Description "Construction row '$($row.rowId)' source artifact"

    if ($null -ne $normalizedSourceArtifactPath) {
        $sampleArtifactPaths = @($sourceSample.artifactPaths | ForEach-Object {
            Resolve-NormalizedEvidencePath -BasePath $resultContext.Item.Directory -Path ([string] $_)
        })
        if ($sampleArtifactPaths -notcontains $normalizedSourceArtifactPath) {
            $failures.Add("Construction row '$($row.rowId)' source artifact is not retained on source sample '$($row.sampleId)'.")
        }
    }

    foreach ($artifactPath in @($sourceSample.artifactPaths)) {
        [void] (Test-InventoryJoin `
            -InventoryContext $resultContext.ChecksumInventory `
            -BasePath $resultContext.Item.Directory `
            -DeclaredPath ([string] $artifactPath) `
            -ExpectedSha256 $null `
            -Description "Source sample '$($row.sampleId)' artifact '$artifactPath'")
    }

    $expectedExclusionFlags = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    Add-ExpectedConstructionExclusionFlags -Flags $expectedExclusionFlags -Row $row -Result $result
    $actualFlags = @($row.analysisExclusionFlags | ForEach-Object { [string] $_ })
    $actualFlagsSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($flag in $actualFlags) {
        [void] $actualFlagsSet.Add($flag)
    }

    if ($expectedExclusionFlags.Count -eq 0) {
        if ($actualFlags.Count -ne 1 -or $actualFlags[0] -ne 'none') {
            $failures.Add("Construction row '$($row.rowId)' should be analysis-clean and use analysisExclusionFlags=['none'].")
        }
    }
    else {
        if ($actualFlagsSet.Contains('none')) {
            $failures.Add("Construction row '$($row.rowId)' cannot retain analysisExclusionFlags=['none'] when observed exclusions are present.")
        }

        foreach ($flag in $expectedExclusionFlags) {
            if (-not $actualFlagsSet.Contains($flag)) {
                $failures.Add("Construction row '$($row.rowId)' is missing required analysis exclusion flag '$flag'.")
            }
        }
    }
}

$summary = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-evidence-validation-v1'
    valid = $failures.Count -eq 0
    localResultCount = $validatedLocalResults.Count
    epochRowCount = $validatedEpochRows.Count
    uniqueEpochRowCount = $seenRowIds.Count
    constructionRowCount = $validatedConstructionRows.Count
    uniqueConstructionRowCount = $seenConstructionRowIds.Count
    checksumInventoryCount = @($localResultContextsByRunId.Values | Where-Object { $null -ne $_.ChecksumInventory }).Count
    uniqueArtifactHashCount = $verifiedArtifactSha256ByPath.Count
    legacyResultLevelEnvironmentExclusionsAllowed = [bool] $AllowLegacyResultLevelEnvironmentExclusions
    legacyResultLevelEnvironmentExclusionRowCount = $legacyResultLevelEnvironmentExclusionRows.Count
    failures = @($failures)
}

$summary | ConvertTo-Json -Depth 10
if ($failures.Count -ne 0) {
    exit 1
}
