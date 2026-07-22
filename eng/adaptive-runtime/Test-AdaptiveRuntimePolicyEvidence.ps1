# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $LocalResultPath,

    [Parameter(Mandatory = $true)]
    [string[]] $EpochDatasetPath,

    [switch] $AllowUnmatchedEpochRows,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$localResultSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-local-result-v1.schema.json'
$epochDatasetSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-epoch-dataset-v1.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$validatedLocalResults = [System.Collections.Generic.List[object]]::new()
$validatedEpochRows = [System.Collections.Generic.List[object]]::new()

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

    if (-not (Test-Path -LiteralPath $normalizedPath -PathType Leaf)) {
        $failures.Add("$Description points to '$normalizedPath', but that file was not found.")
        return $normalizedPath
    }

    $actualSha256 = (Get-FileHash -LiteralPath $normalizedPath -Algorithm SHA256).Hash.ToLowerInvariant()
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
        [object] $Result
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

    if (([long] $Row.preDecisionObservations.lifecycleFlags -band 96) -ne 0) {
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

$seenRowIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenEpochKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($item in $validatedEpochRows) {
    $row = $item.Document
    if (-not $seenRowIds.Add([string] $row.rowId)) {
        $failures.Add("Duplicate epoch-row rowId '$($row.rowId)'.")
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
    Add-ExpectedExclusionFlags -Flags $expectedExclusionFlags -Row $row -Result $result
    $actualFlags = @($row.analysisExclusionFlags | ForEach-Object { [string] $_ })
    $actualFlagsSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($flag in $actualFlags) {
        [void] $actualFlagsSet.Add($flag)
    }

    if ($expectedExclusionFlags.Count -eq 0) {
        if ($actualFlags.Count -ne 1 -or $actualFlags[0] -ne 'none') {
            $failures.Add("Epoch row '$($row.rowId)' should be analysis-clean and use analysisExclusionFlags=['none'].")
        }
    }
    else {
        if ($actualFlagsSet.Contains('none')) {
            $failures.Add("Epoch row '$($row.rowId)' cannot retain analysisExclusionFlags=['none'] when observed exclusions are present.")
        }

        foreach ($flag in $expectedExclusionFlags) {
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
}

$summary = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-evidence-validation-v1'
    valid = $failures.Count -eq 0
    localResultCount = $validatedLocalResults.Count
    epochRowCount = $validatedEpochRows.Count
    uniqueEpochRowCount = $seenRowIds.Count
    checksumInventoryCount = @($localResultContextsByRunId.Values | Where-Object { $null -ne $_.ChecksumInventory }).Count
    failures = @($failures)
}

$summary | ConvertTo-Json -Depth 10
if ($failures.Count -ne 0) {
    exit 1
}
