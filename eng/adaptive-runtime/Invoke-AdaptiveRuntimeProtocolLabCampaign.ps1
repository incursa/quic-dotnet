[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[a-z0-9][a-z0-9-]{2,95}$")]
    [string] $CampaignId,

    [Parameter(Mandatory = $true)]
    [uri] $ControllerUri,

    [ValidateSet("shadow", "forced_counterfactual")]
    [string] $CampaignKind = "shadow",

    [ValidateSet("ABBA", "BAAB")]
    [string] $Sequence = "ABBA",

    [string] $ProtocolLabRoot = "../protocol-lab",

    [string] $ProtocolLabExecutionRoot,

    [string[]] $RuntimeIdentifier = @("linux-x64"),

    [string[]] $ScenarioId = @(
        "quic.transport.multiplex.100x64kb",
        "quic.transport.duplex-streams"
    ),

    [string] $LoadProfileId = "smoke",

    [ValidateRange(1, 100)]
    [int] $Repetitions = 1,

    [ValidateSet("isolated-pair")]
    [string] $PlacementPolicy = "isolated-pair",

    [switch] $CaptureCounters,

    [switch] $CaptureTrace,

    [switch] $Execute,

    [switch] $StopOnFailure,

    [ValidateRange(30, 86400)]
    [int] $TimeoutSeconds = 3600,

    [string] $OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Invoke-GitText {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $value = & git -C $RepositoryRoot @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Git command failed: git $($Arguments -join ' ')"
    }

    return ($value | Out-String).Trim()
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [object] $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    $json = $Value | ConvertTo-Json -Depth 64
    [System.IO.File]::WriteAllText(
        $Path,
        $json + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false))
}

function Test-CampaignManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ManifestPath,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath
    )

    $json = Get-Content -Raw -LiteralPath $ManifestPath
    $schema = Get-Content -Raw -LiteralPath $SchemaPath
    if (-not (Test-Json -Json $json -Schema $schema -ErrorAction Stop)) {
        throw "Adaptive-runtime ProtocolLab campaign manifest failed schema validation."
    }
}

function ConvertTo-CommandToken {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ($Value -match "^[A-Za-z0-9_./:@+-]+$") {
        return $Value
    }

    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-PhysicalHostId {
    param([object] $Node)

    if ($null -eq $Node -or $null -eq $Node.capabilities -or $null -eq $Node.capabilities.labels) {
        return $null
    }

    foreach ($name in @("physicalHostId", "physical-host", "physicalHost", "host")) {
        $property = $Node.capabilities.labels.PSObject.Properties |
            Where-Object { [string]::Equals($_.Name, $name, [StringComparison]::OrdinalIgnoreCase) } |
            Select-Object -First 1
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }

    return $null
}

function Get-TopologyRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Job,

        [object[]] $Nodes = @()
    )

    $sutNodeId = $null
    $loadNodeId = $null
    foreach ($lease in @($Job.reservation.leases)) {
        if ([string]::Equals([string]$lease.roleId, "sut", [StringComparison]::OrdinalIgnoreCase)) {
            $sutNodeId = [string]$lease.nodeId
        }
        elseif ([string]::Equals([string]$lease.roleId, "load", [StringComparison]::OrdinalIgnoreCase)) {
            $loadNodeId = [string]$lease.nodeId
        }
    }

    if ([string]::IsNullOrWhiteSpace($sutNodeId) -and -not [string]::IsNullOrWhiteSpace([string]$Job.assignedNodeId)) {
        $sutNodeId = [string]$Job.assignedNodeId
    }

    $sutNode = $Nodes | Where-Object {
        [string]::Equals([string]$_.nodeId, $sutNodeId, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    $loadNode = $Nodes | Where-Object {
        [string]::Equals([string]$_.nodeId, $loadNodeId, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    $sutPhysicalHostId = Get-PhysicalHostId -Node $sutNode
    $loadPhysicalHostId = Get-PhysicalHostId -Node $loadNode

    $classification = if ([string]::IsNullOrWhiteSpace($sutNodeId) -or [string]::IsNullOrWhiteSpace($loadNodeId)) {
        "topology_unverified"
    }
    elseif ([string]::IsNullOrWhiteSpace($sutPhysicalHostId) -or [string]::IsNullOrWhiteSpace($loadPhysicalHostId)) {
        "physical_host_unverified"
    }
    elseif ([string]::Equals($sutPhysicalHostId, $loadPhysicalHostId, [StringComparison]::OrdinalIgnoreCase)) {
        "shared_physical_host"
    }
    else {
        "independent_physical_hosts"
    }

    return [ordered]@{
        sutNodeId = $sutNodeId
        loadNodeId = $loadNodeId
        sutPhysicalHostId = $sutPhysicalHostId
        loadPhysicalHostId = $loadPhysicalHostId
        classification = $classification
    }
}

function Write-ChecksumInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,

        [Parameter(Mandatory = $true)]
        [string] $InventoryPath,

        [string[]] $AdditionalPaths = @()
    )

    $paths = @(
        Get-ChildItem -LiteralPath $Root -Recurse -File |
            Where-Object { -not [string]::Equals($_.FullName, $InventoryPath, [StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { $_.FullName }
        $AdditionalPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    ) | Sort-Object -Unique

    $entries = foreach ($path in $paths) {
        $item = Get-Item -LiteralPath $path
        [ordered]@{
            path = $item.FullName
            length = $item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    Write-JsonFile -Path $InventoryPath -Value ([ordered]@{
        schemaVersion = "adaptive-runtime-protocol-lab-checksum-inventory-v1"
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
        entries = @($entries)
    })
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$schemaPath = Join-Path $repoRoot "schemas/adaptive-runtime-protocol-lab-campaign-v1.schema.json"
$runHelperPath = Join-Path $repoRoot "eng/protocol-lab/Invoke-QuicDotNetProtocolLabRun.ps1"
$sourceCommit = Invoke-GitText -RepositoryRoot $repoRoot -Arguments @("rev-parse", "HEAD")
$sourceRepository = Invoke-GitText -RepositoryRoot $repoRoot -Arguments @("remote", "get-url", "origin")
$sourceStatus = Invoke-GitText -RepositoryRoot $repoRoot -Arguments @("status", "--porcelain=v1", "--untracked-files=normal")
$sourceClean = [string]::IsNullOrWhiteSpace($sourceStatus)

if ($Execute -and -not $sourceClean) {
    throw "ProtocolLab campaign execution requires exact committed source and a clean worktree. Commit the active slice before using -Execute.`n$sourceStatus"
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot ".artifacts/adaptive-runtime/protocol-lab/$CampaignId"
}
else {
    $OutputRoot = Resolve-AbsolutePath -Path $OutputRoot -BasePath $repoRoot
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$protocolLabRootFullPath = Resolve-AbsolutePath -Path $ProtocolLabRoot -BasePath $repoRoot
$protocolLabExecutionRootFullPath = if ([string]::IsNullOrWhiteSpace($ProtocolLabExecutionRoot)) {
    $null
}
else {
    Resolve-AbsolutePath -Path $ProtocolLabExecutionRoot -BasePath $repoRoot
}

$treatmentModes = if ($CampaignKind -eq "shadow") {
    @{ A = "legacy_current"; B = "shadow" }
}
else {
    @{ A = "legacy_current"; B = "conservative" }
}

$cells = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $Sequence.Length; $index++) {
    $label = [string]$Sequence[$index]
    $mode = [string]$treatmentModes[$label]
    $sequenceNumber = $index + 1
    $packageVersion = "$CampaignId-$mode"
    $runIdPrefix = "$CampaignId-$($sequenceNumber.ToString('00'))-$($label.ToLowerInvariant())"
    $resultRoot = Join-Path $OutputRoot "cells/$($sequenceNumber.ToString('00'))-$($label.ToLowerInvariant())/controller"

    $commandTokens = [System.Collections.Generic.List[string]]::new()
    foreach ($token in @(
        "pwsh",
        "-NoProfile",
        "-File",
        $runHelperPath,
        "-ControllerUri",
        $ControllerUri.AbsoluteUri.TrimEnd("/"),
        "-PackageTarget",
        "RawQuic",
        "-ProtocolLabRoot",
        $protocolLabRootFullPath
    )) {
        $commandTokens.Add((ConvertTo-CommandToken -Value ([string]$token)))
    }
    if (-not [string]::IsNullOrWhiteSpace($protocolLabExecutionRootFullPath)) {
        $commandTokens.Add("-ProtocolLabExecutionRoot")
        $commandTokens.Add((ConvertTo-CommandToken -Value $protocolLabExecutionRootFullPath))
    }
    foreach ($rid in $RuntimeIdentifier) {
        $commandTokens.Add("-RuntimeIdentifier")
        $commandTokens.Add((ConvertTo-CommandToken -Value $rid))
    }
    foreach ($scenario in $ScenarioId) {
        $commandTokens.Add("-ScenarioId")
        $commandTokens.Add((ConvertTo-CommandToken -Value $scenario))
    }
    foreach ($token in @(
        "-LoadProfileId",
        $LoadProfileId,
        "-Repetitions",
        [string]$Repetitions,
        "-AdaptiveRuntimeApplicationSendTurnPolicy",
        $mode,
        "-PackageVersion",
        $packageVersion,
        "-PlacementPolicy",
        $PlacementPolicy,
        "-RunIdPrefix",
        $runIdPrefix,
        "-ResultRoot",
        $resultRoot,
        "-TimeoutSeconds",
        [string]$TimeoutSeconds
    )) {
        $commandTokens.Add((ConvertTo-CommandToken -Value ([string]$token)))
    }
    if ($CaptureCounters) {
        $commandTokens.Add("-CaptureCounters")
    }
    if ($CaptureTrace) {
        $commandTokens.Add("-CaptureTrace")
    }

    $cells.Add([pscustomobject][ordered]@{
        sequenceIndex = $sequenceNumber
        treatmentLabel = $label
        requestedPolicy = $mode
        appliedPolicy = "legacy_current"
        packageVersion = $packageVersion
        runIdPrefix = $runIdPrefix
        state = "planned"
        command = ($commandTokens -join " ")
        resultRoot = $resultRoot
        invocationResultPath = $null
        jobId = $null
        jobStatus = $null
        jobResultPath = $null
        package = $null
        uploadedPackages = @()
        topology = [ordered]@{
            sutNodeId = $null
            loadNodeId = $null
            sutPhysicalHostId = $null
            loadPhysicalHostId = $null
            classification = "topology_unverified"
        }
        error = $null
    })
}

$manifestPath = Join-Path $OutputRoot "campaign-manifest.json"
$inventoryPath = Join-Path $OutputRoot "checksum-inventory.json"
$manifest = [ordered]@{
    schemaVersion = "adaptive-runtime-protocol-lab-campaign-v1"
    campaignId = $CampaignId
    axisId = "application_send_turn_planning"
    campaignKind = $CampaignKind
    executionMode = if ($Execute) { "execute" } else { "plan_only" }
    sequence = $Sequence
    createdAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    updatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    source = [ordered]@{
        repository = $sourceRepository
        commitSha = $sourceCommit
        clean = $sourceClean
        dirtyEntries = @(
            $sourceStatus -split "`r?`n" |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
    policy = [ordered]@{
        appliedPolicy = "legacy_current"
        adjacentAxesFrozenAt = "legacy_current"
        treatments = @(
            [ordered]@{ label = "A"; requestedPolicy = [string]$treatmentModes.A },
            [ordered]@{ label = "B"; requestedPolicy = [string]$treatmentModes.B }
        )
    }
    workload = [ordered]@{
        packageTarget = "RawQuic"
        suiteId = "quic-transport-v1-comparison"
        scenarioIds = @($ScenarioId)
        protocol = "quic"
        testExecutorId = "quic-go-raw-load"
        loadProfileId = $LoadProfileId
        repetitionsPerJob = $Repetitions
        placementPolicy = $PlacementPolicy
        runtimeIdentifiers = @($RuntimeIdentifier)
    }
    controller = [ordered]@{
        uri = $ControllerUri.AbsoluteUri.TrimEnd("/")
        workerSelectionOwner = "controller"
        explicitWorkerIds = @()
        inventoryPath = $null
        inventoryError = $null
    }
    cells = @($cells)
    hostRotation = [ordered]@{
        status = "not_evaluated"
        distinctPhysicalHostPairs = 0
        observedPairKeys = @()
    }
    classification = if ($Execute) { "execution_in_progress" } else { "planned" }
    unresolvedBlockers = @()
    activeInternalAuthorized = $false
    checksumInventoryPath = $inventoryPath
}

Write-JsonFile -Path $manifestPath -Value $manifest
Test-CampaignManifest -ManifestPath $manifestPath -SchemaPath $schemaPath

$artifactPaths = [System.Collections.Generic.List[string]]::new()
if ($Execute) {
    try {
        $nodes = @(Invoke-RestMethod -Method Get -Uri "$($ControllerUri.AbsoluteUri.TrimEnd('/'))/api/lab/nodes" -TimeoutSec 30)
        $inventorySnapshotPath = Join-Path $OutputRoot "controller-nodes-before.json"
        Write-JsonFile -Path $inventorySnapshotPath -Value $nodes
        $manifest.controller.inventoryPath = $inventorySnapshotPath
        $artifactPaths.Add($inventorySnapshotPath)
    }
    catch {
        $manifest.controller.inventoryError = $_.Exception.Message
        $manifest.classification = "environment_invalid"
        $manifest.unresolvedBlockers = @("controller_inventory_unreachable")
        $manifest.updatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
        Write-JsonFile -Path $manifestPath -Value $manifest
        Test-CampaignManifest -ManifestPath $manifestPath -SchemaPath $schemaPath
        Write-ChecksumInventory -Root $OutputRoot -InventoryPath $inventoryPath
        throw
    }

    foreach ($cell in $cells) {
        $cell.state = "executing"
        $manifest.updatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
        Write-JsonFile -Path $manifestPath -Value $manifest

        $arguments = @{
            ControllerUri = $ControllerUri.AbsoluteUri.TrimEnd("/")
            PackageTarget = "RawQuic"
            ProtocolLabRoot = $protocolLabRootFullPath
            RuntimeIdentifier = $RuntimeIdentifier
            ScenarioId = $ScenarioId
            LoadProfileId = $LoadProfileId
            Repetitions = $Repetitions
            AdaptiveRuntimeApplicationSendTurnPolicy = $cell.requestedPolicy
            PackageVersion = $cell.packageVersion
            PlacementPolicy = $PlacementPolicy
            RunIdPrefix = $cell.runIdPrefix
            ResultRoot = $cell.resultRoot
            TimeoutSeconds = $TimeoutSeconds
        }
        if (-not [string]::IsNullOrWhiteSpace($protocolLabExecutionRootFullPath)) {
            $arguments.ProtocolLabExecutionRoot = $protocolLabExecutionRootFullPath
        }
        if ($CaptureCounters) {
            $arguments.CaptureCounters = $true
        }
        if ($CaptureTrace) {
            $arguments.CaptureTrace = $true
        }

        try {
            $rawResult = & $runHelperPath @arguments
            $invocation = ($rawResult | Out-String) | ConvertFrom-Json
            $invocationPath = Join-Path $cell.resultRoot "campaign-invocation.json"
            Write-JsonFile -Path $invocationPath -Value $invocation
            $artifactPaths.Add($invocationPath)

            $cell.invocationResultPath = $invocationPath
            $cell.jobId = [string]$invocation.job.jobId
            $cell.jobStatus = [string]$invocation.job.status
            $cell.jobResultPath = [string]$invocation.jobResultPath
            $cell.package = $invocation.package
            $cell.uploadedPackages = @($invocation.uploadedPackages)
            $cell.topology = Get-TopologyRecord -Job $invocation.job -Nodes $nodes
            $cell.state = "completed"

            if ($null -ne $invocation.package.path -and (Test-Path -LiteralPath $invocation.package.path -PathType Leaf)) {
                $artifactPaths.Add([string]$invocation.package.path)
            }
            if ($null -ne $invocation.package.attestationPath -and (Test-Path -LiteralPath $invocation.package.attestationPath -PathType Leaf)) {
                $artifactPaths.Add([string]$invocation.package.attestationPath)
            }
        }
        catch {
            $cell.state = "failed"
            $cell.error = $_.Exception.Message
            $cell.jobStatus = "submission_or_execution_failed"
            if ($StopOnFailure) {
                $manifest.updatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
                Write-JsonFile -Path $manifestPath -Value $manifest
                break
            }
        }

        $manifest.updatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
        Write-JsonFile -Path $manifestPath -Value $manifest
        Test-CampaignManifest -ManifestPath $manifestPath -SchemaPath $schemaPath
    }

    $pairKeys = @(
        $cells |
            Where-Object { $_.topology.classification -eq "independent_physical_hosts" } |
            ForEach-Object {
                @([string]$_.topology.sutPhysicalHostId, [string]$_.topology.loadPhysicalHostId) |
                    Sort-Object |
                    Join-String -Separator "|"
            }
    )
    $distinctPairKeys = @($pairKeys | Sort-Object -Unique)
    $manifest.hostRotation = [ordered]@{
        status = if ($pairKeys.Count -eq 0) {
            "topology_unverified"
        }
        elseif ($distinctPairKeys.Count -lt [Math]::Min(2, $pairKeys.Count)) {
            "host_rotation_unverified"
        }
        else {
            "observed"
        }
        distinctPhysicalHostPairs = $distinctPairKeys.Count
        observedPairKeys = $distinctPairKeys
    }

    $failedCells = @($cells | Where-Object { $_.state -eq "failed" -or $_.jobStatus -eq "Failed" })
    $sharedHostCells = @($cells | Where-Object { $_.topology.classification -eq "shared_physical_host" })
    $unverifiedTopologyCells = @($cells | Where-Object {
        $_.topology.classification -in @("topology_unverified", "physical_host_unverified")
    })
    $blockers = [System.Collections.Generic.List[string]]::new()
    if ($failedCells.Count -gt 0) {
        $blockers.Add("one_or_more_jobs_failed")
    }
    if ($sharedHostCells.Count -gt 0) {
        $blockers.Add("shared_physical_host")
    }
    if ($unverifiedTopologyCells.Count -gt 0) {
        $blockers.Add("topology_unverified")
    }
    if ($manifest.hostRotation.status -ne "observed") {
        $blockers.Add([string]$manifest.hostRotation.status)
    }

    $manifest.unresolvedBlockers = @($blockers | Sort-Object -Unique)
    $manifest.classification = if ($sharedHostCells.Count -gt 0) {
        "environment_invalid"
    }
    elseif ($failedCells.Count -gt 0) {
        "diagnostic_only"
    }
    else {
        "completed_unclassified"
    }
}

$manifest.updatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
Write-JsonFile -Path $manifestPath -Value $manifest
Test-CampaignManifest -ManifestPath $manifestPath -SchemaPath $schemaPath
Write-ChecksumInventory -Root $OutputRoot -InventoryPath $inventoryPath -AdditionalPaths @($artifactPaths)

[ordered]@{
    campaignId = $CampaignId
    manifestPath = $manifestPath
    checksumInventoryPath = $inventoryPath
    classification = $manifest.classification
    executionMode = $manifest.executionMode
    cellCount = $cells.Count
    sourceCommit = $sourceCommit
    activeInternalAuthorized = $false
} | ConvertTo-Json -Depth 16
