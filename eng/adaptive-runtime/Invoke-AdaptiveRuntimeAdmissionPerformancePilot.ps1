# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $PilotPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json'),
    [string] $OutputRoot = (Join-Path 'C:\shared\temp\quic-dotnet' (
        'admission-performance-pilot-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ProtocolLabRoot = '../protocol-lab',
    [string] $ProtocolLabExecutionRoot,
    [switch] $Execute,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Pilot([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Read-Repo([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function Write-JsonFile([string] $Path, [object] $Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Value | ConvertTo-Json -Depth 100 |
        Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-PhysicalHostId {
    param([object] $Node)
    if ($null -eq $Node -or $null -eq $Node.capabilities -or $null -eq $Node.capabilities.labels) {
        return $null
    }
    foreach ($name in @('physicalHostId', 'physical-host', 'physicalHost', 'host')) {
        $property = $Node.capabilities.labels.PSObject.Properties |
            Where-Object { [string]::Equals($_.Name, $name, [StringComparison]::OrdinalIgnoreCase) } |
            Select-Object -First 1
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }
    return $null
}

function Invoke-ControllerJson {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][string] $Method,
        [object] $Body
    )
    $parameters = @{ Uri = $Uri; Method = $Method; TimeoutSec = 15 }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = ($Body | ConvertTo-Json -Depth 64)
    }
    Invoke-RestMethod @parameters
}

function Resolve-AbsolutePath {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $BasePath
    )
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function ConvertTo-LabPackageReference {
    param([Parameter(Mandatory = $true)] $Metadata)
    [ordered]@{
        packageId = [string]$Metadata.packageId
        packageVersion = [string]$Metadata.packageVersion
        sha256 = [string]$Metadata.sha256
    }
}

function Get-RefKey {
    param([object] $Reference)
    "$($Reference.document_id)|$($Reference.schema_version)|$($Reference.document_version)|$($Reference.content_sha256)"
}

$pilot = Read-AdaptiveRuntimeJsonDocument $PilotPath
Assert-Pilot (Test-AdaptiveRuntimeDocumentHash $pilot) 'pilot_hash_invalid'
Assert-Pilot (
    Test-AdaptiveRuntimeJsonSchema $pilot (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-pilot-v1.schema.json')
) 'pilot_schema_invalid'

$campaign = Read-Repo 'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'
Assert-Pilot (Test-AdaptiveRuntimeDocumentHash $campaign) 'campaign_hash_invalid'
Assert-Pilot (
    [string]$pilot.controller_uri -ceq 'http://10.10.99.176:5088' -and
    [string]$pilot.host_selection.placement_policy -ceq 'isolated-pair' -and
    [string]$pilot.host_selection.worker_selection_owner -ceq 'controller-owned' -and
    [string]$pilot.package_selection.package_target -ceq 'RawQuic' -and
    [int]$pilot.package_selection.repetitions_per_cell -eq 2 -and
    $pilot.timing_execution_authorized -eq $true -and
    $pilot.active_behavior_authorization -eq $false -and
    $pilot.performance_acceptance_authorization -eq $false -and
    $pilot.production_activation_authorization -eq $false
) 'pilot_controls_invalid'

$outputRootFull = Resolve-AbsolutePath -Path $OutputRoot -BasePath $RepositoryRoot
New-Item -ItemType Directory -Force -Path $outputRootFull | Out-Null
$compiledManifestPath = Join-Path $outputRootFull 'compiled-manifest.json'
$executionManifestPath = Join-Path $outputRootFull 'execution-manifest.json'
$controllerIndexPath = Join-Path $outputRootFull 'controller-artifact-index.json'
$preflightPath = Join-Path $outputRootFull 'controller-preflight.json'
$nodesPath = Join-Path $outputRootFull 'controller-nodes.json'
$packagesPath = Join-Path $outputRootFull 'package-identities.json'

$compileResult = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeAdmissionPerformancePilot.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -PilotPath (Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json') `
    -OutputPath $compiledManifestPath `
    -PassThru
Assert-Pilot (Test-Path -LiteralPath $compiledManifestPath -PathType Leaf) `
    'compiled_manifest_missing'

$manifest = Read-AdaptiveRuntimeJsonDocument $compiledManifestPath
Assert-Pilot (Test-AdaptiveRuntimeDocumentHash $manifest) 'compiled_manifest_hash_invalid'
Assert-Pilot (
    Test-AdaptiveRuntimeJsonSchema $manifest (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-pilot-manifest-v1.schema.json')
) 'compiled_manifest_schema_invalid'

$result = [ordered]@{
    mode = if ($Execute) { 'execute' } else { 'plan_only' }
    output_root = $outputRootFull
    compiled_manifest_path = $compiledManifestPath
    compiled_manifest_sha256 = [string]$manifest.content_sha256
    planned_run_count = @($manifest.planned_runs).Count
    submitted_job_count = 0
    controller_artifact_index_path = $null
    controller_artifact_downloads = @()
    preflight = $null
    runs = @()
}

if (-not $Execute) {
    Write-JsonFile -Path $executionManifestPath -Value $manifest
    if ($PassThru) {
        [pscustomobject]$result
    }
    else {
        [pscustomobject]$result | ConvertTo-Json -Depth 12
    }
    return
}

$controllerUri = [string]$pilot.controller_uri
try {
    $nodes = @(Invoke-ControllerJson -Uri "$controllerUri/api/lab/nodes" -Method 'GET')
    Write-JsonFile -Path $nodesPath -Value $nodes
}
catch {
    throw "controller_unreachable:$($_.Exception.Message)"
}

$preflight = [ordered]@{
    controller_uri = $controllerUri
    nodes_path = $nodesPath
    node_count = @($nodes).Count
    package_identity_status = 'unknown'
    blockers = @()
}

$expectedRunInputs = @(
    [pscustomobject][ordered]@{
        cell_id = 'a0'
        oversized_write_admission_quantum = 'legacy_current'
        application_send_batch_formation = 'legacy_current'
        buffer_copy_coalescing = 'legacy_current'
    },
    [pscustomobject][ordered]@{
        cell_id = 'a4'
        oversized_write_admission_quantum = 'single_fragment'
        application_send_batch_formation = 'legacy_current'
        buffer_copy_coalescing = 'legacy_current'
    },
    [pscustomobject][ordered]@{
        cell_id = 'a3'
        oversized_write_admission_quantum = 'legacy_current'
        application_send_batch_formation = 'single_eligible'
        buffer_copy_coalescing = 'memory_conservative'
    },
    [pscustomobject][ordered]@{
        cell_id = 'a7'
        oversized_write_admission_quantum = 'single_fragment'
        application_send_batch_formation = 'single_eligible'
        buffer_copy_coalescing = 'memory_conservative'
    }
)

$runRecords = [System.Collections.Generic.List[object]]::new()
$packageVersionPrefix = 'adaptive-runtime-admission-performance-pilot'
$protocolLabRootFull = Resolve-AbsolutePath -Path $ProtocolLabRoot -BasePath $RepositoryRoot
$protocolLabExecutionRootFull = if ([string]::IsNullOrWhiteSpace($ProtocolLabExecutionRoot)) {
    $null
}
else {
    Resolve-AbsolutePath -Path $ProtocolLabExecutionRoot -BasePath $RepositoryRoot
}

foreach ($runInput in $expectedRunInputs) {
    $cellManifest = @($manifest.cell_bindings | Where-Object cell_id -ceq $runInput.cell_id)[0]
    Assert-Pilot ($null -ne $cellManifest) "cell_manifest_missing:$($runInput.cell_id)"
    $packageVersion = '{0}-{1}' -f $packageVersionPrefix, $runInput.cell_id
    $runIdPrefix = 'pilot-{0}-{1}' -f $runInput.cell_id, $manifest.document_id
    $cellOutputRoot = Join-Path $outputRootFull "cells\$($runInput.cell_id)"
    New-Item -ItemType Directory -Force -Path $cellOutputRoot | Out-Null
    $cellManifestPath = Join-Path $cellOutputRoot 'run-manifest.json'
    $jobResultPath = Join-Path $cellOutputRoot 'job-result.json'
    $artifactIndexPath = Join-Path $cellOutputRoot 'controller-artifact-index.json'
    $downloadRoot = Join-Path $cellOutputRoot 'downloads'
    New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null

    $packageResult = & (Join-Path $PSScriptRoot '..\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1') `
        -PackageTarget RawQuic `
        -ProtocolLabRoot $protocolLabRootFull `
        -Project 'eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj' `
        -Configuration Release `
        -RuntimeIdentifier @('linux-x64') `
        -PackageVersion $packageVersion `
        -AdaptiveRuntimeOversizedWriteAdmissionPolicy ([string]$runInput.oversized_write_admission_quantum) `
        -AdaptiveRuntimeApplicationSendBatchPolicy ([string]$runInput.application_send_batch_formation) `
        -AdaptiveRuntimeBufferCopyPolicy ([string]$runInput.buffer_copy_coalescing) `
        -Force `
        -AllowDirtySource:$false | ConvertFrom-Json

    if ($null -eq $packageResult -or [string]::IsNullOrWhiteSpace([string]$packageResult.path) -or
        [string]::IsNullOrWhiteSpace([string]$packageResult.packageId) -or
        [string]::IsNullOrWhiteSpace([string]$packageResult.packageVersion) -or
        [string]::IsNullOrWhiteSpace([string]$packageResult.sha256)) {
        throw "missing_exact_package_identities:$($runInput.cell_id)"
    }
    $packageRef = ConvertTo-LabPackageReference $packageResult
    $packageIdentity = [string]$packageResult.packageId + '@' + [string]$packageResult.packageVersion + '#' + [string]$packageResult.sha256

    $runRecord = [ordered]@{
        cell_id = [string]$runInput.cell_id
        execution_order_index = @($expectedRunInputs).IndexOf($runInput) + 1
        package_version = $packageVersion
        package_identity = $packageIdentity
        package_ref = $packageRef
        run_id_prefix = $runIdPrefix
        job_id = $null
        run_id = $null
        topology = $null
        outcome = 'planned'
        controller_artifact_index_path = $null
        controller_artifact_downloads = @()
        package_path = [string]$packageResult.path
        package_attestation_path = [string]$packageResult.buildAttestationPath
        result_manifest_path = $cellManifestPath
        job_result_path = $jobResultPath
        placement_policy = 'isolated-pair'
        repetitions = 2
    }

    if ([string]::IsNullOrWhiteSpace([string]$packageResult.packageId) -or
        [string]::IsNullOrWhiteSpace([string]$packageResult.sha256)) {
        throw "missing_exact_package_identities:$($runInput.cell_id)"
    }

    $runHelperArgs = @{
        ControllerUri = $controllerUri
        PackageTarget = 'RawQuic'
        ProtocolLabRoot = $protocolLabRootFull
        ScenarioId = 'quic.transport.multiplex.100x64kb'
        Protocol = 'quic'
        TestExecutorId = 'quic-go-raw-load'
        LoadProfileId = 'raw-quic-peer-confidence'
        Repetitions = 2
        PlacementPolicy = 'isolated-pair'
        PackageVersion = $packageVersion
        RunIdPrefix = $runIdPrefix
        ResultRoot = $cellOutputRoot
        TimeoutSeconds = 3600
        UsePackageReferenceOnly = $true
        PackageReference = ("{0}|{1}|{2}" -f $packageRef.packageId, $packageRef.packageVersion, $packageRef.sha256)
        AdaptiveRuntimeOversizedWriteAdmissionPolicy = [string]$runInput.oversized_write_admission_quantum
        AdaptiveRuntimeApplicationSendBatchPolicy = [string]$runInput.application_send_batch_formation
        AdaptiveRuntimeBufferCopyPolicy = [string]$runInput.buffer_copy_coalescing
    }
    if (-not [string]::IsNullOrWhiteSpace($protocolLabExecutionRootFull)) {
        $runHelperArgs.ProtocolLabExecutionRoot = $protocolLabExecutionRootFull
    }

    try {
        $runResult = & (Join-Path $PSScriptRoot '..\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1') @runHelperArgs
        $runJson = $runResult | ConvertFrom-Json
        Write-JsonFile -Path $cellManifestPath -Value $runJson
        $runRecord.job_id = [string]$runJson.job.jobId
        $runRecord.run_id = [string]$runJson.job.runId
        $runRecord.topology = if ($null -ne $runJson.job.reservation) { $runJson.job.reservation } else { $null }
        $runRecord.outcome = if ([string]::IsNullOrWhiteSpace([string]$runJson.job.status)) { 'submitted' } else { [string]$runJson.job.status }
        $runRecord.controller_artifact_index_path = $artifactIndexPath
        $runRecord.controller_artifact_downloads = @()
        if (Test-Path -LiteralPath $artifactIndexPath -PathType Leaf) {
            $runRecord.controller_artifact_downloads = @(Get-ChildItem -LiteralPath $downloadRoot -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
        }
        $preflight.package_identity_status = 'resolved'
    }
    catch {
        $runRecord.outcome = 'failed'
        $runRecord.controller_artifact_downloads = @()
        $preflight.blockers += $_.Exception.Message
        throw
    }

    [void]$runRecords.Add([pscustomobject]$runRecord)
}

$preflight.package_identity_status = 'resolved'
$preflight.blockers = @()
Write-JsonFile -Path $preflightPath -Value $preflight
Write-JsonFile -Path $packagesPath -Value @($runRecords | ForEach-Object { $_.package_ref })
Write-JsonFile -Path $controllerIndexPath -Value @{
    controller_uri = $controllerUri
    runs = @($runRecords)
}

$manifest.planned_runs = @($runRecords | ForEach-Object {
    [pscustomobject][ordered]@{
        cell_id = $_.cell_id
        execution_order_index = $_.execution_order_index
        repetitions = 2
        state = if ($_.outcome -eq 'submitted') { 'executing' } else { 'completed' }
        job_id = $_.job_id
        package_ref = $_.package_ref
        run_id = $_.run_id
        topology = $_.topology
        outcome = $_.outcome
        controller_artifact_index_path = $_.controller_artifact_index_path
        controller_artifact_downloads = @($_.controller_artifact_downloads)
        policy_controls = [pscustomobject][ordered]@{
            oversized_write_admission_quantum = @($expectedRunInputs | Where-Object cell_id -ceq $_.cell_id)[0].oversized_write_admission_quantum
            application_send_batch_formation = @($expectedRunInputs | Where-Object cell_id -ceq $_.cell_id)[0].application_send_batch_formation
            buffer_copy_coalescing = @($expectedRunInputs | Where-Object cell_id -ceq $_.cell_id)[0].buffer_copy_coalescing
        }
    }
})
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
Write-AdaptiveRuntimeCanonicalDocument $manifest $executionManifestPath

$result.mode = 'execute'
$result.submitted_job_count = @($runRecords).Count
$result.controller_artifact_index_path = $controllerIndexPath
$result.controller_artifact_downloads = @($runRecords | ForEach-Object { $_.controller_artifact_downloads } | Where-Object { $_ })
$result.preflight = $preflight
$result.runs = @($runRecords)

if ($PassThru) {
    [pscustomobject]$result
}
else {
    [pscustomobject]$result | ConvertTo-Json -Depth 12
}
