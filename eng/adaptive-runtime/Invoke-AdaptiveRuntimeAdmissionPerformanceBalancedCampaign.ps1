# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ControlPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-balanced-campaign-v1.json'),
    [string] $OutputRoot = (Join-Path 'C:\shared\temp\quic-dotnet' (
        'admission-performance-balanced-{0}' -f
            (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ProtocolLabRoot = '../protocol-lab',
    [string] $ProtocolLabExecutionRoot,
    [switch] $Execute,
    [switch] $Resume,
    [ValidateRange(1, 64)]
    [int] $StopAfterCompletedRunCount = 64,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Campaign([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Resolve-AbsolutePath([string] $Path, [string] $BasePath) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Write-JsonFile([string] $Path, [object] $Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [void](New-Item -ItemType Directory -Force -Path $parent)
    }
    $Value | ConvertTo-Json -Depth 100 |
        Set-Content -LiteralPath $Path -Encoding utf8
}

function Invoke-ControllerJson {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][string] $Method,
        [object] $Body
    )
    $parameters = @{
        Uri = $Uri
        Method = $Method
        TimeoutSec = 300
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 100 -Compress
    }
    Invoke-RestMethod @parameters
}

function Publish-CampaignPackage {
    param(
        [Parameter(Mandatory = $true)][string] $ControllerUri,
        [Parameter(Mandatory = $true)][string] $Path
    )
    Assert-Campaign (Test-Path -LiteralPath $Path -PathType Leaf) `
        "package_path_missing:$Path"
    Add-Type -AssemblyName System.Net.Http
    $client = [Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromMinutes(5)
    $form = [Net.Http.MultipartFormDataContent]::new()
    $stream = [IO.File]::OpenRead($Path)
    try {
        $content = [Net.Http.StreamContent]::new($stream)
        $form.Add($content, 'file', [IO.Path]::GetFileName($Path))
        $response = $client.PostAsync(
            "$ControllerUri/api/lab/packages",
            $form).GetAwaiter().GetResult()
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        Assert-Campaign $response.IsSuccessStatusCode `
            "package_upload_failed:$($response.StatusCode):$text"
        $text | ConvertFrom-Json
    }
    finally {
        $stream.Dispose()
        $form.Dispose()
        $client.Dispose()
    }
}

function Get-PhysicalHostId([object] $Node) {
    if ($null -eq $Node -or $null -eq $Node.capabilities -or
        $null -eq $Node.capabilities.labels) {
        return $null
    }
    foreach ($name in @(
        'physicalHostId',
        'physical-host',
        'physicalHost',
        'host'
    )) {
        $property = $Node.capabilities.labels.PSObject.Properties |
            Where-Object {
                [string]::Equals(
                    $_.Name,
                    $name,
                    [StringComparison]::OrdinalIgnoreCase)
            } |
            Select-Object -First 1
        if ($null -ne $property -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$property.Value)) {
            return [string]$property.Value
        }
    }
    $null
}

function Get-CampaignTopology([object] $Job, [object[]] $Nodes) {
    $leases = if ($null -ne $Job.reservation -and
        $null -ne $Job.reservation.leases) {
        @($Job.reservation.leases)
    }
    else {
        @()
    }
    $sutLease = @(
        $leases |
            Where-Object { [string]$_.roleId -ceq 'sut' } |
            Select-Object -First 1
    )
    $loadLease = @(
        $leases |
            Where-Object { [string]$_.roleId -ceq 'load' } |
            Select-Object -First 1
    )
    $sutNodeId = if ($sutLease.Count -eq 1) {
        [string]$sutLease[0].nodeId
    }
    else {
        [string]$Job.crossWorkerRun.target.nodeId
    }
    $loadNodeId = if ($loadLease.Count -eq 1) {
        [string]$loadLease[0].nodeId
    }
    else {
        [string]$Job.crossWorkerRun.load.nodeId
    }
    $sutNode = @(
        $Nodes |
            Where-Object {
                [string]$_.nodeId -ceq $sutNodeId
            } |
            Select-Object -First 1
    )
    $loadNode = @(
        $Nodes |
            Where-Object {
                [string]$_.nodeId -ceq $loadNodeId
            } |
            Select-Object -First 1
    )
    $sutPhysicalHostId = if ($sutNode.Count -eq 1) {
        Get-PhysicalHostId $sutNode[0]
    }
    else {
        $null
    }
    $loadPhysicalHostId = if ($loadNode.Count -eq 1) {
        Get-PhysicalHostId $loadNode[0]
    }
    else {
        $null
    }
    $classification = if (
        [string]::IsNullOrWhiteSpace($sutNodeId) -or
        [string]::IsNullOrWhiteSpace($loadNodeId)
    ) {
        'topology_unverified'
    }
    elseif (
        [string]::IsNullOrWhiteSpace($sutPhysicalHostId) -or
        [string]::IsNullOrWhiteSpace($loadPhysicalHostId)
    ) {
        'physical_host_unverified'
    }
    elseif (
        [string]::Equals(
            $sutPhysicalHostId,
            $loadPhysicalHostId,
            [StringComparison]::OrdinalIgnoreCase)
    ) {
        'shared_physical_host'
    }
    else {
        'independent_physical_hosts'
    }
    [pscustomobject][ordered]@{
        sutNodeId = $sutNodeId
        loadNodeId = $loadNodeId
        sutPhysicalHostId = $sutPhysicalHostId
        loadPhysicalHostId = $loadPhysicalHostId
        classification = $classification
    }
}

function Get-ArtifactText {
    param(
        [Parameter(Mandatory = $true)][string] $ControllerUri,
        [Parameter(Mandatory = $true)][string] $JobId,
        [Parameter(Mandatory = $true)][object] $Artifact,
        [Parameter(Mandatory = $true)][string] $Code
    )
    $detail = Invoke-ControllerJson `
        -Uri "$ControllerUri/api/lab/jobs/$JobId/artifacts/$($Artifact.artifactId)" `
        -Method 'GET'
    Assert-Campaign (
        -not [string]::IsNullOrWhiteSpace([string]$detail.text)
    ) "${Code}:$($Artifact.artifactId)"
    [string]$detail.text
}

function Get-RequiredArtifact {
    param(
        [Parameter(Mandatory = $true)][object] $Index,
        [Parameter(Mandatory = $true)][string] $Pattern,
        [Parameter(Mandatory = $true)][string] $Code
    )
    $artifacts = @(
        $Index.artifacts |
            Where-Object {
                [string]$_.name -match $Pattern -and
                $_.readable -eq $true -and
                $_.inlinePreviewAvailable -eq $true -and
                $_.previewTruncated -ne $true -and
                [long]$_.sizeBytes -gt 0
            }
    )
    Assert-Campaign ($artifacts.Count -eq 1) `
        "${Code}:$($artifacts.Count)"
    $artifacts[0]
}

function Get-OptionalArtifact {
    param(
        [Parameter(Mandatory = $true)][object] $Index,
        [Parameter(Mandatory = $true)][string] $Pattern
    )
    @(
        $Index.artifacts |
            Where-Object {
                [string]$_.name -match $Pattern -and
                $_.readable -eq $true -and
                $_.inlinePreviewAvailable -eq $true -and
                $_.previewTruncated -ne $true -and
                [long]$_.sizeBytes -gt 0
            } |
            Select-Object -First 1
    )
}

function Get-AdapterMetric([object] $Document, [string] $MetricId) {
    $metric = @(
        $Document.metrics |
            Where-Object metricId -CEQ $MetricId
    )
    if ($metric.Count -eq 1) {
        return $metric[0].value
    }
    $null
}

function Get-LoadProcessSummary([object] $Document) {
    $samples = @($Document.samples | Sort-Object timestampUtc)
    Assert-Campaign (
        $Document.hasTelemetry -eq $true -and
        $samples.Count -gt 0 -and
        [int]$Document.logicalProcessorCount -gt 0
    ) 'load_process_metrics_invalid'
    $start = [DateTimeOffset]::Parse([string]$Document.startTimeUtc)
    $end = [DateTimeOffset]::Parse([string]$Document.endTimeUtc)
    $durationSeconds = ($end - $start).TotalSeconds
    Assert-Campaign ($durationSeconds -gt 0) `
        'load_process_metrics_duration_invalid'
    $cpuDeltaSeconds = [double]((
        $samples |
            Measure-Object cpuTimeDeltaSeconds -Sum).Sum)
    $memoryMaxBytes = [long]((
        $samples |
            Measure-Object workingSetBytes -Maximum).Maximum)
    $peakNormalizedCpuPercent = 0.0
    $previous = $start
    foreach ($sample in $samples) {
        $timestamp = [DateTimeOffset]::Parse(
            [string]$sample.timestampUtc)
        $intervalSeconds = ($timestamp - $previous).TotalSeconds
        if ($intervalSeconds -gt 0) {
            $normalized = 100.0 *
                [double]$sample.cpuTimeDeltaSeconds /
                $intervalSeconds /
                [int]$Document.logicalProcessorCount
            $peakNormalizedCpuPercent = [math]::Max(
                $peakNormalizedCpuPercent,
                $normalized)
        }
        $previous = $timestamp
    }
    [pscustomobject][ordered]@{
        process_id = [int]$Document.processId
        sample_count = $samples.Count
        duration_seconds = $durationSeconds
        logical_processor_count =
            [int]$Document.logicalProcessorCount
        cpu_time_delta_seconds = $cpuDeltaSeconds
        normalized_cpu_percent_mean =
            100.0 * $cpuDeltaSeconds /
            $durationSeconds /
            [int]$Document.logicalProcessorCount
        normalized_cpu_percent_peak_interval =
            $peakNormalizedCpuPercent
        memory_max_bytes = $memoryMaxBytes
        warnings = @($Document.warnings)
    }
}

function Save-CampaignControllerEvidence {
    param(
        [Parameter(Mandatory = $true)][string] $ControllerUri,
        [Parameter(Mandatory = $true)][string] $JobId,
        [Parameter(Mandatory = $true)][string] $CellId,
        [Parameter(Mandatory = $true)][int] $ExecutionIndex,
        [Parameter(Mandatory = $true)][string] $ArtifactIndexPath,
        [Parameter(Mandatory = $true)][string] $DownloadRoot,
        [Parameter(Mandatory = $true)][long] $StdoutMaxBytes
    )
    [void](New-Item -ItemType Directory -Force -Path $DownloadRoot)
    $artifactIndex = Invoke-ControllerJson `
        -Uri "$ControllerUri/api/lab/jobs/$JobId/artifacts" `
        -Method 'GET'
    Write-JsonFile $ArtifactIndexPath $artifactIndex

    $resultArtifact = Get-RequiredArtifact `
        -Index $artifactIndex `
        -Pattern '(^|/)c1-s100-r1/result\.json$' `
        -Code "result_artifact_count_invalid:$CellId"
    $resultText = Get-ArtifactText `
        -ControllerUri $ControllerUri `
        -JobId $JobId `
        -Artifact $resultArtifact `
        -Code "result_artifact_empty:$CellId"
    $benchmark = $resultText | ConvertFrom-Json
    $metrics = $benchmark.metrics
    Assert-Campaign (
        [int]$benchmark.repetition -eq 1 -and
        [string]$benchmark.benchmarkExecutionStatus -ceq 'succeeded' -and
        [string]$benchmark.validationResult.status -ceq 'passed' -and
        [long]$metrics.totalRequests -gt 0 -and
        [long]$metrics.successfulRequests -eq
            [long]$metrics.totalRequests -and
        [long]$metrics.failedRequests -eq 0 -and
        [long]$metrics.timeoutRequests -eq 0 -and
        [long]$metrics.bytesSent -gt 0 -and
        [long]$metrics.bytesSent -eq
            [long]$metrics.bytesReceived -and
        ([long]$metrics.totalRequests % 100) -eq 0 -and
        [string]$benchmark.loadToolSaturationStatus -ceq
            'load-generator-saturation-not-detected'
    ) "result_invariant_failed:${CellId}:$ExecutionIndex"
    $resultPath = Join-Path $DownloadRoot 'result.json'
    $resultText | Set-Content -LiteralPath $resultPath -Encoding utf8

    $stdoutArtifact = Get-RequiredArtifact `
        -Index $artifactIndex `
        -Pattern '^sut/.+/adapter-child-artifacts/server\.stdout/server\.stdout\.txt$' `
        -Code "bounded_stdout_artifact_count_invalid:$CellId"
    $stdoutText = Get-ArtifactText `
        -ControllerUri $ControllerUri `
        -JobId $JobId `
        -Artifact $stdoutArtifact `
        -Code "bounded_stdout_artifact_empty:$CellId"
    $stdoutBytes = [Text.UTF8Encoding]::new($false).GetByteCount(
        $stdoutText)
    Assert-Campaign (
        $stdoutBytes -gt 0 -and
        $stdoutBytes -le $StdoutMaxBytes -and
        $stdoutText -match
            '(?m)^QUIC_ADAPTIVE_RUNTIME_EVIDENCE_MODE=bounded_aggregate$'
    ) "bounded_stdout_invalid:${CellId}:$stdoutBytes"
    $boundedLines = @(
        $stdoutText -split '\r?\n' |
            Where-Object {
                $_ -like
                    'QUIC_ADAPTIVE_RUNTIME_BOUNDED_AGGREGATE_EPOCH_JSON=*'
            }
    )
    Assert-Campaign ($boundedLines.Count -gt 0) `
        "bounded_epoch_missing:$CellId"
    $bounded = (
        [string]$boundedLines[-1] -replace
            '^QUIC_ADAPTIVE_RUNTIME_BOUNDED_AGGREGATE_EPOCH_JSON=',
            ''
    ) | ConvertFrom-Json
    Assert-Campaign (
        [string]$bounded.SchemaVersion -ceq
            'adaptive-runtime-bounded-aggregate-epoch-v1' -and
        $bounded.ArithmeticSaturated -eq $false -and
        [long]$bounded.ApplicationSendBatchEvidenceCount -gt 0 -and
        [long]$bounded.OversizedWriteEvidenceCount -gt 0 -and
        [long]$bounded.OversizedCommittedBytes -gt 0 -and
        [long]$bounded.BufferCopyOperationCount -gt 0 -and
        [long]$bounded.OwnerReleaseCount -gt 0
    ) "bounded_epoch_invalid:$CellId"
    $stdoutPath = Join-Path $DownloadRoot 'server.stdout.txt'
    $stdoutText | Set-Content -LiteralPath $stdoutPath -Encoding utf8

    $loadArtifact = Get-RequiredArtifact `
        -Index $artifactIndex `
        -Pattern '^implementations/.+/c1-s100-r1/load-tool-process-metrics-summary\.json$' `
        -Code "load_metrics_artifact_count_invalid:$CellId"
    $loadText = Get-ArtifactText `
        -ControllerUri $ControllerUri `
        -JobId $JobId `
        -Artifact $loadArtifact `
        -Code "load_metrics_artifact_empty:$CellId"
    $loadDocument = $loadText | ConvertFrom-Json
    $loadSummary = Get-LoadProcessSummary $loadDocument
    $loadPath = Join-Path $DownloadRoot `
        'load-tool-process-metrics-summary.json'
    $loadText | Set-Content -LiteralPath $loadPath -Encoding utf8

    $adapterArtifact = Get-RequiredArtifact `
        -Index $artifactIndex `
        -Pattern '^sut/implementations/.+/c1-s100-r1/adapter-metrics\.json$' `
        -Code "target_adapter_metrics_artifact_count_invalid:$CellId"
    $adapterText = Get-ArtifactText `
        -ControllerUri $ControllerUri `
        -JobId $JobId `
        -Artifact $adapterArtifact `
        -Code "target_adapter_metrics_artifact_empty:$CellId"
    $adapterDocument = $adapterText | ConvertFrom-Json
    $targetProcessId = Get-AdapterMetric $adapterDocument 'process.id'
    $targetWorkingSet = Get-AdapterMetric $adapterDocument `
        'process.working-set-bytes'
    $targetCpuSeconds = Get-AdapterMetric $adapterDocument `
        'process.cpu-seconds'
    Assert-Campaign (
        [string]$adapterDocument.availability -ceq 'available' -and
        [long]$targetProcessId -gt 0 -and
        [long]$targetWorkingSet -gt 0 -and
        [double]$targetCpuSeconds -ge 0
    ) "target_adapter_metrics_invalid:$CellId"
    $adapterPath = Join-Path $DownloadRoot 'target-adapter-metrics.json'
    $adapterText | Set-Content -LiteralPath $adapterPath -Encoding utf8

    $counterArtifacts = Get-OptionalArtifact `
        -Index $artifactIndex `
        -Pattern '^sut/implementations/.+/c1-s100-r1/counters-summary\.json$'
    $counterStatus = 'unavailable'
    $counterSampleCount = 0
    $counterPath = $null
    if ($counterArtifacts.Count -eq 1) {
        $counterText = Get-ArtifactText `
            -ControllerUri $ControllerUri `
            -JobId $JobId `
            -Artifact $counterArtifacts[0] `
            -Code "target_counter_artifact_empty:$CellId"
        $counterDocument = $counterText | ConvertFrom-Json
        $counterSampleCount = [int]$counterDocument.samples
        $counterStatus = if ($counterSampleCount -gt 0) {
            'captured'
        }
        else {
            'unavailable'
        }
        $counterPath = Join-Path $DownloadRoot `
            'target-counters-summary.json'
        $counterText |
            Set-Content -LiteralPath $counterPath -Encoding utf8
    }

    $summaryPath = Join-Path $DownloadRoot 'measurement-summary.json'
    $summary = [pscustomobject][ordered]@{
        schema_version =
            'adaptive-runtime-admission-performance-balanced-measurement-summary-v1'
        execution_index = $ExecutionIndex
        cell_id = $CellId
        job_id = $JobId
        benchmark = [pscustomobject][ordered]@{
            requests_per_second =
                [double]$metrics.requestsPerSecond
            throughput_bytes_per_second =
                [double]$metrics.throughputBytesPerSecond
            latency_p50_ms = [double]$metrics.latencyP50Ms
            latency_p95_ms = [double]$metrics.latencyP95Ms
            total_requests = [long]$metrics.totalRequests
            successful_requests =
                [long]$metrics.successfulRequests
            failed_requests = [long]$metrics.failedRequests
            timeout_requests = [long]$metrics.timeoutRequests
            bytes_sent = [long]$metrics.bytesSent
            bytes_received = [long]$metrics.bytesReceived
            load_generator_saturation_status =
                [string]$benchmark.loadToolSaturationStatus
        }
        bounded_aggregate = [pscustomobject][ordered]@{
            epoch_count = $boundedLines.Count
            stdout_bytes = $stdoutBytes
            final_epoch = $bounded
        }
        load_process_metrics = $loadSummary
        target_process_metrics = [pscustomobject][ordered]@{
            source = 'adapter_startup_snapshot'
            process_id = [long]$targetProcessId
            working_set_bytes = [long]$targetWorkingSet
            cpu_time_seconds = [double]$targetCpuSeconds
            runtime_counter_status = $counterStatus
            runtime_counter_sample_count = $counterSampleCount
        }
        performance_acceptance_authorized = $false
        adaptive_rule_derivation_authorized = $false
        active_behavior_authorized = $false
        production_activation_authorized = $false
    }
    Write-JsonFile $summaryPath $summary
    [pscustomobject][ordered]@{
        artifact_index_path = $ArtifactIndexPath
        downloads = @(
            $resultPath,
            $stdoutPath,
            $loadPath,
            $adapterPath,
            $counterPath,
            $summaryPath
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        }
        measurement_summary_path = $summaryPath
        measurement_summary = $summary
    }
}

function ConvertTo-PackageReference([object] $Package) {
    [pscustomobject][ordered]@{
        packageId = [string]$Package.packageId
        packageVersion = [string]$Package.packageVersion
        sha256 = [string]$Package.sha256
    }
}

$control = Read-AdaptiveRuntimeJsonDocument $ControlPath
Assert-Campaign (Test-AdaptiveRuntimeDocumentHash $control) `
    'balanced_campaign_hash_invalid'
Assert-Campaign (
    Test-AdaptiveRuntimeJsonSchema $control (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-balanced-campaign-v1.schema.json')
) 'balanced_campaign_schema_invalid'
Assert-Campaign (
    $control.measurement_capability_authorized -eq $true -and
    $control.timing_execution_authorized -eq $true -and
    $control.performance_acceptance_authorization -eq $false -and
    $control.adaptive_rule_derivation_authorization -eq $false -and
    $control.active_behavior_authorization -eq $false -and
    $control.production_activation_authorization -eq $false -and
    $control.covering_array_generator_implemented -eq $false -and
    $control.covering_array_required -eq $false
) 'balanced_campaign_authorization_invalid'

$outputRootFull = Resolve-AbsolutePath $OutputRoot $RepositoryRoot
[void](New-Item -ItemType Directory -Force -Path $outputRootFull)
$manifestPath = Join-Path $outputRootFull 'compiled-manifest.json'
$statePath = Join-Path $outputRootFull 'campaign-state.json'
$nodesPath = Join-Path $outputRootFull 'controller-nodes.json'
$packagesPath = Join-Path $outputRootFull 'package-identities.json'

& (Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeAdmissionPerformanceBalancedCampaign.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -ControlPath $ControlPath `
    -OutputPath $manifestPath | Out-Null
$manifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
Assert-Campaign (Test-AdaptiveRuntimeDocumentHash $manifest) `
    'balanced_manifest_hash_invalid'

$planResult = [pscustomobject][ordered]@{
    mode = if ($Execute) {
        if ($Resume) { 'resume' } else { 'execute' }
    }
    else {
        'plan_only'
    }
    output_root = $outputRootFull
    compiled_manifest_path = $manifestPath
    compiled_manifest_sha256 = [string]$manifest.content_sha256
    planned_run_count = @($manifest.planned_runs).Count
    completed_run_count = 0
    failed_attempt_count = 0
    actual_measurements_run = 0
}
if (-not $Execute) {
    if ($PassThru) {
        $planResult
    }
    else {
        $planResult | ConvertTo-Json -Depth 10
    }
    return
}

$sourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
Assert-Campaign (
    $LASTEXITCODE -eq 0 -and
    $sourceCommit -match '^[0-9a-f]{40}$'
) 'source_commit_unresolved'
$dirty = @(& git -C $RepositoryRoot status --porcelain)
Assert-Campaign ($LASTEXITCODE -eq 0 -and $dirty.Count -eq 0) `
    'source_tree_not_clean'

$controllerUri = [string]$control.controller_uri
$nodeResponse = Invoke-ControllerJson `
    -Uri "$controllerUri/api/lab/nodes" `
    -Method 'GET'
$nodes = @(
    $nodeResponse |
        ForEach-Object { $_ }
)
Assert-Campaign ($nodes.Count -gt 0) 'controller_nodes_missing'
Write-JsonFile $nodesPath $nodes

$protocolLabRootFull = Resolve-AbsolutePath `
    $ProtocolLabRoot $RepositoryRoot
$protocolLabExecutionRootFull = if (
    [string]::IsNullOrWhiteSpace($ProtocolLabExecutionRoot)
) {
    $null
}
else {
    Resolve-AbsolutePath $ProtocolLabExecutionRoot $RepositoryRoot
}
$componentReferenceStrings = @(
    $control.package_selection.component_package_references |
        ForEach-Object {
            '{0}|{1}|{2}' -f
                [string]$_.package_id,
                [string]$_.package_version,
                [string]$_.sha256
        }
)

if ($Resume) {
    Assert-Campaign (
        (Test-Path -LiteralPath $statePath -PathType Leaf) -and
        (Test-Path -LiteralPath $packagesPath -PathType Leaf)
    ) 'resume_state_missing'
    $state = Get-Content -LiteralPath $statePath -Raw |
        ConvertFrom-Json
    $packageIdentities = @(
        Get-Content -LiteralPath $packagesPath -Raw |
            ConvertFrom-Json
    )
    Assert-Campaign (
        [string]$state.source_commit -ceq $sourceCommit -and
        [string]$state.control_sha256 -ceq
            [string]$control.content_sha256 -and
        [string]$state.manifest_sha256 -ceq
            [string]$manifest.content_sha256 -and
        $packageIdentities.Count -eq 8
    ) 'resume_identity_mismatch'
    $attempts =
        [System.Collections.Generic.List[object]]::new()
    foreach ($attempt in @($state.attempts)) {
        [void]$attempts.Add($attempt)
    }
}
else {
    Assert-Campaign (-not (Test-Path -LiteralPath $statePath)) `
        'campaign_state_already_exists'
    $packageIdentities =
        [System.Collections.Generic.List[object]]::new()
    $attempts =
        [System.Collections.Generic.List[object]]::new()
    $packagePrefix =
        'adaptive-runtime-admission-balanced-{0}-{1}' -f
            ([string]$control.content_sha256).Substring(0, 8),
            $sourceCommit.Substring(0, 8)
    foreach ($binding in @($control.cell_bindings)) {
        $cellId = [string]$binding.cell_id
        Write-Host "Building balanced campaign package for $cellId."
        $packageVersion = "$packagePrefix-$cellId"
        $packageResult = & (Join-Path $PSScriptRoot `
            '..\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1') `
            -PackageTarget RawQuic `
            -ProtocolLabRoot $protocolLabRootFull `
            -Project 'eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj' `
            -Configuration Release `
            -RuntimeIdentifier @('linux-x64') `
            -PackageVersion $packageVersion `
            -AdaptiveRuntimeOversizedWriteAdmissionPolicy (
                [string]$binding.oversized_write_admission_quantum) `
            -AdaptiveRuntimeApplicationSendBatchPolicy (
                [string]$binding.application_send_batch_formation) `
            -AdaptiveRuntimeBufferCopyPolicy (
                [string]$binding.buffer_copy_coalescing) `
            -AdaptiveRuntimeAdmissionPerformanceManifestContentSha256 (
                [string]$manifest.content_sha256) `
            -Force `
            -AllowDirtySource:$false |
                ConvertFrom-Json
        Assert-Campaign (
            $null -ne $packageResult -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$packageResult.path) -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$packageResult.packageId) -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$packageResult.packageVersion) -and
            [string]$packageResult.sha256 -match '^[0-9a-f]{64}$'
        ) "package_identity_missing:$cellId"
        $packageRef = ConvertTo-PackageReference $packageResult
        $uploaded = Publish-CampaignPackage `
            -ControllerUri $controllerUri `
            -Path ([string]$packageResult.path)
        Assert-Campaign (
            [string]$uploaded.packageId -ceq
                [string]$packageRef.packageId -and
            [string]$uploaded.packageVersion -ceq
                [string]$packageRef.packageVersion -and
            [string]$uploaded.sha256 -ceq
                [string]$packageRef.sha256
        ) "uploaded_package_identity_mismatch:$cellId"
        [void]$packageIdentities.Add(
            [pscustomobject][ordered]@{
                cell_id = $cellId
                package_ref = $packageRef
                package_path = [string]$packageResult.path
                package_attestation_path =
                    [string]$packageResult.buildAttestationPath
            })
    }
    Write-JsonFile $packagesPath @($packageIdentities)
}

function Write-CampaignState {
    $completedIndices = @(
        $attempts |
            Where-Object outcome -CEQ 'Completed' |
            ForEach-Object execution_index |
            Sort-Object -Unique
    )
    $failedAttempts = @(
        $attempts |
            Where-Object outcome -CNE 'Completed'
    )
    Write-JsonFile $statePath ([pscustomobject][ordered]@{
        schema_version =
            'adaptive-runtime-admission-performance-balanced-state-v1'
        control_sha256 = [string]$control.content_sha256
        manifest_sha256 = [string]$manifest.content_sha256
        source_commit = $sourceCommit
        source_dirty_state = 'clean'
        controller_uri = $controllerUri
        nodes_path = $nodesPath
        packages_path = $packagesPath
        planned_run_count = 64
        completed_run_count = $completedIndices.Count
        failed_attempt_count = $failedAttempts.Count
        attempts = @($attempts)
        performance_acceptance_authorization = $false
        adaptive_rule_derivation_authorization = $false
        active_behavior_authorization = $false
        production_activation_authorization = $false
    })
}

Write-CampaignState
foreach ($plannedRun in @(
    $manifest.planned_runs |
        Sort-Object execution_index
)) {
    $currentCompletedRunCount = @(
        $attempts |
            Where-Object outcome -CEQ 'Completed' |
            ForEach-Object execution_index |
            Sort-Object -Unique
    ).Count
    if ($currentCompletedRunCount -ge $StopAfterCompletedRunCount) {
        break
    }
    $completed = @(
        $attempts |
            Where-Object {
                [int]$_.execution_index -eq
                    [int]$plannedRun.execution_index -and
                [string]$_.outcome -ceq 'Completed'
            }
    )
    if ($completed.Count -gt 0) {
        continue
    }
    $cellId = [string]$plannedRun.cell_id
    $packageIdentity = @(
        $packageIdentities |
            Where-Object cell_id -CEQ $cellId
    )
    Assert-Campaign ($packageIdentity.Count -eq 1) `
        "package_identity_invalid:$cellId"
    $packageRef = $packageIdentity[0].package_ref
    $executionIndex = [int]$plannedRun.execution_index
    $runFolderName = '{0:D3}-b{1:D2}-p{2:D2}-{3}' -f
        $executionIndex,
        [int]$plannedRun.block_index,
        [int]$plannedRun.position_index,
        $cellId
    $runRoot = Join-Path $outputRootFull "runs\$runFolderName"
    [void](New-Item -ItemType Directory -Force -Path $runRoot)
    $runIdPrefix =
        'balanced-b{0:D2}-p{1:D2}-{2}-{3}' -f
            [int]$plannedRun.block_index,
            [int]$plannedRun.position_index,
            $cellId,
            $manifest.document_id
    Write-Host (
        'Executing {0}/64: block {1}, position {2}, cell {3}.' -f
            $executionIndex,
            [int]$plannedRun.block_index,
            [int]$plannedRun.position_index,
            $cellId)
    $runHelperArguments = @{
        ControllerUri = $controllerUri
        PackageTarget = 'RawQuic'
        ProtocolLabRoot = $protocolLabRootFull
        ScenarioId = 'quic.transport.multiplex.100x64kb'
        Protocol = 'quic'
        TestExecutorId = 'quic-go-raw-load'
        LoadProfileId = 'raw-quic-peer-confidence'
        Repetitions = 1
        PlacementPolicy = 'isolated-pair'
        PackageVersion = [string]$packageRef.packageVersion
        RunIdPrefix = $runIdPrefix
        ResultRoot = $runRoot
        TimeoutSeconds = 3600
        UsePackageReferenceOnly = $true
        RequiredCapability = @(
            'evidenceTier=offline-ml-two-host-vm'
        )
        PackageReference = @(
            ('{0}|{1}|{2}' -f
                [string]$packageRef.packageId,
                [string]$packageRef.packageVersion,
                [string]$packageRef.sha256)
        ) + $componentReferenceStrings
        AdaptiveRuntimeOversizedWriteAdmissionPolicy =
            [string]$plannedRun.policy_controls.
                oversized_write_admission_quantum
        AdaptiveRuntimeApplicationSendBatchPolicy =
            [string]$plannedRun.policy_controls.
                application_send_batch_formation
        AdaptiveRuntimeBufferCopyPolicy =
            [string]$plannedRun.policy_controls.
                buffer_copy_coalescing
    }
    if (-not [string]::IsNullOrWhiteSpace(
        $protocolLabExecutionRootFull)) {
        $runHelperArguments.ProtocolLabExecutionRoot =
            $protocolLabExecutionRootFull
    }

    $attempt = [ordered]@{
        execution_index = $executionIndex
        block_index = [int]$plannedRun.block_index
        position_index = [int]$plannedRun.position_index
        cell_id = $cellId
        attempt_index = @(
            $attempts |
                Where-Object {
                    [int]$_.execution_index -eq $executionIndex
                }).Count + 1
        package_ref = $packageRef
        job_id = $null
        run_id = $null
        topology = $null
        outcome = 'submitted'
        failure_reason_code = $null
        controller_artifact_index_path = $null
        controller_artifact_downloads = @()
        measurement_summary_path = $null
    }
    try {
        $runResult = & (Join-Path $PSScriptRoot `
            '..\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1') `
            @runHelperArguments
        $runJson = $runResult | ConvertFrom-Json
        Write-JsonFile (Join-Path $runRoot 'run-manifest.json') `
            $runJson
        Write-JsonFile (Join-Path $runRoot 'job-result.json') `
            $runJson.job
        $attempt.job_id = [string]$runJson.job.jobId
        $attempt.run_id = [string]$runJson.job.result.runId
        $attempt.topology = Get-CampaignTopology `
            -Job $runJson.job `
            -Nodes $nodes
        $attempt.outcome = [string]$runJson.job.status
        $attempt.failure_reason_code =
            [string]$runJson.job.result.failureReasonCode
        Assert-Campaign (
            [string]$attempt.outcome -ceq 'Completed'
        ) "balanced_job_failed:${executionIndex}:${cellId}:$($attempt.job_id):$($attempt.failure_reason_code)"
        Assert-Campaign (
            [string]$attempt.topology.classification -ceq
                'independent_physical_hosts'
        ) "balanced_topology_not_credible:${executionIndex}:${cellId}:$($attempt.topology.classification)"
        $evidence = Save-CampaignControllerEvidence `
            -ControllerUri $controllerUri `
            -JobId ([string]$attempt.job_id) `
            -CellId $cellId `
            -ExecutionIndex $executionIndex `
            -ArtifactIndexPath (
                Join-Path $runRoot 'controller-artifact-index.json') `
            -DownloadRoot (Join-Path $runRoot 'downloads') `
            -StdoutMaxBytes (
                [long]$control.resource_metrics.
                    bounded_server_stdout_max_bytes)
        $attempt.controller_artifact_index_path =
            [string]$evidence.artifact_index_path
        $attempt.controller_artifact_downloads =
            @($evidence.downloads)
        $attempt.measurement_summary_path =
            [string]$evidence.measurement_summary_path
    }
    catch {
        if ([string]$attempt.outcome -ceq 'Completed') {
            $attempt.outcome = 'failed_evidence_validation'
        }
        elseif ([string]$attempt.outcome -ceq 'submitted') {
            $attempt.outcome = 'failed'
        }
        $attempt.failure_reason_code = $_.Exception.Message
        [void]$attempts.Add([pscustomobject]$attempt)
        Write-CampaignState
        throw
    }
    [void]$attempts.Add([pscustomobject]$attempt)
    Write-CampaignState
}

$completedAttempts = @(
    $attempts |
        Where-Object outcome -CEQ 'Completed'
)
$completedRunCount = @(
    $completedAttempts.execution_index |
        Sort-Object -Unique
).Count
if ($StopAfterCompletedRunCount -eq 64) {
    Assert-Campaign ($completedRunCount -eq 64) `
        'balanced_campaign_incomplete'
}
$campaignStatus = if ($completedRunCount -eq 64) {
    'complete'
}
else {
    'operator_paused'
}
$result = [pscustomobject][ordered]@{
    mode = if ($Resume) { 'resume' } else { 'execute' }
    campaign_status = $campaignStatus
    output_root = $outputRootFull
    compiled_manifest_path = $manifestPath
    compiled_manifest_sha256 = [string]$manifest.content_sha256
    state_path = $statePath
    planned_run_count = 64
    completed_run_count = $completedRunCount
    failed_attempt_count = @(
        $attempts |
            Where-Object outcome -CNE 'Completed'
    ).Count
    actual_measurements_run = $completedRunCount
    performance_acceptance_authorization = $false
    adaptive_rule_derivation_authorization = $false
    active_behavior_authorization = $false
    production_activation_authorization = $false
}
if ($PassThru) {
    $result
}
else {
    $result | ConvertTo-Json -Depth 12
}
