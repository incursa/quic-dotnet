# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ControlPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-queued-send-performance-campaign-v1.json'),
    [string] $OutputRoot = (Join-Path 'C:\shared\temp\quic-dotnet' (
        'queued-send-performance-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ProtocolLabRoot = '../protocol-lab',
    [string] $ProtocolLabExecutionRoot,
    [switch] $Execute,
    [switch] $Resume,
    [ValidateRange(1, 16)]
    [int] $StopAfterCompletedRunCount = 16,
    [string] $ReplayEvidenceJobId,
    [ValidateSet(
        'cell.queued_send_burst_budget.performance.q0',
        'cell.queued_send_burst_budget.performance.q1')]
    [string] $ReplayEvidenceCellId =
        'cell.queued_send_burst_budget.performance.q1',
    [ValidateRange(0, 16)]
    [int] $ReplayEvidenceExecutionIndex = 0,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Campaign([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
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
    $parameters = @{ Uri = $Uri; Method = $Method; TimeoutSec = 300 }
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
            "$ControllerUri/api/lab/packages", $form).GetAwaiter().GetResult()
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        Assert-Campaign $response.IsSuccessStatusCode `
            "package_upload_failed:$($response.StatusCode):$text"
        $text | ConvertFrom-Json
    }
    finally {
        $stream.Dispose(); $form.Dispose(); $client.Dispose()
    }
}

function Get-PhysicalHostId([object] $Node) {
    if ($null -eq $Node -or $null -eq $Node.capabilities -or
        $null -eq $Node.capabilities.labels) { return $null }
    foreach ($name in @('physicalHostId','physical-host','physicalHost','host')) {
        $property = $Node.capabilities.labels.PSObject.Properties |
            Where-Object { [string]::Equals($_.Name, $name,
                [StringComparison]::OrdinalIgnoreCase) } |
            Select-Object -First 1
        if ($null -ne $property -and
            -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }
    $null
}

function Get-CampaignTopology([object] $Job, [object[]] $Nodes) {
    $leases = if ($null -ne $Job.reservation -and
        $null -ne $Job.reservation.leases) { @($Job.reservation.leases) }
        else { @() }
    $sutLease = @($leases | Where-Object { [string]$_.roleId -ceq 'sut' } |
        Select-Object -First 1)
    $loadLease = @($leases | Where-Object { [string]$_.roleId -ceq 'load' } |
        Select-Object -First 1)
    $sutNodeId = if ($sutLease.Count -eq 1) { [string]$sutLease[0].nodeId }
        else { [string]$Job.crossWorkerRun.target.nodeId }
    $loadNodeId = if ($loadLease.Count -eq 1) { [string]$loadLease[0].nodeId }
        else { [string]$Job.crossWorkerRun.load.nodeId }
    $sutNode = @($Nodes | Where-Object { [string]$_.nodeId -ceq $sutNodeId } |
        Select-Object -First 1)
    $loadNode = @($Nodes | Where-Object { [string]$_.nodeId -ceq $loadNodeId } |
        Select-Object -First 1)
    $sutHost = if ($sutNode.Count -eq 1) { Get-PhysicalHostId $sutNode[0] }
        else { $null }
    $loadHost = if ($loadNode.Count -eq 1) { Get-PhysicalHostId $loadNode[0] }
        else { $null }
    $classification = if ([string]::IsNullOrWhiteSpace($sutNodeId) -or
        [string]::IsNullOrWhiteSpace($loadNodeId)) { 'topology_unverified' }
        elseif ([string]::IsNullOrWhiteSpace($sutHost) -or
            [string]::IsNullOrWhiteSpace($loadHost)) { 'physical_host_unverified' }
        elseif ([string]::Equals($sutHost, $loadHost,
            [StringComparison]::OrdinalIgnoreCase)) { 'shared_physical_host' }
        else { 'independent_physical_hosts' }
    [pscustomobject][ordered]@{
        sutNodeId = $sutNodeId; loadNodeId = $loadNodeId
        sutPhysicalHostId = $sutHost; loadPhysicalHostId = $loadHost
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
    Assert-Campaign (-not [string]::IsNullOrWhiteSpace([string]$detail.text)) `
        "${Code}:$($Artifact.artifactId)"
    [string]$detail.text
}

function Get-RequiredArtifact([object] $Index, [string] $Pattern, [string] $Code) {
    $matches = @($Index.artifacts | Where-Object {
        [string]$_.name -match $Pattern -and $_.readable -eq $true -and
        $_.inlinePreviewAvailable -eq $true -and $_.previewTruncated -ne $true -and
        [long]$_.sizeBytes -gt 0 })
    Assert-Campaign ($matches.Count -eq 1) "${Code}:$($matches.Count)"
    $matches[0]
}

function Get-OptionalArtifact([object] $Index, [string] $Pattern) {
    @($Index.artifacts | Where-Object {
        [string]$_.name -match $Pattern -and $_.readable -eq $true -and
        $_.inlinePreviewAvailable -eq $true -and $_.previewTruncated -ne $true -and
        [long]$_.sizeBytes -gt 0 } | Select-Object -First 1)
}

function Get-AdapterMetric([object] $Document, [string] $MetricId) {
    $metric = @($Document.metrics | Where-Object metricId -CEQ $MetricId)
    if ($metric.Count -eq 1) { return $metric[0].value }
    $null
}

function Get-LoadProcessSummary([object] $Document) {
    $samples = @($Document.samples | Sort-Object timestampUtc)
    Assert-Campaign ($Document.hasTelemetry -eq $true -and $samples.Count -gt 0 -and
        [int]$Document.logicalProcessorCount -gt 0) 'load_process_metrics_invalid'
    $start = [DateTimeOffset]::Parse([string]$Document.startTimeUtc)
    $end = [DateTimeOffset]::Parse([string]$Document.endTimeUtc)
    $duration = ($end - $start).TotalSeconds
    Assert-Campaign ($duration -gt 0) 'load_process_metrics_duration_invalid'
    $cpu = [double](($samples | Measure-Object cpuTimeDeltaSeconds -Sum).Sum)
    $memory = [long](($samples | Measure-Object workingSetBytes -Maximum).Maximum)
    $peak = 0.0; $previous = $start
    foreach ($sample in $samples) {
        $timestamp = [DateTimeOffset]::Parse([string]$sample.timestampUtc)
        $interval = ($timestamp - $previous).TotalSeconds
        if ($interval -gt 0) {
            $peak = [math]::Max($peak, 100.0 * [double]$sample.cpuTimeDeltaSeconds /
                $interval / [int]$Document.logicalProcessorCount)
        }
        $previous = $timestamp
    }
    [pscustomobject][ordered]@{
        process_id = [int]$Document.processId; sample_count = $samples.Count
        duration_seconds = $duration
        logical_processor_count = [int]$Document.logicalProcessorCount
        cpu_time_delta_seconds = $cpu
        normalized_cpu_percent_mean =
            100.0 * $cpu / $duration / [int]$Document.logicalProcessorCount
        normalized_cpu_percent_peak_interval = $peak
        memory_max_bytes = $memory; warnings = @($Document.warnings)
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
        [Parameter(Mandatory = $true)][long] $StdoutMaxBytes,
        [Parameter(Mandatory = $true)][bool] $AcceptedTimedRow,
        [switch] $RequireActivation
    )
    [void](New-Item -ItemType Directory -Force -Path $DownloadRoot)
    $index = Invoke-ControllerJson -Uri "$ControllerUri/api/lab/jobs/$JobId/artifacts" -Method 'GET'
    Write-JsonFile $ArtifactIndexPath $index
    $resultArtifact = Get-RequiredArtifact $index '(^|/)c1-s100-r1/result\.json$' `
        "result_artifact_count_invalid:$CellId"
    $resultText = Get-ArtifactText $ControllerUri $JobId $resultArtifact `
        "result_artifact_empty:$CellId"
    $benchmark = $resultText | ConvertFrom-Json
    $metrics = $benchmark.metrics
    Assert-Campaign ([int]$benchmark.repetition -eq 1 -and
        [string]$benchmark.benchmarkExecutionStatus -ceq 'succeeded' -and
        [string]$benchmark.validationResult.status -ceq 'passed' -and
        [long]$metrics.totalRequests -gt 0 -and
        [long]$metrics.successfulRequests -eq [long]$metrics.totalRequests -and
        [long]$metrics.failedRequests -eq 0 -and [long]$metrics.timeoutRequests -eq 0 -and
        [long]$metrics.bytesSent -gt 0 -and [long]$metrics.bytesSent -eq [long]$metrics.bytesReceived -and
        [string]$benchmark.loadToolSaturationStatus -ceq
            'load-generator-saturation-not-detected') `
        "result_invariant_failed:${CellId}:$ExecutionIndex"
    $resultPath = Join-Path $DownloadRoot 'result.json'
    $resultText | Set-Content -LiteralPath $resultPath -Encoding utf8

    $stdoutArtifact = Get-RequiredArtifact $index `
        '^sut/.+/adapter-child-artifacts/server\.stdout/server\.stdout\.txt$' `
        "bounded_stdout_artifact_count_invalid:$CellId"
    $stdoutText = Get-ArtifactText $ControllerUri $JobId $stdoutArtifact `
        "bounded_stdout_artifact_empty:$CellId"
    $stdoutBytes = [Text.UTF8Encoding]::new($false).GetByteCount($stdoutText)
    Assert-Campaign ($stdoutBytes -gt 0 -and $stdoutBytes -le $StdoutMaxBytes -and
        $stdoutText -match '(?m)^QUIC_ADAPTIVE_RUNTIME_EVIDENCE_MODE=bounded_aggregate$') `
        "bounded_stdout_invalid:${CellId}:$stdoutBytes"
    $boundedLines = @($stdoutText -split '\r?\n' | Where-Object {
        $_ -like 'QUIC_ADAPTIVE_RUNTIME_BOUNDED_AGGREGATE_EPOCH_JSON=*' })
    Assert-Campaign ($boundedLines.Count -gt 0) "bounded_epoch_missing:$CellId"
    $bounded = ([string]$boundedLines[-1] -replace
        '^QUIC_ADAPTIVE_RUNTIME_BOUNDED_AGGREGATE_EPOCH_JSON=', '') | ConvertFrom-Json
    Assert-Campaign ([string]$bounded.SchemaVersion -ceq
        'adaptive-runtime-bounded-aggregate-epoch-v1' -and
        $bounded.ArithmeticSaturated -eq $false -and
        [long]$bounded.QueuedSendBurstEvidenceCount -gt 0) `
        "queued_bounded_epoch_invalid:$CellId"
    $activationCountProperty = $bounded.PSObject.Properties[
        'QueuedSendBurstLegalBudgetGreaterThanOneCount']
    Assert-Campaign ($null -ne $activationCountProperty) `
        'queued_activation_counter_missing'
    $activationCount = [long]$activationCountProperty.Value
    if ($RequireActivation) {
        Assert-Campaign ($CellId -ceq
            'cell.queued_send_burst_budget.performance.q1' -and
            $activationCount -gt 0) `
            'queued_q1_activation_predicate_not_observed'
    }
    $stdoutPath = Join-Path $DownloadRoot 'server.stdout.txt'
    $stdoutText | Set-Content -LiteralPath $stdoutPath -Encoding utf8

    $loadArtifact = Get-RequiredArtifact $index `
        '^implementations/.+/c1-s100-r1/load-tool-process-metrics-summary\.json$' `
        "load_metrics_artifact_count_invalid:$CellId"
    $loadText = Get-ArtifactText $ControllerUri $JobId $loadArtifact `
        "load_metrics_artifact_empty:$CellId"
    $loadDocument = $loadText | ConvertFrom-Json
    $loadSummary = Get-LoadProcessSummary $loadDocument
    $loadPath = Join-Path $DownloadRoot 'load-tool-process-metrics-summary.json'
    $loadText | Set-Content -LiteralPath $loadPath -Encoding utf8

    $adapterArtifact = Get-RequiredArtifact $index `
        '^sut/implementations/.+/c1-s100-r1/adapter-metrics\.json$' `
        "target_adapter_metrics_artifact_count_invalid:$CellId"
    $adapterText = Get-ArtifactText $ControllerUri $JobId $adapterArtifact `
        "target_adapter_metrics_artifact_empty:$CellId"
    $adapter = $adapterText | ConvertFrom-Json
    $targetPid = Get-AdapterMetric $adapter 'process.id'
    $targetMemory = Get-AdapterMetric $adapter 'process.working-set-bytes'
    $targetCpu = Get-AdapterMetric $adapter 'process.cpu-seconds'
    Assert-Campaign ([string]$adapter.availability -ceq 'available' -and
        [long]$targetPid -gt 0 -and [long]$targetMemory -gt 0 -and [double]$targetCpu -ge 0) `
        "target_adapter_metrics_invalid:$CellId"
    $adapterPath = Join-Path $DownloadRoot 'target-adapter-metrics.json'
    $adapterText | Set-Content -LiteralPath $adapterPath -Encoding utf8

    $counterArtifacts = @(Get-OptionalArtifact $index `
        '^sut/implementations/.+/c1-s100-r1/counters-summary\.json$')
    $counterStatus = 'unavailable'; $counterSamples = 0; $counterPath = $null
    if ($counterArtifacts.Count -eq 1) {
        $counterText = Get-ArtifactText $ControllerUri $JobId $counterArtifacts[0] `
            "target_counter_artifact_empty:$CellId"
        $counterDocument = $counterText | ConvertFrom-Json
        $counterSamples = [int]$counterDocument.samples
        if ($counterSamples -gt 0) { $counterStatus = 'captured' }
        $counterPath = Join-Path $DownloadRoot 'target-counters-summary.json'
        $counterText | Set-Content -LiteralPath $counterPath -Encoding utf8
    }

    $summary = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-queued-send-performance-measurement-summary-v1'
        execution_index = $ExecutionIndex; cell_id = $CellId; job_id = $JobId
        accepted_timed_row = $AcceptedTimedRow
        activation_predicate = [pscustomobject][ordered]@{
            predicate_id = 'predicate.queued_send.legal_budget_gt_one'
            observed = ($activationCount -gt 0)
            observation_count = $activationCount
        }
        benchmark = [pscustomobject][ordered]@{
            requests_per_second = [double]$metrics.requestsPerSecond
            throughput_bytes_per_second = [double]$metrics.throughputBytesPerSecond
            latency_p50_ms = [double]$metrics.latencyP50Ms
            latency_p95_ms = [double]$metrics.latencyP95Ms
            total_requests = [long]$metrics.totalRequests
            successful_requests = [long]$metrics.successfulRequests
            failed_requests = [long]$metrics.failedRequests
            timeout_requests = [long]$metrics.timeoutRequests
            bytes_sent = [long]$metrics.bytesSent; bytes_received = [long]$metrics.bytesReceived
            load_generator_saturation_status = [string]$benchmark.loadToolSaturationStatus
        }
        bounded_aggregate = [pscustomobject][ordered]@{
            epoch_count = $boundedLines.Count; stdout_bytes = $stdoutBytes
            final_epoch = $bounded
        }
        load_process_metrics = $loadSummary
        target_process_metrics = [pscustomobject][ordered]@{
            source = 'adapter_startup_snapshot'; process_id = [long]$targetPid
            working_set_bytes = [long]$targetMemory; cpu_time_seconds = [double]$targetCpu
            runtime_counter_status = $counterStatus
            runtime_counter_sample_count = $counterSamples
        }
        performance_acceptance_authorized = $false
        adaptive_rule_derivation_authorized = $false
        active_behavior_authorized = $false
        production_activation_authorized = $false
    }
    $summaryPath = Join-Path $DownloadRoot 'measurement-summary.json'
    Write-JsonFile $summaryPath $summary
    [pscustomobject][ordered]@{
        artifact_index_path = $ArtifactIndexPath
        downloads = @($resultPath,$stdoutPath,$loadPath,$adapterPath,$counterPath,$summaryPath) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        measurement_summary_path = $summaryPath
        activation_observed = ($activationCount -gt 0)
    }
}

function ConvertTo-PackageReference([object] $Package) {
    [pscustomobject][ordered]@{
        packageId = [string]$Package.packageId
        packageVersion = [string]$Package.packageVersion
        sha256 = [string]$Package.sha256
    }
}

function Assert-CampaignPackageIdentities {
    param(
        [Parameter(Mandatory = $true)][object[]] $PackageIdentities,
        [Parameter(Mandatory = $true)][object[]] $CellBindings,
        [Parameter(Mandatory = $true)][string] $ExpectedVersionPrefix,
        [Parameter(Mandatory = $true)][string] $SourceCommit,
        [Parameter(Mandatory = $true)][string] $ManifestContentSha256
    )

    Assert-Campaign ($PackageIdentities.Count -eq 2 -and
        $CellBindings.Count -eq 2) 'package_identity_count_invalid'
    foreach ($binding in $CellBindings) {
        $cellId = [string]$binding.cell_id
        $matches = @($PackageIdentities | Where-Object {
            [string]$_.cell_id -ceq $cellId })
        Assert-Campaign ($matches.Count -eq 1) `
            "package_identity_cell_invalid:$cellId"
        $identity = $matches[0]
        $reference = $identity.package_ref
        $expectedVersion = "$ExpectedVersionPrefix-$cellId"
        Assert-Campaign (
            [string]$reference.packageId -ceq 'quic-dotnet-raw-dev' -and
            [string]$reference.packageVersion -ceq $expectedVersion -and
            [string]$reference.sha256 -cmatch '^[0-9a-f]{64}$') `
            "package_reference_invalid:$cellId"

        $packagePath = [string]$identity.package_path
        $attestationPath = [string]$identity.package_attestation_path
        Assert-Campaign ((Test-Path -LiteralPath $packagePath -PathType Leaf) -and
            (Test-Path -LiteralPath $attestationPath -PathType Leaf)) `
            "package_resume_artifact_missing:$cellId"
        $actualPackageSha256 = (Get-FileHash -LiteralPath $packagePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Campaign ($actualPackageSha256 -ceq
            [string]$reference.sha256) "package_resume_hash_mismatch:$cellId"

        $attestation = Get-Content -LiteralPath $attestationPath -Raw |
            ConvertFrom-Json -Depth 100
        Assert-Campaign (
            [string]$attestation.schemaVersion -ceq
                'protocol-lab.package-build-attestation.v1' -and
            $attestation.parityEligible -eq $true -and
            $attestation.source.workingTreeClean -eq $true -and
            [string]$attestation.source.commitSha -ceq $SourceCommit -and
            [string]$attestation.package.packageId -ceq
                [string]$reference.packageId -and
            [string]$attestation.package.packageVersion -ceq
                [string]$reference.packageVersion -and
            [string]$attestation.package.sha256 -ceq
                [string]$reference.sha256 -and
            $attestation.package.queuedSendPerformancePackagePathSelected -eq
                $true -and
            [string]$attestation.package.queuedSendPerformanceCampaignId -ceq
                'campaign.queued_send_burst_budget.performance.v1' -and
            [string]$attestation.package.queuedSendPerformanceManifestContentSha256 -ceq
                $ManifestContentSha256 -and
            [string]$attestation.package.queuedSendPerformanceCellId -ceq
                $cellId -and
            [string]$attestation.package.queuedSendPerformanceCellContentSha256 -ceq
                [string]$binding.content_sha256 -and
            [string]$attestation.package.adaptiveRuntimeQueuedSendBurstPolicy -ceq
                [string]$binding.queued_send_burst_budget) `
            "package_resume_attestation_mismatch:$cellId"
    }
}

$control = Read-AdaptiveRuntimeJsonDocument $ControlPath
Assert-Campaign (Test-AdaptiveRuntimeDocumentHash $control) 'queued_campaign_hash_invalid'
$controlSchemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-queued-send-performance-campaign-v1.schema.json'
Assert-Campaign (Test-AdaptiveRuntimeJsonSchema $control $controlSchemaPath) `
    'queued_campaign_schema_invalid'
Assert-Campaign ([string]$control.controller_uri -ceq 'http://10.10.99.176:5088' -and
    [string]$control.package_selection.scenario_id -ceq
        'quic.transport.stream-throughput.1mb' -and
    [string]$control.host_selection.placement_policy -ceq 'isolated-pair' -and
    [string]$control.host_selection.sut_node_id -ceq 'plab-worker-x64-02' -and
    [string]$control.host_selection.load_node_id -ceq 'plab-worker-x64-03' -and
    [string]::Join('|', @($control.selected_cells)) -ceq
        'cell.queued_send_burst_budget.performance.q0|cell.queued_send_burst_budget.performance.q1' -and
    [int]$control.design.block_count -eq 8 -and
    [int]$control.design.repetitions_per_cell -eq 8 -and
    [int]$control.design.total_job_count -eq 16 -and
    $control.measurement_capability_authorized -eq $true -and
    $control.timing_execution_authorized -eq $true -and
    $control.performance_acceptance_authorization -eq $false -and
    $control.adaptive_rule_derivation_authorization -eq $false -and
    $control.active_behavior_authorization -eq $false -and
    $control.production_activation_authorization -eq $false -and
    $control.covering_array_generator_implemented -eq $false -and
    $control.covering_array_required -eq $false) 'queued_campaign_controls_invalid'
Assert-Campaign (@($control.cell_bindings).Count -eq 2 -and
    [string]$control.cell_bindings[0].cell_id -ceq
        'cell.queued_send_burst_budget.performance.q0' -and
    [string]$control.cell_bindings[0].queued_send_burst_budget -ceq
        'legacy_current' -and
    [string]$control.cell_bindings[1].cell_id -ceq
        'cell.queued_send_burst_budget.performance.q1' -and
    [string]$control.cell_bindings[1].queued_send_burst_budget -ceq
        'single_datagram') 'queued_campaign_cell_bindings_invalid'
foreach ($binding in @($control.cell_bindings)) {
    Assert-Campaign (@($binding.adjacent_axes.PSObject.Properties |
        Where-Object { [string]$_.Value -cne 'legacy_current' }).Count -eq 0) `
        "queued_campaign_adjacent_axis_invalid:$($binding.cell_id)"
}

$outputRootFull = Resolve-AbsolutePath $OutputRoot $RepositoryRoot
[void](New-Item -ItemType Directory -Force -Path $outputRootFull)
$manifestPath = Join-Path $outputRootFull 'compiled-manifest.json'
$statePath = Join-Path $outputRootFull 'campaign-state.json'
$nodesPath = Join-Path $outputRootFull 'controller-nodes.json'
$packagesPath = Join-Path $outputRootFull 'package-identities.json'
$preflightPath = Join-Path $outputRootFull 'activation-preflight.json'
$compilerPath = Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeQueuedSendPerformanceCampaign.ps1'
Assert-Campaign (Test-Path -LiteralPath $compilerPath -PathType Leaf) `
    'queued_campaign_compiler_missing'
& $compilerPath -RepositoryRoot $RepositoryRoot -ControlPath $ControlPath `
    -OutputPath $manifestPath | Out-Null
$manifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
Assert-Campaign (Test-AdaptiveRuntimeDocumentHash $manifest) 'queued_manifest_hash_invalid'
Assert-Campaign ([string]$manifest.control_ref.content_sha256 -ceq
    [string]$control.content_sha256 -and @($manifest.planned_runs).Count -eq 16) `
    'queued_manifest_run_count_invalid'

$plan = [pscustomobject][ordered]@{
    mode = if ($Execute) { if ($Resume) { 'resume' } else { 'execute' } }
        else { 'plan_only' }
    output_root = $outputRootFull; compiled_manifest_path = $manifestPath
    compiled_manifest_sha256 = [string]$manifest.content_sha256
    planned_run_count = 16; completed_run_count = 0; failed_attempt_count = 0
    activation_preflight_run_count = 0; actual_measurements_run = 0
}
if (-not [string]::IsNullOrWhiteSpace($ReplayEvidenceJobId)) {
    Assert-Campaign (-not $Execute -and -not $Resume) 'evidence_replay_cannot_execute'
    $replay = Save-CampaignControllerEvidence `
        -ControllerUri ([string]$control.controller_uri) -JobId $ReplayEvidenceJobId `
        -CellId $ReplayEvidenceCellId -ExecutionIndex $ReplayEvidenceExecutionIndex `
        -ArtifactIndexPath (Join-Path $outputRootFull 'replayed-artifact-index.json') `
        -DownloadRoot (Join-Path $outputRootFull 'replayed-evidence') `
        -StdoutMaxBytes ([long]$control.resource_metrics.bounded_server_stdout_max_bytes) `
        -AcceptedTimedRow:($ReplayEvidenceExecutionIndex -gt 0) `
        -RequireActivation:($ReplayEvidenceExecutionIndex -eq 0)
    $result = [pscustomobject][ordered]@{
        mode = 'evidence_replay'; job_id = $ReplayEvidenceJobId
        cell_id = $ReplayEvidenceCellId; execution_index = $ReplayEvidenceExecutionIndex
        measurement_summary_path = [string]$replay.measurement_summary_path
        actual_measurements_run = 0
    }
    if ($PassThru) { $result } else { $result | ConvertTo-Json -Depth 8 }
    return
}
if (-not $Execute) {
    if ($PassThru) { $plan } else { $plan | ConvertTo-Json -Depth 8 }
    return
}

$sourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
Assert-Campaign ($LASTEXITCODE -eq 0 -and $sourceCommit -match '^[0-9a-f]{40}$') `
    'source_commit_unresolved'
$dirty = @(& git -C $RepositoryRoot status --porcelain)
Assert-Campaign ($LASTEXITCODE -eq 0 -and $dirty.Count -eq 0) 'source_tree_not_clean'
$controllerUri = [string]$control.controller_uri
$nodes = @(Invoke-ControllerJson -Uri "$controllerUri/api/lab/nodes" -Method 'GET' |
    ForEach-Object { $_ })
Assert-Campaign ($nodes.Count -gt 0) 'controller_nodes_missing'
Write-JsonFile $nodesPath $nodes
$protocolLabRootFull = Resolve-AbsolutePath $ProtocolLabRoot $RepositoryRoot
$protocolLabExecutionRootFull = if ([string]::IsNullOrWhiteSpace($ProtocolLabExecutionRoot)) {
    $null } else { Resolve-AbsolutePath $ProtocolLabExecutionRoot $RepositoryRoot }
$componentRefs = @($control.package_selection.component_package_references |
    ForEach-Object { '{0}|{1}|{2}' -f $_.package_id,$_.package_version,$_.sha256 })
$packageVersionPrefix = 'adaptive-runtime-queued-send-{0}-{1}' -f
    ([string]$control.content_sha256).Substring(0,8),$sourceCommit.Substring(0,8)

if ($Resume) {
    Assert-Campaign ((Test-Path $statePath -PathType Leaf) -and
        (Test-Path $packagesPath -PathType Leaf) -and
        (Test-Path $preflightPath -PathType Leaf)) 'resume_state_missing'
    $state = Get-Content $statePath -Raw | ConvertFrom-Json -Depth 100
    $packageIdentities = @(Get-Content $packagesPath -Raw | ConvertFrom-Json -Depth 100)
    $preflight = Get-Content $preflightPath -Raw | ConvertFrom-Json -Depth 100
    Assert-Campaign ([string]$state.source_commit -ceq $sourceCommit -and
        [string]$state.control_sha256 -ceq [string]$control.content_sha256 -and
        [string]$state.manifest_sha256 -ceq [string]$manifest.content_sha256 -and
        $packageIdentities.Count -eq 2 -and $preflight.activation_observed -eq $true) `
        'resume_identity_mismatch'
    Assert-CampaignPackageIdentities `
        -PackageIdentities $packageIdentities `
        -CellBindings @($control.cell_bindings) `
        -ExpectedVersionPrefix $packageVersionPrefix `
        -SourceCommit $sourceCommit `
        -ManifestContentSha256 ([string]$manifest.content_sha256)
    $attempts = [Collections.Generic.List[object]]::new()
    foreach ($attempt in @($state.attempts)) { [void]$attempts.Add($attempt) }
}
else {
    Assert-Campaign (-not (Test-Path $statePath)) 'campaign_state_already_exists'
    $packageIdentities = [Collections.Generic.List[object]]::new()
    $attempts = [Collections.Generic.List[object]]::new()
    foreach ($binding in @($control.cell_bindings)) {
        $cellId = [string]$binding.cell_id
        $packageResult = & (Join-Path $PSScriptRoot `
            '..\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1') `
            -PackageTarget RawQuic -ProtocolLabRoot $protocolLabRootFull `
            -Project 'eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj' `
            -Configuration Release -RuntimeIdentifier @('linux-x64') `
            -PackageVersion "$packageVersionPrefix-$cellId" `
            -AdaptiveRuntimeQueuedSendBurstPolicy ([string]$binding.queued_send_burst_budget) `
            -AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256 `
                ([string]$manifest.content_sha256) -Force -AllowDirtySource:$false |
                ConvertFrom-Json
        Assert-Campaign ($null -ne $packageResult -and
            [string]$packageResult.sha256 -match '^[0-9a-f]{64}$') `
            "package_identity_missing:$cellId"
        $packageRef = ConvertTo-PackageReference $packageResult
        $uploaded = Publish-CampaignPackage $controllerUri ([string]$packageResult.path)
        Assert-Campaign ([string]$uploaded.packageId -ceq [string]$packageRef.packageId -and
            [string]$uploaded.packageVersion -ceq [string]$packageRef.packageVersion -and
            [string]$uploaded.sha256 -ceq [string]$packageRef.sha256) `
            "uploaded_package_identity_mismatch:$cellId"
        [void]$packageIdentities.Add([pscustomobject][ordered]@{
            cell_id = $cellId; package_ref = $packageRef
            package_path = [string]$packageResult.path
            package_attestation_path = [string]$packageResult.buildAttestationPath
        })
    }
    Assert-CampaignPackageIdentities `
        -PackageIdentities @($packageIdentities) `
        -CellBindings @($control.cell_bindings) `
        -ExpectedVersionPrefix $packageVersionPrefix `
        -SourceCommit $sourceCommit `
        -ManifestContentSha256 ([string]$manifest.content_sha256)
    Write-JsonFile $packagesPath @($packageIdentities)

    $q1Package = @($packageIdentities | Where-Object {
        [string]$_.cell_id -ceq
            'cell.queued_send_burst_budget.performance.q1' })
    Assert-Campaign ($q1Package.Count -eq 1) 'q1_preflight_package_missing'
    $priorPreflightAttempts = @()
    if (Test-Path -LiteralPath $preflightPath -PathType Leaf) {
        $priorPreflightAttempts = @((Get-Content -LiteralPath $preflightPath -Raw |
            ConvertFrom-Json -Depth 100).attempts)
    }
    $preflightAttemptIndex = $priorPreflightAttempts.Count + 1
    $preflightRoot = Join-Path $outputRootFull (
        'activation-preflight\attempt-{0:D2}' -f $preflightAttemptIndex)
    $preflightArgs = @{
        ControllerUri=$controllerUri; PackageTarget='RawQuic'
        ProtocolLabRoot=$protocolLabRootFull; ScenarioId='quic.transport.stream-throughput.1mb'
        Protocol='quic'; TestExecutorId='quic-go-raw-load'
        LoadProfileId=[string]$control.package_selection.load_profile_id
        Repetitions=1; PlacementPolicy='isolated-pair'
        PackageVersion=[string]$q1Package[0].package_ref.packageVersion
        RunIdPrefix="queued-activation-$($manifest.document_id)"; ResultRoot=$preflightRoot
        TimeoutSeconds=3600; UsePackageReferenceOnly=$true
        RequiredCapability=@('evidenceTier=offline-ml-two-host-vm')
        PackageReference=@(('{0}|{1}|{2}' -f
            $q1Package[0].package_ref.packageId,$q1Package[0].package_ref.packageVersion,
            $q1Package[0].package_ref.sha256)) + $componentRefs
        AdaptiveRuntimeQueuedSendBurstPolicy='single_datagram'
        AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256=
            [string]$manifest.content_sha256
    }
    if ($null -ne $protocolLabExecutionRootFull) {
        $preflightArgs.ProtocolLabExecutionRoot = $protocolLabExecutionRootFull
    }
    $preflightAttempt = [ordered]@{
        attempt_index = $preflightAttemptIndex
        cell_id = 'cell.queued_send_burst_budget.performance.q1'
        package_ref = $q1Package[0].package_ref
        job_id = $null; run_id = $null; topology = $null
        outcome = 'submitted'; failure_reason_code = $null
        measurement_summary_path = $null; activation_observed = $false
        accepted_timed_row = $false
    }
    try {
        $preflightRun = & (Join-Path $PSScriptRoot `
            '..\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1') @preflightArgs |
            ConvertFrom-Json
        $preflightAttempt.job_id = [string]$preflightRun.job.jobId
        $preflightAttempt.run_id = [string]$preflightRun.job.result.runId
        $preflightAttempt.topology = Get-CampaignTopology $preflightRun.job $nodes
        $preflightAttempt.outcome = [string]$preflightRun.job.status
        $preflightAttempt.failure_reason_code =
            [string]$preflightRun.job.result.failureReasonCode
        Assert-Campaign ([string]$preflightAttempt.outcome -ceq 'Completed' -and
            [string]$preflightAttempt.topology.classification -ceq
                'independent_physical_hosts' -and
            [string]$preflightAttempt.topology.sutNodeId -ceq
                'plab-worker-x64-02' -and
            [string]$preflightAttempt.topology.loadNodeId -ceq
                'plab-worker-x64-03') `
            'queued_activation_preflight_job_or_topology_invalid'
        $preflightEvidence = Save-CampaignControllerEvidence `
            -ControllerUri $controllerUri `
            -JobId ([string]$preflightAttempt.job_id) `
            -CellId 'cell.queued_send_burst_budget.performance.q1' `
            -ExecutionIndex 0 `
            -ArtifactIndexPath (Join-Path $preflightRoot `
                'controller-artifact-index.json') `
            -DownloadRoot (Join-Path $preflightRoot 'downloads') `
            -StdoutMaxBytes (
                [long]$control.resource_metrics.bounded_server_stdout_max_bytes) `
            -AcceptedTimedRow:$false -RequireActivation
        $preflightAttempt.measurement_summary_path =
            [string]$preflightEvidence.measurement_summary_path
        $preflightAttempt.activation_observed =
            [bool]$preflightEvidence.activation_observed
    }
    catch {
        if ([string]$preflightAttempt.outcome -ceq 'Completed') {
            $preflightAttempt.outcome = 'failed_evidence_validation'
        } elseif ([string]$preflightAttempt.outcome -ceq 'submitted') {
            $preflightAttempt.outcome = 'failed'
        }
        $preflightAttempt.failure_reason_code = $_.Exception.Message
        Write-JsonFile $preflightPath ([pscustomobject][ordered]@{
            predicate_id = 'predicate.queued_send.legal_budget_gt_one'
            cell_id = 'cell.queued_send_burst_budget.performance.q1'
            job_id = [string]$preflightAttempt.job_id
            run_id = [string]$preflightAttempt.run_id
            topology = $preflightAttempt.topology; activation_observed = $false
            accepted_timed_row = $false
            attempts = @($priorPreflightAttempts) + @([pscustomobject]$preflightAttempt)
            performance_acceptance_authorization = $false
            adaptive_rule_derivation_authorization = $false
            active_behavior_authorization = $false
            production_activation_authorization = $false
        })
        throw
    }
    Write-JsonFile $preflightPath ([pscustomobject][ordered]@{
        predicate_id = 'predicate.queued_send.legal_budget_gt_one'
        cell_id = 'cell.queued_send_burst_budget.performance.q1'
        job_id = [string]$preflightAttempt.job_id
        run_id = [string]$preflightAttempt.run_id
        topology = $preflightAttempt.topology; activation_observed = $true
        accepted_timed_row = $false
        attempts = @($priorPreflightAttempts) + @([pscustomobject]$preflightAttempt)
        performance_acceptance_authorization = $false
        adaptive_rule_derivation_authorization = $false
        active_behavior_authorization = $false
        production_activation_authorization = $false
    })
}

function Write-CampaignState {
    $completed = @($attempts | Where-Object outcome -CEQ 'Completed' |
        ForEach-Object execution_index | Sort-Object -Unique)
    $failed = @($attempts | Where-Object outcome -CNE 'Completed')
    Write-JsonFile $statePath ([pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-queued-send-performance-state-v1'
        control_sha256 = [string]$control.content_sha256
        manifest_sha256 = [string]$manifest.content_sha256
        source_commit = $sourceCommit; source_dirty_state = 'clean'
        controller_uri = $controllerUri; nodes_path = $nodesPath
        packages_path = $packagesPath; activation_preflight_path = $preflightPath
        planned_run_count = 16; completed_run_count = $completed.Count
        failed_attempt_count = $failed.Count; attempts = @($attempts)
        performance_acceptance_authorization = $false
        adaptive_rule_derivation_authorization = $false
        active_behavior_authorization = $false
        production_activation_authorization = $false
    })
}

Write-CampaignState
foreach ($plannedRun in @($manifest.planned_runs | Sort-Object execution_index)) {
    $completedCount = @($attempts | Where-Object outcome -CEQ 'Completed' |
        ForEach-Object execution_index | Sort-Object -Unique).Count
    if ($completedCount -ge $StopAfterCompletedRunCount) { break }
    if (@($attempts | Where-Object { [int]$_.execution_index -eq
        [int]$plannedRun.execution_index -and [string]$_.outcome -ceq 'Completed' }).Count -gt 0) {
        continue
    }
    $cellId = [string]$plannedRun.cell_id
    $cellLabel = $cellId.Split('.')[-1]
    $package = @($packageIdentities | Where-Object cell_id -CEQ $cellId)
    Assert-Campaign ($package.Count -eq 1) "package_identity_invalid:$cellId"
    $executionIndex = [int]$plannedRun.execution_index
    $runName = '{0:D2}-b{1:D2}-p{2:D2}-{3}' -f $executionIndex,
        [int]$plannedRun.block_index,[int]$plannedRun.position_index,$cellLabel
    $runRoot = Join-Path $outputRootFull "runs\$runName"
    [void](New-Item -ItemType Directory -Force -Path $runRoot)
    $runArgs = @{
        ControllerUri=$controllerUri; PackageTarget='RawQuic'; ProtocolLabRoot=$protocolLabRootFull
        ScenarioId='quic.transport.stream-throughput.1mb'; Protocol='quic'
        TestExecutorId='quic-go-raw-load'; LoadProfileId=[string]$control.package_selection.load_profile_id
        Repetitions=1; PlacementPolicy='isolated-pair'
        PackageVersion=[string]$package[0].package_ref.packageVersion
        RunIdPrefix=('queued-b{0:D2}-p{1:D2}-{2}-{3}' -f
            [int]$plannedRun.block_index,[int]$plannedRun.position_index,$cellLabel,$manifest.document_id)
        ResultRoot=$runRoot; TimeoutSeconds=3600; UsePackageReferenceOnly=$true
        RequiredCapability=@('evidenceTier=offline-ml-two-host-vm')
        PackageReference=@(('{0}|{1}|{2}' -f $package[0].package_ref.packageId,
            $package[0].package_ref.packageVersion,$package[0].package_ref.sha256)) + $componentRefs
        AdaptiveRuntimeQueuedSendBurstPolicy=[string]$plannedRun.policy_controls.queued_send_burst_budget
        AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256=
            [string]$manifest.content_sha256
    }
    if ($null -ne $protocolLabExecutionRootFull) {
        $runArgs.ProtocolLabExecutionRoot = $protocolLabExecutionRootFull
    }
    $attempt = [ordered]@{
        execution_index=$executionIndex; block_index=[int]$plannedRun.block_index
        position_index=[int]$plannedRun.position_index; cell_id=$cellId
        attempt_index=@($attempts | Where-Object { [int]$_.execution_index -eq $executionIndex }).Count + 1
        package_ref=$package[0].package_ref; job_id=$null; run_id=$null; topology=$null
        outcome='submitted'; failure_reason_code=$null
        controller_artifact_index_path=$null; controller_artifact_downloads=@()
        measurement_summary_path=$null
    }
    try {
        $run = & (Join-Path $PSScriptRoot `
            '..\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1') @runArgs |
            ConvertFrom-Json
        Write-JsonFile (Join-Path $runRoot 'run-manifest.json') $run
        Write-JsonFile (Join-Path $runRoot 'job-result.json') $run.job
        $attempt.job_id=[string]$run.job.jobId; $attempt.run_id=[string]$run.job.result.runId
        $attempt.topology=Get-CampaignTopology $run.job $nodes
        $attempt.outcome=[string]$run.job.status
        $attempt.failure_reason_code=[string]$run.job.result.failureReasonCode
        Assert-Campaign ([string]$attempt.outcome -ceq 'Completed') `
            "queued_job_failed:${executionIndex}:${cellId}:$($attempt.job_id):$($attempt.failure_reason_code)"
        Assert-Campaign ([string]$attempt.topology.classification -ceq 'independent_physical_hosts' -and
            [string]$attempt.topology.sutNodeId -ceq 'plab-worker-x64-02' -and
            [string]$attempt.topology.loadNodeId -ceq 'plab-worker-x64-03') `
            "queued_topology_not_credible:${executionIndex}:${cellId}"
        $evidence = Save-CampaignControllerEvidence -ControllerUri $controllerUri `
            -JobId ([string]$attempt.job_id) -CellId $cellId -ExecutionIndex $executionIndex `
            -ArtifactIndexPath (Join-Path $runRoot 'controller-artifact-index.json') `
            -DownloadRoot (Join-Path $runRoot 'downloads') `
            -StdoutMaxBytes ([long]$control.resource_metrics.bounded_server_stdout_max_bytes) `
            -AcceptedTimedRow:$true
        $attempt.controller_artifact_index_path=[string]$evidence.artifact_index_path
        $attempt.controller_artifact_downloads=@($evidence.downloads)
        $attempt.measurement_summary_path=[string]$evidence.measurement_summary_path
    }
    catch {
        if ([string]$attempt.outcome -ceq 'Completed') { $attempt.outcome='failed_evidence_validation' }
        elseif ([string]$attempt.outcome -ceq 'submitted') { $attempt.outcome='failed' }
        $attempt.failure_reason_code=$_.Exception.Message
        [void]$attempts.Add([pscustomobject]$attempt); Write-CampaignState; throw
    }
    [void]$attempts.Add([pscustomobject]$attempt); Write-CampaignState
}

$completedRunCount = @($attempts | Where-Object outcome -CEQ 'Completed' |
    ForEach-Object execution_index | Sort-Object -Unique).Count
if ($StopAfterCompletedRunCount -eq 16) {
    Assert-Campaign ($completedRunCount -eq 16) 'queued_campaign_incomplete'
}
$result = [pscustomobject][ordered]@{
    mode = if ($Resume) { 'resume' } else { 'execute' }
    campaign_status = if ($completedRunCount -eq 16) { 'complete' } else { 'operator_paused' }
    output_root=$outputRootFull; compiled_manifest_path=$manifestPath
    compiled_manifest_sha256=[string]$manifest.content_sha256; state_path=$statePath
    activation_preflight_path=$preflightPath; activation_preflight_run_count=1
    planned_run_count=16; completed_run_count=$completedRunCount
    failed_attempt_count=@($attempts | Where-Object outcome -CNE 'Completed').Count
    actual_measurements_run=$completedRunCount
    performance_acceptance_authorization=$false
    adaptive_rule_derivation_authorization=$false
    active_behavior_authorization=$false
    production_activation_authorization=$false
}
if ($PassThru) { $result } else { $result | ConvertTo-Json -Depth 12 }
