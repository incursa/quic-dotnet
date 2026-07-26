# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceRoot,
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $ManifestPath = (Join-Path $EvidenceRoot `
        'compiled-manifest.json'),
    [string] $OutputPath = (Join-Path $EvidenceRoot `
        'performance-projection.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-ProjectionCondition([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function New-DocumentReference([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [long]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

$resolvedEvidenceRoot = (Resolve-Path $EvidenceRoot).Path
$rawPaths = @(Get-ChildItem (Join-Path $resolvedEvidenceRoot 'raw') `
    -Filter '*.json' -File | Sort-Object Name | ForEach-Object FullName)
Assert-ProjectionCondition ($rawPaths.Count -gt 0) `
    'performance_projection_raw_evidence_missing'

$validation = & (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1') `
    -CampaignPath $CampaignPath `
    -ManifestPath $ManifestPath `
    -RawEvidencePath ([string[]]$rawPaths) `
    -RepositoryRoot $RepositoryRoot `
    -PassThru
$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
$manifest = Read-AdaptiveRuntimeJsonDocument $ManifestPath
$catalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v2.json')
Assert-ProjectionCondition (Test-AdaptiveRuntimeDocumentHash $catalog) `
    'performance_projection_catalog_hash_mismatch'

$classificationsByPath = @{}
foreach ($classification in @($validation.classifications)) {
    $classificationsByPath[
        [IO.Path]::GetFullPath([string]$classification.path)] =
            [string]$classification.classification
}

$rawRefs = [Collections.Generic.List[object]]::new()
$behaviorAggregates = [Collections.Generic.List[object]]::new()
$outcomeAggregates = [Collections.Generic.List[object]]::new()
$metrics = [Collections.Generic.List[object]]::new()
$classifications = [Collections.Generic.List[object]]::new()

foreach ($path in $rawPaths) {
    $raw = Read-AdaptiveRuntimeJsonDocument $path
    $runId = ('run.{0}.{1}.b{2}.{3}' -f
        ([string]$raw.split).ToLowerInvariant(),
        ([string]$raw.workloadId).ToLowerInvariant(),
        [long]$raw.block,
        ([string]$raw.cellId).ToLowerInvariant())
    $classification = $classificationsByPath[[IO.Path]::GetFullPath($path)]
    Assert-ProjectionCondition (
        -not [string]::IsNullOrWhiteSpace($classification)
    ) 'performance_projection_classification_missing'
    [void]$rawRefs.Add([pscustomobject][ordered]@{
        run_id = $runId
        relative_path = [IO.Path]::GetRelativePath(
            $resolvedEvidenceRoot,
            $path).Replace('\', '/')
        content_sha256 = (Get-FileHash $path -Algorithm SHA256).
            Hash.ToLowerInvariant()
        workload_id = [string]$raw.workloadId
        split = [string]$raw.split
        cell_id = [string]$raw.cellId
        block = [long]$raw.block
        classification = $classification
    })

    foreach ($event in @($raw.mechanismEventCounts |
        Sort-Object axisId, mechanismEventId)) {
        $definition = @($catalog.effective_behaviors |
            Where-Object {
                [string]$_.axis_id -ceq [string]$event.axisId -and
                @($_.mechanism_event_ids) -ccontains
                    [string]$event.mechanismEventId
            })
        Assert-ProjectionCondition ($definition.Count -eq 1) `
            'performance_projection_behavior_derivation_invalid'
        [void]$behaviorAggregates.Add([pscustomobject][ordered]@{
            run_id = $runId
            axis_id = [string]$event.axisId
            effective_behavior_id =
                [string]$definition[0].effective_behavior_id
            operation_count = [long]$event.operationCount
            work_amount = [long]$event.workAmount
        })
    }
    foreach ($result in @($raw.operationResultCounts |
        Sort-Object axisId, resultKind)) {
        $definition = @($catalog.outcome_definitions |
            Where-Object {
                @($_.result_kinds) -ccontains [string]$result.resultKind
            })
        Assert-ProjectionCondition ($definition.Count -eq 1) `
            'performance_projection_outcome_derivation_invalid'
        [void]$outcomeAggregates.Add([pscustomobject][ordered]@{
            run_id = $runId
            axis_id = [string]$result.axisId
            outcome_id = [string]$definition[0].outcome_id
            operation_count = [long]$result.operationCount
            requires_retained_classification =
                [bool]$definition[0].requires_retained_classification
        })
    }

    $metricValues = [ordered]@{
        'metric.performance.useful_bytes_per_second' =
            @([double]$raw.sample.usefulBytesPerSecond, 'bytes_per_second')
        'metric.performance.operations_per_second' =
            @([double]$raw.sample.operationsPerSecond, 'operations_per_second')
        'metric.guardrail.latency_p95' =
            @([double]$raw.sample.latencyP95Milliseconds, 'milliseconds')
        'metric.guardrail.cpu_per_operation' =
            @([double]$raw.sample.cpuMicrosecondsPerOperation, 'microseconds')
        'metric.guardrail.allocated_bytes_per_operation' =
            @([double]$raw.sample.allocatedBytesPerOperation, 'bytes')
        'metric.guardrail.jain_fairness' =
            @([double]$raw.sample.jainFairness, 'ratio')
        'metric.mechanism.copied_bytes' =
            @([double]$raw.sample.evidence.copiedBytes, 'bytes')
        'metric.mechanism.retained_bytes' =
            @([double]$raw.sample.evidence.retainedBytes, 'bytes')
    }
    foreach ($entry in $metricValues.GetEnumerator()) {
        [void]$metrics.Add([pscustomobject][ordered]@{
            run_id = $runId
            metric_id = [string]$entry.Key
            value = [double]$entry.Value[0]
            unit = [string]$entry.Value[1]
        })
    }
    [void]$classifications.Add([pscustomobject][ordered]@{
        run_id = $runId
        classification = $classification
        retained = $true
        reason_code = "reason.performance.$classification"
    })
}

$orderedBehavior = @($behaviorAggregates |
    Sort-Object run_id, axis_id, effective_behavior_id)
$orderedOutcomes = @($outcomeAggregates |
    Sort-Object run_id, axis_id, outcome_id)
$behaviorHash = Get-AdaptiveRuntimeSha256 (
    ConvertTo-AdaptiveRuntimeCanonicalJson $orderedBehavior)
$outcomeHash = Get-AdaptiveRuntimeSha256 (
    ConvertTo-AdaptiveRuntimeCanonicalJson $orderedOutcomes)

$projection = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-composition-performance-projection-v1'
    document_id = "projection.send_composition.performance.$(
        ([string]$manifest.source_commit).Substring(0,12))"
    document_version = 1
    content_sha256 = '0' * 64
    campaign_ref = New-DocumentReference $campaign
    manifest_ref = New-DocumentReference $manifest
    behavior_catalog_ref = New-DocumentReference $catalog
    raw_evidence_refs = @($rawRefs | Sort-Object run_id)
    behavior_aggregates = $orderedBehavior
    outcome_aggregates = $orderedOutcomes
    metric_observations = @($metrics | Sort-Object run_id, metric_id)
    classifications = @($classifications | Sort-Object run_id)
    behavior_materialization_sha256 = $behaviorHash
    outcome_materialization_sha256 = $outcomeHash
    all_operations_accounted = $true
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    production_activation_authorization = $false
    trace_references = $campaign.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $projection)
Assert-ProjectionCondition (
    Test-AdaptiveRuntimeJsonSchema $projection (
        Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-send-composition-performance-projection-v1.schema.json')
) 'performance_projection_schema_invalid'
Assert-ProjectionCondition (
    Test-AdaptiveRuntimeDocumentHash $projection
) 'performance_projection_hash_mismatch'
Write-AdaptiveRuntimeCanonicalDocument $projection $OutputPath

if ($PassThru) {
    $projection
}
else {
    [pscustomobject][ordered]@{
        projection_path = [IO.Path]::GetFullPath($OutputPath)
        projection_sha256 = [string]$projection.content_sha256
        behavior_materialization_sha256 = $behaviorHash
        outcome_materialization_sha256 = $outcomeHash
        run_count = @($rawRefs).Count
    } | ConvertTo-Json -Depth 6
}
