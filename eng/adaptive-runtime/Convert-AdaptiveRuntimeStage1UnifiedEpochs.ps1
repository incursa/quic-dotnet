# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RawEpochPath,

    [Parameter(Mandatory = $true)]
    [string] $RawExportManifestPath,

    [Parameter(Mandatory = $true)]
    [string] $LocalResultPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

$unifiedSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-unified-epoch-v1.schema.json'
$decisionSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-axis-decision-v1.schema.json'
$manifestSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-unified-materialization-manifest-v1.schema.json'
$validatorPath = Join-Path $RepositoryRoot 'eng\adaptive-runtime\Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1'
$resolvedRawEpochPath = (Resolve-Path -LiteralPath $RawEpochPath).Path
$resolvedRawManifestPath = (Resolve-Path -LiteralPath $RawExportManifestPath).Path
$resolvedLocalResultPath = (Resolve-Path -LiteralPath $LocalResultPath).Path
$resolvedOutputDirectory = Resolve-AdaptiveRuntimePath -Path $OutputDirectory
$unifiedPath = Join-Path $resolvedOutputDirectory 'stage1-unified-epochs.jsonl'
$decisionPath = Join-Path $resolvedOutputDirectory 'stage1-axis-decisions.jsonl'
$validationPath = Join-Path $resolvedOutputDirectory 'unified-validation-summary.json'
$manifestPath = Join-Path $resolvedOutputDirectory 'unified-materialization-manifest.json'

foreach ($path in @($unifiedPath, $decisionPath, $validationPath, $manifestPath)) {
    if (Test-Path -LiteralPath $path) {
        throw "Append-only output path already exists: $path"
    }
}

$rawManifest = Get-Content -LiteralPath $resolvedRawManifestPath -Raw |
    ConvertFrom-Json -Depth 100
$localResult = Get-Content -LiteralPath $resolvedLocalResultPath -Raw |
    ConvertFrom-Json -Depth 100
$rawLines = @(
    Get-Content -LiteralPath $resolvedRawEpochPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)
if ($rawLines.Count -ne [int] $rawManifest.rowCount) {
    throw "Raw row count '$($rawLines.Count)' does not match export manifest '$($rawManifest.rowCount)'."
}

$samplesById = @{}
foreach ($sample in $localResult.samples) {
    $samplesById[[string] $sample.sampleId] = $sample
}

$sourceAssignments = [System.Collections.Generic.List[object]]::new()
foreach ($source in $rawManifest.sources) {
    $sampleId = Split-Path -Leaf (Split-Path -Parent ([string] $source.path))
    if (-not $samplesById.ContainsKey($sampleId)) {
        throw "Raw source '$($source.path)' does not resolve to a local-result sample."
    }

    for ($index = 0; $index -lt [int] $source.rowCount; $index++) {
        [void] $sourceAssignments.Add([pscustomobject]@{
            SampleId = $sampleId
            SourcePath = [string] $source.path
            SourceSha256 = [string] $source.sha256
        })
    }
}

if ($sourceAssignments.Count -ne $rawLines.Count) {
    throw "Raw source assignments '$($sourceAssignments.Count)' do not match row count '$($rawLines.Count)'."
}

$repositoryIdentity = @(
    $localResult.repositoryIdentities |
        Where-Object { [string] $_.name -eq 'quic-dotnet' }
) | Select-Object -First 1
$benchmarkAssembly = @(
    $localResult.binaryProvenance.assemblies |
        Where-Object { [string] $_.role -eq 'candidate_benchmark' }
) | Select-Object -First 1
$runtimeAssembly = @(
    $localResult.binaryProvenance.assemblies |
        Where-Object { [string] $_.role -eq 'candidate_runtime' }
) | Select-Object -First 1
if ($null -eq $repositoryIdentity -or
    $null -eq $benchmarkAssembly -or
    $null -eq $runtimeAssembly) {
    throw 'Local result does not contain the required repository and binary provenance.'
}

$axisDefinitions = @(
    [pscustomobject]@{
        Property = 'applicationSendTurnPlanning'
        AxisId = 'application_send_turn_planning'
    },
    [pscustomobject]@{
        Property = 'applicationSendBatchFormation'
        AxisId = 'application_send_batch_formation'
    },
    [pscustomobject]@{
        Property = 'queuedSendBurstBudget'
        AxisId = 'queued_send_burst_budget'
    },
    [pscustomobject]@{
        Property = 'oversizedWriteAdmissionQuantum'
        AxisId = 'oversized_write_admission_quantum'
    }
)

function Convert-PolicyValue {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacyCurrent' { 'legacy_current' }
        'Conservative' { 'conservative' }
        'SingleEligible' { 'single_eligible' }
        'SingleDatagram' { 'single_datagram' }
        'SingleFragment' { 'single_fragment' }
        'BoundedMultiFragment' { 'bounded_multi_fragment' }
        default { throw "Unknown Stage 1 policy value '$Value'." }
    }
}

function Convert-SelectionSource {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacySelector' { 'legacy_selector' }
        'Forced' { 'forced' }
        'ShadowRule' { 'shadow_rule' }
        'Fallback' { 'fallback' }
        'SafetyOverride' { 'safety_override' }
        default { throw "Unknown Stage 1 selection source '$Value'." }
    }
}

function Convert-Boundary {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'ActorTurn' { 'actor_turn' }
        'PacketPlan' { 'packet_plan' }
        'LogicalWriteAdmission' { 'logical_write_admission' }
        default { throw "Unknown Stage 1 decision boundary '$Value'." }
    }
}

function Convert-Lifetime {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'ActorTurn' { 'actor_turn' }
        'PacketPlan' { 'packet_plan' }
        'LogicalWrite' { 'logical_write' }
        default { throw "Unknown Stage 1 latch lifetime '$Value'." }
    }
}

function Convert-LatchState {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'Unlatched' { 'unlatched' }
        'Latched' { 'latched' }
        'Completed' { 'completed' }
        'Fallback' { 'fallback' }
        'Terminal' { 'terminal' }
        default { throw "Unknown Stage 1 latch state '$Value'." }
    }
}

function Convert-FallbackState {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'NotRequired' { 'not_required' }
        'Eligible' { 'eligible' }
        'Applied' { 'applied' }
        'Terminal' { 'terminal' }
        default { throw "Unknown Stage 1 fallback state '$Value'." }
    }
}

function Convert-SafetyReason {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ($Value -eq 'None') {
        return $null
    }

    switch ($Value) {
        'MissingSignal' { 'missing_signal' }
        'StaleSignal' { 'stale_signal' }
        'Saturated' { 'saturated' }
        'Contradictory' { 'contradictory' }
        'OutOfDomain' { 'out_of_domain' }
        'Recovery' { 'recovery' }
        'Congestion' { 'congestion' }
        'Pacing' { 'pacing' }
        'FlowControl' { 'flow_control' }
        'Resource' { 'resource' }
        'Cancellation' { 'cancellation' }
        'Disposal' { 'disposal' }
        'Terminal' { 'terminal' }
        default { throw "Unknown Stage 1 safety reason '$Value'." }
    }
}

function Convert-OutcomeScope {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'Epoch' { 'epoch' }
        'Operation' { 'operation' }
        'Plan' { 'plan' }
        'ActorTurn' { 'actor_turn' }
        default { throw "Unknown Stage 1 outcome scope '$Value'." }
    }
}

function Test-ValidityFlag {
    param(
        [Parameter(Mandatory = $true)][string] $Validity,
        [Parameter(Mandatory = $true)][string] $Flag
    )

    return @($Validity -split ',\s*') -contains $Flag
}

function Convert-AxisRecord {
    param(
        [Parameter(Mandatory = $true)][object] $RawRecord,
        [Parameter(Mandatory = $true)][string] $AxisId
    )

    $decision = $RawRecord.decision
    $validity = [string] $decision.validity
    $safetyReason = Convert-SafetyReason -Value ([string] $decision.safetyOverrideReason)
    return [ordered]@{
        axisId = $AxisId
        observationContractVersion = [string] $decision.observationContractVersion
        ruleVersion = [string] $decision.ruleVersion
        snapshotVersion = [string] $decision.snapshotVersion
        reasonVersion = [string] $decision.reasonVersion
        provenanceVersion = [string] $decision.provenanceVersion
        decisionSequence = [ulong] $decision.decisionSequence
        observationValues = [ordered]@{
            queuedApplicationWrites = $RawRecord.observationValues.queuedApplicationWrites
            outboundBacklogBytes = $RawRecord.observationValues.outboundBacklogBytes
            distinctQueuedSendStreams = $RawRecord.observationValues.distinctQueuedSendStreams
            oldestQueuedSendAgeMicros = $RawRecord.observationValues.oldestQueuedSendAgeMicros
            queueDelayEwmaMicros = $RawRecord.observationValues.queueDelayEwmaMicros
            actorServiceTimeEwmaMicros = $RawRecord.observationValues.actorServiceTimeEwmaMicros
            maximumPayloadBytes = $RawRecord.observationValues.maximumPayloadBytes
            eligibleWriteCount = $RawRecord.observationValues.eligibleWriteCount
            eligibleWriteBytes = $RawRecord.observationValues.eligibleWriteBytes
            legalMaximumDatagrams = $RawRecord.observationValues.legalMaximumDatagrams
            configuredMaximumDatagrams = $RawRecord.observationValues.configuredMaximumDatagrams
            burstLimitHits = $RawRecord.observationValues.burstLimitHits
            logicalWriteRemainingBytes = $RawRecord.observationValues.logicalWriteRemainingBytes
            maximumChunkBytes = $RawRecord.observationValues.maximumChunkBytes
            retainedSendBuffers = $RawRecord.observationValues.retainedSendBuffers
            retainedSendBytes = $RawRecord.observationValues.retainedSendBytes
            bytesInFlight = $RawRecord.observationValues.bytesInFlight
            congestionWindowBytes = $RawRecord.observationValues.congestionWindowBytes
            handshakeConfirmed = $RawRecord.observationValues.handshakeConfirmed
            cancellationRequested = $RawRecord.observationValues.cancellationRequested
            disposalStarted = $RawRecord.observationValues.disposalStarted
            terminalStarted = $RawRecord.observationValues.terminalStarted
        }
        validity = [ordered]@{
            missing = Test-ValidityFlag -Validity $validity -Flag 'Missing'
            stale = Test-ValidityFlag -Validity $validity -Flag 'Stale'
            saturated = Test-ValidityFlag -Validity $validity -Flag 'Saturated'
            contradictory = Test-ValidityFlag -Validity $validity -Flag 'Contradictory'
            outOfDomain = Test-ValidityFlag -Validity $validity -Flag 'OutOfDomain'
        }
        forcedValue = if ([bool] $decision.hasForcedValue) {
            Convert-PolicyValue -Value ([string] $decision.forcedValue)
        } else { $null }
        shadowRecommendation = if ([bool] $decision.hasShadowRecommendation) {
            Convert-PolicyValue -Value ([string] $decision.shadowRecommendation)
        } else { $null }
        selectedValue = Convert-PolicyValue -Value ([string] $decision.selectedValue)
        appliedValue = Convert-PolicyValue -Value ([string] $decision.appliedValue)
        selectionSource = Convert-SelectionSource -Value ([string] $decision.selectionSource)
        reasonCode = "code_$([int] $decision.reasonCode)"
        safetyOverride = [ordered]@{
            applied = $null -ne $safetyReason
            reasonCode = $safetyReason
        }
        decisionBoundary = Convert-Boundary -Value ([string] $decision.decisionBoundary)
        latch = [ordered]@{
            lifetime = Convert-Lifetime -Value ([string] $decision.latchLifetime)
            state = Convert-LatchState -Value ([string] $decision.latchState)
            sequence = [ulong] $decision.latchSequence
            operationKey = $null
            planKey = $null
        }
        fallbackState = Convert-FallbackState -Value ([string] $decision.fallbackState)
        outcomes = [ordered]@{
            scope = Convert-OutcomeScope -Value ([string] $RawRecord.outcomes.scope)
            selectedWriteCount = $RawRecord.outcomes.selectedWriteCount
            selectedPayloadBytes = $RawRecord.outcomes.selectedPayloadBytes
            appliedDatagramCap = $RawRecord.outcomes.appliedDatagramCap
            emittedDatagrams = $RawRecord.outcomes.emittedDatagrams
            admittedFragments = $RawRecord.outcomes.admittedFragments
            continuationCount = $RawRecord.outcomes.continuationCount
            completedOperations = $RawRecord.outcomes.completedOperations
        }
    }
}

$unifiedLines = [System.Collections.Generic.List[string]]::new()
$decisionLines = [System.Collections.Generic.List[string]]::new()
for ($rowIndex = 0; $rowIndex -lt $rawLines.Count; $rowIndex++) {
    $raw = $rawLines[$rowIndex] | ConvertFrom-Json -Depth 100
    $assignment = $sourceAssignments[$rowIndex]
    $sample = $samplesById[$assignment.SampleId]
    $epoch = $raw.epoch
    $rowId = [string]::Join(
        '|',
        @(
            [string] $localResult.runId,
            [string] $assignment.SampleId,
            [string] $raw.connectionKey,
            [string] $epoch.epochIndex
        ))
    $axisRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($axis in $axisDefinitions) {
        [void] $axisRecords.Add(
            (Convert-AxisRecord `
                -RawRecord $epoch.($axis.Property) `
                -AxisId $axis.AxisId))
    }

    $violationCodes = @($sample.correctness.invariantViolations)
    $unified = [ordered]@{
        schemaVersion = 'adaptive-runtime-stage1-unified-epoch-v1'
        rowId = $rowId
        campaignId = [string] $localResult.campaignId
        runId = [string] $localResult.runId
        cellId = [string] $localResult.cellId
        sampleId = [string] $assignment.SampleId
        connectionKey = [string] $raw.connectionKey
        epochIndex = [ulong] $epoch.epochIndex
        epochStartOffsetMicros = [ulong] $epoch.epochStartOffsetMicros
        epochDurationMicros = [ulong] $epoch.epochDurationMicros
        axisRecords = @($axisRecords)
        correctnessFlags = [ordered]@{
            payloadValid = [bool] $sample.correctness.payloadValidated
            protocolValid = [int] $sample.correctness.protocolErrors -eq 0
            timedOut = [int] $sample.correctness.timedOutOperations -ne 0
            ownershipValid = [int] $sample.correctness.failedOperations -eq 0
            terminalValid =
                [int] $sample.correctness.cancellationFailures -eq 0 -and
                [int] $sample.correctness.disposalFailures -eq 0
            violationCodes = $violationCodes
        }
        provenance = [ordered]@{
            repositoryCommit = [string] $repositoryIdentity.commit
            benchmarkSha256 = [string] $benchmarkAssembly.sha256
            runtimeSha256 = [string] $runtimeAssembly.sha256
            hostFingerprint = [string] $localResult.environment.hostFingerprint
            sourceArtifactPath = [string] $assignment.SourcePath
            sourceArtifactSha256 = [string] $assignment.SourceSha256
        }
        workloadAnalysisOnly = [ordered]@{
            excludedFromProductionFeatures = $true
            scenarioId = [string] $localResult.workload.scenarioId
            trafficShape = [string] $localResult.workload.trafficShape
            payloadBytes = [ulong] $localResult.workload.payloadBytes
            requestedConcurrency = [ulong] $localResult.workload.concurrency
            effectiveConcurrency = [ulong] $localResult.workload.effectiveConcurrency
        }
    }
    [void] $unifiedLines.Add(($unified | ConvertTo-Json -Depth 100 -Compress))

    for ($axisIndex = 0; $axisIndex -lt $axisDefinitions.Count; $axisIndex++) {
        $axisRecord = $axisRecords[$axisIndex]
        $axisDecision = [ordered]@{
            schemaVersion = 'adaptive-runtime-stage1-axis-decision-v1'
            epochRowId = $rowId
            campaignId = [string] $localResult.campaignId
            runId = [string] $localResult.runId
            cellId = [string] $localResult.cellId
            sampleId = [string] $assignment.SampleId
            connectionKey = [string] $raw.connectionKey
            epochIndex = [ulong] $epoch.epochIndex
            axisId = [string] $axisRecord.axisId
            decisionSequence = [ulong] $axisRecord.decisionSequence
            recordKind = 'epoch_summary'
            operationKey = $null
            planKey = $null
            forcedValue = $axisRecord.forcedValue
            selectedValue = [string] $axisRecord.selectedValue
            appliedValue = [string] $axisRecord.appliedValue
            sourceArtifactPath = [string] $assignment.SourcePath
            sourceArtifactSha256 = [string] $assignment.SourceSha256
        }
        [void] $decisionLines.Add(
            ($axisDecision | ConvertTo-Json -Depth 100 -Compress))
    }
}

New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
[System.IO.File]::WriteAllLines(
    $unifiedPath,
    $unifiedLines,
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllLines(
    $decisionPath,
    $decisionLines,
    [System.Text.UTF8Encoding]::new($false))

$validationJson = & $validatorPath `
    -UnifiedEpochPath $unifiedPath `
    -AxisDecisionPath $decisionPath `
    -RepositoryRoot $RepositoryRoot
if (-not $?) {
    throw "Stage 1 unified evidence validation failed.`n$validationJson"
}

$validationDocument = $validationJson | ConvertFrom-Json -Depth 100
[System.IO.File]::WriteAllText(
    $validationPath,
    ($validationDocument | ConvertTo-Json -Depth 100) + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false))

$manifest = [ordered]@{
    schemaVersion = 'adaptive-runtime-stage1-unified-materialization-manifest-v1'
    createdUtc = (Get-Date).ToUniversalTime().ToString('o')
    classification = [string] $localResult.classification
    rawEpochPath = $resolvedRawEpochPath
    rawEpochSha256 = Get-FileSha256Hex -Path $resolvedRawEpochPath
    rawExportManifestPath = $resolvedRawManifestPath
    rawExportManifestSha256 = Get-FileSha256Hex -Path $resolvedRawManifestPath
    localResultPath = $resolvedLocalResultPath
    localResultSha256 = Get-FileSha256Hex -Path $resolvedLocalResultPath
    unifiedEpochPath = $unifiedPath
    unifiedEpochSha256 = Get-FileSha256Hex -Path $unifiedPath
    axisDecisionPath = $decisionPath
    axisDecisionSha256 = Get-FileSha256Hex -Path $decisionPath
    validationPath = $validationPath
    validationSha256 = Get-FileSha256Hex -Path $validationPath
    unifiedEpochRowCount = [int] $validationDocument.unifiedEpochRowCount
    axisDecisionRowCount = [int] $validationDocument.axisDecisionRowCount
    excludedFromPolicyAcceptance =
        [string] $localResult.classification -ne 'accepted'
}
[void] (Write-ValidatedJsonDocument `
    -Document $manifest `
    -SchemaPath $manifestSchemaPath `
    -OutputPath $manifestPath)

[ordered]@{
    schemaVersion = 'adaptive-runtime-stage1-unified-materialization-result-v1'
    classification = $manifest.classification
    unifiedEpochRowCount = $manifest.unifiedEpochRowCount
    axisDecisionRowCount = $manifest.axisDecisionRowCount
    excludedFromPolicyAcceptance = $manifest.excludedFromPolicyAcceptance
    unifiedEpochPath = $unifiedPath
    axisDecisionPath = $decisionPath
    validationPath = $validationPath
    manifestPath = $manifestPath
} | ConvertTo-Json -Depth 100
