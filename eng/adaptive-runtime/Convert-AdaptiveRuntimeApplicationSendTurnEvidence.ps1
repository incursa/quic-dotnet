# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RawEvidencePath,

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
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $BenchmarkSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $RuntimeSha256,

    [Parameter(Mandatory = $true)]
    [string] $HostFingerprint,

    [Parameter(Mandatory = $true)]
    [string] $CorrectnessFlagsJson,

    [string[]] $AdditionalAnalysisExclusionFlags = @(),

    [Parameter(Mandatory = $true)]
    [string] $ScenarioId,

    [Parameter(Mandatory = $true)]
    [ValidateSet('upload', 'download', 'duplex', 'request_response', 'streaming')]
    [string] $TrafficShape,

    [Parameter(Mandatory = $true)]
    [ValidateSet('fixed_total', 'fixed_per_stream')]
    [string] $AccountingMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet('sparse', 'bursty', 'sustained', 'stream_churn')]
    [string] $ArrivalPattern,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, [long]::MaxValue)]
    [long] $PayloadBytes,

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

    [ValidateRange(1, [long]::MaxValue)]
    [long] $MonotonicTimerFrequencyHz = [Diagnostics.Stopwatch]::Frequency,

    [string] $RepositoryRoot = [System.IO.Path]::GetFullPath(
        (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),

    [string] $RepositoryCommit = (git -C ([System.IO.Path]::GetFullPath(
        (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))) rev-parse HEAD).Trim(),

    [switch] $RepositoryDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

trap {
    [Console]::Error.WriteLine($_.Exception.Message)
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 1
}

function ConvertTo-Mask {
    param(
        [AllowNull()]
        [object] $Value,

        [Parameter(Mandatory = $true)]
        [hashtable] $Map
    )

    if ($null -eq $Value) {
        return 0L
    }

    $numeric = 0L
    if ([long]::TryParse(
            [string] $Value,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref] $numeric)) {
        return $numeric
    }

    $mask = 0L
    foreach ($name in ([string] $Value).Split(',', [StringSplitOptions]::RemoveEmptyEntries)) {
        $trimmed = $name.Trim()
        if ($trimmed -eq 'None') {
            continue
        }
        if (-not $Map.ContainsKey($trimmed)) {
            throw "Unknown flag '$trimmed'."
        }
        $mask = $mask -bor [long] $Map[$trimmed]
    }
    return $mask
}

function ConvertTo-PolicyValue {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacyCurrent' { 'legacy_current' }
        'Conservative' { 'conservative' }
        default { throw "Unsupported application-send-turn policy '$Value'." }
    }
}

function ConvertTo-ControllerState {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacyCurrent' { 'legacy_current' }
        'Fallback' { 'fallback' }
        'Terminal' { 'terminal' }
        default { throw "Unsupported application-send-turn controller state '$Value'." }
    }
}

function ConvertTo-ReasonCode {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacyCurrent' { 'legacy_selector' }
        'MissingSignal' { 'missing_signal' }
        'StaleSignal' { 'stale_signal' }
        'ContradictorySignals' { 'contradictory_signals' }
        'OutOfDomain' { 'out_of_domain' }
        'RuleVersionMismatch' { 'rule_version_mismatch' }
        'ArithmeticSaturated' { 'arithmetic_saturated' }
        'TerminalStarted' { 'terminal_started' }
        'ResourceGuard' { 'resource_guard' }
        'RecoveryGuard' { 'recovery_guard' }
        'CancellationOrDisposal' { 'cancellation_or_disposal' }
        default { throw "Unsupported application-send-turn reason '$Value'." }
    }
}

function Add-ExclusionFlag {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]] $Flags,

        [Parameter(Mandatory = $true)]
        [string] $Value
    )

    [void] $Flags.Add($Value)
}

function ConvertTo-Microseconds {
    param(
        [Parameter(Mandatory = $true)]
        [long] $TickDelta,

        [Parameter(Mandatory = $true)]
        [long] $FrequencyHz
    )

    if ($TickDelta -le 0) {
        return 0L
    }

    $scaled = [System.Numerics.BigInteger] $TickDelta * 1000000
    $micros = $scaled / [System.Numerics.BigInteger] $FrequencyHz
    if ($micros -gt [long]::MaxValue) {
        return [long]::MaxValue
    }

    return [long] $micros
}

$rawPath = (Resolve-Path -LiteralPath $RawEvidencePath -ErrorAction Stop).Path
$rawSchemaPath = Join-Path (Join-Path $RepositoryRoot 'schemas') 'adaptive-runtime-application-send-turn-raw-v1.schema.json'
if (-not (Test-Path -LiteralPath $rawSchemaPath -PathType Leaf)) {
    throw "Raw send-turn evidence schema was not found: $rawSchemaPath"
}
$schemaPath = Join-Path (Join-Path $RepositoryRoot 'schemas') 'adaptive-runtime-policy-epoch-dataset-v1.schema.json'
if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
    throw "Epoch dataset schema was not found: $schemaPath"
}

$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $resolvedOutputDirectory) {
    throw "Send-turn evidence output target already exists and will not be overwritten: $resolvedOutputDirectory"
}
New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
$pendingDirectory = Join-Path $resolvedOutputDirectory '.pending'
New-Item -ItemType Directory -Path $pendingDirectory -Force | Out-Null

try {
    $correctnessFlags = $CorrectnessFlagsJson | ConvertFrom-Json -Depth 8
}
catch {
    throw "CorrectnessFlagsJson is not valid JSON. $($_.Exception.Message)"
}
foreach ($propertyName in @(
        'payloadValid',
        'protocolValid',
        'timedOut',
        'ownershipValid',
        'terminalValid',
        'violationCodes')) {
    if ($null -eq $correctnessFlags.PSObject.Properties[$propertyName]) {
        throw "CorrectnessFlagsJson is missing required property '$propertyName'."
    }
}

$normalizedCorrectnessFlags = [ordered]@{
    payloadValid = [bool] $correctnessFlags.payloadValid
    protocolValid = [bool] $correctnessFlags.protocolValid
    timedOut = [bool] $correctnessFlags.timedOut
    cancellationValid = $null
    disposalValid = $null
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

$allowedAdditionalFlags = @(
    'requested_effective_mismatch',
    'binary_identity_missing',
    'binary_changed',
    'target_health_invalid',
    'generator_health_invalid',
    'instrumentation_mismatch',
    'policy_mismatch',
    'source_join_failed')
foreach ($flag in $AdditionalAnalysisExclusionFlags) {
    if ($flag -notin $allowedAdditionalFlags) {
        throw "Additional analysis exclusion flag '$flag' is not valid for application-send-turn evidence."
    }
}

$records = @(
    Get-Content -LiteralPath $rawPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object {
            try {
                if (-not ($_ | Test-Json -SchemaFile $rawSchemaPath -ErrorAction Stop)) {
                    throw 'schema validation returned false'
                }
                $_ | ConvertFrom-Json -Depth 32
            }
            catch {
                throw "Send-turn evidence source contains invalid JSON or schema-invalid data: $rawPath. $($_.Exception.Message)"
            }
        }
)
if ($records.Count -eq 0) {
    throw "Send-turn evidence source contains no records: $rawPath"
}

$signalMap = @{
    QueuedApplicationWrites = 1
    OutboundBacklogBytes = 2
    DistinctQueuedStreams = 4
    OldestQueuedSendAge = 8
    QueueDelayEwma = 16
    ActorServiceTimeEwma = 32
    BurstLimitHits = 64
    Congestion = 128
    RetainedSendState = 256
    Lifecycle = 512
    Recovery = 1024
    Resource = 2048
}
$lifecycleMap = @{
    Establishing = 1
    Active = 2
    Closing = 4
    Draining = 8
    Discarded = 16
    Terminal = 32
    Disposed = 64
}
$conditionMap = @{
    ArithmeticSaturated = 1
    Contradictory = 2
    OutOfDomain = 4
    RecoveryUnstable = 8
    ResourceConstrained = 16
}
$sourceHash = (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant()
$repositoryBranch = [string] (git -C $RepositoryRoot branch --show-current 2>$null)
$repositoryBranch = $repositoryBranch.Trim()
$repositoryRemoteUrl = [string] (git -C $RepositoryRoot remote get-url origin 2>$null)
$repositoryRemoteUrl = $repositoryRemoteUrl.Trim()
$rowPaths = [System.Collections.Generic.List[string]]::new()
$pendingRowPaths = [System.Collections.Generic.List[string]]::new()
$seenIdentity = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

foreach ($connectionGroup in @($records | Group-Object -Property connectionKey)) {
    $connectionKey = [string] $connectionGroup.Name
    if ([string]::IsNullOrWhiteSpace($connectionKey)) {
        throw 'Send-turn evidence record has a missing connectionKey.'
    }

    $connectionRecords = @($connectionGroup.Group)
    $previousTurnSequence = 0UL
    $previousSnapshotSequence = 0UL
    for ($recordIndex = 0; $recordIndex -lt $connectionRecords.Count; $recordIndex++) {
        $record = $connectionRecords[$recordIndex]
        if ([string] $record.schemaVersion -ne 'adaptive-runtime-application-send-turn-raw-v1') {
            throw "Send-turn evidence record has an unsupported schemaVersion: $($record.schemaVersion)"
        }
        $mode = [string] $record.mode
        if ($mode -notin @('ObserveOnly', 'Shadow')) {
            throw "Send-turn evidence record has an unsupported mode: $mode"
        }

        $turnSequence = [uint64] $record.observation.turnSequence
        if ($turnSequence -eq 0 -or $turnSequence -le $previousTurnSequence) {
            throw "Send-turn evidence for '$connectionKey' is duplicate or out of order at turn $turnSequence."
        }
        $previousTurnSequence = $turnSequence
        if (-not $seenIdentity.Add("$connectionKey|$turnSequence")) {
            throw "Duplicate send-turn evidence identity '$connectionKey|$turnSequence'."
        }
        if ([string] $record.observation.observationContractVersion -ne
            'adaptive-runtime-application-send-turn-observation-v1') {
            throw "Send-turn evidence has an unsupported observation contract version."
        }
        if ([string] $record.observation.policyRuleVersion -ne
            'application-send-turn-shadow-neutral-v1') {
            throw "Send-turn evidence has an unsupported observation rule version."
        }

        $hasRecommendation = [bool] $record.hasRecommendation
        if (($mode -eq 'Shadow') -ne $hasRecommendation) {
            throw "Send-turn evidence mode '$mode' has an inconsistent recommendation flag."
        }
        if ($hasRecommendation -and $null -eq $record.snapshot) {
            throw "Shadow send-turn evidence is missing its policy snapshot."
        }
        if (-not $hasRecommendation -and $null -ne $record.snapshot) {
            throw "Observe-only send-turn evidence unexpectedly contains a policy snapshot."
        }
        if ($hasRecommendation) {
            $snapshotSequence = [uint64] $record.snapshot.snapshotSequence
            if ($snapshotSequence -eq 0 -or $snapshotSequence -le $previousSnapshotSequence) {
                throw "Shadow send-turn evidence for '$connectionKey' is duplicate or out of order at snapshot $snapshotSequence."
            }
            $previousSnapshotSequence = $snapshotSequence
            if ([string] $record.snapshot.snapshotContractVersion -ne
                'adaptive-runtime-application-send-turn-snapshot-v1' -or
                [string] $record.snapshot.observationContractVersion -ne
                'adaptive-runtime-application-send-turn-observation-v1' -or
                [string] $record.snapshot.ruleVersion -ne
                'application-send-turn-shadow-neutral-v1' -or
                [string] $record.snapshot.reasonVersion -ne
                'adaptive-runtime-application-send-turn-reasons-v1' -or
                [string] $record.snapshot.provenanceVersion -ne
                'adaptive-runtime-application-send-turn-shadow-provenance-v1' -or
                [string] $record.snapshot.axisId -ne
                'application_send_turn_planning' -or
                [uint64] $record.snapshot.turnSequence -ne $turnSequence) {
                throw "Shadow send-turn evidence has inconsistent snapshot identity or versions at turn $turnSequence."
            }
        }

        $missingSignalMask = ConvertTo-Mask -Value $record.observation.missingSignalMask -Map $signalMap
        $staleSignalMask = ConvertTo-Mask -Value $record.observation.staleSignalMask -Map $signalMap
        $lifecycleFlags = ConvertTo-Mask -Value $record.observation.lifecycleFlags -Map $lifecycleMap
        $conditionMask = ConvertTo-Mask -Value $record.observation.conditions -Map $conditionMap
        $outOfDomain = ($conditionMask -band 4) -ne 0
        $capturedAtTicks = [long] $record.observation.capturedAtTicks
        if ($recordIndex -eq 0) {
            $firstCapturedAtTicks = $capturedAtTicks
        }
        $epochStartOffsetMicros = ConvertTo-Microseconds `
            -TickDelta ($capturedAtTicks - $firstCapturedAtTicks) `
            -FrequencyHz $MonotonicTimerFrequencyHz

        $exclusionFlags = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($additionalFlag in $AdditionalAnalysisExclusionFlags) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value $additionalFlag
        }
        if ($correctnessInvalid) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'correctness_failed'
        }
        if ($missingSignalMask -ne 0) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'observation_missing'
        }
        if ($staleSignalMask -ne 0) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'observation_stale'
        }
        if (($conditionMask -band 1) -ne 0) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'observation_saturated'
        }
        if ($outOfDomain) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'out_of_domain'
        }
        if ($epochStartOffsetMicros -lt $WarmupMicros) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'warmup'
        }
        if (($lifecycleFlags -band 96) -ne 0) {
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'terminal_partial_epoch'
        }

        if ($recordIndex + 1 -lt $connectionRecords.Count) {
            $nextCapturedAtTicks = [long] $connectionRecords[$recordIndex + 1].observation.capturedAtTicks
            if ($nextCapturedAtTicks -le $capturedAtTicks) {
                $epochDurationMicros = 1L
                Add-ExclusionFlag -Flags $exclusionFlags -Value 'instrumentation_mismatch'
            }
            else {
                $epochDurationMicros = [Math]::Max(
                    1L,
                    (ConvertTo-Microseconds `
                        -TickDelta ($nextCapturedAtTicks - $capturedAtTicks) `
                        -FrequencyHz $MonotonicTimerFrequencyHz))
            }
        }
        else {
            $epochDurationMicros = 1L
            Add-ExclusionFlag -Flags $exclusionFlags -Value 'terminal_partial_epoch'
        }

        $queueDelayMissing = ($missingSignalMask -band 16) -ne 0
        $actorServiceMissing = ($missingSignalMask -band 32) -ne 0
        $queueDelayMicros = if ($queueDelayMissing) { $null } else { [long] $record.observation.queueDelayEwmaMicros }
        $actorServiceMicros = if ($actorServiceMissing) { $null } else { [long] $record.observation.actorServiceTimeEwmaMicros }
        $queueToServiceRatioQ16 = if ($null -eq $queueDelayMicros -or
            $null -eq $actorServiceMicros -or
            $actorServiceMicros -eq 0) {
            $null
        }
        else {
            $scaledQueueDelay = [System.Numerics.BigInteger] $queueDelayMicros * 65536
            $ratio = $scaledQueueDelay / [System.Numerics.BigInteger] $actorServiceMicros
            [long] [System.Numerics.BigInteger]::Min([uint32]::MaxValue, $ratio)
        }

        if ($hasRecommendation) {
            $state = ConvertTo-ControllerState -Value ([string] $record.snapshot.state)
            $previousState = ConvertTo-ControllerState -Value ([string] $record.snapshot.previousState)
            $appliedPolicy = ConvertTo-PolicyValue -Value ([string] $record.snapshot.appliedPolicy)
            $recommendedPolicy = ConvertTo-PolicyValue -Value ([string] $record.snapshot.recommendedPolicy)
            $reasonCode = ConvertTo-ReasonCode -Value ([string] $record.snapshot.reason)
            $snapshotVersion = [string] $record.snapshot.snapshotContractVersion
            $ruleVersion = [string] $record.snapshot.ruleVersion
            $transitioned = [bool] $record.snapshot.transitioned
            $selectionSource = 'shadow_rule'
        }
        else {
            $state = 'quiescent'
            $previousState = 'quiescent'
            $appliedPolicy = 'legacy_current'
            $recommendedPolicy = $null
            $reasonCode = 'none'
            $snapshotVersion = 'adaptive-runtime-application-send-turn-observe-only-v1'
            $ruleVersion = [string] $record.observation.policyRuleVersion
            $transitioned = $false
            $selectionSource = 'legacy'
        }

        [string[]] $normalizedExclusionFlags = if ($exclusionFlags.Count -eq 0) {
            , 'none'
        }
        else {
            @($exclusionFlags | Sort-Object)
        }
        $rowId = "$SampleId-$connectionKey-turn-$turnSequence"
        $row = [ordered]@{
            schemaVersion = 'adaptive-runtime-policy-epoch-dataset-v1'
            datasetId = $DatasetId
            rowId = $rowId
            campaignId = $CampaignId
            runId = $RunId
            cellId = $CellId
            sampleId = $SampleId
            repetition = 0
            connectionKey = $connectionKey
            epochIndex = [long] ($turnSequence - 1)
            epochStartOffsetMicros = $epochStartOffsetMicros
            epochDurationMicros = $epochDurationMicros
            preDecisionObservations = [ordered]@{
                openStreams = $null
                liveObserverStreams = $null
                activeStreams = $null
                runnableStreams = $null
                receiveActiveStreams = $null
                sendActiveStreams = $null
                inboundBytesEpoch = $null
                outboundBytesEpoch = $null
                inboundRateEwmaBps = $null
                outboundRateEwmaBps = $null
                queuedApplicationWrites = [long] $record.observation.queuedApplicationWrites
                distinctQueuedSendStreams = [long] $record.observation.distinctQueuedStreams
                oldestApplicationSendAgeMicros = [long] $record.observation.oldestQueuedSendAgeMicros
                queueDelayEwmaMicros = $queueDelayMicros
                actorServiceTimeEwmaMicros = $actorServiceMicros
                queueToServiceRatioQ16 = $queueToServiceRatioQ16
                connectionReceiveHeadroomBytes = $null
                estimatedReceiveExhaustionMicros = $null
                connectionCreditPendingBytes = $null
                timeSinceCreditPublicationMicros = $null
                connectionFlowBlockedMicrosEpoch = $null
                streamFlowBlockedMicrosEpoch = $null
                outboundBacklogBytes = [long] $record.observation.outboundBacklogBytes
                burstLimitHitsEpoch = [long] $record.observation.burstLimitHits
                congestionWindowBytes = [long] $record.observation.congestionWindowBytes
                bytesInFlight = [long] $record.observation.bytesInFlight
                lossEventsEpoch = $null
                retransmissionsEpoch = $null
                ptoEventsEpoch = $null
                retainedSendBuffers = [long] $record.observation.retainedSendBuffers
                retainedSendBytes = [long] $record.observation.retainedSendBytes
                retainedReceiveBytes = $null
                advisorAgeMicros = $null
                hasIssuedApplicationData = $null
                missingSignalMask = $missingSignalMask
                staleSignalMask = $staleSignalMask
                lifecycleFlags = $lifecycleFlags
                outOfDomain = $outOfDomain
            }
            currentPolicyState = [ordered]@{
                snapshotVersion = $snapshotVersion
                ruleVersion = $ruleVersion
                observationContractVersion = [string] $record.observation.observationContractVersion
                state = $state
                appliedPolicy = $appliedPolicy
                hasIssuedApplicationData = $null
            }
            candidatePolicySelection = [ordered]@{
                selectionSource = $selectionSource
                selectedPolicy = $appliedPolicy
                shadowRecommendation = $recommendedPolicy
                reasonCode = $reasonCode
                contradictorySignals = $reasonCode -eq 'contradictory_signals'
            }
            transitionState = [ordered]@{
                previousState = $previousState
                state = $state
                transitioned = $transitioned
                reasonCode = $reasonCode
            }
            dwellState = [ordered]@{
                stateEpochCount = 0
                stateDurationMicros = 0
                candidateEvidenceCount = 0
                reliefEvidenceCount = 0
            }
            postEpochOutcomes = [ordered]@{
                applicationBytes = $null
                completedOperations = $null
                throughputBytesPerSecond = $null
                latencyP95Micros = $null
                allocatedBytes = $null
                peakRetainedBytes = $null
                queueDelayP95Micros = $null
                lossEvents = $null
                ptoEvents = $null
            }
            correctnessFlags = $normalizedCorrectnessFlags
            fairnessFlags = [ordered]@{
                assessed = $false
                starvationObserved = $false
                guardrailViolated = $false
                violationCodes = @()
            }
            provenance = [ordered]@{
                repositoryName = 'quic-dotnet'
                repositoryPath = [System.IO.Path]::GetFullPath($RepositoryRoot)
                repositoryBranch = if ([string]::IsNullOrWhiteSpace($repositoryBranch)) { $null } else { $repositoryBranch }
                repositoryRemoteUrl = if ([string]::IsNullOrWhiteSpace($repositoryRemoteUrl)) { $null } else { $repositoryRemoteUrl }
                repositoryCommit = $RepositoryCommit
                repositoryDirty = [bool] $RepositoryDirty
                benchmarkSha256 = $BenchmarkSha256.ToLowerInvariant()
                runtimeSha256 = $RuntimeSha256.ToLowerInvariant()
                hostFingerprint = $HostFingerprint
                os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
                architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
                processorCount = [Environment]::ProcessorCount
                dotnetRuntime = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
                monotonicTimerFrequencyHz = $MonotonicTimerFrequencyHz
                scriptVersion = 'adaptive-runtime-send-turn-epoch-export-v1'
                toolVersions = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString() }
                resultSchemaVersion = 'adaptive-runtime-policy-local-result-v1'
                datasetSchemaVersion = 'adaptive-runtime-policy-epoch-dataset-v1'
                ruleVersion = $ruleVersion
                observationContractVersion = [string] $record.observation.observationContractVersion
                sourceArtifactPath = $rawPath
                sourceArtifactSha256 = $sourceHash
                transformation = [ordered]@{
                    name = 'adaptive-runtime-send-turn-epoch-export'
                    version = '1.0.0'
                    codeCommit = $RepositoryCommit
                    inputSha256 = $sourceHash
                    outputSha256 = ('0' * 64)
                }
            }
            workloadAnalysisOnly = [ordered]@{
                excludedFromProductionFeatures = $true
                scenarioId = $ScenarioId
                trafficShape = $TrafficShape
                payloadBytes = $PayloadBytes
                accountingMode = $AccountingMode
                requestedConnections = $Connections
                effectiveConnections = $Connections
                requestedStreamsPerConnection = $StreamsPerConnection
                effectiveStreamsPerConnection = $StreamsPerConnection
                requestedConcurrency = $Connections * $StreamsPerConnection
                effectiveConcurrency = $Connections * $StreamsPerConnection
                warmupMicros = $WarmupMicros
                measurementMicros = $MeasurementMicros
                arrivalPattern = $ArrivalPattern
                lossPercent = 0
                delayMs = 0
            }
            analysisExclusionFlags = $normalizedExclusionFlags
        }

        $canonical = $row | ConvertTo-Json -Depth 100 -Compress
        $row.provenance.transformation.outputSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
        $connectionHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($connectionKey))).ToLowerInvariant()
        $rowFileName = "send-turn-row-$connectionHash-$turnSequence.json"
        $rowPath = Join-Path $resolvedOutputDirectory $rowFileName
        $pendingRowPath = Join-Path $pendingDirectory $rowFileName
        $row | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $pendingRowPath -Encoding utf8
        if (-not ((Get-Content -LiteralPath $pendingRowPath -Raw) |
                Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
            throw "Generated send-turn epoch row did not validate: $pendingRowPath"
        }
        $rowPaths.Add($rowPath)
        $pendingRowPaths.Add($pendingRowPath)
    }
}

for ($rowIndex = 0; $rowIndex -lt $rowPaths.Count; $rowIndex++) {
    Move-Item -LiteralPath $pendingRowPaths[$rowIndex] -Destination $rowPaths[$rowIndex] -ErrorAction Stop
}
Remove-Item -LiteralPath $pendingDirectory -ErrorAction Stop

$rowChecksums = @(
    $rowPaths | ForEach-Object {
        [ordered]@{
            path = $_
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
)
[ordered]@{
    schemaVersion = 'adaptive-runtime-application-send-turn-epoch-export-manifest-v1'
    sourceArtifactPath = $rawPath
    sourceArtifactSha256 = $sourceHash
    rowCount = $rowPaths.Count
    rowPaths = @($rowPaths)
    rowChecksums = $rowChecksums
} | ConvertTo-Json -Depth 16 |
    Set-Content -LiteralPath (Join-Path $resolvedOutputDirectory 'send-turn-epoch-export-manifest.json') -Encoding utf8

Write-Output (@($rowPaths) | ConvertTo-Json -Depth 4)
