# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = 'C:\shared\src\incursa\protocol-lab',

    [string] $ProtocolLabExecutionRoot = 'C:\shared\src\incursa\protocol-lab-internal',

    [string] $CampaignId = "adaptive-receive-credit-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [string] $CellId = 'duplex-64kb-x1-s16',

    [ValidateSet('ABBA', 'BAAB')]
    [string] $SequenceProtocol = 'ABBA',

    [ValidateSet('legacy_current', 'immediate', 'read_dominant_batch')]
    [string] $PolicyA = 'legacy_current',

    [ValidateSet('legacy_current', 'immediate', 'read_dominant_batch')]
    [string] $PolicyB = 'read_dominant_batch',

    [switch] $ShadowOnly,

    [switch] $StressOnly,

    [string] $ScenarioId = 'quic.transport.duplex-streams-peer-matrix',

    [ValidateSet('upload', 'download', 'duplex', 'request_response', 'streaming')]
    [string] $TrafficShape = 'duplex',

    [ValidateSet('fixed_total', 'fixed_per_stream')]
    [string] $AccountingMode = 'fixed_per_stream',

    [ValidateSet('sparse', 'bursty', 'sustained', 'stream_churn')]
    [string] $ArrivalPattern = 'sustained',

    [ValidateRange(0, [int]::MaxValue)]
    [int] $PayloadBytes = 65536,

    [ValidateRange(1, 1024)]
    [int] $Connections = 1,

    [ValidateRange(1, 1024)]
    [int] $StreamsPerConnection = 16,

    [ValidateRange(0, 3600)]
    [int] $WarmupSeconds = 2,

    [ValidateRange(1, 3600)]
    [int] $DurationSeconds = 5,

    [string] $OutputRoot,

    [switch] $NoBuild,

    [switch] $NoRestore,

    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$localBenchmarkScript = Join-Path $repoRoot 'scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1'
$resultSchemaPath = Join-Path $repoRoot 'schemas\adaptive-runtime-policy-local-result-v1.schema.json'
$epochSchemaPath = Join-Path $repoRoot 'schemas\adaptive-runtime-policy-epoch-dataset-v1.schema.json'
$evidenceValidationScript = Join-Path $repoRoot 'eng\adaptive-runtime\Test-AdaptiveRuntimePolicyEvidence.ps1'
$serverProjectPath = Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\IncursaRawQuicServer.csproj'
$serverBinaryPath = Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\bin\Release\net10.0\IncursaRawQuicServer.dll'
$runtimeBinaryPath = Join-Path $repoRoot 'src\Incursa.Quic\bin\Release\net10.0\Incursa.Quic.dll'
$resolvedOutputRoot = if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    Join-Path $repoRoot ".artifacts\adaptive-runtime\$CampaignId\$CellId"
}
elseif ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    [System.IO.Path]::GetFullPath($OutputRoot)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputRoot))
}

function Get-GitIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $commit = (& git -C $Path rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read Git commit for $Path."
    }

    $branch = (& git -C $Path branch --show-current).Trim()
    $status = @(& git -C $Path status --porcelain)
    $remote = (& git -C $Path remote get-url origin 2>$null)
    if ($LASTEXITCODE -ne 0) {
        $remote = $null
    }

    return [ordered]@{
        name = $Name
        path = [System.IO.Path]::GetFullPath($Path)
        branch = if ([string]::IsNullOrWhiteSpace($branch)) { $null } else { $branch }
        commit = $commit
        dirty = $status.Count -ne 0
        remoteUrl = if ([string]::IsNullOrWhiteSpace($remote)) { $null } else { $remote.Trim() }
    }
}

function Get-FileIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Role,

        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required frozen binary was not found: $Path"
    }

    $item = Get-Item -LiteralPath $Path
    return [ordered]@{
        role = $Role
        path = $item.FullName
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        fileVersion = $item.VersionInfo.FileVersion
    }
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

function Get-RelativeRange {
    param([AllowNull()][object[]] $Values)

    $numbers = @($Values | Where-Object { $null -ne $_ } | ForEach-Object { [double] $_ })
    $median = Get-Median -Values $numbers
    if ($numbers.Count -lt 2 -or $null -eq $median -or $median -eq 0) {
        return $null
    }

    $minimum = ($numbers | Measure-Object -Minimum).Minimum
    $maximum = ($numbers | Measure-Object -Maximum).Maximum
    return [Math]::Abs($maximum - $minimum) / [Math]::Abs($median)
}

function Get-RoundedMedianInt64 {
    param([AllowNull()][object[]] $Values)

    $median = Get-Median -Values $Values
    if ($null -eq $median) {
        return $null
    }

    return [long] [Math]::Round([double] $median, 0, [MidpointRounding]::AwayFromZero)
}

function Get-Outcome {
    param(
        [AllowNull()][object] $Aggregate,
        [AllowNull()][object] $RunEvidence
    )

    if ($null -eq $Aggregate) {
        return [ordered]@{
            throughputBytesPerSecond = $null
            operationsPerSecond = $null
            latencyP50Ms = $null
            latencyP95Ms = $null
            latencyP99Ms = $null
            allocatedBytes = $null
            peakRetainedBytes = $null
            bufferPoolRentedBytes = if ($null -eq $RunEvidence) { $null } else { $RunEvidence.bufferPoolRentedBytes }
            bufferPoolOutstandingPeakBytes = if ($null -eq $RunEvidence) { $null } else { $RunEvidence.bufferPoolOutstandingPeakBytes }
            queueDelayP50Ms = $null
            queueDelayP95Ms = $null
            lossEvents = $null
            ptoEvents = $null
        }
    }

    return [ordered]@{
        throughputBytesPerSecond = $Aggregate.throughputBytesPerSecond.median
        operationsPerSecond = $Aggregate.requestsPerSecond.median
        latencyP50Ms = $Aggregate.latencyP50Ms.median
        latencyP95Ms = $Aggregate.latencyP95Ms.median
        latencyP99Ms = $Aggregate.latencyP99Ms.median
        allocatedBytes = $null
        peakRetainedBytes = $null
        bufferPoolRentedBytes = if ($null -eq $RunEvidence) { $null } else { $RunEvidence.bufferPoolRentedBytes }
        bufferPoolOutstandingPeakBytes = if ($null -eq $RunEvidence) { $null } else { $RunEvidence.bufferPoolOutstandingPeakBytes }
        queueDelayP50Ms = $null
        queueDelayP95Ms = $null
        lossEvents = $null
        ptoEvents = $null
    }
}

function Get-Correctness {
    param(
        [int] $ExitCode,
        [AllowNull()][object] $Aggregate
    )

    $payloadValidated = $false
    $failedOperations = if ($ExitCode -eq 0) { 0 } else { 1 }
    $timedOutOperations = 0
    $protocolErrors = 0
    $violations = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Aggregate) {
        $violations.Add('protocol-lab-aggregate-missing')
    }
    else {
        $failedOperations += [int] $Aggregate.failedRequests
        $timedOutOperations = [int] $Aggregate.timeoutRequests
        $protocolErrors = [int] $Aggregate.errorCount
        $payloadValidated = [int] $Aggregate.validation.passed -gt 0 -and
            [int] $Aggregate.validation.failed -eq 0 -and
            [int] $Aggregate.validation.infrastructureFailure -eq 0 -and
            [int] $Aggregate.parsedMetricsCount -gt 0

        foreach ($reason in @($Aggregate.failureReasons)) {
            if (-not [string]::IsNullOrWhiteSpace([string] $reason)) {
                $violations.Add([string] $reason)
            }
        }
    }

    if ($ExitCode -ne 0) {
        $violations.Add("protocol-lab-exit-code-$ExitCode")
    }
    if (-not $payloadValidated) {
        $violations.Add('exact-payload-validation-not-proven')
    }

    return [ordered]@{
        payloadValidated = $payloadValidated
        failedOperations = $failedOperations
        timedOutOperations = $timedOutOperations
        protocolErrors = $protocolErrors
        cancellationFailures = 0
        disposalFailures = 0
        invariantViolations = @($violations)
    }
}

function Get-ArtifactKind {
    param([Parameter(Mandatory = $true)][string] $Path)

    $name = [System.IO.Path]::GetFileName($Path)
    if ($name -eq 'cell-manifest.json') { return 'manifest' }
    if ($name -eq 'checksum-inventory.json') { return 'checksum_inventory' }
    if ($name -eq 'aggregate-results.json') { return 'metrics' }
    if ($name -eq 'adaptive-runtime-epochs.raw.jsonl' -or $name.StartsWith('epoch-row-', [StringComparison]::OrdinalIgnoreCase)) { return 'dataset' }
    if ($name.EndsWith('.stdout.log', [StringComparison]::OrdinalIgnoreCase) -or $name -eq 'server.stdout.txt') { return 'stdout' }
    if ($name.EndsWith('.stderr.log', [StringComparison]::OrdinalIgnoreCase) -or $name -eq 'server.stderr.txt') { return 'stderr' }
    return 'other'
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

function ConvertTo-NullableInt {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) {
        return $null
    }

    return [int] $Value
}

function ConvertTo-NullableLong {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) {
        return $null
    }

    return [long] $Value
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

function Resolve-SampleRunEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SampleId,

        [Parameter(Mandatory = $true)]
        [string] $RunRoot,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]] $ArtifactPathSet,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $ContractFailures
    )

    $quicBufferPoolSummaryPath = Get-ChildItem -LiteralPath $RunRoot -Filter 'quic-buffer-pool-summary.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    $quicBufferPoolSummary = $null
    if ([string]::IsNullOrWhiteSpace([string] $quicBufferPoolSummaryPath) -or
        -not (Test-Path -LiteralPath $quicBufferPoolSummaryPath -PathType Leaf)) {
        $ContractFailures.Add("$SampleId`: quic-buffer-pool-summary.json was not retained.")
    }
    else {
        try {
            $quicBufferPoolSummary = Get-Content -LiteralPath $quicBufferPoolSummaryPath -Raw | ConvertFrom-Json -Depth 100
            [void] $ArtifactPathSet.Add($quicBufferPoolSummaryPath)
        }
        catch {
            $ContractFailures.Add("$SampleId`: quic-buffer-pool-summary.json could not be parsed.")
        }
    }

    $bufferPoolRentedBytes = $null
    $bufferPoolOutstandingPeakBytes = $null
    if ($null -ne $quicBufferPoolSummary) {
        if (-not [bool] (Get-OptionalObjectProperty -Object $quicBufferPoolSummary -Name 'available')) {
            $ContractFailures.Add("$SampleId`: quic-buffer-pool-summary.json reported available=false.")
        }
        else {
            $bufferPoolRentedBytes = ConvertTo-NullableLong (Get-MetricValueFromSummary `
                -Summary $quicBufferPoolSummary `
                -MetricName 'incursa.quic.buffer_pool.bytes.rented' `
                -PropertyName 'total')
            $bufferPoolOutstandingPeakBytes = ConvertTo-NullableLong (Get-MetricValueFromSummary `
                -Summary $quicBufferPoolSummary `
                -MetricName 'incursa.quic.buffer_pool.outstanding.bytes' `
                -PropertyName 'max')

            if ($null -eq $bufferPoolRentedBytes) {
                $ContractFailures.Add("$SampleId`: quic-buffer-pool-summary.json did not retain incursa.quic.buffer_pool.bytes.rented total.")
            }
            if ($null -eq $bufferPoolOutstandingPeakBytes) {
                $ContractFailures.Add("$SampleId`: quic-buffer-pool-summary.json did not retain incursa.quic.buffer_pool.outstanding.bytes max.")
            }
        }
    }

    return [ordered]@{
        bufferPoolRentedBytes = $bufferPoolRentedBytes
        bufferPoolOutstandingPeakBytes = $bufferPoolOutstandingPeakBytes
        quicBufferPoolSummaryArtifactPath = if ([string]::IsNullOrWhiteSpace([string] $quicBufferPoolSummaryPath)) { $null } else { $quicBufferPoolSummaryPath }
    }
}

function Resolve-SampleTargetAttribution {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SampleId,

        [Parameter(Mandatory = $true)]
        [string] $RunRoot,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]] $ArtifactPathSet,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $ContractFailures
    )

    $runnerResultPath = Get-ChildItem -LiteralPath $RunRoot -Filter 'result.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    $diagnosticTargetPath = Get-ChildItem -LiteralPath $RunRoot -Filter 'diagnostic-target.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    $counterSummaryPath = Get-ChildItem -LiteralPath $RunRoot -Filter 'counters-summary.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName

    foreach ($path in @($runnerResultPath, $diagnosticTargetPath, $counterSummaryPath)) {
        if (-not [string]::IsNullOrWhiteSpace([string] $path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void] $ArtifactPathSet.Add($path)
        }
    }

    $benchmarkResult = $null
    if (-not [string]::IsNullOrWhiteSpace([string] $runnerResultPath) -and (Test-Path -LiteralPath $runnerResultPath -PathType Leaf)) {
        $benchmarkResult = Get-Content -LiteralPath $runnerResultPath -Raw | ConvertFrom-Json -Depth 100
    }
    else {
        $ContractFailures.Add("$SampleId`: authoritative benchmark result.json was not retained.")
    }

    $diagnosticTarget = Get-OptionalObjectProperty -Object $benchmarkResult -Name 'diagnosticTarget'
    if ($null -eq $diagnosticTarget -and
        -not [string]::IsNullOrWhiteSpace([string] $diagnosticTargetPath) -and
        (Test-Path -LiteralPath $diagnosticTargetPath -PathType Leaf)) {
        $diagnosticTarget = Get-Content -LiteralPath $diagnosticTargetPath -Raw | ConvertFrom-Json -Depth 50
    }

    $targetProcessMetrics = Get-OptionalObjectProperty -Object $benchmarkResult -Name 'targetProcessMetrics'
    $counterCaptureStatus = [string] (Get-OptionalObjectProperty -Object $benchmarkResult -Name 'countersCaptureStatus')
    $countersAvailable = [bool] (Get-OptionalObjectProperty -Object $benchmarkResult -Name 'countersAvailable')

    $rootProcessId = ConvertTo-NullableInt (Get-OptionalObjectProperty -Object $diagnosticTarget -Name 'rootProcessId')
    $resolvedProcessId = ConvertTo-NullableInt (Get-OptionalObjectProperty -Object $diagnosticTarget -Name 'resolvedProcessId')
    $measuredProcessId = ConvertTo-NullableInt (Get-OptionalObjectProperty -Object $targetProcessMetrics -Name 'processId')
    $resolutionStrategy = [string] (Get-OptionalObjectProperty -Object $diagnosticTarget -Name 'resolutionStrategy')

    $targetMetricWarnings = @((Get-OptionalObjectProperty -Object $targetProcessMetrics -Name 'warnings') | ForEach-Object { [string] $_ })
    $targetMetricSamples = @((Get-OptionalObjectProperty -Object $targetProcessMetrics -Name 'samples'))
    $measurementSource = if ($targetMetricWarnings -contains 'target-process-metrics-adapter-derived') {
        if ($targetMetricSamples.Count -gt 0) { 'adapter-resolved-live-process' } else { 'adapter-metrics-snapshots' }
    }
    elseif ([string]::Equals($resolutionStrategy, 'root-process', [StringComparison]::OrdinalIgnoreCase)) {
        'root-process'
    }
    elseif ([string]::IsNullOrWhiteSpace($resolutionStrategy)) {
        $null
    }
    else {
        'resolved-process'
    }

    $counterProcessId = if (-not [string]::IsNullOrWhiteSpace($counterCaptureStatus) -and
        $counterCaptureStatus -eq 'succeeded' -and
        -not [string]::IsNullOrWhiteSpace([string] $counterSummaryPath) -and
        (Test-Path -LiteralPath $counterSummaryPath -PathType Leaf) -and
        $resolvedProcessId -ne $null) {
        $resolvedProcessId
    }
    else {
        $null
    }
    $counterProcessIdSource = if ($counterProcessId -ne $null) { 'runner-counter-attach-resolved-process' } else { $null }

    $rootEqualsResolved = $rootProcessId -ne $null -and $resolvedProcessId -ne $null -and $rootProcessId -eq $resolvedProcessId
    $resolvedEqualsMeasured = $resolvedProcessId -ne $null -and $measuredProcessId -ne $null -and $resolvedProcessId -eq $measuredProcessId
    $resolvedEqualsCounter = $resolvedProcessId -ne $null -and $counterProcessId -ne $null -and $resolvedProcessId -eq $counterProcessId
    $commandLine = [string] (Get-OptionalObjectProperty -Object $diagnosticTarget -Name 'commandLine')
    $executablePath = [string] (Get-OptionalObjectProperty -Object $diagnosticTarget -Name 'executablePath')
    $workingDirectory = [string] (Get-OptionalObjectProperty -Object $diagnosticTarget -Name 'workingDirectory')
    $commandIdentityAvailable = -not [string]::IsNullOrWhiteSpace($commandLine) -or
        -not [string]::IsNullOrWhiteSpace($executablePath) -or
        -not [string]::IsNullOrWhiteSpace($workingDirectory)

    $valid = $rootProcessId -ne $null -and
        $resolvedProcessId -ne $null -and
        $measuredProcessId -ne $null -and
        $counterProcessId -ne $null -and
        -not [string]::IsNullOrWhiteSpace($resolutionStrategy) -and
        -not [string]::IsNullOrWhiteSpace($measurementSource) -and
        $resolvedEqualsMeasured -and
        $resolvedEqualsCounter -and
        (
            -not [string]::Equals($resolutionStrategy, 'root-process', [StringComparison]::OrdinalIgnoreCase) -or
            $rootEqualsResolved
        )

    if ($null -eq $diagnosticTarget) {
        $ContractFailures.Add("$SampleId`: diagnostic-target.json was not retained or could not be parsed.")
    }
    if ($null -eq $targetProcessMetrics) {
        $ContractFailures.Add("$SampleId`: targetProcessMetrics were not retained in result.json.")
    }
    if ([string]::IsNullOrWhiteSpace([string] $counterSummaryPath) -or -not (Test-Path -LiteralPath $counterSummaryPath -PathType Leaf)) {
        $ContractFailures.Add("$SampleId`: counters-summary.json was not retained for target attribution.")
    }
    elseif ($counterCaptureStatus -ne 'succeeded') {
        $ContractFailures.Add("$SampleId`: counters capture did not succeed (status '$counterCaptureStatus').")
    }
    if (-not $valid) {
        $ContractFailures.Add("$SampleId`: target attribution proof is invalid or incomplete (root=$rootProcessId resolved=$resolvedProcessId measured=$measuredProcessId counter=$counterProcessId strategy='$resolutionStrategy' source='$measurementSource').")
    }

    return [ordered]@{
        rootProcessId = $rootProcessId
        resolvedProcessId = $resolvedProcessId
        measuredProcessId = $measuredProcessId
        counterProcessId = $counterProcessId
        resolutionStrategy = if ([string]::IsNullOrWhiteSpace($resolutionStrategy)) { $null } else { $resolutionStrategy }
        measurementSource = $measurementSource
        counterProcessIdSource = $counterProcessIdSource
        resultArtifactPath = if ([string]::IsNullOrWhiteSpace([string] $runnerResultPath)) { $null } else { $runnerResultPath }
        diagnosticTargetArtifactPath = if ([string]::IsNullOrWhiteSpace([string] $diagnosticTargetPath)) { $null } else { $diagnosticTargetPath }
        counterSummaryArtifactPath = if ([string]::IsNullOrWhiteSpace([string] $counterSummaryPath)) { $null } else { $counterSummaryPath }
        counterCaptureStatus = if ([string]::IsNullOrWhiteSpace($counterCaptureStatus)) { $null } else { $counterCaptureStatus }
        countersAvailable = $countersAvailable
        rootCommandLine = if ([string]::IsNullOrWhiteSpace($commandLine)) { $null } else { $commandLine }
        rootExecutablePath = if ([string]::IsNullOrWhiteSpace($executablePath)) { $null } else { $executablePath }
        rootWorkingDirectory = if ([string]::IsNullOrWhiteSpace($workingDirectory)) { $null } else { $workingDirectory }
        commandIdentityAvailable = $commandIdentityAvailable
        rootEqualsResolved = $rootEqualsResolved
        resolvedEqualsMeasured = $resolvedEqualsMeasured
        resolvedEqualsCounter = $resolvedEqualsCounter
        valid = $valid
    }
}

function ConvertTo-ControllerState {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'Conservative' { 'conservative' }
        'Candidate' { 'candidate' }
        'Fallback' { 'fallback' }
        'Terminal' { 'terminal' }
        default { throw "Unknown adaptive controller state '$Value'." }
    }
}

function ConvertTo-PolicyValue {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacyCurrent' { 'legacy_current' }
        'Immediate' { 'immediate' }
        'ReadDominantBatch' { 'read_dominant_batch' }
        default { throw "Unknown receive-credit policy '$Value'." }
    }
}

function ConvertTo-ReasonCode {
    param([Parameter(Mandatory = $true)][string] $Value)

    switch ($Value) {
        'LegacyImmediate' { 'legacy_selector' }
        'LegacyReadDominantBatch' { 'legacy_selector' }
        'MissingSignal' { 'missing_signal' }
        'StaleSignal' { 'stale_signal' }
        'ContradictorySignals' { 'contradictory_signals' }
        'OutOfDomain' { 'out_of_domain' }
        'RuleVersionMismatch' { 'rule_version_mismatch' }
        'ArithmeticSaturated' { 'arithmetic_saturated' }
        'TerminalStarted' { 'terminal_started' }
        'ResourceGuard' { 'resource_guard' }
        'RecoveryGuard' { 'recovery_guard' }
        'FlowProgressGuard' { 'flow_progress_guard' }
        'CancellationOrDisposal' { 'cancellation_or_disposal' }
        'Shutdown' { 'shutdown' }
        default { throw "Unknown adaptive policy reason '$Value'." }
    }
}

function ConvertTo-SignalMask {
    param([AllowNull()][object] $Value)

    [uint64] $numeric = 0
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value) -or [string] $Value -eq 'None') {
        return $numeric
    }
    if ([uint64]::TryParse([string] $Value, [ref] $numeric)) {
        return $numeric
    }

    foreach ($name in ([string] $Value -split ',' | ForEach-Object { $_.Trim() })) {
        $bit = switch ($name) {
            'HasIssuedApplicationData' { 1 }
            'LiveObserverStreams' { 2 }
            'Lifecycle' { 4 }
            'QueueDelayEwma' { 8 }
            default { throw "Unknown adaptive observation signal '$name'." }
        }
        $numeric = $numeric -bor $bit
    }
    return $numeric
}

function ConvertTo-LifecycleFlags {
    param([AllowNull()][object] $Value)

    [uint64] $numeric = 0
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value) -or [string] $Value -eq 'None') {
        return $numeric
    }
    if ([uint64]::TryParse([string] $Value, [ref] $numeric)) {
        return $numeric
    }

    foreach ($name in ([string] $Value -split ',' | ForEach-Object { $_.Trim() })) {
        $bit = switch ($name) {
            'Establishing' { 1 }
            'Active' { 2 }
            'Closing' { 4 }
            'Draining' { 8 }
            'Discarded' { 16 }
            'Terminal' { 32 }
            'Disposed' { 64 }
            default { throw "Unknown adaptive lifecycle flag '$name'." }
        }
        $numeric = $numeric -bor $bit
    }
    return $numeric
}

function Get-ScenarioShape {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ExecutionRoot,

        [Parameter(Mandatory = $true)]
        [string] $Scenario
    )

    $scenarioRoot = Join-Path $ExecutionRoot 'scenarios'
    $escapedId = [regex]::Escape($Scenario)
    $idPattern = "(?m)^id:\s*$escapedId\s*$"
    foreach ($file in Get-ChildItem -LiteralPath $scenarioRoot -Filter '*.yaml' -Recurse -File) {
        $content = Get-Content -LiteralPath $file.FullName -Raw
        if ($content -notmatch $idPattern) {
            continue
        }

        $streamMatch = [regex]::Match($content, 'streamCount:\s*(\d+)')
        $payloadMatch = [regex]::Match($content, 'payloadSizeBytes:\s*(\d+)')
        $directionMatch = [regex]::Match($content, 'payloadDirection:\s*([^,}\r\n]+)')
        if (-not $streamMatch.Success -or -not $payloadMatch.Success) {
            throw "Scenario '$Scenario' does not declare a parseable QUIC stream count and payload size in $($file.FullName)."
        }

        return [ordered]@{
            path = $file.FullName
            streamsPerConnection = [int] $streamMatch.Groups[1].Value
            payloadBytes = [int] $payloadMatch.Groups[1].Value
            payloadDirection = if ($directionMatch.Success) { $directionMatch.Groups[1].Value.Trim().Trim('"', "'") } else { $null }
        }
    }

    throw "Scenario '$Scenario' was not found under $scenarioRoot."
}

foreach ($requiredPath in @($localBenchmarkScript, $resultSchemaPath, $epochSchemaPath, $evidenceValidationScript, $serverProjectPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required campaign input was not found: $requiredPath"
    }
}

if (-not $ShadowOnly) {
    if ($PolicyA -eq $PolicyB) {
        throw 'PolicyA and PolicyB must name different forced treatments.'
    }
    if (($PolicyA -eq 'legacy_current') -eq ($PolicyB -eq 'legacy_current')) {
        throw 'Exactly one treatment must be legacy_current so local classification has an explicit baseline.'
    }
}

$scenarioShape = Get-ScenarioShape -ExecutionRoot $ProtocolLabExecutionRoot -Scenario $ScenarioId
if ($scenarioShape.streamsPerConnection -ne $StreamsPerConnection) {
    throw "Scenario '$ScenarioId' requires $($scenarioShape.streamsPerConnection) streams per connection, but the cell requested $StreamsPerConnection."
}
if ($scenarioShape.payloadBytes -ne $PayloadBytes) {
    throw "Scenario '$ScenarioId' requires payloadBytes=$($scenarioShape.payloadBytes), but the cell requested $PayloadBytes."
}

if (-not $DryRun -and (Test-Path -LiteralPath $resolvedOutputRoot)) {
    $existingArtifact = Get-ChildItem -LiteralPath $resolvedOutputRoot -Force -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $existingArtifact) {
        throw "Campaign output already exists and will not be rewritten: $resolvedOutputRoot"
    }
}

New-Item -ItemType Directory -Path $resolvedOutputRoot -Force | Out-Null
$engineOutputRoot = Join-Path $resolvedOutputRoot 'protocol-lab-runs'
$samplesRoot = Join-Path $resolvedOutputRoot 'samples'
New-Item -ItemType Directory -Path $engineOutputRoot, $samplesRoot -Force | Out-Null

if (-not $NoBuild -and -not $DryRun) {
    $buildArguments = @('build', $serverProjectPath, '-c', 'Release')
    if ($NoRestore) {
        $buildArguments += '--no-restore'
    }

    & dotnet @buildArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Frozen campaign host build failed with exit code $LASTEXITCODE."
    }
}

if ($DryRun) {
    if ($ShadowOnly) {
        Write-Host 'Dry run: would execute one custom shadow-only sample with legacy_current applied.'
    }
    else {
        Write-Host "Dry run: would execute $SequenceProtocol for A=$PolicyA and B=$PolicyB."
    }
    Write-Host "Output root: $resolvedOutputRoot"
    return
}

$binaryIdentities = @(
    Get-FileIdentity -Role 'candidate_benchmark' -Path $serverBinaryPath
    Get-FileIdentity -Role 'candidate_runtime' -Path $runtimeBinaryPath
)
$frozenServerHash = $binaryIdentities[0].sha256
$frozenRuntimeHash = $binaryIdentities[1].sha256
$repositoryIdentities = @(
    Get-GitIdentity -Name 'quic-dotnet' -Path $repoRoot
    Get-GitIdentity -Name 'protocol-lab' -Path $ProtocolLabRoot
    Get-GitIdentity -Name 'protocol-lab-internal' -Path $ProtocolLabExecutionRoot
)
$effectiveSequenceProtocol = if ($ShadowOnly) { 'custom' } else { $SequenceProtocol }
$sequence = if ($ShadowOnly) {
    @('A')
}
elseif ($SequenceProtocol -eq 'ABBA') {
    @('A', 'B', 'B', 'A')
}
else {
    @('B', 'A', 'A', 'B')
}
$sequence = @($sequence)
$policyByTreatment = if ($ShadowOnly) { @{ A = 'legacy_current' } } else { @{ A = $PolicyA; B = $PolicyB } }
$samples = [System.Collections.Generic.List[object]]::new()
$shadowEpochsBySample = @{}
$sampleRunEvidenceBySampleId = @{}
$artifactPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$commands = [System.Collections.Generic.List[object]]::new()
$contractFailures = [System.Collections.Generic.List[string]]::new()
$pressureArtifactPaths = [System.Collections.Generic.List[string]]::new()
$environmentInvalid = $false
$startedUtc = (Get-Date).ToUniversalTime()

for ($index = 0; $index -lt $sequence.Count; $index++) {
    $treatment = $sequence[$index]
    $policy = $policyByTreatment[$treatment]
    $hostPolicy = if ($ShadowOnly) { 'shadow' } else { $policy }
    $sampleId = "sample-$($index + 1)-$treatment-$policy"
    $sampleRoot = Join-Path $samplesRoot $sampleId
    New-Item -ItemType Directory -Path $sampleRoot -Force | Out-Null
    $stdoutPath = Join-Path $sampleRoot 'campaign.stdout.log'
    $stderrPath = Join-Path $sampleRoot 'campaign.stderr.log'
    $commandPath = Join-Path $sampleRoot 'command.txt'
    $runIdPrefix = "$CampaignId-$CellId-$($index + 1)-$treatment"
    $runRoot = Join-Path $engineOutputRoot "$runIdPrefix-quic-transport-v1-comparison"
    $aggregatePath = Join-Path $runRoot 'aggregate-results.json'
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $localBenchmarkScript,
        '-ProtocolLabRoot', $ProtocolLabRoot,
        '-ProtocolLabExecutionRoot', $ProtocolLabExecutionRoot,
        '-UseProjectReferences',
        '-Suite', 'quic-transport-v1-comparison',
        '-Implementation', 'quic-dotnet-raw-dev',
        '-Scenario', $ScenarioId,
        '-WorkflowProfile', 'Quick',
        '-RunIdPrefix', $runIdPrefix,
        '-DurationSeconds', $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        '-WarmupSeconds', $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        '-Repetitions', '1',
        '-Connections', $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
        '-StreamsPerConnection', $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
        '-Output', $engineOutputRoot,
        '-FailOnError'
    )
    if ($NoRestore) {
        $arguments += '-NoRestore'
    }
    # Always capture host/process counters so forced-policy samples retain permanent pressure evidence.
    $arguments += @('-CaptureCounters', '-CounterRefreshInterval', '1')

    $commandText = 'pwsh ' + (($arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' ')
    Set-Content -LiteralPath $commandPath -Value $commandText -Encoding utf8
    $commands.Add([ordered]@{ sampleId = $sampleId; treatment = $treatment; policy = $policy; hostMode = $hostPolicy; command = $commandText })
    [void] $artifactPaths.Add($commandPath)

    $sampleStartedUtc = (Get-Date).ToUniversalTime()
    $previousPolicy = [Environment]::GetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY')
    try {
        [Environment]::SetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY', $hostPolicy)
        & pwsh @arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        [Environment]::SetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY', $previousPolicy)
    }
    $sampleEndedUtc = (Get-Date).ToUniversalTime()
    [void] $artifactPaths.Add($stdoutPath)
    [void] $artifactPaths.Add($stderrPath)

    $aggregate = $null
    if (Test-Path -LiteralPath $aggregatePath -PathType Leaf) {
        $aggregateDocument = Get-Content -LiteralPath $aggregatePath -Raw | ConvertFrom-Json -Depth 100
        $aggregate = @($aggregateDocument.aggregates | Where-Object {
            $_.implementationId -match 'incursa|quic-dotnet'
        }) | Select-Object -First 1
        [void] $artifactPaths.Add($aggregatePath)
    }
    $pressureArtifactPath = Get-ChildItem -LiteralPath $runRoot -Filter 'counters-summary.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if ([string]::IsNullOrWhiteSpace([string] $pressureArtifactPath)) {
        if (-not $ShadowOnly) {
            $contractFailures.Add("$sampleId`: counters-summary.json was not retained.")
        }
    }
    else {
        $pressureArtifactPaths.Add($pressureArtifactPath)
        [void] $artifactPaths.Add($pressureArtifactPath)
    }

    $adapterArtifactsPath = Get-ChildItem -LiteralPath $runRoot -Filter 'adapter-artifacts.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    $campaignHostStdoutPath = Join-Path $sampleRoot 'campaign-host.stdout.log'
    $campaignHostStderrPath = Join-Path $sampleRoot 'campaign-host.stderr.log'
    $shadowRawPath = $null
    $campaignHostSourceStdout = $null
    $campaignHostSourceStderr = $null
    if ($null -ne $adapterArtifactsPath) {
        [void] $artifactPaths.Add($adapterArtifactsPath)
        $adapterArtifacts = Get-Content -LiteralPath $adapterArtifactsPath -Raw | ConvertFrom-Json -Depth 30
        $campaignHostSourceStdout = @($adapterArtifacts.artifacts | Where-Object artifactId -eq 'server.stdout') |
            Select-Object -First 1 -ExpandProperty path
        $campaignHostSourceStderr = @($adapterArtifacts.artifacts | Where-Object artifactId -eq 'server.stderr') |
            Select-Object -First 1 -ExpandProperty path
    }

    if ([string]::IsNullOrWhiteSpace($campaignHostSourceStdout) -or
        -not (Test-Path -LiteralPath $campaignHostSourceStdout -PathType Leaf)) {
        $contractFailures.Add("$sampleId`: authoritative campaign-host stdout was not retained.")
    }
    else {
        Copy-Item -LiteralPath $campaignHostSourceStdout -Destination $campaignHostStdoutPath
        [void] $artifactPaths.Add($campaignHostStdoutPath)
        $reportedPolicy = [regex]::Match(
            (Get-Content -LiteralPath $campaignHostStdoutPath -Raw),
            'QUIC_RECEIVE_CREDIT_POLICY=([^\r\n]+)').Groups[1].Value
        if ($reportedPolicy -ne $hostPolicy) {
            $contractFailures.Add("$sampleId`: requested host mode '$hostPolicy' but host reported '$reportedPolicy'.")
        }

        $shadowContract = [regex]::Match(
            (Get-Content -LiteralPath $campaignHostStdoutPath -Raw),
            'QUIC_ADAPTIVE_RUNTIME_EPOCH_CONTRACT=([^\r\n]+)').Groups[1].Value
        if ($shadowContract -ne 'adaptive-runtime-epoch-raw-v1') {
            $contractFailures.Add("$sampleId`: adaptive-runtime epoch raw contract was not reported.")
        }

        $shadowRawPath = Join-Path $sampleRoot 'adaptive-runtime-epochs.raw.jsonl'
        $shadowPrefix = 'QUIC_ADAPTIVE_RUNTIME_EPOCH_JSON='
        $shadowLines = @(Get-Content -LiteralPath $campaignHostStdoutPath | Where-Object {
            $_.StartsWith($shadowPrefix, [StringComparison]::Ordinal)
        } | ForEach-Object {
            $_.Substring($shadowPrefix.Length)
        })
        if ($shadowLines.Count -eq 0) {
            $contractFailures.Add("$sampleId`: no adaptive-runtime epochs were retained.")
        }
        else {
            [System.IO.File]::WriteAllLines($shadowRawPath, $shadowLines, [System.Text.UTF8Encoding]::new($false))
            [void] $artifactPaths.Add($shadowRawPath)
            $shadowEpochsBySample[$sampleId] = @($shadowLines | ForEach-Object {
                $_ | ConvertFrom-Json -Depth 30
            })
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($campaignHostSourceStderr) -and
        (Test-Path -LiteralPath $campaignHostSourceStderr -PathType Leaf)) {
        Copy-Item -LiteralPath $campaignHostSourceStderr -Destination $campaignHostStderrPath
        [void] $artifactPaths.Add($campaignHostStderrPath)
    }

    $currentServerHash = (Get-FileHash -LiteralPath $serverBinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $currentRuntimeHash = (Get-FileHash -LiteralPath $runtimeBinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentServerHash -ne $frozenServerHash -or $currentRuntimeHash -ne $frozenRuntimeHash) {
        $contractFailures.Add("$sampleId`: a frozen campaign binary changed during the sequence.")
    }

    if ($null -ne $aggregate) {
        if ([int] $aggregate.connections -ne $Connections -or
            [int] $aggregate.effectiveStreamsPerConnection -ne $StreamsPerConnection -or
            [int] $aggregate.effectiveConcurrency -ne ($Connections * $StreamsPerConnection)) {
            $contractFailures.Add("$sampleId`: requested and effective workload shapes do not match.")
        }

        if ([string] $aggregate.evidence.comparabilityStatus -eq 'invalid') {
            $environmentInvalid = $true
        }
    }

    $targetAttribution = Resolve-SampleTargetAttribution `
        -SampleId $sampleId `
        -RunRoot $runRoot `
        -ArtifactPathSet $artifactPaths `
        -ContractFailures $contractFailures
    $sampleRunEvidence = Resolve-SampleRunEvidence `
        -SampleId $sampleId `
        -RunRoot $runRoot `
        -ArtifactPathSet $artifactPaths `
        -ContractFailures $contractFailures
    $sampleRunEvidenceBySampleId[$sampleId] = $sampleRunEvidence
    $outcome = Get-Outcome -Aggregate $aggregate -RunEvidence $sampleRunEvidence
    $correctness = Get-Correctness -ExitCode $exitCode -Aggregate $aggregate
    $samples.Add([ordered]@{
        sampleId = $sampleId
        treatment = $treatment
        sequenceIndex = $index
        exitCode = $exitCode
        outcomes = $outcome
        correctness = $correctness
        targetAttribution = $targetAttribution
        artifactPaths = @(
            $commandPath,
            $stdoutPath,
            $stderrPath,
            $aggregatePath,
            $campaignHostStdoutPath,
            $campaignHostStderrPath,
            $shadowRawPath,
            $pressureArtifactPath,
            $targetAttribution.resultArtifactPath,
            $targetAttribution.diagnosticTargetArtifactPath,
            $targetAttribution.counterSummaryArtifactPath,
            $sampleRunEvidence.quicBufferPoolSummaryArtifactPath
        ) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) -and (Test-Path -LiteralPath $_ -PathType Leaf) }
    })
}

$forcedEpochPolicyValues = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($sample in $samples) {
    if ($ShadowOnly -or -not $shadowEpochsBySample.ContainsKey($sample.sampleId)) {
        continue
    }

    $samplePolicy = [string] $policyByTreatment[$sample.treatment]
    $epochPolicies = @($shadowEpochsBySample[$sample.sampleId] | ForEach-Object {
        ConvertTo-PolicyValue -Value ([string] $_.snapshot.appliedPolicy)
    })
    foreach ($epochPolicy in $epochPolicies) {
        [void] $forcedEpochPolicyValues.Add($epochPolicy)
    }

    if (@($epochPolicies | Where-Object { $_ -ne $samplePolicy }).Count -gt 0) {
        $contractFailures.Add("$($sample.sampleId)`: policy_mismatch: declared '$samplePolicy' but one or more epoch snapshots reported a different applied policy.")
    }
}

$endedUtc = (Get-Date).ToUniversalTime()
$hasCorrectnessFailure = @($samples | Where-Object {
    -not $_.correctness.payloadValidated -or
    $_.correctness.failedOperations -ne 0 -or
    $_.correctness.timedOutOperations -ne 0 -or
    $_.correctness.protocolErrors -ne 0 -or
    $_.correctness.invariantViolations.Count -ne 0
}).Count -ne 0
$baselineTreatment = if ($PolicyA -eq 'legacy_current') { 'A' } else { 'B' }
$candidateTreatment = if ($baselineTreatment -eq 'A') { 'B' } else { 'A' }
$baselineSamples = @($samples | Where-Object { $_.treatment -eq $baselineTreatment })
$candidateSamples = @($samples | Where-Object { $_.treatment -eq $candidateTreatment })
$baselineThroughput = Get-Median -Values @($baselineSamples.outcomes.throughputBytesPerSecond)
$candidateThroughput = if ($ShadowOnly) { $null } else { Get-Median -Values @($candidateSamples.outcomes.throughputBytesPerSecond) }
$baselineP95 = Get-Median -Values @($baselineSamples.outcomes.latencyP95Ms)
$candidateP95 = if ($ShadowOnly) { $null } else { Get-Median -Values @($candidateSamples.outcomes.latencyP95Ms) }
$withinTreatmentRelativeRanges = @(@(
    Get-RelativeRange -Values @($baselineSamples.outcomes.throughputBytesPerSecond)
    Get-RelativeRange -Values @($baselineSamples.outcomes.latencyP95Ms)
    if (-not $ShadowOnly) {
        Get-RelativeRange -Values @($candidateSamples.outcomes.throughputBytesPerSecond)
        Get-RelativeRange -Values @($candidateSamples.outcomes.latencyP95Ms)
    }
) | Where-Object { $null -ne $_ })
$maximumWithinTreatmentRelativeRange = if ($withinTreatmentRelativeRanges.Count -eq 0) {
    $null
}
else {
    ($withinTreatmentRelativeRanges | Measure-Object -Maximum).Maximum
}
if ($null -ne $maximumWithinTreatmentRelativeRange -and $maximumWithinTreatmentRelativeRange -gt 0.05) {
    $environmentInvalid = $true
}
$classification = if ($contractFailures.Count -ne 0) {
    'invalid_contract'
}
elseif ($hasCorrectnessFailure) {
    'failed_correctness'
}
elseif ($environmentInvalid) {
    'invalid_environment'
}
elseif ($StressOnly) {
    'stress_only'
}
else {
    if (($null -ne $baselineThroughput -and $null -ne $candidateThroughput -and $candidateThroughput -lt ($baselineThroughput * 0.95)) -or
        ($null -ne $baselineP95 -and $null -ne $candidateP95 -and $candidateP95 -gt ($baselineP95 * 1.05))) {
        'negative_retained'
    }
    elseif ($null -ne $baselineThroughput -and $null -ne $candidateThroughput -and
        $candidateThroughput -ge ($baselineThroughput * 1.05) -and
        ($null -eq $baselineP95 -or $null -eq $candidateP95 -or $candidateP95 -le ($baselineP95 * 1.05))) {
        'accepted_local'
    }
    else {
        'neutral_local'
    }
}

$resultRunId = if ($ShadowOnly) {
    "$CampaignId-$CellId-shadow"
}
else {
    "$CampaignId-$CellId-$($SequenceProtocol.ToLowerInvariant())"
}
$epochRowPaths = [System.Collections.Generic.List[string]]::new()
$allShadowEpochs = @($shadowEpochsBySample.Values | ForEach-Object { @($_) })
if ($contractFailures.Count -eq 0) {
    $quicRepository = @($repositoryIdentities | Where-Object name -eq 'quic-dotnet') | Select-Object -First 1
    $benchmarkHash = [string] $binaryIdentities[0].sha256
    $runtimeHash = [string] $binaryIdentities[1].sha256
    $hostFingerprint = "$env:COMPUTERNAME|$([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)|$([Environment]::ProcessorCount)"
    $epochRoot = Join-Path $resolvedOutputRoot 'epoch-rows'
    New-Item -ItemType Directory -Path $epochRoot -Force | Out-Null

    foreach ($sample in $samples) {
        if (-not $shadowEpochsBySample.ContainsKey($sample.sampleId)) {
            continue
        }

        $rawPath = @($sample.artifactPaths | Where-Object {
            [System.IO.Path]::GetFileName($_) -eq 'adaptive-runtime-epochs.raw.jsonl'
        }) | Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace([string] $rawPath)) {
            $contractFailures.Add("$($sample.sampleId): retained shadow epochs have no raw source artifact.")
            continue
        }

        $sourceHash = (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $firstEpochStartByConnection = @{}
        foreach ($epoch in @($shadowEpochsBySample[$sample.sampleId])) {
            $connectionKey = [string] $epoch.connectionKey
            if (-not $firstEpochStartByConnection.ContainsKey($connectionKey)) {
                $firstEpochStartByConnection[$connectionKey] = [long] $epoch.observation.epochStartTicks
            }

            $epochStartOffsetMicros = [long] [Math]::Max(
                0,
                (([long] $epoch.observation.epochStartTicks - [long] $firstEpochStartByConnection[$connectionKey]) * 1000000.0) /
                    [Diagnostics.Stopwatch]::Frequency)
            $reasonCode = ConvertTo-ReasonCode -Value ([string] $epoch.snapshot.reason)
            $state = ConvertTo-ControllerState -Value ([string] $epoch.snapshot.state)
            $previousState = ConvertTo-ControllerState -Value ([string] $epoch.snapshot.previousState)
            $appliedPolicy = ConvertTo-PolicyValue -Value ([string] $epoch.snapshot.appliedPolicy)
            $proposedPolicy = ConvertTo-PolicyValue -Value ([string] $epoch.snapshot.proposedPolicy)
            $missingSignalMask = ConvertTo-SignalMask -Value $epoch.observation.missingSignalMask
            $staleSignalMask = ConvertTo-SignalMask -Value $epoch.observation.staleSignalMask
            $lifecycleFlags = ConvertTo-LifecycleFlags -Value $epoch.observation.lifecycleFlags
            $outOfDomain = $reasonCode -eq 'out_of_domain'
            $exclusionFlags = [System.Collections.Generic.List[string]]::new()
            if (-not $ShadowOnly -and $appliedPolicy -ne $policyByTreatment[$sample.treatment]) { $exclusionFlags.Add('policy_mismatch') }
            if ($missingSignalMask -ne 0) { $exclusionFlags.Add('observation_missing') }
            if ($staleSignalMask -ne 0) { $exclusionFlags.Add('observation_stale') }
            if ($reasonCode -eq 'arithmetic_saturated') { $exclusionFlags.Add('observation_saturated') }
            if ($outOfDomain) { $exclusionFlags.Add('out_of_domain') }
            if ($epochStartOffsetMicros -lt ($WarmupSeconds * 1000000L)) { $exclusionFlags.Add('warmup') }
            if (($lifecycleFlags -band 96) -ne 0) { $exclusionFlags.Add('terminal_partial_epoch') }
            if ($exclusionFlags.Count -eq 0) { $exclusionFlags.Add('none') }

            $rowId = "$($sample.sampleId)-$connectionKey-epoch-$([uint64]$epoch.observation.connectionEpochSequence)"
            $row = [ordered]@{
                schemaVersion = 'adaptive-runtime-policy-epoch-dataset-v1'
                datasetId = "$CampaignId-$CellId-$(if ($ShadowOnly) { 'shadow' } else { 'forced' })-dataset"
                rowId = $rowId
                campaignId = $CampaignId
                runId = $resultRunId
                cellId = $CellId
                sampleId = [string] $sample.sampleId
                repetition = 0
                connectionKey = $connectionKey
                epochIndex = [long] ([uint64] $epoch.observation.connectionEpochSequence - 1)
                epochStartOffsetMicros = $epochStartOffsetMicros
                epochDurationMicros = [long] $epoch.observation.activeDurationMicros
                preDecisionObservations = [ordered]@{
                    openStreams = [long] $epoch.observation.openStreams
                    liveObserverStreams = [long] $epoch.observation.liveObserverStreams
                    activeStreams = $null
                    runnableStreams = $null
                    receiveActiveStreams = $null
                    sendActiveStreams = $null
                    inboundBytesEpoch = $null
                    outboundBytesEpoch = $null
                    inboundRateEwmaBps = $null
                    outboundRateEwmaBps = $null
                    queuedApplicationWrites = [long] $epoch.observation.queuedApplicationWrites
                    distinctQueuedSendStreams = $null
                    queueDelayEwmaMicros = if (($missingSignalMask -band 8) -ne 0) { $null } else { [long] $epoch.observation.queueDelayEwmaMicros }
                    actorServiceTimeEwmaMicros = $null
                    queueToServiceRatioQ16 = $null
                    connectionReceiveHeadroomBytes = $null
                    estimatedReceiveExhaustionMicros = $null
                    connectionCreditPendingBytes = $null
                    timeSinceCreditPublicationMicros = $null
                    connectionFlowBlockedMicrosEpoch = $null
                    streamFlowBlockedMicrosEpoch = $null
                    outboundBacklogBytes = $null
                    congestionWindowBytes = $null
                    bytesInFlight = $null
                    lossEventsEpoch = $null
                    retransmissionsEpoch = $null
                    ptoEventsEpoch = $null
                    retainedSendBytes = $null
                    retainedReceiveBytes = $null
                    advisorAgeMicros = $null
                    hasIssuedApplicationData = [bool] $epoch.observation.hasIssuedApplicationData
                    missingSignalMask = [long] $missingSignalMask
                    staleSignalMask = [long] $staleSignalMask
                    lifecycleFlags = [long] $lifecycleFlags
                    outOfDomain = $outOfDomain
                }
                currentPolicyState = [ordered]@{
                    snapshotVersion = [string] $epoch.snapshot.snapshotVersion
                    ruleVersion = [string] $epoch.snapshot.ruleVersion
                    observationContractVersion = [string] $epoch.observation.observationContractVersion
                    state = $state
                    appliedPolicy = $appliedPolicy
                    hasIssuedApplicationData = [bool] $epoch.snapshot.hasIssuedApplicationData
                }
                candidatePolicySelection = [ordered]@{
                    selectionSource = if ($ShadowOnly) { 'shadow_rule' } else { 'forced' }
                    selectedPolicy = $appliedPolicy
                    shadowRecommendation = $proposedPolicy
                    reasonCode = $reasonCode
                    contradictorySignals = $reasonCode -eq 'contradictory_signals'
                }
                transitionState = [ordered]@{
                    previousState = $previousState
                    state = $state
                    transitioned = [bool] $epoch.snapshot.transitioned
                    reasonCode = $reasonCode
                }
                dwellState = [ordered]@{
                    stateEpochCount = [long] $epoch.snapshot.stateEpochCount
                    stateDurationMicros = [long] $epoch.snapshot.stateDurationMicros
                    candidateEvidenceCount = [long] $epoch.snapshot.candidateEvidenceCount
                    reliefEvidenceCount = [long] $epoch.snapshot.reliefEvidenceCount
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
                correctnessFlags = [ordered]@{
                    payloadValid = [bool] $sample.correctness.payloadValidated
                    protocolValid = [int] $sample.correctness.protocolErrors -eq 0
                    timedOut = [int] $sample.correctness.timedOutOperations -ne 0
                    cancellationValid = $null
                    disposalValid = $null
                    ownershipValid = [int] $sample.correctness.failedOperations -eq 0
                    terminalValid = [int] $sample.correctness.failedOperations -eq 0
                    violationCodes = @($sample.correctness.invariantViolations)
                }
                fairnessFlags = [ordered]@{
                    assessed = $false
                    starvationObserved = $false
                    guardrailViolated = $false
                    violationCodes = @()
                }
                provenance = [ordered]@{
                    repositoryName = [string] $quicRepository.name
                    repositoryPath = [string] $quicRepository.path
                    repositoryBranch = $quicRepository.branch
                    repositoryRemoteUrl = $quicRepository.remoteUrl
                    repositoryCommit = [string] $quicRepository.commit
                    repositoryDirty = [bool] $quicRepository.dirty
                    benchmarkSha256 = $benchmarkHash
                    runtimeSha256 = $runtimeHash
                    hostFingerprint = $hostFingerprint
                    os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
                    architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
                    processorCount = [Environment]::ProcessorCount
                    dotnetRuntime = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
                    monotonicTimerFrequencyHz = [Diagnostics.Stopwatch]::Frequency
                    scriptVersion = 'adaptive-runtime-epoch-export-v1'
                    toolVersions = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString() }
                    resultSchemaVersion = 'adaptive-runtime-policy-local-result-v1'
                    datasetSchemaVersion = 'adaptive-runtime-policy-epoch-dataset-v1'
                    ruleVersion = [string] $epoch.snapshot.ruleVersion
                    observationContractVersion = [string] $epoch.observation.observationContractVersion
                    sourceArtifactPath = [System.IO.Path]::GetFullPath($rawPath)
                    sourceArtifactSha256 = $sourceHash
                    transformation = [ordered]@{
                        name = 'adaptive-runtime-epoch-export'
                        version = '1.0.0'
                        codeCommit = [string] $quicRepository.commit
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
                    warmupMicros = $WarmupSeconds * 1000000L
                    measurementMicros = $DurationSeconds * 1000000L
                    arrivalPattern = $ArrivalPattern
                    lossPercent = 0
                    delayMs = 0
                }
                analysisExclusionFlags = @($exclusionFlags)
            }

            $canonicalRow = $row | ConvertTo-Json -Depth 100 -Compress
            $canonicalHash = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonicalRow))).ToLowerInvariant()
            $row.provenance.transformation.outputSha256 = $canonicalHash
            $rowPath = Join-Path $epochRoot "$rowId.json"
            $row | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $rowPath -Encoding utf8
            $rowJson = Get-Content -LiteralPath $rowPath -Raw
            if (-not ($rowJson | Test-Json -SchemaFile $epochSchemaPath -ErrorAction Stop)) {
                throw "Generated epoch row did not validate against $epochSchemaPath. Retained row: $rowPath"
            }

            $epochRowPaths.Add($rowPath)
            [void] $artifactPaths.Add($rowPath)
        }
    }
}

$manifestPath = Join-Path $resolvedOutputRoot 'cell-manifest.json'
$manifest = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-local-cell-manifest-v1'
    campaignId = $CampaignId
    cellId = $CellId
    sequenceProtocol = $effectiveSequenceProtocol
    sequence = $sequence
    treatments = if ($ShadowOnly) { [ordered]@{ A = 'legacy_current' } } else { [ordered]@{ A = $PolicyA; B = $PolicyB } }
    workload = [ordered]@{
        scenarioId = $ScenarioId
        trafficShape = $TrafficShape
        accountingMode = $AccountingMode
        arrivalPattern = $ArrivalPattern
        payloadBytes = $PayloadBytes
        connections = $Connections
        streamsPerConnection = $StreamsPerConnection
        warmupSeconds = $WarmupSeconds
        durationSeconds = $DurationSeconds
    }
    repositories = $repositoryIdentities
    binaries = $binaryIdentities
    commands = @($commands)
    retainedNegativeEvidence = @(
        'C:\shared\temp\quic-flow-credit-cadence-20260720',
        'docs/performance-improvement-wishlist.md'
    )
}
$manifest | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $manifestPath -Encoding utf8
[void] $artifactPaths.Add($manifestPath)

$checksumInventoryPath = Join-Path $resolvedOutputRoot 'checksum-inventory.json'
$checksumRows = @($artifactPaths | Sort-Object | ForEach-Object {
    if (Test-Path -LiteralPath $_ -PathType Leaf) {
        [ordered]@{
            path = [System.IO.Path]::GetFullPath($_)
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
})
[ordered]@{
    schemaVersion = 'adaptive-runtime-policy-checksum-inventory-v1'
    generatedUtc = (Get-Date).ToUniversalTime().ToString('O')
    files = $checksumRows
} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $checksumInventoryPath -Encoding utf8
[void] $artifactPaths.Add($checksumInventoryPath)

$artifacts = @($artifactPaths | Sort-Object | ForEach-Object {
    if (Test-Path -LiteralPath $_ -PathType Leaf) {
        [ordered]@{
            kind = Get-ArtifactKind -Path $_
            path = [System.IO.Path]::GetFullPath($_)
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
})
$allWarnings = @($samples | ForEach-Object { $_.correctness.invariantViolations })
$sampleRunEvidence = @($sampleRunEvidenceBySampleId.Values)
$resultNotes = [System.Collections.Generic.List[string]]::new()
$resultNotes.Add('Local diagnostic evidence only; this result does not authorize active_internal or ProtocolLab submission.')
if ($StressOnly) {
    $resultNotes.Add('This cell was declared stress-only and cannot serve as a regression or promotion gate.')
}
$resultNotes.Add('The host and generator share a machine, so target and generator health remain limited.')
$resultNotes.Add('Sample and aggregate buffer-pool rent and peak-outstanding measurements come only from retained quic-buffer-pool-summary.json metrics; generic managed-allocation and peak-retained-memory fields remain null.')
$resultNotes.Add('Fairness remains unassessed because retained request latency/completion metrics are not proof of stream-level fairness. Per-epoch completion and memory outcomes also remain null.')
foreach ($failure in $contractFailures) {
    $resultNotes.Add("contract: $failure")
}
$hostFingerprint = "$env:COMPUTERNAME|$([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)|$([Environment]::ProcessorCount)"
$reasonCounts = [ordered]@{}
foreach ($epoch in $allShadowEpochs) {
    $reason = ConvertTo-ReasonCode -Value ([string] $epoch.snapshot.reason)
    if (-not $reasonCounts.Contains($reason)) {
        $reasonCounts[$reason] = 0
    }
    $reasonCounts[$reason]++
}
$shadowSummaryArtifactPath = @($artifactPaths | Where-Object {
    [System.IO.Path]::GetFileName($_) -eq 'adaptive-runtime-epochs.raw.jsonl'
}) | Select-Object -First 1
$resultPath = Join-Path $resolvedOutputRoot 'local-result.json'
$result = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-local-result-v1'
    campaignId = $CampaignId
    runId = $resultRunId
    cellId = $CellId
    startedUtc = $startedUtc.ToString('O')
    endedUtc = $endedUtc.ToString('O')
    repoRoot = $repoRoot
    classification = $classification
    repositoryIdentities = $repositoryIdentities
    binaryProvenance = [ordered]@{ frozen = $true; assemblies = $binaryIdentities }
    policyAxis = 'receive_credit_publication'
    mode = if ($ShadowOnly) { 'shadow' } else { 'forced' }
    policyConfiguration = [ordered]@{
        appliedPolicy = if ($ShadowOnly) {
            'legacy_current'
        }
        elseif ($forcedEpochPolicyValues.Count -eq 1) {
            $forcedEpochPolicyValues | Select-Object -First 1
        }
        else {
            'not_applicable'
        }
        forcedPolicy = if (-not $ShadowOnly -and $forcedEpochPolicyValues.Count -eq 1) {
            $forcedEpochPolicyValues | Select-Object -First 1
        }
        else {
            $null
        }
        shadowEnabled = [bool] $ShadowOnly
        shadowPolicy = if ($allShadowEpochs.Count -gt 0) {
            $shadowPolicies = @($allShadowEpochs | ForEach-Object {
                ConvertTo-PolicyValue -Value ([string] $_.snapshot.proposedPolicy)
            } | Select-Object -Unique)
            if ($shadowPolicies.Count -eq 1) { $shadowPolicies[0] } else { $null }
        }
        else {
            $null
        }
        ruleVersion = 'receive-credit-legacy-v1'
        observationContractVersion = 'adaptive-runtime-connection-observation-v1'
        anomalyBudgets = [ordered]@{
            maxMissingEpochPercent = 0
            maxStaleEpochPercent = 0
            maxOutOfDomainEpochPercent = 0
            maxContradictoryEpochPercent = 0
        }
        legacySelectorCommit = '1b2611e1'
        stickyWriteEligibilityBypassed = -not $ShadowOnly -and ($PolicyA -eq 'read_dominant_batch' -or $PolicyB -eq 'read_dominant_batch')
        axisSettings = [ordered]@{
            treatmentA = $PolicyA
            treatmentB = $PolicyB
            baselineTreatment = $baselineTreatment
            candidateTreatment = $candidateTreatment
            baselineThroughputBytesPerSecond = $baselineThroughput
            candidateThroughputBytesPerSecond = $candidateThroughput
            baselineLatencyP95Ms = $baselineP95
            candidateLatencyP95Ms = $candidateP95
            maximumWithinTreatmentRelativeRange = $maximumWithinTreatmentRelativeRange
        }
    }
    workload = [ordered]@{
        scenarioId = $ScenarioId
        trafficShape = $TrafficShape
        payloadBytes = $PayloadBytes
        totalBytes = $null
        accountingMode = $AccountingMode
        connections = $Connections
        streamsPerConnection = $StreamsPerConnection
        concurrency = $Connections * $StreamsPerConnection
        arrivalPattern = $ArrivalPattern
        warmupSeconds = $WarmupSeconds
        durationSeconds = $DurationSeconds
        repetitions = $sequence.Count
        effectivePayloadBytes = $PayloadBytes
        effectiveConnections = $Connections
        effectiveStreamsPerConnection = $StreamsPerConnection
        effectiveConcurrency = $Connections * $StreamsPerConnection
        lossPercent = 0
        delayMs = 0
        receiveWindowBytes = 16777216
        applicationConsumptionDelayMs = 0
        requestedEffectiveMatch = $contractFailures.Count -eq 0
    }
    environment = [ordered]@{
        hostFingerprint = $hostFingerprint
        os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        processorCount = [Environment]::ProcessorCount
        availableMemoryBytes = [GC]::GetGCMemoryInfo().TotalAvailableMemoryBytes
        dotnetRuntime = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
        monotonicTimerFrequencyHz = [Diagnostics.Stopwatch]::Frequency
        toolVersions = [ordered]@{ dotnet = (& dotnet --version).Trim(); powershell = $PSVersionTable.PSVersion.ToString() }
        topology = 'same_host'
        targetHealth = if ($environmentInvalid) { 'invalid' } else { 'limited' }
        generatorHealth = if ($environmentInvalid) { 'invalid' } else { 'limited' }
        cpuLimit = $null
        pressureArtifactPath = if ($pressureArtifactPaths.Count -eq 0) { $null } else { $pressureArtifactPaths[0] }
    }
    sequenceProtocol = $effectiveSequenceProtocol
    treatments = if ($ShadowOnly) {
        [ordered]@{
            A = [ordered]@{ policy = 'legacy_current'; benchmarkBinaryRole = 'candidate_benchmark'; runtimeBinaryRole = 'candidate_runtime' }
        }
    }
    else {
        [ordered]@{
            A = [ordered]@{ policy = $PolicyA; benchmarkBinaryRole = 'candidate_benchmark'; runtimeBinaryRole = 'candidate_runtime' }
            B = [ordered]@{ policy = $PolicyB; benchmarkBinaryRole = 'candidate_benchmark'; runtimeBinaryRole = 'candidate_runtime' }
        }
    }
    sequence = $sequence
    samples = @($samples)
    aggregateOutcomes = [ordered]@{
        throughputBytesPerSecond = Get-Median -Values @($samples.outcomes.throughputBytesPerSecond)
        operationsPerSecond = Get-Median -Values @($samples.outcomes.operationsPerSecond)
        latencyP50Ms = Get-Median -Values @($samples.outcomes.latencyP50Ms)
        latencyP95Ms = Get-Median -Values @($samples.outcomes.latencyP95Ms)
        latencyP99Ms = Get-Median -Values @($samples.outcomes.latencyP99Ms)
        allocatedBytes = $null
        peakRetainedBytes = $null
        bufferPoolRentedBytes = Get-RoundedMedianInt64 -Values @($samples.outcomes.bufferPoolRentedBytes)
        bufferPoolOutstandingPeakBytes = Get-RoundedMedianInt64 -Values @($samples.outcomes.bufferPoolOutstandingPeakBytes)
        queueDelayP50Ms = $null
        queueDelayP95Ms = $null
        lossEvents = $null
        ptoEvents = $null
    }
    correctnessOutcomes = [ordered]@{
        payloadValidated = -not $hasCorrectnessFailure
        failedOperations = [int] ($samples | Measure-Object -Property { $_.correctness.failedOperations } -Sum).Sum
        timedOutOperations = [int] ($samples | Measure-Object -Property { $_.correctness.timedOutOperations } -Sum).Sum
        protocolErrors = [int] ($samples | Measure-Object -Property { $_.correctness.protocolErrors } -Sum).Sum
        cancellationFailures = 0
        disposalFailures = 0
        invariantViolations = @($allWarnings)
    }
    fairnessOutcomes = [ordered]@{
        assessed = $false
        streamCompletionP95Ms = $null
        streamCompletionP99Ms = $null
        starvationCount = 0
        violations = @()
    }
    diagnosticSignals = [ordered]@{
        observationEnabled = $allShadowEpochs.Count -gt 0
        shadowEpochCount = $allShadowEpochs.Count
        transitionCount = @($allShadowEpochs | Where-Object { $_.snapshot.transitioned }).Count
        outOfDomainEpochCount = @($allShadowEpochs | Where-Object { $_.snapshot.reason -eq 'OutOfDomain' }).Count
        contradictoryEpochCount = @($allShadowEpochs | Where-Object { $_.snapshot.reason -eq 'ContradictorySignals' }).Count
        missingEpochCount = @($allShadowEpochs | Where-Object { (ConvertTo-SignalMask -Value $_.observation.missingSignalMask) -ne 0 }).Count
        staleEpochCount = @($allShadowEpochs | Where-Object { (ConvertTo-SignalMask -Value $_.observation.staleSignalMask) -ne 0 }).Count
        reasonCounts = $reasonCounts
        summaryArtifactPath = if ([string]::IsNullOrWhiteSpace([string] $shadowSummaryArtifactPath)) { $null } else { [string] $shadowSummaryArtifactPath }
    }
    artifacts = $artifacts
    retainedEvidenceRefs = @(
        'C:\shared\temp\quic-flow-credit-cadence-20260720',
        'docs/performance-improvement-wishlist.md'
    )
    notes = @($resultNotes)
}
if ($classification -eq 'negative_retained') {
    $result.negativeEvidenceClass = 'other'
}
$result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $resultPath -Encoding utf8

$resultJson = Get-Content -LiteralPath $resultPath -Raw
if (-not ($resultJson | Test-Json -SchemaFile $resultSchemaPath -ErrorAction Stop)) {
    throw "Generated local result did not validate against $resultSchemaPath. Retained result: $resultPath"
}

if ($epochRowPaths.Count -gt 0) {
    & $evidenceValidationScript -LocalResultPath $resultPath -EpochDatasetPath @($epochRowPaths) |
        Set-Content -LiteralPath (Join-Path $resolvedOutputRoot 'evidence-validation.json') -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "Generated adaptive-runtime evidence did not pass schema/join validation. Retained output: $resolvedOutputRoot"
    }
}

Write-Host "Adaptive runtime local cell completed."
Write-Host "  classification: $classification"
Write-Host "  result: $resultPath"
Write-Host "  manifest: $manifestPath"
Write-Host "  checksum inventory: $checksumInventoryPath"
