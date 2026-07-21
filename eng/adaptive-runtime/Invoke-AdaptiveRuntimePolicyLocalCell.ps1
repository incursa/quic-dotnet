# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = 'C:\shared\src\incursa\protocol-lab',

    [string] $ProtocolLabExecutionRoot = 'C:\shared\src\incursa\protocol-lab-internal',

    [string] $CampaignId = "adaptive-receive-credit-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [string] $CellId = 'sustained-upload-1kb-c16',

    [ValidateSet('ABBA', 'BAAB')]
    [string] $SequenceProtocol = 'ABBA',

    [ValidateSet('legacy_current', 'immediate', 'read_dominant_batch')]
    [string] $PolicyA = 'legacy_current',

    [ValidateSet('legacy_current', 'immediate', 'read_dominant_batch')]
    [string] $PolicyB = 'read_dominant_batch',

    [string] $ScenarioId = 'quic.transport.sustained-stream.16384x1kb',

    [ValidateSet('upload', 'download', 'duplex', 'request_response', 'streaming')]
    [string] $TrafficShape = 'upload',

    [ValidateSet('fixed_total', 'fixed_per_stream')]
    [string] $AccountingMode = 'fixed_total',

    [ValidateSet('sparse', 'bursty', 'sustained', 'stream_churn')]
    [string] $ArrivalPattern = 'sustained',

    [ValidateRange(0, [int]::MaxValue)]
    [int] $PayloadBytes = 1024,

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

function Get-Outcome {
    param([AllowNull()][object] $Aggregate)

    if ($null -eq $Aggregate) {
        return [ordered]@{
            throughputBytesPerSecond = $null
            operationsPerSecond = $null
            latencyP50Ms = $null
            latencyP95Ms = $null
            latencyP99Ms = $null
            allocatedBytes = $null
            peakRetainedBytes = $null
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
    if ($name.EndsWith('.stdout.log', [StringComparison]::OrdinalIgnoreCase) -or $name -eq 'server.stdout.txt') { return 'stdout' }
    if ($name.EndsWith('.stderr.log', [StringComparison]::OrdinalIgnoreCase) -or $name -eq 'server.stderr.txt') { return 'stderr' }
    return 'other'
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

foreach ($requiredPath in @($localBenchmarkScript, $resultSchemaPath, $serverProjectPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required campaign input was not found: $requiredPath"
    }
}

if ($PolicyA -eq $PolicyB) {
    throw 'PolicyA and PolicyB must name different forced treatments.'
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
    Write-Host "Dry run: would execute $SequenceProtocol for A=$PolicyA and B=$PolicyB."
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
$sequence = if ($SequenceProtocol -eq 'ABBA') { @('A', 'B', 'B', 'A') } else { @('B', 'A', 'A', 'B') }
$policyByTreatment = @{ A = $PolicyA; B = $PolicyB }
$samples = [System.Collections.Generic.List[object]]::new()
$artifactPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$commands = [System.Collections.Generic.List[object]]::new()
$contractFailures = [System.Collections.Generic.List[string]]::new()
$environmentInvalid = $false
$startedUtc = (Get-Date).ToUniversalTime()

for ($index = 0; $index -lt $sequence.Count; $index++) {
    $treatment = $sequence[$index]
    $policy = $policyByTreatment[$treatment]
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

    $commandText = 'pwsh ' + (($arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' ')
    Set-Content -LiteralPath $commandPath -Value $commandText -Encoding utf8
    $commands.Add([ordered]@{ sampleId = $sampleId; treatment = $treatment; policy = $policy; command = $commandText })
    [void] $artifactPaths.Add($commandPath)

    $sampleStartedUtc = (Get-Date).ToUniversalTime()
    $previousPolicy = [Environment]::GetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY')
    try {
        [Environment]::SetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY', $policy)
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

    $adapterArtifactsPath = Get-ChildItem -LiteralPath $runRoot -Filter 'adapter-artifacts.json' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    $campaignHostStdoutPath = Join-Path $sampleRoot 'campaign-host.stdout.log'
    $campaignHostStderrPath = Join-Path $sampleRoot 'campaign-host.stderr.log'
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
        if ($reportedPolicy -ne $policy) {
            $contractFailures.Add("$sampleId`: requested policy '$policy' but host reported '$reportedPolicy'.")
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

    $outcome = Get-Outcome -Aggregate $aggregate
    $correctness = Get-Correctness -ExitCode $exitCode -Aggregate $aggregate
    $samples.Add([ordered]@{
        sampleId = $sampleId
        treatment = $treatment
        sequenceIndex = $index
        exitCode = $exitCode
        outcomes = $outcome
        correctness = $correctness
        artifactPaths = @($commandPath, $stdoutPath, $stderrPath, $aggregatePath, $campaignHostStdoutPath, $campaignHostStderrPath) |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    })
}

$endedUtc = (Get-Date).ToUniversalTime()
$hasCorrectnessFailure = @($samples | Where-Object {
    -not $_.correctness.payloadValidated -or
    $_.correctness.failedOperations -ne 0 -or
    $_.correctness.timedOutOperations -ne 0 -or
    $_.correctness.protocolErrors -ne 0 -or
    $_.correctness.invariantViolations.Count -ne 0
}).Count -ne 0
$classification = if ($contractFailures.Count -ne 0) {
    'invalid_contract'
}
elseif ($hasCorrectnessFailure) {
    'failed_correctness'
}
elseif ($environmentInvalid) {
    'invalid_environment'
}
else {
    $aSamples = @($samples | Where-Object { $_.treatment -eq 'A' })
    $bSamples = @($samples | Where-Object { $_.treatment -eq 'B' })
    $aThroughput = Get-Median -Values @($aSamples.outcomes.throughputBytesPerSecond)
    $bThroughput = Get-Median -Values @($bSamples.outcomes.throughputBytesPerSecond)
    $aP95 = Get-Median -Values @($aSamples.outcomes.latencyP95Ms)
    $bP95 = Get-Median -Values @($bSamples.outcomes.latencyP95Ms)
    if (($null -ne $aThroughput -and $null -ne $bThroughput -and $bThroughput -lt ($aThroughput * 0.95)) -or
        ($null -ne $aP95 -and $null -ne $bP95 -and $bP95 -gt ($aP95 * 1.05))) {
        'negative_retained'
    }
    else {
        'neutral_local'
    }
}

$manifestPath = Join-Path $resolvedOutputRoot 'cell-manifest.json'
$manifest = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-local-cell-manifest-v1'
    campaignId = $CampaignId
    cellId = $CellId
    sequenceProtocol = $SequenceProtocol
    sequence = $sequence
    treatments = [ordered]@{ A = $PolicyA; B = $PolicyB }
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
$resultNotes = [System.Collections.Generic.List[string]]::new()
$resultNotes.Add('Local diagnostic evidence only; this result does not authorize active_internal or ProtocolLab submission.')
$resultNotes.Add('The host and generator share a machine, so target and generator health remain limited.')
$resultNotes.Add('Allocation, retained-memory, and fairness outcomes require separate instrumentation before acceptance.')
foreach ($failure in $contractFailures) {
    $resultNotes.Add("contract: $failure")
}
$hostFingerprint = "$env:COMPUTERNAME|$([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)|$([Environment]::ProcessorCount)"
$resultPath = Join-Path $resolvedOutputRoot 'local-result.json'
$result = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-local-result-v1'
    campaignId = $CampaignId
    runId = "$CampaignId-$CellId-$($SequenceProtocol.ToLowerInvariant())"
    cellId = $CellId
    startedUtc = $startedUtc.ToString('O')
    endedUtc = $endedUtc.ToString('O')
    repoRoot = $repoRoot
    classification = $classification
    repositoryIdentities = $repositoryIdentities
    binaryProvenance = [ordered]@{ frozen = $true; assemblies = $binaryIdentities }
    policyAxis = 'receive_credit_publication'
    mode = 'forced'
    policyConfiguration = [ordered]@{
        appliedPolicy = 'not_applicable'
        forcedPolicy = $null
        shadowEnabled = $false
        shadowPolicy = $null
        ruleVersion = 'receive-credit-shadow-v1'
        observationContractVersion = 'adaptive-runtime-observation-v1'
        anomalyBudgets = [ordered]@{
            maxMissingEpochPercent = 0
            maxStaleEpochPercent = 0
            maxOutOfDomainEpochPercent = 0
            maxContradictoryEpochPercent = 0
        }
        legacySelectorCommit = '1b2611e1'
        stickyWriteEligibilityBypassed = $PolicyA -eq 'read_dominant_batch' -or $PolicyB -eq 'read_dominant_batch'
        axisSettings = [ordered]@{ treatmentA = $PolicyA; treatmentB = $PolicyB }
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
        repetitions = 4
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
        pressureArtifactPath = $null
    }
    sequenceProtocol = $SequenceProtocol
    treatments = [ordered]@{
        A = [ordered]@{ policy = $PolicyA; benchmarkBinaryRole = 'candidate_benchmark'; runtimeBinaryRole = 'candidate_runtime' }
        B = [ordered]@{ policy = $PolicyB; benchmarkBinaryRole = 'candidate_benchmark'; runtimeBinaryRole = 'candidate_runtime' }
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
        observationEnabled = $false
        shadowEpochCount = 0
        transitionCount = 0
        outOfDomainEpochCount = 0
        contradictoryEpochCount = 0
        missingEpochCount = 0
        staleEpochCount = 0
        reasonCounts = [ordered]@{}
        summaryArtifactPath = $null
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

Write-Host "Adaptive runtime local cell completed."
Write-Host "  classification: $classification"
Write-Host "  result: $resultPath"
Write-Host "  manifest: $manifestPath"
Write-Host "  checksum inventory: $checksumInventoryPath"
