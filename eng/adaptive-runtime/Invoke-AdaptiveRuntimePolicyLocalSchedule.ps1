# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = 'C:\shared\src\incursa\protocol-lab',

    [string] $ProtocolLabExecutionRoot = 'C:\shared\src\incursa\protocol-lab-internal',

    [string] $CampaignId = "adaptive-receive-credit-schedule-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [ValidateSet('balanced', 'connection_first', 'stream_first')]
    [string] $ScheduleProfile = 'balanced',

    [ValidateSet('legacy_current', 'immediate', 'read_dominant_batch')]
    [string] $PolicyA = 'legacy_current',

    [ValidateSet('legacy_current', 'immediate', 'read_dominant_batch')]
    [string] $PolicyB = 'read_dominant_batch',

    [ValidateRange(0, 3600)]
    [int] $WarmupSeconds = 2,

    [ValidateRange(1, 3600)]
    [int] $DurationSeconds = 5,

    [switch] $IncludeStress,

    [switch] $ContinueOnFailure,

    [switch] $Resume,

    [switch] $NoBuild,

    [switch] $NoRestore,

    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resolvedProtocolLabRoot = (Resolve-Path -LiteralPath $ProtocolLabRoot).Path
$resolvedProtocolLabExecutionRoot = (Resolve-Path -LiteralPath $ProtocolLabExecutionRoot).Path
$cellRunnerPath = Join-Path $PSScriptRoot 'Invoke-AdaptiveRuntimePolicyLocalCell.ps1'
$serverProjectPath = Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\IncursaRawQuicServer.csproj'
$serverBinaryPath = Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\bin\Release\net10.0\IncursaRawQuicServer.dll'
$runtimeBinaryPath = Join-Path $repoRoot 'src\Incursa.Quic\bin\Release\net10.0\Incursa.Quic.dll'
$campaignRoot = Join-Path $repoRoot ".artifacts\adaptive-runtime\$CampaignId"
$schedulePath = Join-Path $campaignRoot 'measurement-schedule.json'
$completionPath = Join-Path $campaignRoot 'measurement-schedule-completion.json'
$attemptId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
$attemptPath = Join-Path $campaignRoot "measurement-schedule-attempt-$attemptId.json"

function New-MeasurementCell {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CellId,

        [Parameter(Mandatory = $true)]
        [string] $ScenarioId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('upload', 'download', 'duplex')]
        [string] $TrafficShape,

        [Parameter(Mandatory = $true)]
        [int] $PayloadBytes,

        [Parameter(Mandatory = $true)]
        [int] $Connections,

        [Parameter(Mandatory = $true)]
        [int] $StreamsPerConnection,

        [Parameter(Mandatory = $true)]
        [ValidateSet('sparse', 'bursty', 'sustained')]
        [string] $ArrivalPattern,

        [bool] $StressOnly = $false
    )

    return [pscustomobject][ordered]@{
        cellId = $CellId
        scenarioId = $ScenarioId
        trafficShape = $TrafficShape
        accountingMode = 'fixed_per_stream'
        arrivalPattern = $ArrivalPattern
        payloadBytes = $PayloadBytes
        connections = $Connections
        streamsPerConnection = $StreamsPerConnection
        effectiveConcurrency = $Connections * $StreamsPerConnection
        stressOnly = $StressOnly
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

    return [ordered]@{
        role = $Role
        path = [System.IO.Path]::GetFullPath($Path)
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

if (-not (Test-Path -LiteralPath $cellRunnerPath -PathType Leaf)) {
    throw "Permanent local cell runner was not found: $cellRunnerPath"
}

if ($PolicyA -eq $PolicyB) {
    throw 'PolicyA and PolicyB must name different forced treatments.'
}
if (($PolicyA -eq 'legacy_current') -eq ($PolicyB -eq 'legacy_current')) {
    throw 'Exactly one treatment must be legacy_current.'
}

$connectionCells = @(
    New-MeasurementCell `
        -CellId 'upload-1mb-x16-s1' `
        -ScenarioId 'quic.transport.stream-throughput.1mb' `
        -TrafficShape upload `
        -PayloadBytes 1MB `
        -Connections 16 `
        -StreamsPerConnection 1 `
        -ArrivalPattern sustained
    New-MeasurementCell `
        -CellId 'download-1mb-x16-s1' `
        -ScenarioId 'quic.transport.stream-download.1mb' `
        -TrafficShape download `
        -PayloadBytes 1MB `
        -Connections 16 `
        -StreamsPerConnection 1 `
        -ArrivalPattern sustained
)

$streamCells = @(
    New-MeasurementCell `
        -CellId 'duplex-64kb-x1-s16' `
        -ScenarioId 'quic.transport.duplex-streams-peer-matrix' `
        -TrafficShape duplex `
        -PayloadBytes 64KB `
        -Connections 1 `
        -StreamsPerConnection 16 `
        -ArrivalPattern sustained
    New-MeasurementCell `
        -CellId 'duplex-64kb-x4-s16' `
        -ScenarioId 'quic.transport.duplex-streams-peer-matrix' `
        -TrafficShape duplex `
        -PayloadBytes 64KB `
        -Connections 4 `
        -StreamsPerConnection 16 `
        -ArrivalPattern sustained
    New-MeasurementCell `
        -CellId 'multiplex-1kb-x1-s100' `
        -ScenarioId 'quic.transport.multiplex.100x1kb' `
        -TrafficShape duplex `
        -PayloadBytes 1KB `
        -Connections 1 `
        -StreamsPerConnection 100 `
        -ArrivalPattern bursty
)

$balancedCells = @(
    $connectionCells[0]
    $streamCells[0]
    $connectionCells[1]
    $streamCells[2]
    $streamCells[1]
)

$cells = switch ($ScheduleProfile) {
    'connection_first' { @($connectionCells + $streamCells) }
    'stream_first' { @($streamCells + $connectionCells) }
    default { $balancedCells }
}

if ($IncludeStress) {
    $cells += @(
        New-MeasurementCell `
            -CellId 'upload-1mb-x32-s1-stress' `
            -ScenarioId 'quic.transport.stream-throughput.1mb' `
            -TrafficShape upload `
            -PayloadBytes 1MB `
            -Connections 32 `
            -StreamsPerConnection 1 `
            -ArrivalPattern sustained `
            -StressOnly $true
        New-MeasurementCell `
            -CellId 'download-1mb-x32-s1-stress' `
            -ScenarioId 'quic.transport.stream-download.1mb' `
            -TrafficShape download `
            -PayloadBytes 1MB `
            -Connections 32 `
            -StreamsPerConnection 1 `
            -ArrivalPattern sustained `
            -StressOnly $true
        New-MeasurementCell `
            -CellId 'multiplex-1kb-x4-s100-stress' `
            -ScenarioId 'quic.transport.multiplex.100x1kb' `
            -TrafficShape duplex `
            -PayloadBytes 1KB `
            -Connections 4 `
            -StreamsPerConnection 100 `
            -ArrivalPattern bursty `
            -StressOnly $true
    )
}

$plannedCells = @(for ($index = 0; $index -lt $cells.Count; $index++) {
    $cell = $cells[$index]
    [pscustomobject][ordered]@{
        scheduleIndex = $index
        sequenceProtocol = if (($index % 2) -eq 0) { 'ABBA' } else { 'BAAB' }
        cellId = $cell.cellId
        scenarioId = $cell.scenarioId
        trafficShape = $cell.trafficShape
        accountingMode = $cell.accountingMode
        arrivalPattern = $cell.arrivalPattern
        payloadBytes = $cell.payloadBytes
        connections = $cell.connections
        streamsPerConnection = $cell.streamsPerConnection
        effectiveConcurrency = $cell.effectiveConcurrency
        stressOnly = $cell.stressOnly
    }
})

if ($DryRun) {
    Write-Host "Dry run: $ScheduleProfile schedule for campaign '$CampaignId'."
    $plannedCells |
        Select-Object scheduleIndex, sequenceProtocol, cellId, scenarioId, connections, streamsPerConnection, effectiveConcurrency, stressOnly |
        Format-Table -AutoSize
    return
}

$scheduleDocument = $null
if (Test-Path -LiteralPath $schedulePath -PathType Leaf) {
    if (-not $Resume) {
        throw "Campaign schedule already exists; use -Resume to continue without rewriting it: $schedulePath"
    }

    $scheduleDocument = Get-Content -LiteralPath $schedulePath -Raw | ConvertFrom-Json -Depth 30
    if ([string] $scheduleDocument.campaignId -ne $CampaignId -or
        [string] $scheduleDocument.scheduleProfile -ne $ScheduleProfile -or
        [string] $scheduleDocument.policyA -ne $PolicyA -or
        [string] $scheduleDocument.policyB -ne $PolicyB -or
        [bool] $scheduleDocument.includeStress -ne [bool] $IncludeStress -or
        [bool] $scheduleDocument.continueOnFailure -ne [bool] $ContinueOnFailure -or
        [int] $scheduleDocument.warmupSeconds -ne $WarmupSeconds -or
        [int] $scheduleDocument.durationSeconds -ne $DurationSeconds -or
        [string] $scheduleDocument.protocolLabRoot -ne $resolvedProtocolLabRoot -or
        [string] $scheduleDocument.protocolLabExecutionRoot -ne $resolvedProtocolLabExecutionRoot) {
        throw 'Resume parameters do not match the retained measurement schedule.'
    }

    $currentScheduleRunnerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $currentCellRunnerHash = (Get-FileHash -LiteralPath $cellRunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentScheduleRunnerHash -ne [string] $scheduleDocument.scheduleRunnerSha256 -or
        $currentCellRunnerHash -ne [string] $scheduleDocument.cellRunnerSha256) {
        throw 'A permanent measurement runner changed before resume.'
    }

    $retainedCellsJson = @($scheduleDocument.cells) | ConvertTo-Json -Depth 20 -Compress
    $currentCellsJson = $plannedCells | ConvertTo-Json -Depth 20 -Compress
    if ($retainedCellsJson -ne $currentCellsJson) {
        throw 'The retained measurement cells changed before resume.'
    }

    if (Test-Path -LiteralPath $completionPath -PathType Leaf) {
        throw "Campaign schedule already has a completion record: $completionPath"
    }

    foreach ($identity in @($scheduleDocument.frozenBinaries)) {
        $currentHash = (Get-FileHash -LiteralPath ([string] $identity.path) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($currentHash -ne [string] $identity.sha256) {
            throw "Frozen $($identity.role) binary changed before resume."
        }
    }
}
else {
    if ($Resume) {
        throw "Cannot resume because the retained measurement schedule was not found: $schedulePath"
    }

    if (Test-Path -LiteralPath $campaignRoot) {
        $existingArtifact = Get-ChildItem -LiteralPath $campaignRoot -Force -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $existingArtifact) {
            throw "Campaign output already exists without a resumable schedule: $campaignRoot"
        }
    }

    if (-not $NoBuild) {
        $buildArguments = @('build', $serverProjectPath, '-c', 'Release')
        if ($NoRestore) {
            $buildArguments += '--no-restore'
        }

        & dotnet @buildArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Frozen campaign host build failed with exit code $LASTEXITCODE."
        }
    }

    $frozenBinaries = @(
        Get-FileIdentity -Role 'candidate_benchmark' -Path $serverBinaryPath
        Get-FileIdentity -Role 'candidate_runtime' -Path $runtimeBinaryPath
    )
    New-Item -ItemType Directory -Path $campaignRoot -Force | Out-Null
    $scheduleDocument = [ordered]@{
        schemaVersion = 'adaptive-runtime-policy-local-schedule-v1'
        campaignId = $CampaignId
        createdAtUtc = (Get-Date).ToUniversalTime().ToString('O')
        scheduleProfile = $ScheduleProfile
        includeStress = [bool] $IncludeStress
        continueOnFailure = [bool] $ContinueOnFailure
        policyA = $PolicyA
        policyB = $PolicyB
        protocolLabRoot = $resolvedProtocolLabRoot
        protocolLabExecutionRoot = $resolvedProtocolLabExecutionRoot
        warmupSeconds = $WarmupSeconds
        durationSeconds = $DurationSeconds
        scheduleRunnerSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        cellRunnerSha256 = (Get-FileHash -LiteralPath $cellRunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        counterCaptureRequired = $true
        activePolicyAuthorized = $false
        onlineLearningAuthorized = $false
        protocolLabSubmissionAuthorized = $false
        frozenBinaries = $frozenBinaries
        cells = $plannedCells
    }
    $scheduleDocument | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $schedulePath -Encoding utf8
}

$cellResults = [System.Collections.Generic.List[object]]::new()
$hasFailure = $false
foreach ($cell in $plannedCells) {
    $cellRoot = Join-Path $campaignRoot $cell.cellId
    $localResultPath = Join-Path $cellRoot 'local-result.json'
    if ($Resume -and (Test-Path -LiteralPath $localResultPath -PathType Leaf)) {
        $retainedResult = Get-Content -LiteralPath $localResultPath -Raw | ConvertFrom-Json -Depth 30
        $retainedClassification = [string] $retainedResult.classification
        $retainedTerminalFailure = $retainedClassification -in @('invalid_contract', 'failed_correctness')
        $cellResults.Add([ordered]@{
            scheduleIndex = $cell.scheduleIndex
            cellId = $cell.cellId
            status = if ($retainedTerminalFailure) { 'retained_terminal_failure' } else { 'retained_completed' }
            classification = $retainedClassification
            exitCode = if ($retainedTerminalFailure) { 1 } else { 0 }
            localResultPath = $localResultPath
        })
        if ($retainedTerminalFailure) {
            $hasFailure = $true
            if (-not $ContinueOnFailure) {
                break
            }
        }
        continue
    }
    if ($Resume -and (Test-Path -LiteralPath $cellRoot)) {
        $retainedArtifact = Get-ChildItem -LiteralPath $cellRoot -Force -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $retainedArtifact) {
            $cellResults.Add([ordered]@{
                scheduleIndex = $cell.scheduleIndex
                cellId = $cell.cellId
                status = 'retained_incomplete_artifacts'
                classification = $null
                exitCode = 1
                localResultPath = $null
            })
            $hasFailure = $true
            if (-not $ContinueOnFailure) {
                break
            }
            continue
        }
    }

    $arguments = @{
        ProtocolLabRoot = $resolvedProtocolLabRoot
        ProtocolLabExecutionRoot = $resolvedProtocolLabExecutionRoot
        CampaignId = $CampaignId
        CellId = $cell.cellId
        SequenceProtocol = $cell.sequenceProtocol
        PolicyA = $PolicyA
        PolicyB = $PolicyB
        ScenarioId = $cell.scenarioId
        TrafficShape = $cell.trafficShape
        AccountingMode = $cell.accountingMode
        ArrivalPattern = $cell.arrivalPattern
        PayloadBytes = $cell.payloadBytes
        Connections = $cell.connections
        StreamsPerConnection = $cell.streamsPerConnection
        WarmupSeconds = $WarmupSeconds
        DurationSeconds = $DurationSeconds
        OutputRoot = $cellRoot
        NoBuild = $true
        NoRestore = [bool] $NoRestore
        StressOnly = [bool] $cell.stressOnly
    }

    Write-Host "Running schedule cell $($cell.scheduleIndex + 1)/$($plannedCells.Count): $($cell.cellId) ($($cell.sequenceProtocol))."
    $exitCode = 0
    $failureMessage = $null
    try {
        & $cellRunnerPath @arguments
    }
    catch {
        $exitCode = 1
        $failureMessage = $_.Exception.Message
    }
    $classification = $null
    if (Test-Path -LiteralPath $localResultPath -PathType Leaf) {
        $localResult = Get-Content -LiteralPath $localResultPath -Raw | ConvertFrom-Json -Depth 30
        $classification = [string] $localResult.classification
    }
    $terminalFailure = $classification -in @('invalid_contract', 'failed_correctness')
    $status = if ($exitCode -eq 0 -and $null -ne $classification -and -not $terminalFailure) {
        'completed'
    }
    elseif ($terminalFailure) {
        'terminal_failure_retained'
    }
    else {
        'failed_retained'
    }
    $cellResults.Add([ordered]@{
        scheduleIndex = $cell.scheduleIndex
        cellId = $cell.cellId
        status = $status
        classification = $classification
        exitCode = $exitCode
        failureMessage = $failureMessage
        localResultPath = if (Test-Path -LiteralPath $localResultPath -PathType Leaf) { $localResultPath } else { $null }
    })

    if ($status -in @('failed_retained', 'terminal_failure_retained')) {
        $hasFailure = $true
        if (-not $ContinueOnFailure) {
            break
        }
    }
}

$attemptDocument = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-local-schedule-attempt-v1'
    campaignId = $CampaignId
    scheduleSha256 = (Get-FileHash -LiteralPath $schedulePath -Algorithm SHA256).Hash.ToLowerInvariant()
    attemptId = $attemptId
    endedAtUtc = (Get-Date).ToUniversalTime().ToString('O')
    status = if ($hasFailure -or $cellResults.Count -ne $plannedCells.Count) { 'incomplete_retained' } else { 'completed' }
    cells = @($cellResults)
}
$attemptDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $attemptPath -Encoding utf8

if ($attemptDocument.status -ne 'completed') {
    throw "Measurement schedule did not complete. Retained attempt: $attemptPath"
}

$completionDocument = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-local-schedule-completion-v1'
    campaignId = $CampaignId
    scheduleSha256 = $attemptDocument.scheduleSha256
    completedAtUtc = $attemptDocument.endedAtUtc
    successfulAttemptPath = $attemptPath
    cells = @($cellResults)
}
$completionDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $completionPath -Encoding utf8
Write-Host "Measurement schedule completed: $completionPath"
