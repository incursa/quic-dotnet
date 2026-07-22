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
$cellRunnerPath = Join-Path $PSScriptRoot 'Invoke-AdaptiveRuntimePolicyLocalCell.ps1'
$sameConnectionExecutorPath = Join-Path $PSScriptRoot 'Invoke-AdaptiveRuntimeSameConnectionPhaseExecutor.ps1'
$phaseTransitionSchemaPath = Join-Path $repoRoot 'schemas\adaptive-runtime-policy-phase-transition-schedule-v1.schema.json'
$serverProjectPath = Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\IncursaRawQuicServer.csproj'
$serverBinaryPath = Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\bin\Release\net10.0\IncursaRawQuicServer.dll'
$runtimeBinaryPath = Join-Path $repoRoot 'src\Incursa.Quic\bin\Release\net10.0\Incursa.Quic.dll'
$campaignRoot = Join-Path $repoRoot ".artifacts\adaptive-runtime\$CampaignId"
$phaseTransitionArtifactPath = Join-Path $campaignRoot 'phase-transition-schedule.json'
$sameConnectionExecutionProofPath = Join-Path $campaignRoot 'same-connection-phase-execution.json'
$schedulePath = Join-Path $campaignRoot 'measurement-schedule.json'
$completionPath = Join-Path $campaignRoot 'measurement-schedule-completion.json'
$attemptId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
$attemptPath = Join-Path $campaignRoot "measurement-schedule-attempt-$attemptId.json"

function Resolve-DeclaredRootPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [bool] $Required
    )

    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    if ($Required) {
        throw "Required path was not found: $Path"
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

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

        [Parameter(Mandatory = $true)]
        [string] $PhaseId,

        [Parameter(Mandatory = $true)]
        [string] $PhaseLabel,

        [Parameter(Mandatory = $true)]
        [ValidateSet('baseline', 'connection_wave', 'stream_wave', 'recovery')]
        [string] $TransitionKind,

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
        phaseId = $PhaseId
        phaseLabel = $PhaseLabel
        transitionKind = $TransitionKind
        stressOnly = $StressOnly
    }
}

function New-PhaseTransitionArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Cells,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedProtocolLabRoot,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedProtocolLabExecutionRoot
    )

    $phaseRows = [System.Collections.Generic.List[object]]::new()
    $phaseRowsById = @{}
    foreach ($cell in $Cells) {
        if (-not $phaseRowsById.ContainsKey($cell.phaseId)) {
            $phaseRow = [ordered]@{
                phaseId = [string] $cell.phaseId
                phaseLabel = [string] $cell.phaseLabel
                transitionKind = [string] $cell.transitionKind
                executionStatus = 'mapped_to_cells'
                measurementCells = [System.Collections.Generic.List[object]]::new()
            }
            $phaseRowsById[$cell.phaseId] = $phaseRow
            $phaseRows.Add($phaseRow)
        }

        $phaseRowsById[$cell.phaseId].measurementCells.Add([ordered]@{
            cellId = $cell.cellId
            scenarioId = $cell.scenarioId
            trafficShape = $cell.trafficShape
            payloadBytes = $cell.payloadBytes
            connections = $cell.connections
            streamsPerConnection = $cell.streamsPerConnection
            effectiveConcurrency = $cell.effectiveConcurrency
            stressOnly = $cell.stressOnly
        })
    }

    $phaseRows = @($phaseRows | ForEach-Object {
        [ordered]@{
            phaseId = $_.phaseId
            phaseLabel = $_.phaseLabel
            transitionKind = $_.transitionKind
            executionStatus = $_.executionStatus
            measurementCells = @($_.measurementCells | ForEach-Object {
                [ordered]@{
                    cellId = $_.cellId
                    scenarioId = $_.scenarioId
                    trafficShape = $_.trafficShape
                    payloadBytes = $_.payloadBytes
                    connections = $_.connections
                    streamsPerConnection = $_.streamsPerConnection
                    effectiveConcurrency = $_.effectiveConcurrency
                    stressOnly = $_.stressOnly
                }
            })
        }
    })

    $phaseRows += [ordered]@{
        phaseId = "adaptive-runtime.$ScheduleProfile.recovery.planned.v1"
        phaseLabel = 'Few-to-many-to-few recovery return'
        transitionKind = 'recovery'
        executionStatus = 'same_connection_probe'
        sameConnectionShape = [ordered]@{
            trafficShape = 'duplex'
            payloadBytes = 65536
            connections = 1
            streamsPerConnection = 16
            effectiveConcurrency = 16
        }
        measurementCells = @()
    }

    $cellArguments = @($Cells | ForEach-Object {
        [ordered]@{
            cellId = $_.cellId
            phaseId = $_.phaseId
            sequenceProtocol = $_.sequenceProtocol
            scenarioId = $_.scenarioId
            trafficShape = $_.trafficShape
            accountingMode = $_.accountingMode
            arrivalPattern = $_.arrivalPattern
            payloadBytes = $_.payloadBytes
            connections = $_.connections
            streamsPerConnection = $_.streamsPerConnection
            stressOnly = $_.stressOnly
        }
    })

    return [ordered]@{
        schemaVersion = 'adaptive-runtime-policy-phase-transition-schedule-v1'
        campaignId = $CampaignId
        scheduleProfile = $ScheduleProfile
        scheduleId = "adaptive-runtime.$ScheduleProfile.phase-transition.v1"
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('O')
        executionModel = 'independent_cell_sequence'
        sameConnectionPhaseExecution = 'supported_by_helper'
        policyAxis = 'receive_credit_publication'
        activePolicyAuthorized = $false
        onlineLearningAuthorized = $false
        protocolLabSubmissionAuthorized = $false
        transitionIntent = 'few_to_many_to_few_review_artifact'
        phases = $phaseRows
        commandLineage = [ordered]@{
            scheduleScriptPath = $PSCommandPath
            scheduleScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
            cellRunnerPath = $cellRunnerPath
            cellRunnerSha256 = (Get-FileHash -LiteralPath $cellRunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
            sameConnectionExecutorPath = $sameConnectionExecutorPath
            sameConnectionExecutorSha256 = (Get-FileHash -LiteralPath $sameConnectionExecutorPath -Algorithm SHA256).Hash.ToLowerInvariant()
            protocolLabRoot = $ResolvedProtocolLabRoot
            protocolLabExecutionRoot = $ResolvedProtocolLabExecutionRoot
            sharedArguments = [ordered]@{
                policyA = $PolicyA
                policyB = $PolicyB
                warmupSeconds = $WarmupSeconds
                durationSeconds = $DurationSeconds
                includeStress = [bool] $IncludeStress
                continueOnFailure = [bool] $ContinueOnFailure
            }
            cells = $cellArguments
        }
        notes = @(
            'This artifact declares deterministic measurement phases and exact command lineage only.',
            'The scheduler still executes independent measurement cells for metrics collection.',
            'A same-connection helper is the only supported path for the preserved few-to-many-to-few recovery probe, and its retained proof lives beside the schedule rather than inside this deterministic artifact.',
            'The recovery phase keeps its stable phase ID so the helper and the review artifact refer to the same return target.'
        )
    }
}

function Get-ComparablePhaseTransitionArtifact {
    param([Parameter(Mandatory = $true)][object] $Artifact)

    $clone = $Artifact | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
    $clone.PSObject.Properties.Remove('generatedAtUtc')
    return $clone
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
if (-not (Test-Path -LiteralPath $sameConnectionExecutorPath -PathType Leaf)) {
    throw "Permanent same-connection phase executor was not found: $sameConnectionExecutorPath"
}

$resolvedProtocolLabRoot = Resolve-DeclaredRootPath -Path $ProtocolLabRoot -Required (-not $DryRun)
$resolvedProtocolLabExecutionRoot = Resolve-DeclaredRootPath -Path $ProtocolLabExecutionRoot -Required (-not $DryRun)

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
        -ArrivalPattern sustained `
        -PhaseId 'adaptive-runtime.connection-wave.upload.v1' `
        -PhaseLabel 'Connection-wave upload hold' `
        -TransitionKind connection_wave
    New-MeasurementCell `
        -CellId 'download-1mb-x16-s1' `
        -ScenarioId 'quic.transport.stream-download.1mb' `
        -TrafficShape download `
        -PayloadBytes 1MB `
        -Connections 16 `
        -StreamsPerConnection 1 `
        -ArrivalPattern sustained `
        -PhaseId 'adaptive-runtime.connection-wave.download.v1' `
        -PhaseLabel 'Connection-wave download hold' `
        -TransitionKind connection_wave
)

$streamCells = @(
    New-MeasurementCell `
        -CellId 'duplex-64kb-x1-s16' `
        -ScenarioId 'quic.transport.duplex-streams-peer-matrix' `
        -TrafficShape duplex `
        -PayloadBytes 64KB `
        -Connections 1 `
        -StreamsPerConnection 16 `
        -ArrivalPattern sustained `
        -PhaseId 'adaptive-runtime.few-streams.baseline.v1' `
        -PhaseLabel 'Few-stream baseline' `
        -TransitionKind baseline
    New-MeasurementCell `
        -CellId 'duplex-64kb-x4-s16' `
        -ScenarioId 'quic.transport.duplex-streams-peer-matrix' `
        -TrafficShape duplex `
        -PayloadBytes 64KB `
        -Connections 4 `
        -StreamsPerConnection 16 `
        -ArrivalPattern sustained `
        -PhaseId 'adaptive-runtime.stream-wave.duplex-ramp.v1' `
        -PhaseLabel 'Stream-wave duplex ramp' `
        -TransitionKind stream_wave
    New-MeasurementCell `
        -CellId 'multiplex-1kb-x1-s100' `
        -ScenarioId 'quic.transport.multiplex.100x1kb' `
        -TrafficShape duplex `
        -PayloadBytes 1KB `
        -Connections 1 `
        -StreamsPerConnection 100 `
        -ArrivalPattern bursty `
        -PhaseId 'adaptive-runtime.stream-wave.multiplex-burst.v1' `
        -PhaseLabel 'Stream-wave multiplex burst' `
        -TransitionKind stream_wave
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
            -PhaseId 'adaptive-runtime.connection-wave.upload-stress.v1' `
            -PhaseLabel 'Connection-wave upload stress extension' `
            -TransitionKind connection_wave `
            -StressOnly $true
        New-MeasurementCell `
            -CellId 'download-1mb-x32-s1-stress' `
            -ScenarioId 'quic.transport.stream-download.1mb' `
            -TrafficShape download `
            -PayloadBytes 1MB `
            -Connections 32 `
            -StreamsPerConnection 1 `
            -ArrivalPattern sustained `
            -PhaseId 'adaptive-runtime.connection-wave.download-stress.v1' `
            -PhaseLabel 'Connection-wave download stress extension' `
            -TransitionKind connection_wave `
            -StressOnly $true
        New-MeasurementCell `
            -CellId 'multiplex-1kb-x4-s100-stress' `
            -ScenarioId 'quic.transport.multiplex.100x1kb' `
            -TrafficShape duplex `
            -PayloadBytes 1KB `
            -Connections 4 `
            -StreamsPerConnection 100 `
            -ArrivalPattern bursty `
            -PhaseId 'adaptive-runtime.stream-wave.multiplex-stress.v1' `
            -PhaseLabel 'Stream-wave multiplex stress extension' `
            -TransitionKind stream_wave `
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
        phaseId = $cell.phaseId
        phaseLabel = $cell.phaseLabel
        transitionKind = $cell.transitionKind
        stressOnly = $cell.stressOnly
    }
})

$phaseTransitionArtifact = New-PhaseTransitionArtifact `
    -Cells $plannedCells `
    -ResolvedProtocolLabRoot $resolvedProtocolLabRoot `
    -ResolvedProtocolLabExecutionRoot $resolvedProtocolLabExecutionRoot
$phaseTransitionArtifactJson = $phaseTransitionArtifact | ConvertTo-Json -Depth 30
if (-not ($phaseTransitionArtifactJson | Test-Json -SchemaFile $phaseTransitionSchemaPath -ErrorAction Stop)) {
    throw "Generated phase-transition schedule did not validate against $phaseTransitionSchemaPath."
}

if ($DryRun) {
    New-Item -ItemType Directory -Path $campaignRoot -Force | Out-Null
    $phaseTransitionArtifactJson | Set-Content -LiteralPath $phaseTransitionArtifactPath -Encoding utf8
    Write-Host "Dry run: $ScheduleProfile schedule for campaign '$CampaignId'."
    Write-Host "  phase transition artifact: $phaseTransitionArtifactPath"
    $plannedCells |
        Select-Object scheduleIndex, phaseId, sequenceProtocol, cellId, scenarioId, connections, streamsPerConnection, effectiveConcurrency, stressOnly |
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

    $retainedPhaseTransitionJson = (Get-ComparablePhaseTransitionArtifact -Artifact $scheduleDocument.phaseTransitionSchedule) | ConvertTo-Json -Depth 20 -Compress
    $currentPhaseTransitionJson = (Get-ComparablePhaseTransitionArtifact -Artifact $phaseTransitionArtifact) | ConvertTo-Json -Depth 20 -Compress
    if ($retainedPhaseTransitionJson -ne $currentPhaseTransitionJson) {
        throw 'The retained phase-transition artifact changed before resume.'
    }

    if (Test-Path -LiteralPath $completionPath -PathType Leaf) {
        throw "Campaign schedule already has a completion record: $completionPath"
    }

    if ([string]::IsNullOrWhiteSpace([string] $scheduleDocument.sameConnectionExecutionProofPath) -or
        -not (Test-Path -LiteralPath ([string] $scheduleDocument.sameConnectionExecutionProofPath) -PathType Leaf)) {
        throw 'The retained same-connection execution proof is missing before resume.'
    }
    $retainedProofHash = (Get-FileHash -LiteralPath ([string] $scheduleDocument.sameConnectionExecutionProofPath) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace([string] $scheduleDocument.sameConnectionExecutionProofSha256) -or
        $retainedProofHash -ne [string] $scheduleDocument.sameConnectionExecutionProofSha256) {
        throw 'The retained same-connection execution proof changed before resume.'
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

    & $sameConnectionExecutorPath `
        -CampaignId $CampaignId `
        -OutputPath $sameConnectionExecutionProofPath `
        -FewPhaseId 'adaptive-runtime.few-streams.baseline.v1' `
        -ManyPhaseId 'adaptive-runtime.stream-wave.multiplex-burst.v1' `
        -RecoveryPhaseId "adaptive-runtime.$ScheduleProfile.recovery.planned.v1" `
        -ServerProjectPath $serverProjectPath `
        -ServerBinaryPath $serverBinaryPath `
        -NoBuild `
        -NoRestore:$NoRestore
    $sameConnectionExecutionProof = Get-Content -LiteralPath $sameConnectionExecutionProofPath -Raw | ConvertFrom-Json -Depth 30
    $sameConnectionExecutionProofSha256 = (Get-FileHash -LiteralPath $sameConnectionExecutionProofPath -Algorithm SHA256).Hash.ToLowerInvariant()

    New-Item -ItemType Directory -Path $campaignRoot -Force | Out-Null
    $phaseTransitionArtifactJson | Set-Content -LiteralPath $phaseTransitionArtifactPath -Encoding utf8
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
        phaseTransitionSchedulePath = $phaseTransitionArtifactPath
        phaseTransitionSchedule = $phaseTransitionArtifact
        sameConnectionExecutionProofPath = $sameConnectionExecutionProofPath
        sameConnectionExecutionProofSha256 = $sameConnectionExecutionProofSha256
        sameConnectionExecutionProof = $sameConnectionExecutionProof
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
