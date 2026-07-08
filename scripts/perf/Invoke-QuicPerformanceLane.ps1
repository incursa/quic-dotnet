[CmdletBinding()]
param(
    [ValidateSet("Smoke", "Confidence")]
    [string] $Lane = "Smoke",

    [ValidateSet("CoreProtocolLab", "RawQuicMultiplex", "RawQuicDuplex", "RawQuicSendCore", "PublicApiStream")]
    [string] $Surface = "RawQuicMultiplex",

    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",

    [string] $ProtocolLabExecutionRoot,

    [switch] $NoRestore,

    [switch] $NoBuild,

    [string] $RunIdPrefix = "local-quic-perf-$((Get-Date).ToString('yyyyMMddHHmmss'))",

    [string] $ArtifactsRoot = ".artifacts\perf-lanes",

    [string] $Scenario,

    [string] $Http3Scenario = "http3.payload.bytes.64kb",

    [string] $RawQuicScenario = "quic.transport.multiplex.100x64kb",

    [switch] $CaptureCounters,

    [int] $CounterRefreshInterval = 1,

    [switch] $SkipProtocolLab,

    [switch] $FailOnProtocolLabError,

    [switch] $SkipBenchmarks,

    [switch] $DryRun,

    [string] $PowerShellPath = "pwsh"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Format-CommandLine {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $escaped = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argument
        }
    }

    "$FileName $($escaped -join ' ')"
}

function Get-RepoRoot {
    $candidate = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $candidate "Incursa.Quic.slnx"))) {
        throw "Could not locate quic-dotnet repository root from '$PSScriptRoot'."
    }

    return [System.IO.Path]::GetFullPath($candidate)
}

function Resolve-ProtocolLabExecutionRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ContractRoot,

        [string] $RequestedExecutionRoot,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($RequestedExecutionRoot)) {
        $candidates.Add((Resolve-FullPath -Path $RequestedExecutionRoot -BasePath $BasePath)) | Out-Null
    }

    $environmentRoot = [Environment]::GetEnvironmentVariable("PROTOCOL_LAB_EXECUTION_ROOT")
    if (-not [string]::IsNullOrWhiteSpace($environmentRoot)) {
        $candidates.Add((Resolve-FullPath -Path $environmentRoot -BasePath $BasePath)) | Out-Null
    }

    $candidates.Add($ContractRoot) | Out-Null
    $candidates.Add((Join-Path (Split-Path -Parent $ContractRoot) "protocol-lab-internal")) | Out-Null

    $checked = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $resolvedCandidate = [System.IO.Path]::GetFullPath($candidate)
        if ($checked.Contains($resolvedCandidate)) {
            continue
        }

        $checked.Add($resolvedCandidate) | Out-Null
        $benchmarkScript = Join-Path $resolvedCandidate "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"
        $solutionPath = Join-Path $resolvedCandidate "Incursa.ProtocolLab.sln"
        if ((Test-Path -LiteralPath $benchmarkScript -PathType Leaf) -and
            (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
            return $resolvedCandidate
        }
    }

    throw "ProtocolLab benchmark execution root was not found. Checked: $($checked -join ', '). Expected scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1 and Incursa.ProtocolLab.sln. Keep public contracts in -ProtocolLabRoot and pass -ProtocolLabExecutionRoot for the runnable internal checkout."
}

function Get-SliceName {
    param([Parameter(Mandatory = $true)][string] $Filter)

    $sliceName = $Filter.Trim("*")
    $sliceName = [System.Text.RegularExpressions.Regex]::Replace($sliceName, "[^A-Za-z0-9_.-]+", "-").Trim("-")
    if ([string]::IsNullOrWhiteSpace($sliceName)) {
        return "benchmarks"
    }

    return $sliceName
}

function Get-SurfaceConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RequestedSurface,

        [string] $RequestedScenario,

        [string] $RequestedHttp3Scenario,

        [string] $RequestedRawQuicScenario
    )

    $sendFilters = @(
        "*QuicApplicationSendPriorityBenchmarks*",
        "*QuicApplicationSendQueueSortingBenchmarks*",
        "*QuicApplicationSendBatchPayloadBenchmarks*",
        "*QuicStreamParsingBenchmarks*"
    )

    switch ($RequestedSurface) {
        "CoreProtocolLab" {
            return [pscustomobject]@{
                BenchmarkScript = $null
                BenchmarkFilters = @()
                ProtocolLabEnabled = $true
                ProtocolLabJobs = @(
                    [pscustomobject]@{
                        Id = "h3"
                        Name = "HTTP/3"
                        Suite = "h3-local-v1"
                        Implementation = "incursa-http3"
                        Scenario = if ([string]::IsNullOrWhiteSpace($RequestedHttp3Scenario)) { "http3.payload.bytes.64kb" } else { $RequestedHttp3Scenario }
                        Connections = 16
                        StreamsPerConnection = 10
                    },
                    [pscustomobject]@{
                        Id = "raw-quic"
                        Name = "Raw QUIC"
                        Suite = "quic-transport-v1-comparison"
                        Implementation = "incursa-raw-quic-adapter-v1"
                        Scenario = if ([string]::IsNullOrWhiteSpace($RequestedRawQuicScenario)) { "quic.transport.multiplex.100x64kb" } else { $RequestedRawQuicScenario }
                        Connections = 1
                        StreamsPerConnection = 1
                    }
                )
            }
        }
        "RawQuicMultiplex" {
            return [pscustomobject]@{
                BenchmarkScript = "scripts\benchmarks\Invoke-QuicBaseline.ps1"
                BenchmarkFilters = $sendFilters
                ProtocolLabEnabled = $true
                ProtocolLabScenario = if ([string]::IsNullOrWhiteSpace($RequestedScenario)) { "quic.transport.multiplex.100x64kb" } else { $RequestedScenario }
                Connections = 1
                StreamsPerConnection = 1
                ProtocolLabJobs = @()
            }
        }
        "RawQuicDuplex" {
            return [pscustomobject]@{
                BenchmarkScript = "scripts\benchmarks\Invoke-QuicBaseline.ps1"
                BenchmarkFilters = $sendFilters + @("*QuicConnectionStreamStateBenchmarks*")
                ProtocolLabEnabled = $true
                ProtocolLabScenario = if ([string]::IsNullOrWhiteSpace($RequestedScenario)) { "quic.transport.duplex-streams" } else { $RequestedScenario }
                Connections = 1
                StreamsPerConnection = 16
                ProtocolLabJobs = @()
            }
        }
        "RawQuicSendCore" {
            return [pscustomobject]@{
                BenchmarkScript = "scripts\benchmarks\Invoke-QuicBaseline.ps1"
                BenchmarkFilters = @(
                    "*QuicApplicationSendPriorityBenchmarks*",
                    "*QuicApplicationSendQueueSortingBenchmarks*",
                    "*QuicApplicationSendBatchPayloadBenchmarks*",
                    "*QuicApplicationSendDistinctStreamIdBenchmarks*",
                    "*QuicCongestionControlBenchmarks*",
                    "*QuicCongestionControlDiscardBenchmarks*"
                )
                ProtocolLabEnabled = -not [string]::IsNullOrWhiteSpace($RequestedScenario)
                ProtocolLabScenario = $RequestedScenario
                Connections = 1
                StreamsPerConnection = 1
                ProtocolLabJobs = @()
            }
        }
        "PublicApiStream" {
            return [pscustomobject]@{
                BenchmarkScript = "scripts\benchmarks\Invoke-QuicPublicComparison.ps1"
                BenchmarkFilters = @("*QuicPublicApiStreamTransferBenchmarks*")
                ProtocolLabEnabled = $false
                ProtocolLabScenario = $null
                Connections = 1
                StreamsPerConnection = 1
                ProtocolLabJobs = @()
            }
        }
        default {
            throw "Unsupported surface '$RequestedSurface'."
        }
    }
}

function Invoke-LaneCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [Parameter(Mandatory = $true)]
        [string] $WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [bool] $IsDryRun
    )

    Write-Host ""
    Write-Host "Working directory: $WorkingDirectory" -ForegroundColor DarkGray
    Write-Host (Format-CommandLine $FileName $Arguments) -ForegroundColor Yellow

    if ($IsDryRun) {
        return
    }

    Push-Location $WorkingDirectory
    try {
        & $FileName @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Add-SummaryLine {
    param(
        [System.Collections.Generic.List[string]] $Lines,

        [string] $Line
    )

    $Lines.Add($Line) | Out-Null
}

function Get-ProtocolLabJobs {
    param($SurfaceConfiguration)

    $jobs = @($SurfaceConfiguration.ProtocolLabJobs)
    if ($jobs.Count -gt 0) {
        return $jobs
    }

    if (-not [bool]$SurfaceConfiguration.ProtocolLabEnabled) {
        return @()
    }

    if ([string]::IsNullOrWhiteSpace($SurfaceConfiguration.ProtocolLabScenario)) {
        return @()
    }

    return @(
        [pscustomobject]@{
            Id = "raw-quic"
            Name = "Raw QUIC"
            Suite = "quic-transport-v1-comparison"
            Implementation = "incursa-raw-quic-adapter-v1"
            Scenario = $SurfaceConfiguration.ProtocolLabScenario
            Connections = $SurfaceConfiguration.Connections
            StreamsPerConnection = $SurfaceConfiguration.StreamsPerConnection
        }
    )
}

function Format-Number {
    param([object] $Value)

    if ($null -eq $Value) {
        return "n/a"
    }

    if ($Value -is [double] -or $Value -is [float] -or $Value -is [decimal]) {
        return ([double]$Value).ToString("0.###", [Globalization.CultureInfo]::InvariantCulture)
    }

    return [string]$Value
}

function Format-MetricRange {
    param($Metric)

    if ($null -eq $Metric) {
        return "n/a"
    }

    $propertyNames = @($Metric.PSObject.Properties.Name)
    if (-not ($propertyNames -contains "median")) {
        return "n/a"
    }

    $median = Format-Number $Metric.median
    $best = if ($propertyNames -contains "best") { Format-Number $Metric.best } else { "n/a" }
    $worst = if ($propertyNames -contains "worst") { Format-Number $Metric.worst } else { "n/a" }
    return "$median (best $best, worst $worst)"
}

function Add-ProtocolLabAggregateSummary {
    param(
        [System.Collections.Generic.List[string]] $Lines,

        [string] $AggregatePath
    )

    if (-not (Test-Path -LiteralPath $AggregatePath -PathType Leaf)) {
        Add-SummaryLine $Lines "- Aggregate summary: missing"
        return
    }

    $aggregateDocument = Get-Content -LiteralPath $AggregatePath -Raw | ConvertFrom-Json
    foreach ($aggregate in @($aggregateDocument.aggregates)) {
        Add-SummaryLine $Lines "- Cell: ``$($aggregate.implementationId)`` / ``$($aggregate.scenarioId)``"
        Add-SummaryLine $Lines "  - Validation: passed ``$($aggregate.validation.passed)`` failed ``$($aggregate.validation.failed)`` infrastructure ``$($aggregate.validation.infrastructureFailure)``"
        Add-SummaryLine $Lines "  - Benchmark: ``$($aggregate.benchmarkExecutionStatuses | ConvertTo-Json -Compress)``"
        Add-SummaryLine $Lines "  - Evidence: ``$($aggregate.evidence.evidenceClass)`` / ``$($aggregate.evidence.comparabilityStatus)``"
        Add-SummaryLine $Lines "  - Repetitions: requested ``$($aggregate.requestedRepetitions)`` observed ``$($aggregate.observedRepetitions)`` missing ``$($aggregate.missingRepetitions)``"
        Add-SummaryLine $Lines "  - Requests/sec: ``$(Format-MetricRange $aggregate.requestsPerSecond)``"
        Add-SummaryLine $Lines "  - Throughput bytes/sec: ``$(Format-MetricRange $aggregate.throughputBytesPerSecond)``"
        Add-SummaryLine $Lines "  - Latency p95 ms: ``$(Format-MetricRange $aggregate.latencyP95Ms)``"
        Add-SummaryLine $Lines "  - Relative range: ``$(Format-Number $aggregate.relativeRange)``"

        if ($aggregate.publishabilityGate) {
            Add-SummaryLine $Lines "  - Publishability gate: ``$($aggregate.publishabilityGate.status)`` blockers ``$($aggregate.publishabilityGate.blockers -join ', ')``"
        }

        if ($aggregate.failureReasons -and $aggregate.failureReasons.Count -gt 0) {
            Add-SummaryLine $Lines "  - Failure reasons: ``$($aggregate.failureReasons -join ', ')``"
        }
    }
}

function Get-ProtocolLabAggregateHealth {
    param(
        [string] $AggregatePath,

        [bool] $IsDryRun
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    if (-not (Test-Path -LiteralPath $AggregatePath -PathType Leaf)) {
        if (-not $IsDryRun) {
            $reasons.Add("missing aggregate results: $AggregatePath") | Out-Null
        }

        return [pscustomobject]@{
            HasFailures = $reasons.Count -gt 0
            Reasons = @($reasons)
        }
    }

    $aggregateDocument = Get-Content -LiteralPath $AggregatePath -Raw | ConvertFrom-Json
    foreach ($aggregate in @($aggregateDocument.aggregates)) {
        $cell = "$($aggregate.implementationId)/$($aggregate.scenarioId)"
        $validation = $aggregate.validation
        $validationFailed = [int]$validation.failed
        $validationInfrastructure = [int]$validation.infrastructureFailure
        if ($validationFailed -gt 0 -or $validationInfrastructure -gt 0) {
            $reasons.Add("$cell validation failed=$validationFailed infrastructure=$validationInfrastructure") | Out-Null
        }

        foreach ($status in @($aggregate.benchmarkExecutionStatuses.PSObject.Properties)) {
            if ([string]::Equals($status.Name, "failed", [StringComparison]::OrdinalIgnoreCase) -and [int]$status.Value -gt 0) {
                $reasons.Add("$cell benchmark failed=$($status.Value)") | Out-Null
            }
        }

        if ([int]$aggregate.errorCount -gt 0) {
            $reasons.Add("$cell errors=$($aggregate.errorCount)") | Out-Null
        }

        if ($aggregate.failureReasons -and $aggregate.failureReasons.Count -gt 0) {
            $reasons.Add("$cell failure reasons: $($aggregate.failureReasons -join '; ')") | Out-Null
        }
    }

    return [pscustomobject]@{
        HasFailures = $reasons.Count -gt 0
        Reasons = @($reasons)
    }
}

$repoRoot = Get-RepoRoot
$resolvedArtifactsRoot = Resolve-FullPath -Path $ArtifactsRoot -BasePath $repoRoot
$runRoot = Join-Path $resolvedArtifactsRoot $RunIdPrefix
$bdnRoot = Join-Path $runRoot "bdn"
$summaryPath = Join-Path $runRoot "summary.md"
$surfaceConfig = Get-SurfaceConfiguration -RequestedSurface $Surface -RequestedScenario $Scenario -RequestedHttp3Scenario $Http3Scenario -RequestedRawQuicScenario $RawQuicScenario
$protocolLabJobs = @(Get-ProtocolLabJobs -SurfaceConfiguration $surfaceConfig)
$benchmarkJob = if ($Lane -eq "Smoke") { "Dry" } else { "Short" }
$durationSeconds = if ($Lane -eq "Smoke") { 1 } else { 15 }
$warmupSeconds = if ($Lane -eq "Smoke") { 1 } else { 5 }
$repetitions = if ($Lane -eq "Smoke") { 1 } else { 9 }
$resolvedProtocolLabRoot = Resolve-FullPath -Path $ProtocolLabRoot -BasePath $repoRoot
$resolvedProtocolLabExecutionRoot = Resolve-ProtocolLabExecutionRoot -ContractRoot $resolvedProtocolLabRoot -RequestedExecutionRoot $ProtocolLabExecutionRoot -BasePath $repoRoot
$commands = New-Object System.Collections.Generic.List[object]
$protocolLabRunRecords = New-Object System.Collections.Generic.List[object]

New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

$gitCommit = (& git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitCommit)) {
    $gitCommit = "unknown"
}
else {
    $gitCommit = $gitCommit.Trim()
}

$gitStatus = @(& git -C $repoRoot status --porcelain 2>$null)
if ($LASTEXITCODE -ne 0) {
    $gitState = "unknown"
}
elseif ($gitStatus.Count -eq 0) {
    $gitState = "clean"
}
else {
    $gitState = "dirty"
}

Write-Host "QUIC performance lane" -ForegroundColor Cyan
Write-Host "Lane: $Lane" -ForegroundColor Yellow
Write-Host "Surface: $Surface" -ForegroundColor Yellow
Write-Host "Run root: $runRoot" -ForegroundColor Yellow

$laneStatus = "passed"
$failureMessage = $null
$shouldRunProtocolLab = -not $SkipProtocolLab -and $protocolLabJobs.Count -gt 0
$effectiveFailOnProtocolLabError = if ($PSBoundParameters.ContainsKey("FailOnProtocolLabError")) { [bool]$FailOnProtocolLabError } else { $Surface -ne "CoreProtocolLab" }

try {
if (-not $SkipBenchmarks) {
    $benchmarkSliceIndex = 0

    foreach ($benchmarkFilter in $surfaceConfig.BenchmarkFilters) {
        $benchmarkScript = Join-Path $repoRoot $surfaceConfig.BenchmarkScript
        $benchmarkSliceIndex++
        $benchmarkArgs = @(
            "-Job", $benchmarkJob,
            "-ArtifactsRoot", $bdnRoot
        )

        if ($NoRestore) {
            $benchmarkArgs += "-NoRestore"
        }

        if ($NoBuild -or $benchmarkSliceIndex -gt 1) {
            $benchmarkArgs += "-NoBuild"
        }

        $benchmarkArgs += @("-BenchmarkFilter", $benchmarkFilter)

        $benchmarkProcessArgs = @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $benchmarkScript
        ) + $benchmarkArgs
        $benchmarkCommand = Format-CommandLine $PowerShellPath $benchmarkProcessArgs
        $commands.Add([pscustomobject]@{
            Name = "BenchmarkDotNet $benchmarkFilter"
            Command = $benchmarkCommand
            Artifacts = $bdnRoot
        }) | Out-Null

        Invoke-LaneCommand -FileName $PowerShellPath -Arguments $benchmarkProcessArgs -WorkingDirectory $repoRoot -IsDryRun:$DryRun
    }
}

if ($shouldRunProtocolLab) {
    $protocolLabScript = Join-Path $repoRoot "scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1"
    $protocolLabBenchmarkScript = Join-Path $resolvedProtocolLabExecutionRoot "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"

    if (-not (Test-Path -LiteralPath $protocolLabBenchmarkScript -PathType Leaf)) {
        throw "ProtocolLab benchmark set script was not found in execution root: $protocolLabBenchmarkScript"
    }

    foreach ($protocolLabJob in $protocolLabJobs) {
        if ([string]::IsNullOrWhiteSpace($protocolLabJob.Scenario)) {
            throw "ProtocolLab job '$($protocolLabJob.Name)' requires a scenario before it can run."
        }

        $jobRunIdPrefix = if ($protocolLabJobs.Count -gt 1) {
            "$RunIdPrefix-$($protocolLabJob.Id)"
        }
        else {
            $RunIdPrefix
        }

        $jobRunId = "$jobRunIdPrefix-$($protocolLabJob.Suite)"
        $jobRunRoot = Join-Path (Join-Path $resolvedProtocolLabExecutionRoot ".artifacts\runs") $jobRunId
        $jobAggregatePath = Join-Path $jobRunRoot "aggregate-results.json"
        $jobSummaryPath = Join-Path $jobRunRoot "summary.md"
        $protocolLabArgs = @(
            "-ProtocolLabRoot", $resolvedProtocolLabRoot,
            "-ProtocolLabExecutionRoot", $resolvedProtocolLabExecutionRoot,
            "-UseProjectReferences",
            "-Suite", $protocolLabJob.Suite,
            "-Implementation", $protocolLabJob.Implementation,
            "-Scenario", $protocolLabJob.Scenario,
            "-WorkflowProfile", "Quick",
            "-RunIdPrefix", $jobRunIdPrefix,
            "-DurationSeconds", $durationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-WarmupSeconds", $warmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-Repetitions", $repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-Connections", $protocolLabJob.Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-StreamsPerConnection", $protocolLabJob.StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture)
        )

        if ($effectiveFailOnProtocolLabError) {
            $protocolLabArgs += "-FailOnError"
        }
        else {
            $protocolLabArgs += "-AllowBenchmarkFailure"
        }

        if ($NoRestore) {
            $protocolLabArgs += "-NoRestore"
        }

        if ($CaptureCounters) {
            $protocolLabArgs += @(
                "-CaptureCounters",
                "-CounterRefreshInterval",
                ([Math]::Max(1, $CounterRefreshInterval)).ToString([Globalization.CultureInfo]::InvariantCulture))
        }

        $protocolLabProcessArgs = @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $protocolLabScript
        ) + $protocolLabArgs
        $protocolLabCommand = Format-CommandLine $PowerShellPath $protocolLabProcessArgs
        $commands.Add([pscustomobject]@{
            Name = "ProtocolLab $($protocolLabJob.Name)"
            Command = $protocolLabCommand
            Artifacts = $jobRunRoot
        }) | Out-Null
        $protocolLabRunRecords.Add([pscustomobject]@{
            Job = $protocolLabJob
            RunId = $jobRunId
            RunRoot = $jobRunRoot
            AggregatePath = $jobAggregatePath
            SummaryPath = $jobSummaryPath
        }) | Out-Null

        Invoke-LaneCommand -FileName $PowerShellPath -Arguments $protocolLabProcessArgs -WorkingDirectory $repoRoot -IsDryRun:$DryRun
    }
}
}
catch {
    $laneStatus = "failed"
    $failureMessage = $_.Exception.Message
}

$protocolLabHealthReasons = New-Object System.Collections.Generic.List[string]
if ($shouldRunProtocolLab) {
    foreach ($record in $protocolLabRunRecords) {
        $health = Get-ProtocolLabAggregateHealth -AggregatePath $record.AggregatePath -IsDryRun:$DryRun
        if ($health.HasFailures) {
            foreach ($reason in @($health.Reasons)) {
                $protocolLabHealthReasons.Add("$($record.Job.Name): $reason") | Out-Null
            }
        }
    }

    if ($laneStatus -eq "passed" -and $protocolLabHealthReasons.Count -gt 0) {
        $laneStatus = "completed-with-diagnostic-failures"
    }
}

$summary = New-Object System.Collections.Generic.List[string]
Add-SummaryLine $summary "# QUIC Performance Lane Summary"
Add-SummaryLine $summary ""
Add-SummaryLine $summary "- Lane: ``$Lane``"
Add-SummaryLine $summary "- Surface: ``$Surface``"
Add-SummaryLine $summary "- Run ID prefix: ``$RunIdPrefix``"
Add-SummaryLine $summary "- Git commit: ``$gitCommit``"
Add-SummaryLine $summary "- Git state: ``$gitState``"
Add-SummaryLine $summary "- Dry run: ``$DryRun``"
Add-SummaryLine $summary "- Status: ``$laneStatus``"
Add-SummaryLine $summary "- Report-only confidence: ``$($Lane -eq "Confidence")``"
Add-SummaryLine $summary "- Evidence quality: ``$(if ($Lane -eq "Confidence") { "confidence-local" } else { "diagnostic-smoke" })``"
Add-SummaryLine $summary ""

if ($failureMessage) {
    Add-SummaryLine $summary "Failure: ``$failureMessage``"
    Add-SummaryLine $summary ""
}

if ($protocolLabHealthReasons.Count -gt 0) {
    Add-SummaryLine $summary "ProtocolLab diagnostic failures:"
    foreach ($reason in $protocolLabHealthReasons) {
        Add-SummaryLine $summary "- ``$reason``"
    }

    Add-SummaryLine $summary ""
}

if ($Lane -eq "Confidence") {
    Add-SummaryLine $summary "Confidence lanes are report-only. This script records repeated evidence but does not enforce performance thresholds."
    Add-SummaryLine $summary ""
}

Add-SummaryLine $summary "## Commands"
Add-SummaryLine $summary ""
if ($commands.Count -eq 0) {
    Add-SummaryLine $summary "- No commands were selected."
}
else {
    foreach ($command in $commands) {
        Add-SummaryLine $summary "- $($command.Name): ``$($command.Command)``"
    }
}

Add-SummaryLine $summary ""
Add-SummaryLine $summary "## BenchmarkDotNet"
Add-SummaryLine $summary ""
if ($SkipBenchmarks) {
    Add-SummaryLine $summary "- Skipped."
}
else {
    Add-SummaryLine $summary "- Job: ``$benchmarkJob``"
    Add-SummaryLine $summary "- Artifacts root: ``$bdnRoot``"
    if ($surfaceConfig.BenchmarkFilters.Count -eq 0) {
        Add-SummaryLine $summary "- No BenchmarkDotNet filters selected for this surface."
    }
    else {
        foreach ($filter in $surfaceConfig.BenchmarkFilters) {
            $sliceName = Get-SliceName -Filter $filter
            Add-SummaryLine $summary "- Filter: ``$filter`` -> ``$(Join-Path (Join-Path $bdnRoot $benchmarkJob) $sliceName)``"
        }
    }
}

Add-SummaryLine $summary ""
Add-SummaryLine $summary "## ProtocolLab"
Add-SummaryLine $summary ""
if (-not $shouldRunProtocolLab) {
    Add-SummaryLine $summary "- Skipped. Surface default or caller option selected no ProtocolLab run."
}
else {
    Add-SummaryLine $summary "- Contract root: ``$resolvedProtocolLabRoot``"
    Add-SummaryLine $summary "- Execution root: ``$resolvedProtocolLabExecutionRoot``"
    Add-SummaryLine $summary "- Duration seconds: ``$durationSeconds``"
    Add-SummaryLine $summary "- Warmup seconds: ``$warmupSeconds``"
    Add-SummaryLine $summary "- Repetitions: ``$repetitions``"
    Add-SummaryLine $summary "- NoRestore requested: ``$NoRestore``"
    Add-SummaryLine $summary "- Fail on ProtocolLab error: ``$effectiveFailOnProtocolLabError``"
    Add-SummaryLine $summary ""

    foreach ($record in $protocolLabRunRecords) {
        Add-SummaryLine $summary "### $($record.Job.Name)"
        Add-SummaryLine $summary ""
        Add-SummaryLine $summary "- Suite: ``$($record.Job.Suite)``"
        Add-SummaryLine $summary "- Implementation: ``$($record.Job.Implementation)``"
        Add-SummaryLine $summary "- Scenario: ``$($record.Job.Scenario)``"
        Add-SummaryLine $summary "- Connections: ``$($record.Job.Connections)``"
        Add-SummaryLine $summary "- Streams per connection: ``$($record.Job.StreamsPerConnection)``"
        Add-SummaryLine $summary "- Run ID: ``$($record.RunId)``"
        Add-SummaryLine $summary "- Run root: ``$($record.RunRoot)``"
        Add-SummaryLine $summary "- Aggregate results: ``$($record.AggregatePath)``"
        Add-SummaryLine $summary "- Summary: ``$($record.SummaryPath)``"
        Add-SummaryLine $summary ""
        Add-ProtocolLabAggregateSummary -Lines $summary -AggregatePath $record.AggregatePath
        Add-SummaryLine $summary ""
    }
}

Set-Content -Path $summaryPath -Value $summary
Write-Host ""
Write-Host "Summary: $summaryPath" -ForegroundColor Green

if ($failureMessage) {
    throw $failureMessage
}
