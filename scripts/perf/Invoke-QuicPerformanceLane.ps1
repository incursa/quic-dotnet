[CmdletBinding()]
param(
    [ValidateSet("Smoke", "Confidence")]
    [string] $Lane = "Smoke",

    [ValidateSet("RawQuicMultiplex", "RawQuicDuplex", "RawQuicSendCore", "PublicApiStream")]
    [string] $Surface = "RawQuicMultiplex",

    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",

    [switch] $NoRestore,

    [switch] $NoBuild,

    [string] $RunIdPrefix = "local-quic-perf-$((Get-Date).ToString('yyyyMMddHHmmss'))",

    [string] $ArtifactsRoot = ".artifacts\perf-lanes",

    [string] $Scenario,

    [switch] $SkipProtocolLab,

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

        [string] $RequestedScenario
    )

    $sendFilters = @(
        "*QuicApplicationSendPriorityBenchmarks*",
        "*QuicApplicationSendQueueSortingBenchmarks*",
        "*QuicApplicationSendBatchPayloadBenchmarks*",
        "*QuicStreamParsingBenchmarks*"
    )

    switch ($RequestedSurface) {
        "RawQuicMultiplex" {
            return [pscustomobject]@{
                BenchmarkScript = "scripts\benchmarks\Invoke-QuicBaseline.ps1"
                BenchmarkFilters = $sendFilters
                ProtocolLabEnabled = $true
                ProtocolLabScenario = if ([string]::IsNullOrWhiteSpace($RequestedScenario)) { "quic.transport.multiplex.100x64kb" } else { $RequestedScenario }
                Connections = 1
                StreamsPerConnection = 1
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

$repoRoot = Get-RepoRoot
$resolvedArtifactsRoot = Resolve-FullPath -Path $ArtifactsRoot -BasePath $repoRoot
$runRoot = Join-Path $resolvedArtifactsRoot $RunIdPrefix
$bdnRoot = Join-Path $runRoot "bdn"
$summaryPath = Join-Path $runRoot "summary.md"
$surfaceConfig = Get-SurfaceConfiguration -RequestedSurface $Surface -RequestedScenario $Scenario
$benchmarkJob = if ($Lane -eq "Smoke") { "Dry" } else { "Short" }
$durationSeconds = if ($Lane -eq "Smoke") { 1 } else { 15 }
$warmupSeconds = if ($Lane -eq "Smoke") { 1 } else { 5 }
$repetitions = if ($Lane -eq "Smoke") { 1 } else { 9 }
$protocolLabSuite = "quic-transport-v1-comparison"
$protocolLabImplementation = "incursa-raw-quic-adapter-v1"
$resolvedProtocolLabRoot = Resolve-FullPath -Path $ProtocolLabRoot -BasePath $repoRoot
$protocolLabRunId = "$RunIdPrefix-$protocolLabSuite"
$protocolLabRunRoot = Join-Path (Join-Path $resolvedProtocolLabRoot ".artifacts\runs") $protocolLabRunId
$protocolLabAggregatePath = Join-Path $protocolLabRunRoot "aggregate-results.json"
$protocolLabSummaryPath = Join-Path $protocolLabRunRoot "summary.md"
$commands = New-Object System.Collections.Generic.List[object]

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
$shouldRunProtocolLab = -not $SkipProtocolLab -and [bool]$surfaceConfig.ProtocolLabEnabled

try {
if (-not $SkipBenchmarks) {
    $benchmarkScript = Join-Path $repoRoot $surfaceConfig.BenchmarkScript
    $benchmarkSliceIndex = 0

    foreach ($benchmarkFilter in $surfaceConfig.BenchmarkFilters) {
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
    if ([string]::IsNullOrWhiteSpace($surfaceConfig.ProtocolLabScenario)) {
        throw "Surface '$Surface' requires -Scenario before ProtocolLab can run."
    }

    $protocolLabScript = Join-Path $repoRoot "scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1"
    $protocolLabBenchmarkScript = Join-Path $resolvedProtocolLabRoot "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"
    $protocolLabArgs = @(
        "-ProtocolLabRoot", $resolvedProtocolLabRoot,
        "-UseProjectReferences",
        "-Suite", $protocolLabSuite,
        "-Implementation", $protocolLabImplementation,
        "-Scenario", $surfaceConfig.ProtocolLabScenario,
        "-WorkflowProfile", "Quick",
        "-RunIdPrefix", $RunIdPrefix,
        "-DurationSeconds", $durationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-WarmupSeconds", $warmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-Repetitions", $repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-Connections", $surfaceConfig.Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-StreamsPerConnection", $surfaceConfig.StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-FailOnError"
    )

    if ($NoRestore) {
        $protocolLabArgs += "-NoRestore"
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
        Name = "ProtocolLab"
        Command = $protocolLabCommand
        Artifacts = $protocolLabRunRoot
    }) | Out-Null

    if (-not (Test-Path -LiteralPath $protocolLabBenchmarkScript -PathType Leaf)) {
        throw "ProtocolLab benchmark set script was not found: $protocolLabBenchmarkScript"
    }

    Invoke-LaneCommand -FileName $PowerShellPath -Arguments $protocolLabProcessArgs -WorkingDirectory $repoRoot -IsDryRun:$DryRun
}
}
catch {
    $laneStatus = "failed"
    $failureMessage = $_.Exception.Message
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
Add-SummaryLine $summary ""

if ($failureMessage) {
    Add-SummaryLine $summary "Failure: ``$failureMessage``"
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
    foreach ($filter in $surfaceConfig.BenchmarkFilters) {
        $sliceName = Get-SliceName -Filter $filter
        Add-SummaryLine $summary "- Filter: ``$filter`` -> ``$(Join-Path (Join-Path $bdnRoot $benchmarkJob) $sliceName)``"
    }
}

Add-SummaryLine $summary ""
Add-SummaryLine $summary "## ProtocolLab"
Add-SummaryLine $summary ""
if (-not $shouldRunProtocolLab) {
    Add-SummaryLine $summary "- Skipped. Surface default or caller option selected no ProtocolLab run."
}
else {
    Add-SummaryLine $summary "- Suite: ``$protocolLabSuite``"
    Add-SummaryLine $summary "- Implementation: ``$protocolLabImplementation``"
    Add-SummaryLine $summary "- Scenario: ``$($surfaceConfig.ProtocolLabScenario)``"
    Add-SummaryLine $summary "- Duration seconds: ``$durationSeconds``"
    Add-SummaryLine $summary "- Warmup seconds: ``$warmupSeconds``"
    Add-SummaryLine $summary "- Repetitions: ``$repetitions``"
    Add-SummaryLine $summary "- NoRestore requested: ``$NoRestore``"
    Add-SummaryLine $summary "- Run ID: ``$protocolLabRunId``"
    Add-SummaryLine $summary "- Run root: ``$protocolLabRunRoot``"
    Add-SummaryLine $summary "- Aggregate results: ``$protocolLabAggregatePath``"
    Add-SummaryLine $summary "- Summary: ``$protocolLabSummaryPath``"
}

Set-Content -Path $summaryPath -Value $summary
Write-Host ""
Write-Host "Summary: $summaryPath" -ForegroundColor Green

if ($failureMessage) {
    throw $failureMessage
}
