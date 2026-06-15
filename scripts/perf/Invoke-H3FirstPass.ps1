[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\src\incursa\protocol-lab",
    [string] $OutputRoot = ".artifacts\perf\incursa-h3-first-pass",
    [string] $RunIdPrefix,
    [int] $DurationSeconds = 10,
    [int] $WarmupSeconds = 2,
    [int] $Repetitions = 3,
    [int[]] $MatrixConnections = @(1, 16, 64),
    [int[]] $MatrixStreamsPerConnection = @(1, 10),
    [string] $TargetConfiguration = "Release",
    [ValidateSet("Dry", "Short", "Medium", "Long")]
    [string] $RawQuicBenchmarkJob = "Short",
    [switch] $SkipRawQuicComparison,
    [switch] $SkipProfilePack,
    [switch] $SkipQlogComparison,
    [switch] $SkipMatrix,
    [switch] $SummaryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RootedPath([string] $Path, [string] $BasePath) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    return [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Format-CommandLine([string] $FileName, [string[]] $Arguments) {
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

function Invoke-LoggedProcess(
    [string] $Name,
    [string] $FileName,
    [string[]] $Arguments,
    [string] $WorkingDirectory,
    [string] $ArtifactRoot) {
    New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
    $commandPath = Join-Path $ArtifactRoot "$Name.command.txt"
    $stdoutPath = Join-Path $ArtifactRoot "$Name.stdout.txt"
    $stderrPath = Join-Path $ArtifactRoot "$Name.stderr.txt"
    Set-Content -Path $commandPath -Value (Format-CommandLine $FileName $Arguments)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new($FileName)
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process) {
        throw "Failed to start $FileName."
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    Set-Content -Path $stdoutPath -Value $stdoutTask.GetAwaiter().GetResult()
    Set-Content -Path $stderrPath -Value $stderrTask.GetAwaiter().GetResult()

    [pscustomobject]@{
        Name = $Name
        Status = if ($process.ExitCode -eq 0) { "succeeded" } else { "failed" }
        ExitCode = $process.ExitCode
        Command = $commandPath
        Stdout = $stdoutPath
        Stderr = $stderrPath
    }
}

function New-ProtocolLabRunArguments(
    [string] $Implementations,
    [string] $Scenarios,
    [string] $Connections,
    [string] $StreamsPerConnection,
    [string] $RunId,
    [string] $ProtocolLabOutput,
    [bool] $DisableQlog,
    [bool] $CaptureLoadToolMetrics) {
    $arguments = @(
        "run",
        "--project", "src/Incursa.ProtocolLab.Cli",
        "--",
        "run",
        "--implementations", $Implementations,
        "--scenarios", $Scenarios,
        "--protocol", "h3",
        "--load-tool", "h2load",
        "--load-tool-mode", "docker",
        "--target-configuration", $TargetConfiguration,
        "--connections", $Connections,
        "--streams-per-connection", $StreamsPerConnection,
        "--duration", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--warmup", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--capture-counters",
        "--counter-refresh-interval", "1",
        "--output", $ProtocolLabOutput,
        "--run-id", $RunId
    )

    if ($DisableQlog) {
        $arguments += "--disable-load-tool-qlog"
    }

    if ($CaptureLoadToolMetrics) {
        $arguments += "--capture-load-tool-metrics"
    }

    $arguments
}

function Get-MedianValue($Object, [string] $PropertyName) {
    if (-not $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if (-not $property -or -not $property.Value) {
        return $null
    }

    $value = $property.Value
    $medianProperty = $value.PSObject.Properties["median"]
    if (-not $medianProperty) {
        return $null
    }

    $medianProperty.Value
}

function Format-NullableNumber($Value, [string] $Format, [string] $Suffix = "") {
    if ($null -eq $Value) {
        return "n/a"
    }

    ("{0:$Format}" -f [double]$Value) + $Suffix
}

function Add-AggregateRows([System.Collections.Generic.List[string]] $Lines, [string] $Title, [string] $RunRoot) {
    $aggregatePath = Join-Path $RunRoot "aggregate-results.json"
    $Lines.Add("")
    $Lines.Add("## $Title")
    $Lines.Add("")
    $Lines.Add("- run root: ``$RunRoot``")
    if (-not (Test-Path -LiteralPath $aggregatePath)) {
        $Lines.Add("- aggregate: not available")
        return
    }

    $aggregate = Get-Content -Path $aggregatePath -Raw | ConvertFrom-Json
    $Lines.Add("")
    $Lines.Add("| implementation | scenario | shape | req/s | p50 | p95 | alloc rate | B/request | exceptions/s | CPU mean | qlog files | warnings |")
    $Lines.Add("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    foreach ($item in $aggregate.aggregates) {
        $rps = Get-MedianValue $item "requestsPerSecond"
        $latencyP50 = Get-MedianValue $item "latencyP50Ms"
        $latencyP95 = Get-MedianValue $item "latencyP95Ms"
        $allocRate = Get-MedianValue $item "counterAllocationRateMean"
        $bytesPerRequest = if ($rps -and $allocRate) { [double]$allocRate / [double]$rps } else { $null }
        $exceptions = Get-MedianValue $item "counterExceptionRateMean"
        $cpu = Get-MedianValue $item "counterCpuMean"
        $shape = "c$($item.connections)-s$($item.streamsPerConnection)"
        $warningText = if ($item.warnings) { ($item.warnings -join "; ") } else { "" }
        $Lines.Add("| ``$($item.implementationId)`` | ``$($item.scenarioId)`` | ``$shape`` | $(Format-NullableNumber $rps "N1") | $(Format-NullableNumber $latencyP50 "N2" " ms") | $(Format-NullableNumber $latencyP95 "N2" " ms") | $(Format-NullableNumber $allocRate "N0") | $(Format-NullableNumber $bytesPerRequest "N0") | $(Format-NullableNumber $exceptions "N2") | $(Format-NullableNumber $cpu "N2" "%") | $($item.qlogFileCountMedian) | $warningText |")
    }
}

function Add-RawQuicRows([System.Collections.Generic.List[string]] $Lines, [string] $ArtifactsRoot, [string] $Job) {
    $csvPaths = @(
        Join-Path $ArtifactsRoot "$Job\QuicPublicApiLoopbackBenchmarks\results\Incursa.Quic.Benchmarks.QuicPublicApiLoopbackBenchmarks-report.csv"
        Join-Path $ArtifactsRoot "$Job\QuicPublicApiStreamTransferBenchmarks\results\Incursa.Quic.Benchmarks.QuicPublicApiStreamTransferBenchmarks-report.csv"
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($csvPath in $csvPaths) {
        if (Test-Path -LiteralPath $csvPath) {
            foreach ($row in (Import-Csv -LiteralPath $csvPath)) {
                $rows.Add($row)
            }
        }
    }

    if ($rows.Count -eq 0) {
        $Lines.Add("- results: not available")
        return
    }

    $Lines.Add("")
    $Lines.Add("| method | implementation | mean | allocated | Gen0 | Gen1 |")
    $Lines.Add("| --- | --- | ---: | ---: | ---: | ---: |")
    foreach ($row in $rows) {
        $Lines.Add("| ``$($row.Method)`` | ``$($row.Implementation)`` | $($row.Mean) | $($row.Allocated) | $($row.Gen0) | $($row.Gen1) |")
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not (Test-Path -LiteralPath $ProtocolLabRoot)) {
    throw "ProtocolLab root was not found: $ProtocolLabRoot"
}

$ProtocolLabRoot = (Resolve-Path -LiteralPath $ProtocolLabRoot).Path
if ([string]::IsNullOrWhiteSpace($RunIdPrefix)) {
    $RunIdPrefix = "incursa-h3-first-pass-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
}

$OutputRoot = Resolve-RootedPath $OutputRoot $repoRoot
$runRoot = Join-Path $OutputRoot $RunIdPrefix
$protocolLabOutput = Join-Path $runRoot "protocol-lab-runs"
New-Item -ItemType Directory -Force -Path $protocolLabOutput | Out-Null

$steps = @()
$rawQuicArtifactsRoot = if ($SkipRawQuicComparison) { $null } else { Join-Path $runRoot "raw-quic-public-comparison" }
$baselineRunId = "$RunIdPrefix-release-qlogoff-counters"
$matrixRunId = if ($SkipMatrix) { $null } else { "$RunIdPrefix-incursa-load-shape-matrix" }
$qlogRunId = if ($SkipQlogComparison) { $null } else { "$RunIdPrefix-incursa-qlogon-counters" }
$profileRoot = Join-Path $runRoot "profile-pack"
$profileRunId = "$RunIdPrefix-profile-plaintext"
$profileRunRoot = if ($SkipProfilePack) { $null } else { Join-Path $profileRoot $profileRunId }

if (-not $SummaryOnly) {
$steps += Invoke-LoggedProcess `
    -Name "quic-dotnet-tool-restore" `
    -FileName "dotnet" `
    -Arguments @("tool", "restore") `
    -WorkingDirectory $repoRoot `
    -ArtifactRoot (Join-Path $runRoot "setup")

$steps += Invoke-LoggedProcess `
    -Name "protocol-lab-tool-restore" `
    -FileName "dotnet" `
    -Arguments @("tool", "restore") `
    -WorkingDirectory $ProtocolLabRoot `
    -ArtifactRoot (Join-Path $runRoot "setup")

$steps += Invoke-LoggedProcess `
    -Name "protocol-lab-build" `
    -FileName "dotnet" `
    -Arguments @("build", "Incursa.ProtocolLab.sln", "-c", $TargetConfiguration) `
    -WorkingDirectory $ProtocolLabRoot `
    -ArtifactRoot (Join-Path $runRoot "setup")

if (-not $SkipRawQuicComparison) {
    $steps += Invoke-LoggedProcess `
        -Name "raw-quic-public-comparison" `
        -FileName "pwsh" `
        -Arguments @(
            "-NoProfile",
            "-File", (Join-Path $repoRoot "scripts\benchmarks\Invoke-QuicPublicComparison.ps1"),
            "-Job", $RawQuicBenchmarkJob,
            "-Configuration", $TargetConfiguration,
            "-ArtifactsRoot", $rawQuicArtifactsRoot
        ) `
        -WorkingDirectory $repoRoot `
        -ArtifactRoot (Join-Path $runRoot "raw-quic-public-comparison-command")
}

$steps += Invoke-LoggedProcess `
    -Name "baseline-release-qlogoff-counters" `
    -FileName "dotnet" `
    -Arguments (New-ProtocolLabRunArguments `
        -Implementations "kestrel-http3,incursa-http3" `
        -Scenarios "http3.core.status,http3.payload.bytes.64kb" `
        -Connections "16" `
        -StreamsPerConnection "10" `
        -RunId $baselineRunId `
        -ProtocolLabOutput $protocolLabOutput `
        -DisableQlog $true `
        -CaptureLoadToolMetrics $true) `
    -WorkingDirectory $ProtocolLabRoot `
    -ArtifactRoot (Join-Path $runRoot "baseline-release-qlogoff-counters")

if (-not $SkipMatrix) {
    $steps += Invoke-LoggedProcess `
        -Name "incursa-load-shape-matrix" `
        -FileName "dotnet" `
        -Arguments (New-ProtocolLabRunArguments `
            -Implementations "incursa-http3" `
            -Scenarios "http3.core.status" `
            -Connections ($MatrixConnections -join ",") `
            -StreamsPerConnection ($MatrixStreamsPerConnection -join ",") `
            -RunId $matrixRunId `
            -ProtocolLabOutput $protocolLabOutput `
            -DisableQlog $true `
            -CaptureLoadToolMetrics $true) `
        -WorkingDirectory $ProtocolLabRoot `
        -ArtifactRoot (Join-Path $runRoot "incursa-load-shape-matrix")
}

if (-not $SkipQlogComparison) {
    $steps += Invoke-LoggedProcess `
        -Name "incursa-qlogon-counters" `
        -FileName "dotnet" `
        -Arguments (New-ProtocolLabRunArguments `
            -Implementations "incursa-http3" `
            -Scenarios "http3.core.status,http3.payload.bytes.64kb" `
            -Connections "16" `
            -StreamsPerConnection "10" `
            -RunId $qlogRunId `
            -ProtocolLabOutput $protocolLabOutput `
            -DisableQlog $false `
            -CaptureLoadToolMetrics $true) `
        -WorkingDirectory $ProtocolLabRoot `
        -ArtifactRoot (Join-Path $runRoot "incursa-qlogon-counters")
}

if (-not $SkipProfilePack) {
    $steps += Invoke-LoggedProcess `
        -Name "profile-pack-status" `
        -FileName "pwsh" `
        -Arguments @(
            "-NoProfile",
            "-File", (Join-Path $PSScriptRoot "Invoke-IncursaH3ProfilePack.ps1"),
            "-ProtocolLabRoot", $ProtocolLabRoot,
            "-OutputRoot", $profileRoot,
            "-RunId", $profileRunId,
            "-Scenario", "http3.core.status",
            "-DurationSeconds", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-WarmupSeconds", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-Repetitions", "1",
            "-Connections", "16",
            "-StreamsPerConnection", "10",
            "-TargetConfiguration", $TargetConfiguration,
            "-DisableLoadToolQlog"
        ) `
        -WorkingDirectory $repoRoot `
        -ArtifactRoot (Join-Path $runRoot "profile-pack-status")
}
}

$summaryLines = [System.Collections.Generic.List[string]]::new()
$summaryLines.Add("# Incursa H3 First Pass $RunIdPrefix")
$summaryLines.Add("")
$summaryLines.Add("- run root: ``$runRoot``")
$summaryLines.Add("- ProtocolLab output: ``$protocolLabOutput``")
$summaryLines.Add("- target configuration: ``$TargetConfiguration``")
$rawQuicJobLabel = if ($SkipRawQuicComparison) { "skipped" } else { $RawQuicBenchmarkJob }
$summaryLines.Add("- raw QUIC public comparison job: ``$rawQuicJobLabel``")
$summaryLines.Add("- primary clean condition: Release target, h2load qlog disabled, runtime counters enabled")
$summaryLines.Add("- duration/warmup/repetitions: $DurationSeconds/$WarmupSeconds/$Repetitions")
$summaryLines.Add("")
$summaryLines.Add("## Step Status")
$summaryLines.Add("")
$summaryLines.Add("| step | status | exit | stdout | stderr |")
$summaryLines.Add("| --- | --- | ---: | --- | --- |")
foreach ($step in $steps) {
    $summaryLines.Add("| ``$($step.Name)`` | ``$($step.Status)`` | $($step.ExitCode) | ``$($step.Stdout)`` | ``$($step.Stderr)`` |")
}

if ($rawQuicArtifactsRoot) {
    $summaryLines.Add("")
    $summaryLines.Add("## Raw QUIC Public Comparison")
    $summaryLines.Add("")
    $summaryLines.Add("- artifact root: ``$rawQuicArtifactsRoot``")
    $summaryLines.Add("- suite: ``QuicPublicApiLoopbackBenchmarks`` and ``QuicPublicApiStreamTransferBenchmarks``")
    $summaryLines.Add("- comparison: Incursa.Quic public facade vs ``System.Net.Quic`` / MSQUIC-backed public facade where supported")
    $summaryLines.Add("")
    $summaryLines.Add("Use this lane before blaming HTTP/3/QPACK. If Incursa is already far behind here, optimize the QUIC transport/runtime path first. If this lane is close but ProtocolLab H3 is far behind, move up to HTTP/3 response, stream, QPACK, or adapter overhead.")
    Add-RawQuicRows $summaryLines $rawQuicArtifactsRoot $RawQuicBenchmarkJob
}

Add-AggregateRows $summaryLines "Baseline: Release, Qlog Off, Counters" (Join-Path $protocolLabOutput $baselineRunId)
if ($matrixRunId) {
    Add-AggregateRows $summaryLines "Incursa Load-Shape Matrix: Qlog Off" (Join-Path $protocolLabOutput $matrixRunId)
}

if ($qlogRunId) {
    Add-AggregateRows $summaryLines "Incursa Qlog-On Comparison" (Join-Path $protocolLabOutput $qlogRunId)
}

if ($profileRunRoot) {
    $summaryLines.Add("")
    $summaryLines.Add("## Profile Pack")
    $summaryLines.Add("")
    $summaryLines.Add("- profile root: ``$profileRunRoot``")
    $summaryLines.Add("- summary: ``$(Join-Path $profileRunRoot "summary.md")``")
    $summaryLines.Add("- raw CPU trace: ``$(Join-Path $profileRunRoot "cpu-trace\trace.nettrace")``")
    $summaryLines.Add("- raw GC trace: ``$(Join-Path $profileRunRoot "gc-trace\trace.nettrace")``")
}

$summaryLines.Add("")
$summaryLines.Add("## How To Use This Evidence")
$summaryLines.Add("")
$summaryLines.Add("Start from the clean baseline row. If Kestrel and Incursa both show valid counter capture, use the Incursa/Kestrel req/s ratio plus CPU, exception rate, and B/request to choose the first slice. Then use the matrix to decide whether the pressure is per-request, per-stream, or per-connection. Use the profile pack for stack-level attribution before editing hot-path code.")

$summaryPath = Join-Path $runRoot "first-pass-summary.md"
$summaryLines | Set-Content -Path $summaryPath

$manifest = [ordered]@{
    runIdPrefix = $RunIdPrefix
    runRoot = $runRoot
    protocolLabOutput = $protocolLabOutput
    targetConfiguration = $TargetConfiguration
    rawQuicBenchmarkJob = if ($SkipRawQuicComparison) { $null } else { $RawQuicBenchmarkJob }
    rawQuicArtifactsRoot = $rawQuicArtifactsRoot
    durationSeconds = $DurationSeconds
    warmupSeconds = $WarmupSeconds
    repetitions = $Repetitions
    baselineRunId = $baselineRunId
    matrixRunId = $matrixRunId
    qlogRunId = $qlogRunId
    profileRunRoot = $profileRunRoot
    summary = $summaryPath
    steps = $steps
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $runRoot "first-pass-manifest.json")
Get-Content -Path $summaryPath
