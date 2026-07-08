[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\src\incursa\protocol-lab",
    [string] $OutputRoot = ".artifacts\perf\incursa-h3-profile-pack",
    [string] $RunId,
    [string] $Scenario = "http3.core.status",
    [int] $DurationSeconds = 10,
    [int] $WarmupSeconds = 2,
    [int] $Repetitions = 1,
    [int] $Connections = 16,
    [int] $StreamsPerConnection = 10,
    [string] $TargetConfiguration = "Release",
    [switch] $DisableLoadToolQlog = $true,
    [switch] $CollectCounters = $true,
    [switch] $CollectCpuTrace = $true,
    [switch] $CollectGcTrace = $true,
    [switch] $CollectGcDump = $false,
    [switch] $CollectPerfView = $false,
    [string] $PerfViewPath,
    [string] $IncursaQuicSourceRoot,
    [switch] $KeepServerRunning = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RootedPath([string] $Path, [string] $BasePath) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    return [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Resolve-ScenarioId([string] $Value) {
    switch -Regex ($Value) {
        '^(status|http3\.core\.status)$' { return "http3.core.status" }
        '^(bytes1|bytes1kb|bytes-1kb|http3\.payload\.bytes\.1kb)$' { return "http3.payload.bytes.1kb" }
        '^(bytes64|bytes-64kb|http3\.payload\.bytes\.64kb)$' { return "http3.payload.bytes.64kb" }
        '^(bytes1mb|bytes-1mb|http3\.payload\.bytes\.1mb)$' { return "http3.payload.bytes.1mb" }
        default { return $Value }
    }
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
    [string] $FileName,
    [string[]] $Arguments,
    [string] $WorkingDirectory,
    [string] $CommandPath,
    [string] $StdoutPath,
    [string] $StderrPath) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $StdoutPath) | Out-Null
    Set-Content -Path $CommandPath -Value (Format-CommandLine $FileName $Arguments)

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
    Set-Content -Path $StdoutPath -Value $stdoutTask.GetAwaiter().GetResult()
    Set-Content -Path $StderrPath -Value $stderrTask.GetAwaiter().GetResult()

    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Command = Get-Content -Path $CommandPath -Raw
        Stdout = $StdoutPath
        Stderr = $StderrPath
    }
}

function Start-LoggedProcess(
    [string] $FileName,
    [string[]] $Arguments,
    [string] $WorkingDirectory,
    [string] $CommandPath,
    [string] $StdoutPath,
    [string] $StderrPath) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $StdoutPath) | Out-Null
    Set-Content -Path $CommandPath -Value (Format-CommandLine $FileName $Arguments)

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

    [pscustomobject]@{
        Process = $process
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
        Stdout = $StdoutPath
        Stderr = $StderrPath
        Command = Get-Content -Path $CommandPath -Raw
    }
}

function Complete-LoggedProcess($StartedProcess) {
    $StartedProcess.Process.WaitForExit()
    Set-Content -Path $StartedProcess.Stdout -Value $StartedProcess.StdoutTask.GetAwaiter().GetResult()
    Set-Content -Path $StartedProcess.Stderr -Value $StartedProcess.StderrTask.GetAwaiter().GetResult()
    $StartedProcess.Process.ExitCode
}

function New-ProtocolLabArguments(
    [string] $ScenarioId,
    [string] $ProtocolLabOutputRoot,
    [string] $ProtocolLabRunId,
    [bool] $CaptureCounterData) {
    $arguments = @(
        "run",
        "--project", "src/Incursa.ProtocolLab.Cli",
        "--",
        "run",
        "--implementations", "incursa-http3",
        "--scenarios", $ScenarioId,
        "--protocol", "h3",
        "--load-tool", "h2load",
        "--load-tool-mode", "docker",
        "--target-configuration", $TargetConfiguration,
        "--connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--streams-per-connection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--duration", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--warmup", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--output", $ProtocolLabOutputRoot,
        "--run-id", $ProtocolLabRunId
    )

    if ($DisableLoadToolQlog) {
        $arguments += "--disable-load-tool-qlog"
    }

    if ($CaptureCounterData) {
        $arguments += @("--capture-counters", "--counter-refresh-interval", "1")
    }

    $arguments
}

function Wait-DiagnosticTarget(
    [string] $ProtocolLabOutputRoot,
    [string] $ProtocolLabRunId,
    [int] $TimeoutSeconds) {
    $runRoot = Join-Path $ProtocolLabOutputRoot $ProtocolLabRunId
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $runRoot) {
            $candidate = Get-ChildItem -LiteralPath $runRoot -Recurse -Filter "diagnostic-target.json" -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($candidate) {
                try {
                    $target = Get-Content -Path $candidate.FullName -Raw | ConvertFrom-Json
                    if ($target.resolvedProcessId) {
                        return [pscustomobject]@{
                            Path = $candidate.FullName
                            ProcessId = [int]$target.resolvedProcessId
                            Confidence = $target.confidence
                            ResolutionStrategy = $target.resolutionStrategy
                        }
                    }
                }
                catch {
                    Start-Sleep -Milliseconds 250
                }
            }
        }

        Start-Sleep -Milliseconds 250
    }

    return $null
}

function Invoke-WrapperPass(
    [string] $Name,
    [string] $TraceMode,
    [bool] $CaptureCounterData) {
    $passRoot = Join-Path $runRoot $Name
    New-Item -ItemType Directory -Force -Path $passRoot | Out-Null
    $protocolRunId = "$RunId-$Name"
    $wrapper = Join-Path $PSScriptRoot "Run-ProtocolLabIncursaH3H2Load.ps1"
    $arguments = @(
        "-NoProfile",
        "-File", $wrapper,
        "-ProtocolLabRoot", $ProtocolLabRoot,
        "-Scenarios", $scenarioId,
        "-Connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-StreamsPerConnection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-DurationSeconds", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-WarmupSeconds", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-Repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-TargetConfiguration", $TargetConfiguration,
        "-RunId", $protocolRunId,
        "-Output", $protocolLabOutputRoot
    )

    if ($DisableLoadToolQlog) {
        $arguments += "-DisableLoadToolQlog"
    }

    if ($CaptureCounterData) {
        $arguments += "-CaptureCounters"
    }

    if ($TraceMode -ne "none") {
        $arguments += @(
            "-TraceMode", $TraceMode,
            "-TraceArtifactRoot", $passRoot,
            "-TraceDurationSeconds", ([Math]::Max(5, $DurationSeconds + $WarmupSeconds + 3)).ToString([Globalization.CultureInfo]::InvariantCulture)
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($IncursaQuicSourceRoot)) {
        $arguments += @("-IncursaQuicSourceRoot", $IncursaQuicSourceRoot)
    }

    $result = Invoke-LoggedProcess `
        -FileName "pwsh" `
        -Arguments $arguments `
        -WorkingDirectory $repoRoot `
        -CommandPath (Join-Path $passRoot "wrapper-command.txt") `
        -StdoutPath (Join-Path $passRoot "wrapper.stdout.txt") `
        -StderrPath (Join-Path $passRoot "wrapper.stderr.txt")

    [pscustomobject]@{
        Name = $Name
        Status = $(if ($result.ExitCode -eq 0) { "succeeded" } else { "failed" })
        ExitCode = $result.ExitCode
        TraceMode = $TraceMode
        CaptureCounters = $CaptureCounterData
        ArtifactRoot = $passRoot
        ProtocolLabRunId = $protocolRunId
        ProtocolLabRunRoot = Join-Path $protocolLabOutputRoot $protocolRunId
        Command = $result.Command
        Stdout = $result.Stdout
        Stderr = $result.Stderr
    }
}

function Invoke-TraceConvert([string] $TraceRoot) {
    $tracePath = Join-Path $TraceRoot "trace.nettrace"
    if (-not (Test-Path -LiteralPath $tracePath)) {
        return [pscustomobject]@{
            Status = "skipped"
            Reason = "trace.nettrace was not found"
        }
    }

    $outputBase = Join-Path $TraceRoot "trace.speedscope"
    $arguments = @("tool", "run", "dotnet-trace", "--", "convert", $tracePath, "--format", "Speedscope", "-o", $outputBase)
    $result = Invoke-LoggedProcess `
        -FileName "dotnet" `
        -Arguments $arguments `
        -WorkingDirectory $repoRoot `
        -CommandPath (Join-Path $TraceRoot "dotnet-trace-convert-speedscope-command.txt") `
        -StdoutPath (Join-Path $TraceRoot "dotnet-trace-convert-speedscope.stdout.txt") `
        -StderrPath (Join-Path $TraceRoot "dotnet-trace-convert-speedscope.stderr.txt")

    $speedscope = Get-ChildItem -LiteralPath $TraceRoot -Filter "*.speedscope.json" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    [pscustomobject]@{
        Status = $(if ($result.ExitCode -eq 0 -and $speedscope) { "succeeded" } else { "failed" })
        ExitCode = $result.ExitCode
        Output = $(if ($speedscope) { $speedscope.FullName } else { $null })
        Command = $result.Command
        Stdout = $result.Stdout
        Stderr = $result.Stderr
    }
}

function Invoke-GcDumpCollect([int] $TargetProcessId, [string] $OutputPath, [string] $ArtifactRoot, [string] $Label) {
    $arguments = @("tool", "run", "dotnet-gcdump", "--", "collect", "-p", $TargetProcessId.ToString([Globalization.CultureInfo]::InvariantCulture), "-o", $OutputPath)
    Invoke-LoggedProcess `
        -FileName "dotnet" `
        -Arguments $arguments `
        -WorkingDirectory $repoRoot `
        -CommandPath (Join-Path $ArtifactRoot "dotnet-gcdump-$Label-command.txt") `
        -StdoutPath (Join-Path $ArtifactRoot "dotnet-gcdump-$Label.stdout.txt") `
        -StderrPath (Join-Path $ArtifactRoot "dotnet-gcdump-$Label.stderr.txt")
}

function Invoke-GcDumpPass {
    $passRoot = Join-Path $runRoot "gcdump"
    New-Item -ItemType Directory -Force -Path $passRoot | Out-Null
    $protocolRunId = "$RunId-gcdump"
    $arguments = New-ProtocolLabArguments $scenarioId $protocolLabOutputRoot $protocolRunId $false
    $started = Start-LoggedProcess `
        -FileName "dotnet" `
        -Arguments $arguments `
        -WorkingDirectory $ProtocolLabRoot `
        -CommandPath (Join-Path $passRoot "protocol-lab-command.txt") `
        -StdoutPath (Join-Path $passRoot "protocol-lab.stdout.txt") `
        -StderrPath (Join-Path $passRoot "protocol-lab.stderr.txt")

    $target = Wait-DiagnosticTarget $protocolLabOutputRoot $protocolRunId 60
    $before = $null
    $after = $null
    $status = "failed"
    $reason = $null

    if ($target) {
        Set-Content -Path (Join-Path $passRoot "diagnostic-target-path.txt") -Value $target.Path
        $before = Invoke-GcDumpCollect $target.ProcessId (Join-Path $passRoot "before.gcdump") $passRoot "before"
        $sleepSeconds = [Math]::Max(1, $DurationSeconds + $WarmupSeconds)
        Start-Sleep -Seconds $sleepSeconds
        if (Get-Process -Id $target.ProcessId -ErrorAction SilentlyContinue) {
            $after = Invoke-GcDumpCollect $target.ProcessId (Join-Path $passRoot "after.gcdump") $passRoot "after"
        }
        else {
            $reason = "Target process exited before after.gcdump collection."
        }
    }
    else {
        $reason = "ProtocolLab diagnostic target was not resolved before gcdump collection."
    }

    $exitCode = Complete-LoggedProcess $started
    if ($before -and $before.ExitCode -eq 0 -and $after -and $after.ExitCode -eq 0 -and $exitCode -eq 0) {
        $status = "succeeded"
    }

    [pscustomobject]@{
        Name = "gcdump"
        Status = $status
        Reason = $reason
        ProtocolLabExitCode = $exitCode
        ArtifactRoot = $passRoot
        ProtocolLabRunId = $protocolRunId
        ProtocolLabRunRoot = Join-Path $protocolLabOutputRoot $protocolRunId
        ProcessId = $(if ($target) { $target.ProcessId } else { $null })
        Before = $(if (Test-Path -LiteralPath (Join-Path $passRoot "before.gcdump")) { Join-Path $passRoot "before.gcdump" } else { $null })
        After = $(if (Test-Path -LiteralPath (Join-Path $passRoot "after.gcdump")) { Join-Path $passRoot "after.gcdump" } else { $null })
    }
}

function Resolve-PerfViewExecutable {
    if (-not [string]::IsNullOrWhiteSpace($PerfViewPath) -and (Test-Path -LiteralPath $PerfViewPath)) {
        return (Resolve-Path -LiteralPath $PerfViewPath).Path
    }

    $command = Get-Command "PerfView.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

function Invoke-PerfViewPass {
    $passRoot = Join-Path $runRoot "perfview"
    New-Item -ItemType Directory -Force -Path $passRoot | Out-Null
    $perfView = Resolve-PerfViewExecutable
    if (-not $perfView) {
        $instructions = @(
            "PerfView.exe was not found on PATH and -PerfViewPath was not supplied.",
            "Manual option:",
            "  PerfView.exe /AcceptEula /NoGui collect /MaxCollectSec:<seconds> /DataFile:<output.etl.zip>",
            "Open the resulting trace in PerfView and inspect GC Alloc Stacks for System.Byte[] and Incursa.Quic/Incursa.Quic.Http3 frames."
        )
        Set-Content -Path (Join-Path $passRoot "perfview-unavailable.txt") -Value $instructions
        return [pscustomobject]@{
            Name = "perfview"
            Status = "unavailable"
            ArtifactRoot = $passRoot
            Instructions = Join-Path $passRoot "perfview-unavailable.txt"
        }
    }

    $protocolRunId = "$RunId-perfview"
    $protocolArguments = New-ProtocolLabArguments $scenarioId $protocolLabOutputRoot $protocolRunId $false
    $started = Start-LoggedProcess `
        -FileName "dotnet" `
        -Arguments $protocolArguments `
        -WorkingDirectory $ProtocolLabRoot `
        -CommandPath (Join-Path $passRoot "protocol-lab-command.txt") `
        -StdoutPath (Join-Path $passRoot "protocol-lab.stdout.txt") `
        -StderrPath (Join-Path $passRoot "protocol-lab.stderr.txt")

    $target = Wait-DiagnosticTarget $protocolLabOutputRoot $protocolRunId 60
    $perfExitCode = $null
    $status = "failed"
    $reason = $null
    if ($target) {
        $seconds = [Math]::Max(5, $DurationSeconds + $WarmupSeconds + 3)
        $dataFile = Join-Path $passRoot "perfview.etl.zip"
        $perfArgs = @("/AcceptEula", "/NoGui", "collect", "/MaxCollectSec:$seconds", "/DataFile:$dataFile", "/Process:$($target.ProcessId)")
        $perfResult = Invoke-LoggedProcess `
            -FileName $perfView `
            -Arguments $perfArgs `
            -WorkingDirectory $passRoot `
            -CommandPath (Join-Path $passRoot "perfview-command.txt") `
            -StdoutPath (Join-Path $passRoot "perfview.stdout.txt") `
            -StderrPath (Join-Path $passRoot "perfview.stderr.txt")
        $perfExitCode = $perfResult.ExitCode
        if ($perfResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $dataFile)) {
            $status = "succeeded"
        }
    }
    else {
        $reason = "ProtocolLab diagnostic target was not resolved before PerfView collection."
    }

    $protocolExitCode = Complete-LoggedProcess $started
    [pscustomobject]@{
        Name = "perfview"
        Status = $status
        Reason = $reason
        ProtocolLabExitCode = $protocolExitCode
        PerfViewExitCode = $perfExitCode
        ArtifactRoot = $passRoot
        ProtocolLabRunId = $protocolRunId
        ProtocolLabRunRoot = Join-Path $protocolLabOutputRoot $protocolRunId
        ProcessId = $(if ($target) { $target.ProcessId } else { $null })
        Output = $(if (Test-Path -LiteralPath (Join-Path $passRoot "perfview.etl.zip")) { Join-Path $passRoot "perfview.etl.zip" } else { $null })
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not (Test-Path -LiteralPath $ProtocolLabRoot)) {
    throw "ProtocolLab root was not found: $ProtocolLabRoot"
}

$ProtocolLabRoot = (Resolve-Path -LiteralPath $ProtocolLabRoot).Path
$scenarioId = Resolve-ScenarioId $Scenario
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "incursa-h3-profile-$($scenarioId.Replace('.', '-'))-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
}

$OutputRoot = Resolve-RootedPath $OutputRoot $repoRoot
$runRoot = Join-Path $OutputRoot $RunId
$protocolLabOutputRoot = Join-Path $runRoot "protocol-lab-runs"
New-Item -ItemType Directory -Force -Path $protocolLabOutputRoot | Out-Null

$toolRoot = Join-Path $runRoot "tools"
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
$toolRestore = Invoke-LoggedProcess `
    -FileName "dotnet" `
    -Arguments @("tool", "restore") `
    -WorkingDirectory $repoRoot `
    -CommandPath (Join-Path $toolRoot "dotnet-tool-restore-command.txt") `
    -StdoutPath (Join-Path $toolRoot "dotnet-tool-restore.stdout.txt") `
    -StderrPath (Join-Path $toolRoot "dotnet-tool-restore.stderr.txt")

$toolVersions = @()
foreach ($tool in @("dotnet-counters", "dotnet-trace", "dotnet-gcdump")) {
    $versionResult = Invoke-LoggedProcess `
        -FileName "dotnet" `
        -Arguments @("tool", "run", $tool, "--version") `
        -WorkingDirectory $repoRoot `
        -CommandPath (Join-Path $toolRoot "$tool-version-command.txt") `
        -StdoutPath (Join-Path $toolRoot "$tool-version.stdout.txt") `
        -StderrPath (Join-Path $toolRoot "$tool-version.stderr.txt")
    $toolVersions += [pscustomobject]@{
        Tool = $tool
        Available = $versionResult.ExitCode -eq 0
        ExitCode = $versionResult.ExitCode
        Version = ((Get-Content -Path $versionResult.Stdout -Raw -ErrorAction SilentlyContinue) + (Get-Content -Path $versionResult.Stderr -Raw -ErrorAction SilentlyContinue)).Trim()
        Stdout = $versionResult.Stdout
        Stderr = $versionResult.Stderr
    }
}

$passes = @()
$speedscope = $null
if ($CollectCounters) {
    $passes += Invoke-WrapperPass "counters" "none" $true
}

if ($CollectCpuTrace) {
    $cpuPass = Invoke-WrapperPass "cpu-trace" "cpu" $false
    $passes += $cpuPass
    $speedscope = Invoke-TraceConvert $cpuPass.ArtifactRoot
}

if ($CollectGcTrace) {
    $passes += Invoke-WrapperPass "gc-trace" "gc-allocation" $false
}

$gcdump = $null
if ($CollectGcDump) {
    $gcdump = Invoke-GcDumpPass
}

$perfview = $null
if ($CollectPerfView) {
    $perfview = Invoke-PerfViewPass
}

$profile = [ordered]@{
    runId = $RunId
    scenario = $Scenario
    scenarioId = $scenarioId
    protocolLabRoot = $ProtocolLabRoot
    outputRoot = $OutputRoot
    runRoot = $runRoot
    protocolLabOutputRoot = $protocolLabOutputRoot
    durationSeconds = $DurationSeconds
    warmupSeconds = $WarmupSeconds
    repetitions = $Repetitions
    connections = $Connections
    streamsPerConnection = $StreamsPerConnection
    targetConfiguration = $TargetConfiguration
    disableLoadToolQlog = [bool]$DisableLoadToolQlog
    incursaQuicSourceRoot = $IncursaQuicSourceRoot
    keepServerRunning = [bool]$KeepServerRunning
    toolRestore = $toolRestore
    toolVersions = $toolVersions
    passes = $passes
    speedscope = $speedscope
    gcdump = $gcdump
    perfview = $perfview
    notes = @(
        "Diagnostic passes are separate ProtocolLab runs unless noted otherwise.",
        "Counters, CPU trace, GC trace, gcdump, and PerfView artifacts must not be treated as one shared timing interval.",
        "Protocol behavior and ProtocolLab benchmark semantics are delegated to the existing Incursa h2load command shape."
    )
}
$profilePath = Join-Path $runRoot "profile-pack.json"
$profile | ConvertTo-Json -Depth 8 | Set-Content -Path $profilePath

$summaryScript = Join-Path $PSScriptRoot "Summarize-IncursaH3ProfilePack.ps1"
if (Test-Path -LiteralPath $summaryScript) {
    & pwsh -NoProfile -File $summaryScript -ProfilePackRoot $runRoot | Out-Null
}

Get-Content -Path $profilePath
