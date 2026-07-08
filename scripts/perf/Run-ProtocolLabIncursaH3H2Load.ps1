[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\src\incursa\protocol-lab",
    [string[]] $Scenarios = @("http3.core.status", "http3.payload.bytes.64kb"),
    [int] $Connections = 16,
    [int] $StreamsPerConnection = 10,
    [int] $DurationSeconds = 10,
    [int] $WarmupSeconds = 2,
    [int] $Repetitions = 1,
    [string] $TargetConfiguration = "Release",
    [switch] $DisableLoadToolQlog = $true,
    [string] $RunId,
    [switch] $CaptureCounters,
    [int] $CounterRefreshIntervalSeconds = 1,
    [string] $Output,
    [ValidateSet("none", "cpu", "gc-allocation")]
    [string] $TraceMode = "none",
    [string] $TraceArtifactRoot,
    [int] $TraceDurationSeconds = 0,
    [int] $ReceiveBufferRingSize = 0,
    [string] $ReceiveBufferDiagnosticsPath,
    [string] $IncursaQuicSourceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Get-ContentWithRetry([string] $Path) {
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            return Get-Content -Path $Path -ErrorAction Stop
        }
        catch {
            if ($attempt -eq 10) {
                Write-Warning "Could not read '$Path' after process exit: $($_.Exception.Message)"
                return @()
            }

            Start-Sleep -Milliseconds (100 * $attempt)
        }
    }
}

if (-not (Test-Path -LiteralPath $ProtocolLabRoot)) {
    throw "ProtocolLab root was not found: $ProtocolLabRoot"
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "local-incursa-h3-p1-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
}

if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $ProtocolLabRoot ".artifacts/runs"
}

$resolvedIncursaQuicSourceRoot = $null
if (-not [string]::IsNullOrWhiteSpace($IncursaQuicSourceRoot)) {
    $resolvedIncursaQuicSourceRoot = (Resolve-Path -LiteralPath $IncursaQuicSourceRoot).Path
}

if ($TraceMode -ne "none" -and $Scenarios.Count -ne 1) {
    throw "Trace capture requires exactly one scenario per wrapper invocation so one diagnostic target can be resolved."
}

$args = @(
    "run",
    "--project", "src/Incursa.ProtocolLab.Cli",
    "--",
    "run",
    "--implementations", "incursa-http3",
    "--scenarios", ($Scenarios -join ","),
    "--protocol", "h3",
    "--load-tool", "h2load",
    "--load-tool-mode", "docker",
    "--target-configuration", $TargetConfiguration,
    "--connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--streams-per-connection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--duration", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--warmup", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--output", $Output,
    "--run-id", $RunId
)

if ($DisableLoadToolQlog) {
    $args += "--disable-load-tool-qlog"
}

if ($CaptureCounters) {
    $args += @(
        "--capture-counters",
        "--counter-refresh-interval", $CounterRefreshIntervalSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
    )
}

$runRoot = Join-Path $Output $RunId
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
Set-Content -Path (Join-Path $runRoot "protocol-lab-command.txt") -Value (Format-CommandLine "dotnet" $args)

$receiveBufferRingSizeVariable = "INCURSA_QUIC_RECEIVE_BUFFER_RING_SIZE"
$receiveBufferDiagnosticsVariable = "INCURSA_QUIC_RECEIVE_BUFFER_DIAGNOSTICS_PATH"
$incursaQuicSourceRootVariable = "PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT"
$previousReceiveBufferRingSize = [Environment]::GetEnvironmentVariable($receiveBufferRingSizeVariable)
$previousReceiveBufferDiagnosticsPath = [Environment]::GetEnvironmentVariable($receiveBufferDiagnosticsVariable)
$previousIncursaQuicSourceRoot = [Environment]::GetEnvironmentVariable($incursaQuicSourceRootVariable)
if ([string]::IsNullOrWhiteSpace($ReceiveBufferDiagnosticsPath)) {
    $ReceiveBufferDiagnosticsPath = Join-Path $runRoot "incursa-quic-receive-buffer-pool-snapshots.jsonl"
}

if ($ReceiveBufferRingSize -gt 0) {
    [Environment]::SetEnvironmentVariable($receiveBufferRingSizeVariable, $ReceiveBufferRingSize.ToString([Globalization.CultureInfo]::InvariantCulture))
}

[Environment]::SetEnvironmentVariable($receiveBufferDiagnosticsVariable, $ReceiveBufferDiagnosticsPath)
if ($resolvedIncursaQuicSourceRoot) {
    [Environment]::SetEnvironmentVariable($incursaQuicSourceRootVariable, $resolvedIncursaQuicSourceRoot)
}

$exitCode = 1
try {
    if ($resolvedIncursaQuicSourceRoot) {
        $adapterProject = Join-Path $ProtocolLabRoot "src/Incursa.ProtocolLab.Adapters.IncursaHttp3/Incursa.ProtocolLab.Adapters.IncursaHttp3.csproj"
        $buildArgs = @(
            "build",
            $adapterProject,
            "--configuration",
            $TargetConfiguration,
            "-p:IncursaQuicSourceRoot=$resolvedIncursaQuicSourceRoot"
        )

        Set-Content -Path (Join-Path $runRoot "protocol-lab-adapter-build-command.txt") -Value (Format-CommandLine "dotnet" $buildArgs)
        Push-Location $ProtocolLabRoot
        try {
            & dotnet @buildArgs
            if ($LASTEXITCODE -ne 0) {
                throw "ProtocolLab Incursa HTTP/3 adapter source-mode build failed with exit code $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }

    if ($TraceMode -eq "none") {
        Push-Location $ProtocolLabRoot
        try {
            & dotnet @args
            $exitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($TraceArtifactRoot)) {
            $repoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
            $TraceArtifactRoot = Join-Path $repoRoot ".artifacts/perf/incursa-h3-p2/$TraceMode-$($Scenarios[0].Replace('.', '-'))"
        }

        New-Item -ItemType Directory -Force -Path $TraceArtifactRoot | Out-Null
        Set-Content -Path (Join-Path $TraceArtifactRoot "protocol-lab-run-id.txt") -Value $RunId

        $protocolLabStdout = Join-Path $runRoot "protocol-lab.stdout.txt"
        $protocolLabStderr = Join-Path $runRoot "protocol-lab.stderr.txt"
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new("dotnet")
        $startInfo.WorkingDirectory = $ProtocolLabRoot
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.UseShellExecute = $false
        foreach ($argument in $args) {
            $startInfo.ArgumentList.Add($argument)
        }

        $process = [System.Diagnostics.Process]::Start($startInfo)
        if (-not $process) {
            throw "Failed to start ProtocolLab run process."
        }

        $protocolLabStdoutTask = $process.StandardOutput.ReadToEndAsync()
        $protocolLabStderrTask = $process.StandardError.ReadToEndAsync()

        $scenarioDirectoryName = $Scenarios[0]
        $diagnosticTargetPath = Join-Path $runRoot "implementations/incursa-http3/$scenarioDirectoryName/h3/local-process/clean/no-load-profile/c$Connections-s$StreamsPerConnection-r1/diagnostic-target.json"
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
        $diagnosticTarget = $null
        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            if ($process.HasExited) {
                break
            }

            if (Test-Path -LiteralPath $diagnosticTargetPath) {
                try {
                    $diagnosticTarget = Get-Content -Path $diagnosticTargetPath -Raw | ConvertFrom-Json
                    if ($diagnosticTarget.resolvedProcessId) {
                        break
                    }
                }
                catch {
                    $diagnosticTarget = $null
                }
            }

            Start-Sleep -Milliseconds 250
        }

        if (-not $diagnosticTarget -or -not $diagnosticTarget.resolvedProcessId) {
            $message = @(
                "ProtocolLab diagnostic target was not resolved before trace startup.",
                "Expected diagnostic target: $diagnosticTargetPath"
            )
            Set-Content -Path (Join-Path $TraceArtifactRoot "trace-start-blocker.txt") -Value $message
        }
        else {
            $traceSeconds = if ($TraceDurationSeconds -gt 0) {
                $TraceDurationSeconds
            }
            else {
                [Math]::Max(5, $DurationSeconds + $WarmupSeconds + 5)
            }

            $traceScript = Join-Path $PSScriptRoot "Collect-IncursaH3Trace.ps1"
            & pwsh -NoProfile -File $traceScript `
                -ProcessId ([int]$diagnosticTarget.resolvedProcessId) `
                -DurationSeconds $traceSeconds `
                -Mode $TraceMode `
                -ArtifactRoot $TraceArtifactRoot
            $traceExitCode = $LASTEXITCODE
            [ordered]@{
                protocolLabRunId = $RunId
                scenario = $Scenarios[0]
                diagnosticTargetPath = $diagnosticTargetPath
                resolvedProcessId = [int]$diagnosticTarget.resolvedProcessId
                traceMode = $TraceMode
                traceExitCode = $traceExitCode
            } | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $TraceArtifactRoot "protocol-lab-trace-target.json")
        }

        [ordered]@{
            runId = $RunId
            exitCode = $exitCode
            output = $Output
            runRoot = $runRoot
            captureCounters = [bool]$CaptureCounters
            targetConfiguration = $TargetConfiguration
            disableLoadToolQlog = [bool]$DisableLoadToolQlog
            traceMode = $TraceMode
            traceArtifactRoot = $TraceArtifactRoot
            receiveBufferRingSize = if ($ReceiveBufferRingSize -gt 0) { $ReceiveBufferRingSize } else { $null }
            receiveBufferDiagnosticsPath = $ReceiveBufferDiagnosticsPath
            incursaQuicSourceRoot = $resolvedIncursaQuicSourceRoot
            command = Get-Content -Path (Join-Path $runRoot "protocol-lab-command.txt") -Raw
        } | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $runRoot "protocol-lab-wrapper-summary.json")

        $process.WaitForExit()
        $exitCode = $process.ExitCode
        Set-Content -Path $protocolLabStdout -Value $protocolLabStdoutTask.GetAwaiter().GetResult()
        Set-Content -Path $protocolLabStderr -Value $protocolLabStderrTask.GetAwaiter().GetResult()
        Get-ContentWithRetry $protocolLabStdout
        Get-ContentWithRetry $protocolLabStderr
    }

    [ordered]@{
        runId = $RunId
        exitCode = $exitCode
        output = $Output
        runRoot = $runRoot
        captureCounters = [bool]$CaptureCounters
        targetConfiguration = $TargetConfiguration
        disableLoadToolQlog = [bool]$DisableLoadToolQlog
        traceMode = $TraceMode
        traceArtifactRoot = $TraceArtifactRoot
        receiveBufferRingSize = if ($ReceiveBufferRingSize -gt 0) { $ReceiveBufferRingSize } else { $null }
        receiveBufferDiagnosticsPath = $ReceiveBufferDiagnosticsPath
        incursaQuicSourceRoot = $resolvedIncursaQuicSourceRoot
        command = Get-Content -Path (Join-Path $runRoot "protocol-lab-command.txt") -Raw
    } | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $runRoot "protocol-lab-wrapper-summary.json")
}
finally {
    [Environment]::SetEnvironmentVariable($receiveBufferRingSizeVariable, $previousReceiveBufferRingSize)
    [Environment]::SetEnvironmentVariable($receiveBufferDiagnosticsVariable, $previousReceiveBufferDiagnosticsPath)
    [Environment]::SetEnvironmentVariable($incursaQuicSourceRootVariable, $previousIncursaQuicSourceRoot)
}

exit $exitCode
