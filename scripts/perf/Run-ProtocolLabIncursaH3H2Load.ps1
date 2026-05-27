[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\src\incursa\protocol-lab",
    [string[]] $Scenarios = @("http.core.plaintext", "http.core.json"),
    [int] $Connections = 16,
    [int] $StreamsPerConnection = 10,
    [int] $DurationSeconds = 10,
    [int] $WarmupSeconds = 2,
    [int] $Repetitions = 1,
    [string] $RunId,
    [switch] $CaptureCounters,
    [int] $CounterRefreshIntervalSeconds = 1,
    [string] $Output,
    [ValidateSet("none", "cpu", "gc-allocation")]
    [string] $TraceMode = "none",
    [string] $TraceArtifactRoot,
    [int] $TraceDurationSeconds = 0
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

if (-not (Test-Path -LiteralPath $ProtocolLabRoot)) {
    throw "ProtocolLab root was not found: $ProtocolLabRoot"
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "local-incursa-h3-p1-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
}

if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $ProtocolLabRoot ".artifacts/runs"
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
    "--connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--streams-per-connection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--duration", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--warmup", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--output", $Output,
    "--run-id", $RunId
)

if ($CaptureCounters) {
    $args += @(
        "--capture-counters",
        "--counter-refresh-interval", $CounterRefreshIntervalSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
    )
}

$runRoot = Join-Path $Output $RunId
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
Set-Content -Path (Join-Path $runRoot "protocol-lab-command.txt") -Value (Format-CommandLine "dotnet" $args)

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
    $process = Start-Process `
        -FilePath "dotnet" `
        -ArgumentList $args `
        -WorkingDirectory $ProtocolLabRoot `
        -RedirectStandardOutput $protocolLabStdout `
        -RedirectStandardError $protocolLabStderr `
        -WindowStyle Hidden `
        -PassThru

    $scenarioDirectoryName = $Scenarios[0]
    $diagnosticTargetPath = Join-Path $runRoot "implementations/incursa-http3/$scenarioDirectoryName/h3/c$Connections-s$StreamsPerConnection-r1/diagnostic-target.json"
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

    $process.WaitForExit()
    $exitCode = $process.ExitCode
    Get-Content -Path $protocolLabStdout -ErrorAction SilentlyContinue
    Get-Content -Path $protocolLabStderr -ErrorAction SilentlyContinue
}

[ordered]@{
    runId = $RunId
    exitCode = $exitCode
    output = $Output
    runRoot = $runRoot
    captureCounters = [bool]$CaptureCounters
    traceMode = $TraceMode
    traceArtifactRoot = $TraceArtifactRoot
    command = Get-Content -Path (Join-Path $runRoot "protocol-lab-command.txt") -Raw
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $runRoot "protocol-lab-wrapper-summary.json")

exit $exitCode
