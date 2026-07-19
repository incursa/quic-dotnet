[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $TargetPath,
    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string] $OutputRoot = ".artifacts\perf\local-http3-target-profile",
    [string] $RunId,
    [ValidateSet("fixed", "streaming", "upload", "duplex")]
    [string] $Scenario = "fixed",
    [ValidateSet(1024, 65536, 1048576)]
    [int] $PayloadSizeBytes = 1048576,
    [ValidateRange(1, 128)]
    [int] $Connections = 1,
    [ValidateRange(1, 128)]
    [int] $StreamsPerConnection = 16,
    [ValidateRange(1, 20)]
    [int] $Samples = 1,
    [ValidateRange(1, 300)]
    [int] $DurationSeconds = 5,
    [ValidateRange(1, 60)]
    [int] $WarmupSeconds = 1,
    [ValidateSet("none", "cpu-sampling", "gc-verbose")]
    [string] $TraceProfile = "gc-verbose",
    [ValidateRange(1, 65535)]
    [int] $Port = 0,
    [switch] $ValidateOnly
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
    $formattedArguments = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argument
        }
    }

    "$FileName $($formattedArguments -join ' ')"
}

function Start-CapturedProcess(
    [string] $FileName,
    [string[]] $Arguments,
    [string] $WorkingDirectory,
    [string] $CommandPath,
    [string] $StdoutPath,
    [string] $StderrPath) {
    Set-Content -Path $CommandPath -Value (Format-CommandLine $FileName $Arguments)

    $startInfo = [Diagnostics.ProcessStartInfo]::new($FileName)
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::Start($startInfo)
    if (-not $process) {
        throw "Failed to start '$FileName'."
    }

    [pscustomobject]@{
        Process = $process
        StandardOutputTask = $process.StandardOutput.ReadToEndAsync()
        StandardErrorTask = $process.StandardError.ReadToEndAsync()
        StdoutPath = $StdoutPath
        StderrPath = $StderrPath
    }
}

function Complete-CapturedProcess($StartedProcess, [int] $TimeoutSeconds = 120) {
    if (-not $StartedProcess.Process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "Process $($StartedProcess.Process.Id) did not exit within $TimeoutSeconds seconds."
    }

    Set-Content -Path $StartedProcess.StdoutPath -Value $StartedProcess.StandardOutputTask.GetAwaiter().GetResult()
    Set-Content -Path $StartedProcess.StderrPath -Value $StartedProcess.StandardErrorTask.GetAwaiter().GetResult()
    return $StartedProcess.Process.ExitCode
}

function Invoke-CapturedProcess(
    [string] $FileName,
    [string[]] $Arguments,
    [string] $WorkingDirectory,
    [string] $CommandPath,
    [string] $StdoutPath,
    [string] $StderrPath,
    [int] $TimeoutSeconds = 300) {
    $started = Start-CapturedProcess $FileName $Arguments $WorkingDirectory $CommandPath $StdoutPath $StderrPath
    $exitCode = Complete-CapturedProcess $started $TimeoutSeconds
    if ($exitCode -ne 0) {
        throw "Command failed with exit code $exitCode. See '$StderrPath'."
    }
}

function Get-AvailableUdpPort {
    $udpClient = [Net.Sockets.UdpClient]::new(0)
    try {
        return ([Net.IPEndPoint]$udpClient.Client.LocalEndPoint).Port
    }
    finally {
        $udpClient.Dispose()
    }
}

function Wait-ForOwnedUdpEndpoint([int] $EndpointPort, [int] $ProcessId, [int] $TimeoutSeconds) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
            throw "HTTP/3 target process $ProcessId exited before opening UDP port $EndpointPort."
        }

        $endpoint = Get-NetUDPEndpoint -LocalPort $EndpointPort -ErrorAction SilentlyContinue |
            Where-Object OwningProcess -eq $ProcessId |
            Select-Object -First 1
        if ($endpoint) {
            return
        }

        Start-Sleep -Milliseconds 100
    }
    while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "HTTP/3 target process $ProcessId did not open UDP port $EndpointPort within $TimeoutSeconds seconds."
}

$repositoryRootPath = Resolve-RootedPath $RepositoryRoot (Get-Location).Path
$targetPathValue = Resolve-RootedPath $TargetPath $repositoryRootPath
if (-not (Test-Path -LiteralPath $targetPathValue -PathType Leaf)) {
    throw "Target executable was not found at '$targetPathValue'."
}

$benchmarkProject = Join-Path $repositoryRootPath "benchmarks\Incursa.Quic.Benchmarks.csproj"
$traceAnalysisProject = Join-Path $repositoryRootPath "eng\tools\Incursa.Quic.TraceAnalysis\Incursa.Quic.TraceAnalysis.csproj"
if (-not (Test-Path -LiteralPath $benchmarkProject -PathType Leaf)) {
    throw "Benchmark project was not found at '$benchmarkProject'."
}

if ($TraceProfile -eq "gc-verbose" -and -not (Test-Path -LiteralPath $traceAnalysisProject -PathType Leaf)) {
    throw "Trace-analysis project was not found at '$traceAnalysisProject'."
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "local-h3-$Scenario-$PayloadSizeBytes-$Connections`x$StreamsPerConnection-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

$outputRootPath = Resolve-RootedPath $OutputRoot $repositoryRootPath
$runRoot = Join-Path $outputRootPath $RunId
if (Test-Path -LiteralPath $runRoot) {
    throw "Run output already exists at '$runRoot'. Choose a different RunId."
}

New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
$resolvedPort = if ($Port -eq 0) { Get-AvailableUdpPort } else { $Port }
$targetHash = (Get-FileHash -LiteralPath $targetPathValue -Algorithm SHA256).Hash
$configuration = [ordered]@{
    schemaVersion = 1
    runId = $RunId
    repositoryRoot = $repositoryRootPath
    targetPath = $targetPathValue
    targetSha256 = $targetHash
    scenario = $Scenario
    payloadSizeBytes = $PayloadSizeBytes
    connections = $Connections
    streamsPerConnection = $StreamsPerConnection
    samples = $Samples
    durationSeconds = $DurationSeconds
    warmupSeconds = $WarmupSeconds
    traceProfile = $TraceProfile
    port = $resolvedPort
    validateOnly = [bool]$ValidateOnly
}
$configuration | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $runRoot "configuration.json")

if ($ValidateOnly) {
    Write-Host "Local HTTP/3 target profile configuration is valid: $runRoot"
    return
}

$target = $null
$trace = $null
$runStartedUtc = [DateTimeOffset]::UtcNow
try {
    $target = Start-CapturedProcess `
        $targetPathValue `
        @("--mode", "endpoint", "--port", $resolvedPort.ToString([Globalization.CultureInfo]::InvariantCulture)) `
        $repositoryRootPath `
        (Join-Path $runRoot "target-command.txt") `
        (Join-Path $runRoot "target.stdout.txt") `
        (Join-Path $runRoot "target.stderr.txt")

    Wait-ForOwnedUdpEndpoint $resolvedPort $target.Process.Id 15

    $tracePath = Join-Path $runRoot "target.nettrace"
    if ($TraceProfile -ne "none") {
        $traceDurationSeconds = [Math]::Max(10, ($Samples * ($DurationSeconds + $WarmupSeconds)) + 8)
        $traceDuration = [TimeSpan]::FromSeconds($traceDurationSeconds).ToString(
            "hh\:mm\:ss",
            [Globalization.CultureInfo]::InvariantCulture)
        $traceArguments = @(
            "tool", "run", "dotnet-trace", "--", "collect",
            "--process-id", $target.Process.Id.ToString([Globalization.CultureInfo]::InvariantCulture),
            "--profile", $TraceProfile,
            "--duration", $traceDuration,
            "--output", $tracePath)
        $trace = Start-CapturedProcess `
            "dotnet" `
            $traceArguments `
            $repositoryRootPath `
            (Join-Path $runRoot "trace-command.txt") `
            (Join-Path $runRoot "trace.stdout.txt") `
            (Join-Path $runRoot "trace.stderr.txt")
        Start-Sleep -Seconds 1
        if ($trace.Process.HasExited) {
            $traceExitCode = Complete-CapturedProcess $trace 5
            throw "dotnet-trace exited before the workload with exit code $traceExitCode."
        }
    }

    $resultPath = Join-Path $runRoot "result.json"
    $benchmarkArguments = @(
        "run", "-c", "Release", "--no-build", "--project", $benchmarkProject, "--",
        "--http3-loopback",
        "--target-base-url", "https://127.0.0.1:$resolvedPort/",
        "--scenarios", $Scenario,
        "--payload-sizes", $PayloadSizeBytes.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--streams-per-connection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--samples", $Samples.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--duration-seconds", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--warmup-seconds", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "--label", $RunId,
        "--json", $resultPath)
    Invoke-CapturedProcess `
        "dotnet" `
        $benchmarkArguments `
        $repositoryRootPath `
        (Join-Path $runRoot "benchmark-command.txt") `
        (Join-Path $runRoot "benchmark.stdout.txt") `
        (Join-Path $runRoot "benchmark.stderr.txt") `
        ([Math]::Max(120, ($Samples * ($DurationSeconds + $WarmupSeconds)) + 60))

    if ($trace) {
        $traceExitCode = Complete-CapturedProcess $trace ([Math]::Max(30, $Samples * ($DurationSeconds + $WarmupSeconds) + 15))
        if ($traceExitCode -ne 0) {
            throw "dotnet-trace failed with exit code $traceExitCode."
        }
    }

    if ($TraceProfile -eq "gc-verbose") {
        Invoke-CapturedProcess `
            "dotnet" `
            @(
                "run", "--project", $traceAnalysisProject, "-c", "Release", "--",
                "--trace", $tracePath,
                "--analysis", "allocations",
                "--output", (Join-Path $runRoot "allocation-attribution"),
                "--top", "40",
                "--max-frames", "48") `
            $repositoryRootPath `
            (Join-Path $runRoot "allocation-analysis-command.txt") `
            (Join-Path $runRoot "allocation-analysis.stdout.txt") `
            (Join-Path $runRoot "allocation-analysis.stderr.txt")
    }

    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $failures = [int](($result.results | Measure-Object -Property failures -Sum).Sum)
    if ($failures -ne 0) {
        throw "The exact HTTP/3 workload recorded $failures failures."
    }

    [ordered]@{
        schemaVersion = 1
        runId = $RunId
        startedUtc = $runStartedUtc
        endedUtc = [DateTimeOffset]::UtcNow
        targetProcessId = $target.Process.Id
        targetSha256 = $targetHash
        traceProfile = $TraceProfile
        exactValidationFailures = $failures
        resultPath = $resultPath
        tracePath = if ($TraceProfile -eq "none") { $null } else { $tracePath }
        allocationAttributionPath = if ($TraceProfile -eq "gc-verbose") {
            Join-Path $runRoot "allocation-attribution\allocation-attribution.json"
        } else { $null }
    } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $runRoot "run-manifest.json")

    Write-Host "Local HTTP/3 target profile completed: $runRoot"
}
finally {
    if ($trace -and -not $trace.Process.HasExited) {
        Stop-Process -Id $trace.Process.Id -Force -ErrorAction SilentlyContinue
    }

    if ($target) {
        if (-not $target.Process.HasExited) {
            Stop-Process -Id $target.Process.Id -Force -ErrorAction SilentlyContinue
        }

        try {
            [void](Complete-CapturedProcess $target 10)
        }
        catch {
            Set-Content -Path $target.StdoutPath -Value $target.StandardOutputTask.GetAwaiter().GetResult()
            Set-Content -Path $target.StderrPath -Value $target.StandardErrorTask.GetAwaiter().GetResult()
        }
    }
}
