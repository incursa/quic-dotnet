[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",
    [string] $ProtocolLabExecutionRoot = "C:\shared\src\incursa\protocol-lab-internal",
    [ValidateSet("h3", "quic")]
    [string] $Protocol = "h3",
    [string] $Suite,
    [Alias("Implementation")]
    [string] $ImplementationId,
    [string] $Scenario,
    [string] $RunId,
    [string] $OutputRoot = ".artifacts\perf\exception-attribution",
    [ValidateSet("Quick", "Regression", "Comparison")]
    [string] $WorkflowProfile = "Quick",
    [int] $Connections = 16,
    [int] $StreamsPerConnection = 10,
    [int] $DurationSeconds = 5,
    [int] $WarmupSeconds = 1,
    [int] $Repetitions = 1,
    [string] $TargetConfiguration = "Release",
    [string] $TraceProfile = "",
    [string] $TraceProviders = "Microsoft-Windows-DotNETRuntime:0x8000:4",
    [int] $TraceBufferMegabytes = 256,
    [switch] $PackageBacked,
    [switch] $NoBuild
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

function Invoke-GitText([string] $WorkingDirectory, [string[]] $Arguments) {
    try {
        $output = & git -C $WorkingDirectory @Arguments 2>$null
        if ($LASTEXITCODE -eq 0) {
            return ($output -join "`n").Trim()
        }
    }
    catch {
    }

    return $null
}

function Get-JsonValue([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$OutputRoot = Resolve-RootedPath $OutputRoot $repoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "local-exception-attribution-$((Get-Date).ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture))"
}

if ([string]::IsNullOrWhiteSpace($Suite)) {
    $Suite = if ($Protocol -eq "quic") { "quic-transport-v1-comparison" } else { "h3-local-v1" }
}

if ([string]::IsNullOrWhiteSpace($ImplementationId)) {
    $ImplementationId = if ($Protocol -eq "quic") { "quic-dotnet-raw-dev" } else { "incursa-http3" }
}

if ([string]::IsNullOrWhiteSpace($Scenario)) {
    $Scenario = if ($Protocol -eq "quic") { "quic.transport.stream-throughput.1mb" } else { "http3.payload.bytes.64kb" }
}

$runRoot = Join-Path $OutputRoot $RunId
$protocolLabOutput = Join-Path $runRoot "protocol-lab-runs"
$publicationOutput = Join-Path $runRoot "publication"
$analysisRoot = Join-Path $runRoot "exception-attribution"
New-Item -ItemType Directory -Force -Path $analysisRoot | Out-Null

$benchmarkScript = Join-Path $PSScriptRoot "Invoke-ProtocolLabLocalQuicBenchmark.ps1"
if (-not (Test-Path -LiteralPath $benchmarkScript -PathType Leaf)) {
    throw "ProtocolLab local benchmark wrapper was not found: $benchmarkScript"
}

$benchmarkArgs = @(
    "-ProtocolLabRoot", $ProtocolLabRoot,
    "-ProtocolLabExecutionRoot", $ProtocolLabExecutionRoot,
    "-Suite", $Suite,
    "-Implementation", $ImplementationId,
    "-Scenario", $Scenario,
    "-WorkflowProfile", $WorkflowProfile,
    "-RunIdPrefix", $RunId,
    "-Output", $protocolLabOutput,
    "-PublicationOutputRoot", $publicationOutput,
    "-TargetConfiguration", $TargetConfiguration,
    "-DurationSeconds", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
    "-WarmupSeconds", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
    "-Repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture),
    "-Connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture),
    "-StreamsPerConnection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture),
    "-CaptureTrace",
    "-TraceProfile", $TraceProfile,
    "-TraceProviders", $TraceProviders,
    "-TraceBufferMegabytes", ([Math]::Max(64, $TraceBufferMegabytes)).ToString([Globalization.CultureInfo]::InvariantCulture),
    "-AllowBenchmarkFailure"
)

if (-not $PackageBacked) {
    $benchmarkArgs += "-UseProjectReferences"
}

$benchmarkCommandPath = Join-Path $runRoot "protocol-lab-command.txt"
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
Set-Content -Path $benchmarkCommandPath -Value (Format-CommandLine "pwsh" (@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $benchmarkScript) + $benchmarkArgs))

& pwsh -NoProfile -ExecutionPolicy Bypass -File $benchmarkScript @benchmarkArgs
$wrapperExit = $LASTEXITCODE

$traceFiles = @()
if (Test-Path -LiteralPath $protocolLabOutput -PathType Container) {
    $traceFiles = @(Get-ChildItem -LiteralPath $protocolLabOutput -Recurse -Filter "trace.nettrace" -File |
        Where-Object { $_.Length -gt 0 } |
        Sort-Object FullName)
}

$analyzer = Join-Path $PSScriptRoot "Analyze-QuicExceptionTrace.ps1"
$analyses = @()
for ($index = 0; $index -lt $traceFiles.Count; $index++) {
    $trace = $traceFiles[$index]
    $traceAnalysisRoot = if ($traceFiles.Count -eq 1) {
        $analysisRoot
    }
    else {
        Join-Path $analysisRoot ("trace-{0:000000}" -f ($index + 1))
    }

    $analyzerArgs = @(
        "-TracePath", $trace.FullName,
        "-OutputRoot", $traceAnalysisRoot
    )

    if ($NoBuild) {
        $analyzerArgs += "-NoBuild"
    }

    & pwsh -NoProfile -ExecutionPolicy Bypass -File $analyzer @analyzerArgs
    $analysisJsonPath = Join-Path $traceAnalysisRoot "exception-attribution.json"
    $analysis = Get-JsonValue $analysisJsonPath
    $relativeTrace = [IO.Path]::GetRelativePath($runRoot, $trace.FullName)
    $relativeAnalysis = [IO.Path]::GetRelativePath($runRoot, $analysisJsonPath)
    $analyses += [pscustomobject]@{
            tracePath = $trace.FullName
            relativeTracePath = $relativeTrace
            analysisPath = $analysisJsonPath
            relativeAnalysisPath = $relativeAnalysis
            eventCount = if ($analysis) { $analysis.eventCount } else { $null }
            eventsLost = if ($analysis) { $analysis.eventsLost } else { $null }
            totalExceptions = if ($analysis) { $analysis.totalExceptions } else { $null }
            totalGroups = if ($analysis) { $analysis.totalGroups } else { $null }
            includedGroups = if ($analysis) { $analysis.includedGroups } else { $null }
        }
}

$quicCommit = Invoke-GitText $repoRoot @("rev-parse", "HEAD")
$quicStatus = Invoke-GitText $repoRoot @("status", "--short")
$resolvedProtocolLabExecutionRoot = if (Test-Path -LiteralPath $ProtocolLabExecutionRoot) { (Resolve-Path -LiteralPath $ProtocolLabExecutionRoot).Path } else { $ProtocolLabExecutionRoot }
$protocolLabCommit = if (Test-Path -LiteralPath $resolvedProtocolLabExecutionRoot) { Invoke-GitText $resolvedProtocolLabExecutionRoot @("rev-parse", "HEAD") } else { $null }
$protocolLabStatus = if (Test-Path -LiteralPath $resolvedProtocolLabExecutionRoot) { Invoke-GitText $resolvedProtocolLabExecutionRoot @("status", "--short") } else { $null }
$sourceMode = if ($PackageBacked) { "package-backed" } else { "source-reference" }

$runDocument = [ordered]@{
    schemaVersion = "incursa.quic.exception-attribution-run.v2"
    runId = $RunId
    protocol = $Protocol
    suite = $Suite
    implementationId = $ImplementationId
    scenario = $Scenario
    workflowProfile = $WorkflowProfile
    protocolLabRoot = if (Test-Path -LiteralPath $ProtocolLabRoot) { (Resolve-Path -LiteralPath $ProtocolLabRoot).Path } else { $ProtocolLabRoot }
    protocolLabExecutionRoot = $resolvedProtocolLabExecutionRoot
    outputRoot = $runRoot
    protocolLabOutput = $protocolLabOutput
    analysisRoot = $analysisRoot
    connections = $Connections
    streamsPerConnection = $StreamsPerConnection
    durationSeconds = $DurationSeconds
    warmupSeconds = $WarmupSeconds
    repetitions = $Repetitions
    targetConfiguration = $TargetConfiguration
    traceProfile = $TraceProfile
    traceProviders = $TraceProviders
    traceBufferMegabytes = [Math]::Max(64, $TraceBufferMegabytes)
    sourceMode = $sourceMode
    sourceRoot = if ($PackageBacked) { $null } else { $repoRoot }
    quicDotNetCommit = $quicCommit
    quicDotNetDirty = -not [string]::IsNullOrWhiteSpace($quicStatus)
    protocolLabCommit = $protocolLabCommit
    protocolLabDirty = -not [string]::IsNullOrWhiteSpace($protocolLabStatus)
    wrapperExitCode = $wrapperExit
    traceCount = $traceFiles.Count
    analyses = $analyses
}

$runJson = Join-Path $runRoot "exception-attribution-run.json"
$runDocument | ConvertTo-Json -Depth 8 | Set-Content -Path $runJson

$summaryLines = @(
    "# QUIC Exception Attribution Run",
    "",
    "- Run ID: ``$RunId``",
    "- Protocol: ``$Protocol``",
    "- Suite: ``$Suite``",
    "- Implementation: ``$ImplementationId``",
    "- Scenario: ``$Scenario``",
    "- Load shape: ``c$Connections-s$StreamsPerConnection-r$Repetitions``",
    "- Source mode: ``$sourceMode``",
    "- quic-dotnet commit: ``$quicCommit``",
    "- ProtocolLab commit: ``$protocolLabCommit``",
    "- Wrapper exit code: ``$wrapperExit``",
    "- Trace count: ``$($traceFiles.Count)``",
    "",
    "## Trace Analyses",
    "",
    "| Trace | Events | Lost | Exceptions | Groups | Analysis |",
    "| --- | ---: | ---: | ---: | ---: | --- |"
)
foreach ($analysis in $analyses) {
    $summaryLines += "| ``$($analysis.relativeTracePath)`` | $($analysis.eventCount) | $($analysis.eventsLost) | $($analysis.totalExceptions) | $($analysis.totalGroups) | ``$($analysis.relativeAnalysisPath)`` |"
}

if ($traceFiles.Count -eq 0) {
    $summaryLines += ""
    $summaryLines += "No non-empty ``trace.nettrace`` files were found under the ProtocolLab output root."
}

Set-Content -Path (Join-Path $runRoot "exception-attribution-run.md") -Value $summaryLines

Get-Content -Path $runJson
if ($wrapperExit -ne 0) {
    exit $wrapperExit
}

if ($traceFiles.Count -eq 0) {
    exit 1
}
