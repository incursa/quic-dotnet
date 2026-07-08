[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab-internal",
    [string] $Scenario = "http3.payload.bytes.64kb",
    [string] $RunId,
    [string] $OutputRoot = ".artifacts\perf\exception-attribution",
    [int] $Connections = 16,
    [int] $StreamsPerConnection = 10,
    [int] $DurationSeconds = 5,
    [int] $WarmupSeconds = 1,
    [int] $Repetitions = 1,
    [string] $TargetConfiguration = "Release",
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

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$OutputRoot = Resolve-RootedPath $OutputRoot $repoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "local-exception-attribution-$((Get-Date).ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture))"
}

$runRoot = Join-Path $OutputRoot $RunId
$traceRoot = Join-Path $runRoot "trace"
$protocolLabOutput = Join-Path $runRoot "protocol-lab-runs"
New-Item -ItemType Directory -Force -Path $traceRoot | Out-Null

$wrapper = Join-Path $PSScriptRoot "Run-ProtocolLabIncursaH3H2Load.ps1"
& pwsh -NoProfile -ExecutionPolicy Bypass -File $wrapper `
    -ProtocolLabRoot $ProtocolLabRoot `
    -Scenarios $Scenario `
    -Connections $Connections `
    -StreamsPerConnection $StreamsPerConnection `
    -DurationSeconds $DurationSeconds `
    -WarmupSeconds $WarmupSeconds `
    -Repetitions $Repetitions `
    -TargetConfiguration $TargetConfiguration `
    -RunId $RunId `
    -Output $protocolLabOutput `
    -TraceMode exception `
    -TraceArtifactRoot $traceRoot `
    -TraceDurationSeconds ([Math]::Max(5, $DurationSeconds + $WarmupSeconds + 3)) `
    -IncursaQuicSourceRoot $repoRoot
$wrapperExit = $LASTEXITCODE

$analysisRoot = Join-Path $runRoot "exception-attribution"
if ((Test-Path -LiteralPath (Join-Path $traceRoot "trace.nettrace")) -and (Get-Item -LiteralPath (Join-Path $traceRoot "trace.nettrace")).Length -gt 0) {
    $analyzer = Join-Path $PSScriptRoot "Analyze-QuicExceptionTrace.ps1"
    $analyzerArgs = @(
        "-TraceRoot", $traceRoot,
        "-OutputRoot", $analysisRoot
    )

    if ($NoBuild) {
        $analyzerArgs += "-NoBuild"
    }

    & pwsh -NoProfile -ExecutionPolicy Bypass -File $analyzer @analyzerArgs
}

[ordered]@{
    schemaVersion = "incursa.quic.exception-attribution-run.v1"
    runId = $RunId
    scenario = $Scenario
    protocolLabRoot = (Resolve-Path -LiteralPath $ProtocolLabRoot).Path
    outputRoot = $runRoot
    protocolLabOutput = $protocolLabOutput
    traceRoot = $traceRoot
    analysisRoot = $analysisRoot
    connections = $Connections
    streamsPerConnection = $StreamsPerConnection
    durationSeconds = $DurationSeconds
    warmupSeconds = $WarmupSeconds
    repetitions = $Repetitions
    targetConfiguration = $TargetConfiguration
    sourceRoot = $repoRoot
    wrapperExitCode = $wrapperExit
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $runRoot "exception-attribution-run.json")

Get-Content -Path (Join-Path $runRoot "exception-attribution-run.json")
exit $wrapperExit
