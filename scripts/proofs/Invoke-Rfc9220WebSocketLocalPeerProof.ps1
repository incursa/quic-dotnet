[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/http3-websocket-local-peer",
    [string]$RunId = "",
    [string]$Configuration = "Release",
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $current = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
    while ($null -ne $current) {
        if (Test-Path (Join-Path $current "Incursa.Quic.slnx")) {
            return $current
        }

        $parent = Split-Path -Parent $current
        if ($parent -eq $current) {
            break
        }

        $current = $parent
    }

    throw "Unable to locate repository root."
}

function Get-RelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    return [System.IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

$runRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) $RunId
$stdoutPath = Join-Path $runRoot "dotnet-test.stdout.log"
$stderrPath = Join-Path $runRoot "dotnet-test.stderr.log"
$manifestPath = Join-Path $runRoot "rfc9220-local-peer-proof.json"
$reportPath = Join-Path $runRoot "rfc9220-local-peer-proof.md"
$filter = "FullyQualifiedName~WebSocketExtendedConnect_LocalPeerHarness_ExercisesClientServerLifecycle"

New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

$testArguments = @(
    "test",
    "tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj",
    "-c",
    $Configuration,
    "--filter",
    $filter,
    "--logger",
    "trx;LogFileName=rfc9220-local-peer.trx",
    "--results-directory",
    $runRoot
)
if ($NoBuild) {
    $testArguments += "--no-build"
}

$startedUtc = (Get-Date).ToUniversalTime().ToString("o")
& dotnet @testArguments > $stdoutPath 2> $stderrPath
$exitCode = $LASTEXITCODE
$finishedUtc = (Get-Date).ToUniversalTime().ToString("o")

$trxPath = Join-Path $runRoot "rfc9220-local-peer.trx"
$counters = $null
if (Test-Path -LiteralPath $trxPath) {
    [xml]$trx = Get-Content -LiteralPath $trxPath
    $trxCounters = $trx.TestRun.ResultSummary.Counters
    $counters = [ordered]@{
        total = [int]$trxCounters.total
        executed = [int]$trxCounters.executed
        passed = [int]$trxCounters.passed
        failed = [int]$trxCounters.failed
        error = [int]$trxCounters.error
        timeout = [int]$trxCounters.timeout
        aborted = [int]$trxCounters.aborted
        inconclusive = [int]$trxCounters.inconclusive
        passedButRunAborted = [int]$trxCounters.passedButRunAborted
        notRunnable = [int]$trxCounters.notRunnable
        notExecuted = [int]$trxCounters.notExecuted
        disconnected = [int]$trxCounters.disconnected
        warning = [int]$trxCounters.warning
        completed = [int]$trxCounters.completed
        inProgress = [int]$trxCounters.inProgress
        pending = [int]$trxCounters.pending
    }
}

$artifactHashes = @(
    Get-ChildItem -LiteralPath $runRoot -File |
        Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $reportPath } |
        Sort-Object FullName |
        ForEach-Object {
            $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            [ordered]@{
                path = Get-RelativePath -Root $repoRoot -Path $_.FullName
                sha256 = $hash.Hash
            }
        }
)

$command = "dotnet " + ($testArguments -join " ")
$manifest = [ordered]@{
    runId = $RunId
    evidenceClass = "local-loopback-peer"
    status = if ($exitCode -eq 0) { "passed" } else { "failed" }
    exitCode = $exitCode
    startedUtc = $startedUtc
    finishedUtc = $finishedUtc
    command = $command
    testFilter = $filter
    requirementIds = @(
        "REQ-QUIC-RFC9220-0017",
        "REQ-QUIC-RFC9220-0018",
        "REQ-QUIC-RFC9220-0019",
        "REQ-QUIC-RFC9220-0022",
        "REQ-QUIC-RFC9220-0030",
        "REQ-QUIC-RFC9220-0031"
    )
    proofScope = @(
        "HTTP/3 Extended CONNECT setup",
        "accepted response metadata",
        "server ping and client pong helper",
        "text frame exchange",
        "buffered binary frame exchange across a 6000-byte payload",
        "client close and server close echo"
    )
    runRoot = Get-RelativePath -Root $repoRoot -Path $runRoot
    stdout = Get-RelativePath -Root $repoRoot -Path $stdoutPath
    stderr = Get-RelativePath -Root $repoRoot -Path $stderrPath
    trx = if (Test-Path -LiteralPath $trxPath) { Get-RelativePath -Root $repoRoot -Path $trxPath } else { $null }
    counters = $counters
    artifactHashes = $artifactHashes
}

$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# RFC9220 WebSocket Local Peer Proof")
$lines.Add("")
$lines.Add("- Run ID: ``$RunId``")
$lines.Add("- Evidence class: ``local-loopback-peer``")
$lines.Add("- Status: ``$($manifest.status)``")
$lines.Add("- Command: ``$command``")
$lines.Add("- TRX: ``$($manifest.trx)``")
if ($null -ne $counters) {
    $lines.Add("- Test counters: total=$($counters.total), passed=$($counters.passed), failed=$($counters.failed), skipped=$($counters.notExecuted)")
}
$lines.Add("")
$lines.Add("## Scope")
foreach ($item in $manifest.proofScope) {
    $lines.Add("- $item")
}
$lines.Add("")
$lines.Add("## Requirement IDs")
foreach ($requirementId in $manifest.requirementIds) {
    $lines.Add("- ``$requirementId``")
}
$lines.Add("")
$lines.Add("## Artifact Hashes")
foreach ($artifact in $artifactHashes) {
    $lines.Add("- ``$($artifact.path)`` SHA256 ``$($artifact.sha256)``")
}
$lines | Set-Content -LiteralPath $reportPath -Encoding utf8

Write-Host "RFC9220 local peer proof manifest: $manifestPath"
Write-Host "RFC9220 local peer proof report:   $reportPath"

if ($exitCode -ne 0) {
    throw "RFC9220 local peer proof failed with exit code $exitCode. See $reportPath."
}
