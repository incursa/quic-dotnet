[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/http3-h3spec",
    [string]$RunId = "",
    [string]$HostName = "127.0.0.1",
    [int]$Port = 4433,
    [string]$H3SpecExecutable = "h3spec",
    [string[]]$H3SpecPrefixArguments = @(),
    [string[]]$Match = @(),
    [string[]]$Skip = @(),
    [int]$TimeoutMilliseconds = 5000,
    [string]$Configuration = "Release",
    [switch]$AcquireH3Spec,
    [string]$AcquireH3SpecVersion = "v0.1.13",
    [switch]$NoBuild,
    [switch]$NoValidateCertificate,
    [switch]$NoStartServer,
    [string]$ServerContextPath = "",
    [switch]$PlanOnly,
    [switch]$FailOnH3SpecFailures
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $current = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
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

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

$h3specTargetHostName = $HostName
if ($AcquireH3Spec) {
    $installOutput = & (Join-Path $PSScriptRoot "Install-H3SpecTool.ps1") `
        -Version $AcquireH3SpecVersion `
        -PassThruJson

    $tool = $installOutput | ConvertFrom-Json
    $H3SpecExecutable = [string]$tool.executable
    $H3SpecPrefixArguments = @($tool.prefixArguments)
    $loopbackHostNames = @("127.0.0.1", "localhost", "::1")
    if ([bool]$tool.usesDockerWrapper -and $loopbackHostNames -contains $HostName) {
        $h3specTargetHostName = [string]$tool.recommendedHostName
    }
}

$runRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) $RunId
$logsRoot = Join-Path $runRoot "logs"
$stdoutPath = Join-Path $logsRoot "h3spec.stdout.log"
$stderrPath = Join-Path $logsRoot "h3spec.stderr.log"
$metadataPath = Join-Path $runRoot "h3spec-metadata.json"
$resultsPath = Join-Path $runRoot "h3spec-results.json"
$reportPath = Join-Path $runRoot "h3spec-report.md"

New-Item -ItemType Directory -Force -Path $runRoot, $logsRoot | Out-Null

$startedServer = $false
if (-not $NoStartServer -and [string]::IsNullOrWhiteSpace($ServerContextPath)) {
    & (Join-Path $PSScriptRoot "Start-H3SpecServer.ps1") `
        -ArtifactsRoot $ArtifactsRoot `
        -RunId $RunId `
        -Port $Port `
        -HostName $HostName `
        -Configuration $Configuration `
        -NoBuild:$NoBuild `
        -PlanOnly:$PlanOnly

    $ServerContextPath = Join-Path $runRoot "server-context.json"
    $startedServer = -not $PlanOnly
}

$h3specArguments = @()
$h3specArguments += $H3SpecPrefixArguments
if ($NoValidateCertificate) {
    $h3specArguments += "--no-validate"
}
foreach ($item in $Match) {
    $h3specArguments += "--match"
    $h3specArguments += $item
}
foreach ($item in $Skip) {
    $h3specArguments += "--skip"
    $h3specArguments += $item
}
$h3specArguments += "--timeout"
$h3specArguments += "$TimeoutMilliseconds"
$h3specArguments += $h3specTargetHostName
$h3specArguments += "$Port"

$metadata = [ordered]@{
    runId = $RunId
    runRoot = $runRoot
    serverContext = $ServerContextPath
    executable = $H3SpecExecutable
    arguments = $h3specArguments
    host = $HostName
    h3specTargetHost = $h3specTargetHostName
    port = $Port
    planOnly = [bool]$PlanOnly
    stdout = $stdoutPath
    stderr = $stderrPath
    startedUtc = (Get-Date).ToUniversalTime().ToString("o")
}

try {
    if ($PlanOnly) {
        Set-Content -LiteralPath $stdoutPath -Value "plan-only: $H3SpecExecutable $($h3specArguments -join ' ')"
        Set-Content -LiteralPath $stderrPath -Value ""
        $metadata["exitCode"] = $null
        $metadata["status"] = "not-run"
    }
    else {
        $process = Start-Process -FilePath $H3SpecExecutable -ArgumentList $h3specArguments -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -NoNewWindow
        $process.WaitForExit()
        $metadata["exitCode"] = $process.ExitCode
        $metadata["status"] = if ($process.ExitCode -eq 0) { "passed" } else { "failed" }
    }
}
finally {
    $metadata["finishedUtc"] = (Get-Date).ToUniversalTime().ToString("o")
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath

    if ($startedServer -and (Test-Path -LiteralPath $ServerContextPath)) {
        & (Join-Path $PSScriptRoot "Stop-H3SpecServer.ps1") -ServerContextPath $ServerContextPath
    }
}

python (Join-Path $PSScriptRoot "parse-h3spec-results.py") `
    --stdout $stdoutPath `
    --stderr $stderrPath `
    --metadata $metadataPath `
    --json-output $resultsPath `
    --markdown-output $reportPath
if ($LASTEXITCODE -ne 0) {
    throw "h3spec result parsing failed with exit code $LASTEXITCODE."
}

Write-Host "h3spec stdout:  $stdoutPath"
Write-Host "h3spec stderr:  $stderrPath"
Write-Host "h3spec results: $resultsPath"
Write-Host "h3spec report:  $reportPath"

if ($FailOnH3SpecFailures -and -not $PlanOnly) {
    $parsed = Get-Content -Raw -LiteralPath $resultsPath | ConvertFrom-Json
    if ([int]$parsed.summary.failures -gt 0 -or ([int]$parsed.summary.exitCode) -ne 0) {
        throw "h3spec reported failures. See $reportPath."
    }
}
