[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/http3-external",
    [string]$ComposeFile = "",
    [string[]]$Targets = @(
        "incursa-client__incursa-server",
        "curl__incursa-server",
        "aioquic-client__incursa-server",
        "quiche-client__incursa-server",
        "ngtcp2-client__incursa-server",
        "incursa-client__aioquic-server",
        "incursa-client__quiche-server",
        "incursa-client__ngtcp2-server"
    ),
    [string[]]$Scenarios = @(
        "get-small",
        "get-empty",
        "get-large",
        "multiple-concurrent-get",
        "not-found",
        "many-headers",
        "split-data",
        "request-cancellation",
        "goaway",
        "connection-close-in-flight"
    ),
    [switch]$PlanOnly,
    [switch]$SkipBuild,
    [switch]$KeepServerRunning
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

function Write-Result {
    param(
        [string]$Target,
        [string]$Scenario,
        [string]$Status,
        [string]$Detail,
        [string]$Artifact = ""
    )

    $row = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        target = $Target
        scenario = $Scenario
        status = $Status
        detail = $Detail
        artifact = $Artifact
    }

    ($row | ConvertTo-Json -Compress) | Add-Content -LiteralPath $script:ResultsPath
}

function New-Fixtures {
    param([string]$WwwRoot)

    New-Item -ItemType Directory -Force -Path $WwwRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $WwwRoot "small.txt") -Value "small http3 fixture" -NoNewline
    New-Item -ItemType File -Force -Path (Join-Path $WwwRoot "empty.txt") | Out-Null

    $largePath = Join-Path $WwwRoot "large.bin"
    $bytes = New-Object byte[] (2 * 1024 * 1024)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [byte]($index % 251)
    }
    [System.IO.File]::WriteAllBytes($largePath, $bytes)
}

function New-Certificate {
    param([string]$CertRoot)

    New-Item -ItemType Directory -Force -Path $CertRoot | Out-Null
    $certPath = Join-Path $CertRoot "cert.pem"
    $keyPath = Join-Path $CertRoot "priv.key"
    if ((Test-Path $certPath) -and (Test-Path $keyPath)) {
        return
    }

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -eq $openssl) {
        throw "OpenSSL is required to generate HTTP/3 interop certificates. Install openssl or pre-create $certPath and $keyPath."
    }

    $configPath = Join-Path $CertRoot "openssl.cnf"
    @"
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=incursa-http3-interop
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
DNS.2=incursa-server
DNS.3=aioquic-server
DNS.4=quiche-server
DNS.5=ngtcp2-server
IP.1=127.0.0.1
"@ | Set-Content -LiteralPath $configPath

    & $openssl.Source req -x509 -newkey rsa:2048 -nodes -days 7 -keyout $keyPath -out $certPath -config $configPath 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL certificate generation failed with exit code $LASTEXITCODE."
    }
}

function Get-ScenarioPath {
    param([string]$Scenario)

    switch ($Scenario) {
        "get-small" { return "/small.txt" }
        "get-empty" { return "/empty.txt" }
        "get-large" { return "/large.bin" }
        "not-found" { return "/missing.txt" }
        default { return "" }
    }
}

function Get-ExpectedStatus {
    param([string]$Scenario)
    if ($Scenario -eq "not-found") {
        return 404
    }

    return 200
}

function Test-ExecutableTarget {
    param([string]$Target, [string]$Scenario)

    if ($Scenario -notin @("get-small", "get-empty", "get-large", "not-found")) {
        return "scenario requires a specialized peer behavior that is not wired in this first harness slice"
    }

    if ($Target -notin @("incursa-client__incursa-server", "curl__incursa-server")) {
        return "target is listed for matrix coverage but requires an external peer command image/server wiring"
    }

    return ""
}

function Invoke-DockerCompose {
    param([string[]]$Arguments)
    & docker compose --file $script:ComposeFilePath @Arguments
    return $LASTEXITCODE
}

function Invoke-TargetScenario {
    param([string]$Target, [string]$Scenario)

    $skipReason = Test-ExecutableTarget -Target $Target -Scenario $Scenario
    if ($skipReason.Length -ne 0) {
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail $skipReason
        return
    }

    $path = Get-ScenarioPath -Scenario $Scenario
    $expectedStatus = Get-ExpectedStatus -Scenario $Scenario
    $safeName = "$Target-$Scenario".Replace("/", "-")
    $artifact = Join-Path $script:RunRoot "$safeName.log"
    $downloadPath = "/downloads/$safeName.out"

    if ($Target -eq "incursa-client__incursa-server") {
        $args = @(
            "run", "--rm", "--no-deps", "incursa-client",
            "https://incursa-server:4433$path",
            $downloadPath,
            "--expect-status", "$expectedStatus"
        )
    }
    elseif ($Target -eq "curl__incursa-server") {
        if ($expectedStatus -eq 200) {
            $args = @(
                "run", "--rm", "--no-deps", "curl",
                "--http3-only", "--insecure", "--silent", "--show-error", "--fail",
                "--output", $downloadPath,
                "https://incursa-server:4433$path"
            )
        }
        else {
            $args = @(
                "run", "--rm", "--no-deps", "curl",
                "--http3-only", "--insecure", "--silent", "--show-error",
                "--output", $downloadPath,
                "--write-out", "%{http_code}",
                "https://incursa-server:4433$path"
            )
        }
    }
    else {
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "target command is not wired"
        return
    }

    if ($PlanOnly) {
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only: docker compose $($args -join ' ')" -Artifact $artifact
        return
    }

    & docker compose --file $script:ComposeFilePath @args *> $artifact
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Result -Target $Target -Scenario $Scenario -Status "pass" -Detail "exit code 0" -Artifact $artifact
    }
    else {
        Write-Result -Target $Target -Scenario $Scenario -Status "fail" -Detail "exit code $exitCode" -Artifact $artifact
    }
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    $script:ComposeFilePath = Join-Path $repoRoot "scripts/interop/http3-external/docker-compose.yml"
}
else {
    $script:ComposeFilePath = (Resolve-Path $ComposeFile).Path
}

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$script:RunRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) $runId
$wwwRoot = Join-Path $script:RunRoot "www"
$downloadsRoot = Join-Path $script:RunRoot "downloads"
$certRoot = Join-Path $script:RunRoot "certs"
$logsRoot = Join-Path $script:RunRoot "logs"
$script:ResultsPath = Join-Path $script:RunRoot "results.jsonl"
$reportPath = Join-Path $script:RunRoot "report.md"

New-Item -ItemType Directory -Force -Path $script:RunRoot, $downloadsRoot, $logsRoot | Out-Null
New-Fixtures -WwwRoot $wwwRoot
if (-not $PlanOnly) {
    New-Certificate -CertRoot $certRoot
}

$env:HTTP3_INTEROP_WWW = $wwwRoot
$env:HTTP3_INTEROP_DOWNLOADS = $downloadsRoot
$env:HTTP3_INTEROP_CERTS = $certRoot
$env:HTTP3_INTEROP_LOGS = $logsRoot

if (-not $PlanOnly) {
    $upArgs = @("up", "--detach")
    if (-not $SkipBuild) {
        $upArgs += "--build"
    }
    $upArgs += "incursa-server"
    $upExitCode = Invoke-DockerCompose -Arguments $upArgs
    if ($upExitCode -ne 0) {
        throw "docker compose up failed with exit code $upExitCode."
    }

    Start-Sleep -Seconds 3
}

try {
    foreach ($target in $Targets) {
        foreach ($scenario in $Scenarios) {
            Invoke-TargetScenario -Target $target -Scenario $scenario
        }
    }
}
finally {
    if (-not $PlanOnly -and -not $KeepServerRunning) {
        Invoke-DockerCompose -Arguments @("down", "--remove-orphans") | Out-Null
    }
}

python (Join-Path $PSScriptRoot "parse-http3-results.py") $script:ResultsPath --output $reportPath
Write-Host "Results: $script:ResultsPath"
Write-Host "Report:  $reportPath"
