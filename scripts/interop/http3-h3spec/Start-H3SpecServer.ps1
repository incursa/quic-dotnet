[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/http3-h3spec",
    [string]$RunId = "",
    [int]$Port = 4433,
    [string]$HostName = "127.0.0.1",
    [string]$Configuration = "Release",
    [switch]$NoBuild,
    [switch]$PlanOnly
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

function New-H3SpecCertificate {
    param([string]$CertRoot)

    New-Item -ItemType Directory -Force -Path $CertRoot | Out-Null
    $certPath = Join-Path $CertRoot "cert.pem"
    $keyPath = Join-Path $CertRoot "priv.key"
    if ((Test-Path $certPath) -and (Test-Path $keyPath)) {
        return
    }

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -eq $openssl) {
        throw "OpenSSL is required to generate h3spec TLS materials. Install openssl or pre-create $certPath and $keyPath."
    }

    $configPath = Join-Path $CertRoot "openssl.cnf"
    @"
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=incursa-h3spec
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
"@ | Set-Content -LiteralPath $configPath

    & $openssl.Source req -x509 -newkey rsa:2048 -nodes -days 7 -keyout $keyPath -out $certPath -config $configPath *> (Join-Path $CertRoot "openssl.log")
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL certificate generation failed with exit code $LASTEXITCODE."
    }
}

function New-H3SpecFixtures {
    param([string]$WwwRoot)

    New-Item -ItemType Directory -Force -Path $WwwRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $WwwRoot "index.html") -Value "incursa h3spec fixture" -NoNewline
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

$runRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) $RunId
$wwwRoot = Join-Path $runRoot "www"
$certRoot = Join-Path $runRoot "certs"
$logsRoot = Join-Path $runRoot "logs"
$contextPath = Join-Path $runRoot "server-context.json"
$stdoutPath = Join-Path $logsRoot "server.stdout.log"
$stderrPath = Join-Path $logsRoot "server.stderr.log"

New-Item -ItemType Directory -Force -Path $runRoot, $logsRoot | Out-Null
New-H3SpecFixtures -WwwRoot $wwwRoot

if ($PlanOnly) {
    $context = [ordered]@{
        runId = $RunId
        runRoot = $runRoot
        host = $HostName
        port = $Port
        planOnly = $true
        status = "not-started"
        stdout = $stdoutPath
        stderr = $stderrPath
    }
    $context | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $contextPath
    Write-Host "Server context: $contextPath"
    return
}

New-H3SpecCertificate -CertRoot $certRoot

$projectPath = Join-Path $repoRoot "samples/Incursa.Quic.Http3.FileServer/Incursa.Quic.Http3.FileServer.csproj"
if (-not $NoBuild) {
    dotnet build $projectPath -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "HTTP/3 file server build failed with exit code $LASTEXITCODE."
    }
}

$arguments = @(
    "run",
    "--project",
    $projectPath,
    "-c",
    $Configuration,
    "--no-build",
    "--",
    $wwwRoot,
    (Join-Path $certRoot "cert.pem"),
    (Join-Path $certRoot "priv.key"),
    "$Port"
)

$process = Start-Process -FilePath "dotnet" -ArgumentList $arguments -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -NoNewWindow
Start-Sleep -Seconds 3
if ($process.HasExited) {
    throw "HTTP/3 file server exited early with code $($process.ExitCode). See $stdoutPath and $stderrPath."
}

$context = [ordered]@{
    runId = $RunId
    runRoot = $runRoot
    host = $HostName
    port = $Port
    planOnly = $false
    status = "started"
    processId = $process.Id
    stdout = $stdoutPath
    stderr = $stderrPath
    www = $wwwRoot
    certs = $certRoot
}
$context | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $contextPath
Write-Host "Server context: $contextPath"
