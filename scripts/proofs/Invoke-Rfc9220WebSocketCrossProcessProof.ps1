[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/http3-websocket-cross-process",
    [string]$RunId = "",
    [int]$Port = 4434,
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

function New-ProofCertificate {
    param([string]$CertRoot)

    New-Item -ItemType Directory -Force -Path $CertRoot | Out-Null
    $certPath = Join-Path $CertRoot "cert.pem"
    $keyPath = Join-Path $CertRoot "priv.key"
    if ((Test-Path -LiteralPath $certPath) -and (Test-Path -LiteralPath $keyPath)) {
        return
    }

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -eq $openssl) {
        throw "OpenSSL is required to generate RFC9220 cross-process TLS materials. Install openssl or pre-create $certPath and $keyPath."
    }

    $configPath = Join-Path $CertRoot "openssl.cnf"
    @"
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=incursa-rfc9220-proof
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
"@ | Set-Content -LiteralPath $configPath

    & $openssl.Source ecparam -name prime256v1 -genkey -noout -out $keyPath *> (Join-Path $CertRoot "openssl.log")
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL private key generation failed with exit code $LASTEXITCODE."
    }

    & $openssl.Source req -x509 -new -key $keyPath -days 7 -out $certPath -config $configPath *>> (Join-Path $CertRoot "openssl.log")
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL certificate generation failed with exit code $LASTEXITCODE."
    }
}

function New-ProofFixtures {
    param([string]$WwwRoot)

    New-Item -ItemType Directory -Force -Path $WwwRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $WwwRoot "index.html") -Value "incursa rfc9220 websocket proof fixture" -NoNewline
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

$runRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) $RunId
$logsRoot = Join-Path $runRoot "logs"
$wwwRoot = Join-Path $runRoot "www"
$certRoot = Join-Path $runRoot "certs"
$serverStdoutPath = Join-Path $logsRoot "server.stdout.log"
$serverStderrPath = Join-Path $logsRoot "server.stderr.log"
$clientStdoutPath = Join-Path $logsRoot "client.stdout.log"
$clientStderrPath = Join-Path $logsRoot "client.stderr.log"
$clientResultPath = Join-Path $runRoot "rfc9220-cross-process-client-result.json"
$manifestPath = Join-Path $runRoot "rfc9220-cross-process-proof.json"
$reportPath = Join-Path $runRoot "rfc9220-cross-process-proof.md"

New-Item -ItemType Directory -Force -Path $runRoot, $logsRoot | Out-Null
New-ProofFixtures -WwwRoot $wwwRoot
New-ProofCertificate -CertRoot $certRoot

$serverProjectPath = Join-Path $repoRoot "samples/Incursa.Quic.Http3.FileServer/Incursa.Quic.Http3.FileServer.csproj"
$clientProjectPath = Join-Path $repoRoot "samples/Incursa.Quic.Http3.Client/Incursa.Quic.Http3.Client.csproj"
if (-not $NoBuild) {
    dotnet build $serverProjectPath -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "HTTP/3 file server build failed with exit code $LASTEXITCODE."
    }

    dotnet build $clientProjectPath -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "HTTP/3 client build failed with exit code $LASTEXITCODE."
    }
}

$serverArguments = @(
    "run",
    "--project",
    $serverProjectPath,
    "-c",
    $Configuration,
    "--no-build",
    "--",
    $wwwRoot,
    (Join-Path $certRoot "cert.pem"),
    (Join-Path $certRoot "priv.key"),
    "$Port",
    "--websocket-proof"
)

$clientArguments = @(
    "run",
    "--project",
    $clientProjectPath,
    "-c",
    $Configuration,
    "--no-build",
    "--",
    "https://localhost:$Port/websocket-proof",
    $clientResultPath,
    "--websocket-proof"
)

$startedUtc = (Get-Date).ToUniversalTime().ToString("o")
$serverProcess = $null
$clientExitCode = $null
$status = "failed"
try {
    $serverProcess = Start-Process -FilePath "dotnet" -ArgumentList $serverArguments -WorkingDirectory $repoRoot -RedirectStandardOutput $serverStdoutPath -RedirectStandardError $serverStderrPath -PassThru -NoNewWindow
    Start-Sleep -Seconds 3
    if ($serverProcess.HasExited) {
        throw "HTTP/3 WebSocket proof server exited early with code $($serverProcess.ExitCode). See $serverStdoutPath and $serverStderrPath."
    }

    & dotnet @clientArguments > $clientStdoutPath 2> $clientStderrPath
    $clientExitCode = $LASTEXITCODE
    if ($clientExitCode -ne 0) {
        throw "HTTP/3 WebSocket proof client failed with exit code $clientExitCode. See $clientStdoutPath and $clientStderrPath."
    }

    $status = "passed"
}
finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
}

$finishedUtc = (Get-Date).ToUniversalTime().ToString("o")
$artifactHashes = @(
    Get-ChildItem -LiteralPath $runRoot -File -Recurse |
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

$manifest = [ordered]@{
    runId = $RunId
    evidenceClass = "local-cross-process-peer"
    status = $status
    startedUtc = $startedUtc
    finishedUtc = $finishedUtc
    port = $Port
    serverProcessId = if ($null -ne $serverProcess) { $serverProcess.Id } else { $null }
    clientExitCode = $clientExitCode
    serverCommand = "dotnet " + ($serverArguments -join " ")
    clientCommand = "dotnet " + ($clientArguments -join " ")
    requirementIds = @(
        "REQ-QUIC-RFC9220-0017",
        "REQ-QUIC-RFC9220-0018",
        "REQ-QUIC-RFC9220-0019",
        "REQ-QUIC-RFC9220-0022",
        "REQ-QUIC-RFC9220-0030",
        "REQ-QUIC-RFC9220-0031"
    )
    proofScope = @(
        "HTTP/3 Extended CONNECT setup across sample client and server processes",
        "accepted response metadata",
        "server ping and client pong helper behavior",
        "client ping and server pong echo",
        "text message echo",
        "6000-byte binary echo",
        "client close and server close echo"
    )
    runRoot = Get-RelativePath -Root $repoRoot -Path $runRoot
    serverStdout = Get-RelativePath -Root $repoRoot -Path $serverStdoutPath
    serverStderr = Get-RelativePath -Root $repoRoot -Path $serverStderrPath
    clientStdout = Get-RelativePath -Root $repoRoot -Path $clientStdoutPath
    clientStderr = Get-RelativePath -Root $repoRoot -Path $clientStderrPath
    clientResult = Get-RelativePath -Root $repoRoot -Path $clientResultPath
    artifactHashes = $artifactHashes
}

$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# RFC9220 WebSocket Cross-Process Proof")
$lines.Add("")
$lines.Add("- Run ID: ``$RunId``")
$lines.Add("- Evidence class: ``local-cross-process-peer``")
$lines.Add("- Status: ``$status``")
$lines.Add("- Server command: ``$($manifest.serverCommand)``")
$lines.Add("- Client command: ``$($manifest.clientCommand)``")
$lines.Add("- Client result: ``$($manifest.clientResult)``")
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

Write-Host "RFC9220 cross-process proof manifest: $manifestPath"
Write-Host "RFC9220 cross-process proof report:   $reportPath"

if ($status -ne "passed") {
    throw "RFC9220 cross-process proof failed. See $reportPath."
}
