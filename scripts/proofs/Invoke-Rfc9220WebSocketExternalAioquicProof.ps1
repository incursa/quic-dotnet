[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/http3-websocket-external-aioquic",
    [string]$RunId = "",
    [int]$Port = 4435,
    [string]$Configuration = "Release",
    [switch]$NoBuild,
    [switch]$SkipImageBuild
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

function Get-CommandOutputText {
    param([scriptblock]$Command)

    try {
        $output = & $Command 2>&1
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            return $null
        }

        return (($output | ForEach-Object { $_.ToString() }) -join "`n").Trim()
    }
    catch {
        return $null
    }
}

function Get-DockerImageInfo {
    param([string]$Image)

    $imageId = Get-CommandOutputText { docker image inspect $Image --format "{{.Id}}" }
    $repoDigestsText = Get-CommandOutputText { docker image inspect $Image --format "{{json .RepoDigests}}" }
    $repoDigests = @()
    if (-not [string]::IsNullOrWhiteSpace($repoDigestsText) -and $repoDigestsText -ne "null") {
        try {
            $repoDigests = @($repoDigestsText | ConvertFrom-Json)
        }
        catch {
            $repoDigests = @()
        }
    }

    return [ordered]@{
        image = $Image
        resolvedImageId = $imageId
        repoDigests = $repoDigests
    }
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
        throw "OpenSSL is required to generate RFC9220 external aioquic TLS materials. Install openssl or pre-create $certPath and $keyPath."
    }

    $configPath = Join-Path $CertRoot "openssl.cnf"
    @"
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=incursa-rfc9220-aioquic-proof
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
DNS.2=host.docker.internal
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
    Set-Content -LiteralPath (Join-Path $WwwRoot "index.html") -Value "incursa rfc9220 external aioquic proof fixture" -NoNewline
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

$aioquicImage = "incursa-http3-external-interop-aioquic:latest"
$runRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) $RunId
$logsRoot = Join-Path $runRoot "logs"
$wwwRoot = Join-Path $runRoot "www"
$certRoot = Join-Path $runRoot "certs"
$serverQlogRoot = Join-Path $runRoot "server-qlog"
$clientQlogRoot = Join-Path $runRoot "client-qlog"
$clientSslKeyLogRoot = Join-Path $runRoot "client-sslkeylog"
$serverStdoutPath = Join-Path $logsRoot "server.stdout.log"
$serverStderrPath = Join-Path $logsRoot "server.stderr.log"
$clientStdoutPath = Join-Path $logsRoot "aioquic-client.stdout.log"
$clientStderrPath = Join-Path $logsRoot "aioquic-client.stderr.log"
$dockerBuildLogPath = Join-Path $logsRoot "aioquic-docker-build.log"
$clientResultPath = Join-Path $runRoot "rfc9220-external-aioquic-client-result.json"
$manifestPath = Join-Path $runRoot "rfc9220-external-aioquic-proof.json"
$reportPath = Join-Path $runRoot "rfc9220-external-aioquic-proof.md"

New-Item -ItemType Directory -Force -Path $runRoot, $logsRoot, $serverQlogRoot, $clientQlogRoot, $clientSslKeyLogRoot | Out-Null
New-ProofFixtures -WwwRoot $wwwRoot
New-ProofCertificate -CertRoot $certRoot

$serverProjectPath = Join-Path $repoRoot "samples/Incursa.Quic.Http3.FileServer/Incursa.Quic.Http3.FileServer.csproj"
if (-not $NoBuild) {
    dotnet build $serverProjectPath -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "HTTP/3 file server build failed with exit code $LASTEXITCODE."
    }
}

if (-not $SkipImageBuild) {
    $dockerfilePath = Join-Path $repoRoot "scripts/interop/http3-external/docker/aioquic.Dockerfile"
    & docker build `
        --build-arg AIOQUIC_VERSION=1.3.0 `
        -f $dockerfilePath `
        -t $aioquicImage `
        $repoRoot > $dockerBuildLogPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "aioquic Docker image build failed with exit code $LASTEXITCODE. See $dockerBuildLogPath."
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

$clientUrl = "https://host.docker.internal:$Port/websocket-proof"
$containerName = "incursa-rfc9220-aioquic-$($RunId.ToLowerInvariant() -replace '[^a-z0-9_.-]', '-')"
$clientArguments = @(
    "run",
    "--rm",
    "--name",
    $containerName,
    "--add-host=host.docker.internal:host-gateway",
    "-v",
    "${runRoot}:/proof",
    "-e",
    "QLOGDIR=/proof/client-qlog",
    "-e",
    "SSLKEYLOGFILE=/proof/client-sslkeylog/keys.log",
    $aioquicImage,
    "/usr/local/bin/aioquic-http3-websocket-client",
    $clientUrl,
    "/proof/rfc9220-external-aioquic-client-result.json",
    "--timeout",
    "20"
)

$startedUtc = (Get-Date).ToUniversalTime().ToString("o")
$serverProcess = $null
$clientExitCode = $null
$status = "failed"
try {
    $serverEnv = @{ QLOGDIR = $serverQlogRoot }
    $serverProcess = Start-Process -FilePath "dotnet" -ArgumentList $serverArguments -WorkingDirectory $repoRoot -RedirectStandardOutput $serverStdoutPath -RedirectStandardError $serverStderrPath -PassThru -NoNewWindow -Environment $serverEnv
    Start-Sleep -Seconds 3
    if ($serverProcess.HasExited) {
        throw "HTTP/3 WebSocket proof server exited early with code $($serverProcess.ExitCode). See $serverStdoutPath and $serverStderrPath."
    }

    & docker @clientArguments > $clientStdoutPath 2> $clientStderrPath
    $clientExitCode = $LASTEXITCODE
    if ($clientExitCode -ne 0) {
        throw "aioquic WebSocket-over-H3 proof client failed with exit code $clientExitCode. See $clientStdoutPath and $clientStderrPath."
    }

    $status = "passed"
}
finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }

    docker rm -f $containerName > $null 2>&1
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
    evidenceClass = "local-external-aioquic-peer"
    status = $status
    startedUtc = $startedUtc
    finishedUtc = $finishedUtc
    port = $Port
    serverProcessId = if ($null -ne $serverProcess) { $serverProcess.Id } else { $null }
    clientExitCode = $clientExitCode
    serverCommand = "dotnet " + ($serverArguments -join " ")
    clientCommand = "docker " + ($clientArguments -join " ")
    peerTool = [ordered]@{
        name = "aioquic"
        package = @{ name = "aioquic"; version = "1.3.0" }
        image = Get-DockerImageInfo -Image $aioquicImage
        docker = [ordered]@{
            version = Get-CommandOutputText { docker --version }
        }
    }
    requirementIds = @(
        "REQ-QUIC-RFC9220-0017",
        "REQ-QUIC-RFC9220-0018",
        "REQ-QUIC-RFC9220-0019",
        "REQ-QUIC-RFC9220-0022",
        "REQ-QUIC-RFC9220-0030",
        "REQ-QUIC-RFC9220-0031"
    )
    proofScope = @(
        "HTTP/3 Extended CONNECT from aioquic client container to Incursa server process",
        "accepted response metadata",
        "server ping and aioquic client pong",
        "aioquic client ping and server pong echo",
        "text message echo",
        "6000-byte binary echo",
        "aioquic client close and server close echo"
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
$lines.Add("# RFC9220 WebSocket External aioquic Proof")
$lines.Add("")
$lines.Add("- Run ID: ``$RunId``")
$lines.Add("- Evidence class: ``local-external-aioquic-peer``")
$lines.Add("- Status: ``$status``")
$lines.Add("- Server command: ``$($manifest.serverCommand)``")
$lines.Add("- Client command: ``$($manifest.clientCommand)``")
$lines.Add("- Client result: ``$($manifest.clientResult)``")
$lines.Add("- Peer image: ``$($manifest.peerTool.image.image)``")
$lines.Add("- Peer image ID: ``$($manifest.peerTool.image.resolvedImageId)``")
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

Write-Host "RFC9220 external aioquic proof manifest: $manifestPath"
Write-Host "RFC9220 external aioquic proof report:   $reportPath"

if ($status -ne "passed") {
    throw "RFC9220 external aioquic proof failed. See $reportPath."
}
