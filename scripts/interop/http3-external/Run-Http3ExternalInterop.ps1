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
    [switch]$KeepServerRunning,
    [string]$PcapSource = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:Http3ExternalServerPort = 4433
$script:Http3ExternalClientHost = "incursa-server"
$script:Http3ExternalClientPort = 4433
$script:Http3ExternalServerConnectTo = ""
$script:Http3ExternalDockerNetworkName = ""
$script:Http3ExternalAioquicVersion = "1.3.0"

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

function Normalize-MatrixValues {
    param([string[]]$Values)

    $normalized = [System.Collections.Generic.List[string]]::new()
    foreach ($value in $Values) {
        foreach ($part in ($value -split ",")) {
            $trimmed = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $normalized.Add($trimmed)
            }
        }
    }

    return $normalized.ToArray()
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

function Get-PeerImageName {
    param(
        [string]$EnvironmentVariable,
        [string]$DefaultImage
    )

    $value = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultImage
    }

    return $value
}

function New-PeerToolInfo {
    param(
        [string]$Tool,
        [string]$Type,
        [string]$EnvironmentVariable,
        [string]$Image,
        [string[]]$Roles,
        [string[]]$SupportedScenarios,
        [string[]]$CommandLineTemplates,
        [string[]]$KnownLimitations,
        [hashtable]$Package = @{}
    )

    return [ordered]@{
        tool = $Tool
        type = $Type
        environmentVariable = $EnvironmentVariable
        package = $Package
        image = Get-DockerImageInfo -Image $Image
        roles = @($Roles)
        supportedScenarios = @($SupportedScenarios)
        commandLineTemplates = @($CommandLineTemplates)
        knownLimitations = @($KnownLimitations)
    }
}

function Write-PeerToolManifest {
    param([string]$Path)

    $curlImage = Get-PeerImageName -EnvironmentVariable "HTTP3_CURL_IMAGE" -DefaultImage "ghcr.io/macbre/curl-http3"
    $quicheImage = Get-PeerImageName -EnvironmentVariable "HTTP3_QUICHE_IMAGE" -DefaultImage "cloudflare/quiche:latest"
    $ngtcp2Image = Get-PeerImageName -EnvironmentVariable "HTTP3_NGTCP2_IMAGE" -DefaultImage "ghcr.io/ngtcp2/ngtcp2-interop:latest"
    $aioquicImage = "incursa-http3-external-interop-aioquic:latest"
    $staticGetScenarios = @("get-small", "get-empty", "get-large", "not-found")
    $staticGetWithHeaderScenario = @("get-small", "get-empty", "get-large", "not-found", "many-headers", "split-data")

    $manifest = [ordered]@{
        schemaVersion = "http3-external-peer-tools-v1"
        runId = Split-Path -Leaf $script:RunRoot
        generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
        planOnly = [bool]$PlanOnly
        composeFile = $script:ComposeFilePath
        targets = @($Targets)
        scenarios = @($Scenarios)
        docker = [ordered]@{
            version = Get-CommandOutputText { docker --version }
            composeVersion = Get-CommandOutputText { docker compose version }
        }
        acquisition = [ordered]@{
            aioquic = New-PeerToolInfo `
                -Tool "aioquic" `
                -Type "repo-local Docker build" `
                -EnvironmentVariable "AIOQUIC_VERSION" `
                -Image $aioquicImage `
                -Package @{ name = "aioquic"; version = $script:Http3ExternalAioquicVersion; dockerfile = "scripts/interop/http3-external/docker/aioquic.Dockerfile" } `
                -Roles @("client", "server") `
                -SupportedScenarios $staticGetWithHeaderScenario `
                -CommandLineTemplates @(
                    "aioquic-http3-client <url> <download-path> --expect-status <status>",
                    "aioquic-http3-server /www /certs/cert.pem /certs/priv.key 4433"
                ) `
                -KnownLimitations @("Repo-local wrapper around aioquic 1.3.0.", "Large-body rows may be skipped if peer response completion stalls are observed.")
            curl = New-PeerToolInfo `
                -Tool "curl" `
                -Type "Docker image" `
                -EnvironmentVariable "HTTP3_CURL_IMAGE" `
                -Image $curlImage `
                -Roles @("client") `
                -SupportedScenarios $staticGetWithHeaderScenario `
                -CommandLineTemplates @("curl --http3-only --max-time 15 --insecure --silent --show-error <url>") `
                -KnownLimitations @("Requires a curl build with --http3-only support.", "Client-only in this harness.")
            quiche = New-PeerToolInfo `
                -Tool "quiche" `
                -Type "Docker image" `
                -EnvironmentVariable "HTTP3_QUICHE_IMAGE" `
                -Image $quicheImage `
                -Roles @("client", "server") `
                -SupportedScenarios $staticGetScenarios `
                -CommandLineTemplates @(
                    "quiche-client --http-version HTTP/3 --no-verify --connect-to <ip:port> --dump-responses <dir> <url>",
                    "quiche-server --listen 0.0.0.0:4433 --cert /certs/cert.pem --key /certs/priv.key --root /www --http-version HTTP/3"
                ) `
                -KnownLimitations @("The image does not expose a --version flag; pin by image ID/repo digest.", "Header-heavy and split-response behavior are not wired for quiche-server rows.")
            ngtcp2 = New-PeerToolInfo `
                -Tool "ngtcp2/nghttp3" `
                -Type "Docker image" `
                -EnvironmentVariable "HTTP3_NGTCP2_IMAGE" `
                -Image $ngtcp2Image `
                -Roles @("client", "server") `
                -SupportedScenarios $staticGetScenarios `
                -CommandLineTemplates @(
                    "wsslclient --download=/downloads --exit-on-all-streams-close --timeout=15s --handshake-timeout=10s --no-http-dump --qlog-dir=/logs/qlog <host> 4433 <url>",
                    "mkdir -p /logs/qlog /logs/sslkeylog && wsslserver --htdocs=/www --qlog-dir=/logs/qlog --no-http-dump --timeout=15s --handshake-timeout=10s 0.0.0.0 4433 /certs/priv.key /certs/cert.pem"
                ) `
                -KnownLimitations @("The interop image default entrypoint is bypassed for server rows.", "The image does not expose a stable no-argument --version output; pin by image ID/repo digest.", "Header-heavy and split-response behavior are not wired for ngtcp2-server rows.")
        }
        evidenceClass = "external-peer-characterization"
        notes = @(
            "Resolved image IDs and repo digests are present only after Docker has pulled or built the image locally.",
            "Skipped rows remain evidence of missing peer command or scenario wiring, not support proof."
        )
    }

    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path
}

function New-Fixtures {
    param([string]$WwwRoot)

    New-Item -ItemType Directory -Force -Path $WwwRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $WwwRoot "small.txt") -Value "small http3 fixture" -NoNewline
    New-Item -ItemType File -Force -Path (Join-Path $WwwRoot "empty.txt") | Out-Null

    $largePath = Join-Path $WwwRoot "large.bin"
    $bytes = New-Object byte[] (64 * 1024)
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

    & $openssl.Source ecparam -name prime256v1 -genkey -noout -out $keyPath 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL private key generation failed with exit code $LASTEXITCODE."
    }

    & $openssl.Source req -x509 -new -key $keyPath -days 7 -out $certPath -config $configPath 2>&1 | Out-Host
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
        "multiple-concurrent-get" { return "/small.txt" }
        "not-found" { return "/missing.txt" }
        "many-headers" { return "/many-headers.txt" }
        "split-data" { return "/split-data.bin" }
        "request-cancellation" { return "/cancel.bin" }
        "goaway" { return "/goaway.txt" }
        "connection-close-in-flight" { return "/close-in-flight.bin" }
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

    $incursaScenarios = @(
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
    )
    $curlScenarios = @("get-small", "get-empty", "get-large", "not-found", "many-headers", "split-data")
    $staticPeerServerScenarios = @("get-small", "get-empty", "get-large", "not-found")
    $aioquicStableScenarios = @("get-small", "get-empty", "not-found", "many-headers")
    $aioquicLargeBodySkipScenarios = @("get-large", "split-data")

    if ($Target -eq "incursa-client__incursa-server" -and $Scenario -in $incursaScenarios) {
        return ""
    }

    if ($Target -eq "curl__incursa-server" -and $Scenario -in $curlScenarios) {
        return ""
    }

    if ($Target -eq "aioquic-client__incursa-server" -and $Scenario -in $aioquicStableScenarios) {
        return ""
    }

    if ($Target -eq "aioquic-client__incursa-server" -and $Scenario -in $aioquicLargeBodySkipScenarios) {
        return "aioquic 1.3.0 large-body peer incompatibility; these rows are documented skips until the peer library is upgraded or replaced"
    }

    if ($Target -eq "aioquic-client__incursa-server" -and $Scenario -in $curlScenarios) {
        return ""
    }

    if ($Target -eq "quiche-client__incursa-server" -and $Scenario -in $curlScenarios) {
        return ""
    }

    if ($Target -eq "ngtcp2-client__incursa-server" -and $Scenario -in $curlScenarios) {
        return ""
    }

    if ($Target -eq "incursa-client__aioquic-server" -and $Scenario -in $curlScenarios) {
        return ""
    }

    if (($Target -eq "incursa-client__quiche-server" -or $Target -eq "incursa-client__ngtcp2-server") -and
        $Scenario -in $staticPeerServerScenarios) {
        return ""
    }

    if ($Scenario -notin $incursaScenarios) {
        return "scenario requires a specialized peer behavior that is not wired in this first harness slice"
    }

    if ($Target -ne "incursa-client__incursa-server") {
        return "target is listed for matrix coverage but requires an external peer command image/server wiring"
    }

    return ""
}

function Invoke-DockerCompose {
    param([string[]]$Arguments)
    & docker compose --file $script:ComposeFilePath @Arguments 2>&1 | Out-Host
    $exitCode = $LASTEXITCODE
    return $exitCode
}

function New-ScenarioArtifactDirectory {
    param(
        [string]$Target,
        [string]$Scenario
    )

    $safeName = "$Target-$Scenario".Replace("/", "-")
    $artifactDirectory = Join-Path $script:ScenarioRoot $safeName
    New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
    return $artifactDirectory
}

function Write-Http3Summary {
    param(
        [string]$ArtifactDirectory,
        [string]$Target,
        [string]$Scenario,
        [string]$Status,
        [string]$Detail,
        [int]$ExitCode,
        [string]$CommandLine
    )

    $summary = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        target = $Target
        scenario = $Scenario
        status = $Status
        detail = $Detail
        exitCode = $ExitCode
        command = $CommandLine
        artifacts = [ordered]@{
            stdout = "stdout.log"
            stderr = "stderr.log"
            command = "command.txt"
            qlog = Resolve-PathOrRelative (Join-Path $script:LogsRoot "*/qlog")
            sslKeyLog = Resolve-PathOrRelative (Join-Path $script:LogsRoot "*/sslkeylog/keys.log")
            pcaps = Resolve-PathOrRelative $script:PcapRoot
        }
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ArtifactDirectory "http3-summary.json")
}

function Resolve-PathOrRelative {
    param([string]$Path)
    return $Path
}

function Copy-PcapArtifacts {
    if ([string]::IsNullOrWhiteSpace($PcapSource)) {
        return
    }

    if (-not (Test-Path -LiteralPath $PcapSource)) {
        Write-Warning "Packet capture source '$PcapSource' does not exist."
        return
    }

    New-Item -ItemType Directory -Force -Path $script:PcapRoot | Out-Null
    Get-ChildItem -LiteralPath $PcapSource -Recurse -File -Include *.pcap,*.pcapng,*.pcap.gz,*.pcapng.gz |
        ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $script:PcapRoot $_.Name) -Force
        }
}

function Invoke-DockerComposeCapture {
    param(
        [string[]]$Arguments,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    & docker compose --file $script:ComposeFilePath @Arguments > $StdoutPath 2> $StderrPath
    return $LASTEXITCODE
}

function Get-ServerConnectToAddress {
    $serverContainerId = (& docker compose --file $script:ComposeFilePath ps -q incursa-server).Trim()
    if ([string]::IsNullOrWhiteSpace($serverContainerId)) {
        throw "Could not resolve the running incursa-server container id."
    }

    $script:Http3ExternalDockerNetworkName = (& docker inspect --format '{{range $networkName, $network := .NetworkSettings.Networks}}{{$networkName}}{{end}}' $serverContainerId).Trim()
    if ([string]::IsNullOrWhiteSpace($script:Http3ExternalDockerNetworkName)) {
        throw "Could not resolve the incursa-server Docker network name."
    }

    $serverIp = (& docker inspect --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" $serverContainerId).Trim()
    if ([string]::IsNullOrWhiteSpace($serverIp)) {
        throw "Could not resolve the incursa-server container IP address."
    }

    return ("{0}:{1}" -f $serverIp, $script:Http3ExternalServerPort)
}

function Invoke-EndpointPreflight {
    $preflightRoot = Join-Path $script:RunRoot "preflight"
    New-Item -ItemType Directory -Force -Path $preflightRoot | Out-Null

    $serverStdout = Join-Path $preflightRoot "server-endpoint.stdout.log"
    $serverStderr = Join-Path $preflightRoot "server-endpoint.stderr.log"
    $clientStdout = Join-Path $preflightRoot "client-endpoint.stdout.log"
    $clientStderr = Join-Path $preflightRoot "client-endpoint.stderr.log"
    $summaryPath = Join-Path $preflightRoot "endpoint-summary.json"

    $serverScript = @"
echo runningInDocker=`${DOTNET_RUNNING_IN_CONTAINER:-unknown}
echo hostname=`$(hostname)
echo addresses=`$(hostname -i 2>/dev/null || true)
echo commandLine=`$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null || true)
echo ss_lunp_begin
(ss -lunp 2>/dev/null || netstat -lunp 2>/dev/null || true)
echo ss_lunp_end
echo proc_net_udp_begin
cat /proc/net/udp 2>/dev/null || true
echo proc_net_udp_end
echo proc_net_udp6_begin
cat /proc/net/udp6 2>/dev/null || true
echo proc_net_udp6_end
"@

    $clientScript = @"
echo runningInDocker=`${DOTNET_RUNNING_IN_CONTAINER:-unknown}
echo hostname=`$(hostname)
echo addresses=`$(hostname -i 2>/dev/null || true)
echo targetHost=$script:Http3ExternalClientHost
echo targetPort=$script:Http3ExternalClientPort
echo hosts_begin
(getent hosts $script:Http3ExternalClientHost || nslookup $script:Http3ExternalClientHost || true)
echo hosts_end
"@

    $serverExitCode = Invoke-DockerComposeCapture `
        -Arguments @("exec", "-T", "incursa-server", "sh", "-c", $serverScript) `
        -StdoutPath $serverStdout `
        -StderrPath $serverStderr
    $clientExitCode = Invoke-DockerComposeCapture `
        -Arguments @("run", "--rm", "--no-deps", "--entrypoint", "/bin/sh", "incursa-client", "-c", $clientScript) `
        -StdoutPath $clientStdout `
        -StderrPath $clientStderr

    $serverText = if (Test-Path $serverStdout) { Get-Content -LiteralPath $serverStdout -Raw } else { "" }
    $clientText = if (Test-Path $clientStdout) { Get-Content -LiteralPath $clientStdout -Raw } else { "" }
    $warnings = [System.Collections.Generic.List[string]]::new()
    if ($script:Http3ExternalClientHost -in @("localhost", "127.0.0.1", "::1", "[::1]")) {
        $warnings.Add("wrong-client-host")
    }

    if ($script:Http3ExternalClientPort -ne $script:Http3ExternalServerPort) {
        $warnings.Add("wrong-client-port")
    }

    if ($serverText -match "127\.0\.0\.1:$script:Http3ExternalServerPort|::1:$script:Http3ExternalServerPort") {
        $warnings.Add("server-loopback-bind")
    }

    if (($serverText -notmatch ":$($script:Http3ExternalServerPort)\b") -and ($serverText -notmatch ":1151\b")) {
        $warnings.Add("server-wrong-port")
    }

    if ($clientText -notmatch [regex]::Escape($script:Http3ExternalClientHost)) {
        $warnings.Add("client-host-resolution-not-observed")
    }

    $summary = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        serverConfiguredPort = $script:Http3ExternalServerPort
        clientTargetHost = $script:Http3ExternalClientHost
        clientTargetPort = $script:Http3ExternalClientPort
        serverPreflightExitCode = $serverExitCode
        clientPreflightExitCode = $clientExitCode
        serverUdpPortObserved = ($serverText -match ":$($script:Http3ExternalServerPort)\b") -or ($serverText -match ":1151\b")
        clientHostResolutionObserved = $clientText -match [regex]::Escape($script:Http3ExternalClientHost)
        warnings = @($warnings)
        artifacts = [ordered]@{
            serverStdout = "preflight/server-endpoint.stdout.log"
            serverStderr = "preflight/server-endpoint.stderr.log"
            clientStdout = "preflight/client-endpoint.stdout.log"
            clientStderr = "preflight/client-endpoint.stderr.log"
        }
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath
}

function Write-UdpReachabilityReport {
    param([string]$ReportPath)

    $preflightSummaryPath = Join-Path $script:RunRoot "preflight/endpoint-summary.json"
    $preflight = if (Test-Path $preflightSummaryPath) {
        Get-Content -LiteralPath $preflightSummaryPath -Raw | ConvertFrom-Json
    }
    else {
        $null
    }

    $results = if (Test-Path $script:ResultsPath) {
        Get-Content -LiteralPath $script:ResultsPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json }
    }
    else {
        @()
    }

    $classification = "inconclusive"
    $warnings = if ($preflight -and $preflight.warnings) { @($preflight.warnings) } else { @() }
    if ($warnings -contains "wrong-client-host") {
        $classification = "wrong-client-host"
    }
    elseif ($warnings -contains "wrong-client-port") {
        $classification = "wrong-client-port"
    }
    elseif ($warnings -contains "server-loopback-bind") {
        $classification = "server-loopback-bind"
    }
    elseif ($warnings -contains "server-wrong-port") {
        $classification = "server-wrong-port"
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# HTTP/3 Docker UDP Reachability Investigation")
    $lines.Add("")
    $lines.Add("## Classification")
    $lines.Add("")
    $lines.Add("- Classification: $classification")
    $lines.Add("- Scope: QUIC/container handshake only. HTTP/3 and QPACK semantics were not changed or evaluated.")
    $lines.Add("")
    $lines.Add("## Endpoint Preflight")
    $lines.Add("")
    if ($preflight) {
        $lines.Add("- Client target host: $($preflight.clientTargetHost)")
        $lines.Add("- Client target port: $($preflight.clientTargetPort)")
        $lines.Add("- Server configured port: $($preflight.serverConfiguredPort)")
        $lines.Add("- Server UDP port observed in container: $($preflight.serverUdpPortObserved)")
        $lines.Add("- Client host resolution observed: $($preflight.clientHostResolutionObserved)")
        $warningArray = @($warnings)
        $warningText = if ($warningArray.Count -eq 0) { "none" } else { [string]::Join(", ", [string[]]$warningArray) }
        $lines.Add("- Preflight warnings: $warningText")
    }
    else {
        $lines.Add("- Endpoint preflight did not run.")
    }

    $lines.Add("")
    $lines.Add("## Scenario Results")
    $lines.Add("")
    foreach ($result in $results) {
        $lines.Add("- $($result.target) / $($result.scenario): $($result.status) - $($result.detail)")
    }

    $lines.Add("")
    $lines.Add("## Artifacts")
    $lines.Add("")
    $lines.Add("- Results: results.jsonl")
    $lines.Add("- Parsed report: report.md")
    $lines.Add("- Server endpoint preflight: preflight/server-endpoint.stdout.log")
    $lines.Add("- Client endpoint preflight: preflight/client-endpoint.stdout.log")
    $lines.Add("- Scenario command/stdout/stderr: scenarios/")
    $lines.Add("- qlog output: logs/*/qlog/")
    $lines.Add("- Packet captures copied from caller source: pcaps/")

    $lines.Add("")
    $lines.Add("## Hard Rule")
    $lines.Add("")
    $lines.Add("Do not change QPACK, HTTP/3 frame parsing, SETTINGS, pseudo-header validation, request/response handling, or HTTP/3 error mapping until QUIC handshake reachability is proven in Docker.")

    $lines | Set-Content -LiteralPath $ReportPath
}

function Invoke-IncursaConcurrentGetScenario {
    param(
        [string]$Target,
        [string]$Scenario,
        [string]$ArtifactDirectory,
        [string]$CommandPath,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    $clientCount = 4
    $commands = [System.Collections.Generic.List[string]]::new()
    $processes = [System.Collections.Generic.List[object]]::new()
    if ($PlanOnly) {
        for ($index = 0; $index -lt $clientCount; $index++) {
            $downloadPath = "/downloads/$Target-$Scenario-$index.out"
            $commands.Add("docker compose --file `"$script:ComposeFilePath`" run --rm --no-deps incursa-client https://incursa-server:4433/small.txt $downloadPath --expect-status 200")
        }

        $commands | Set-Content -LiteralPath $CommandPath
        New-Item -ItemType File -Force -Path $StdoutPath, $StderrPath | Out-Null
        Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only" -ExitCode 0 -CommandLine ([string]::Join("; ", $commands))
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only: $([string]::Join("; ", $commands))" -Artifact $ArtifactDirectory
        return
    }

    for ($index = 0; $index -lt $clientCount; $index++) {
        $downloadPath = "/downloads/$Target-$Scenario-$index.out"
        $clientStdout = Join-Path $ArtifactDirectory "stdout.$index.log"
        $clientStderr = Join-Path $ArtifactDirectory "stderr.$index.log"
        $arguments = @(
            "compose", "--file", $script:ComposeFilePath,
            "run", "--rm", "--no-deps", "incursa-client",
            "https://incursa-server:4433/small.txt",
            $downloadPath,
            "--expect-status", "200"
        )
        $commands.Add("docker $($arguments -join ' ')")
        $processes.Add([pscustomobject]@{
            Index = $index
            Process = Start-Process -FilePath "docker" -ArgumentList $arguments -RedirectStandardOutput $clientStdout -RedirectStandardError $clientStderr -PassThru -NoNewWindow
            Stdout = $clientStdout
            Stderr = $clientStderr
        })
    }

    $commands | Set-Content -LiteralPath $CommandPath
    $exitCodes = [System.Collections.Generic.List[int]]::new()
    foreach ($item in $processes) {
        $item.Process.WaitForExit()
        $exitCodes.Add($item.Process.ExitCode)
    }

    foreach ($item in $processes) {
        Add-Content -LiteralPath $StdoutPath -Value "=== client $($item.Index) stdout ==="
        if (Test-Path -LiteralPath $item.Stdout) {
            Get-Content -LiteralPath $item.Stdout -Raw | Add-Content -LiteralPath $StdoutPath
        }

        Add-Content -LiteralPath $StderrPath -Value "=== client $($item.Index) stderr ==="
        if (Test-Path -LiteralPath $item.Stderr) {
            Get-Content -LiteralPath $item.Stderr -Raw | Add-Content -LiteralPath $StderrPath
        }
    }

    $failed = @($exitCodes | Where-Object { $_ -ne 0 })
    $combinedExitCode = if ($failed.Count -eq 0) { 0 } else { $failed[0] }
    if ($combinedExitCode -eq 0) {
        Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "pass" -Detail "$clientCount concurrent clients exited 0" -ExitCode 0 -CommandLine ([string]::Join("; ", $commands))
        Write-Result -Target $Target -Scenario $Scenario -Status "pass" -Detail "$clientCount concurrent clients exited 0" -Artifact $ArtifactDirectory
        return
    }

    Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "fail" -Detail "one or more concurrent clients failed: $([string]::Join(',', $exitCodes))" -ExitCode $combinedExitCode -CommandLine ([string]::Join("; ", $commands))
    Write-Result -Target $Target -Scenario $Scenario -Status "fail" -Detail "one or more concurrent clients failed: $([string]::Join(',', $exitCodes))" -Artifact $ArtifactDirectory
}

function Invoke-IncursaClientPeerServerScenario {
    param(
        [string]$Target,
        [string]$Scenario,
        [string]$Path,
        [int]$ExpectedStatus,
        [string]$ArtifactDirectory,
        [string]$CommandPath,
        [string]$StdoutPath,
        [string]$StderrPath,
        [string]$DownloadPath
    )

    $peerName = if ($Target -eq "incursa-client__quiche-server") { "quiche" } else { "ngtcp2" }
    $peerImage = if ($peerName -eq "quiche") {
        Get-PeerImageName -EnvironmentVariable "HTTP3_QUICHE_IMAGE" -DefaultImage "cloudflare/quiche:latest"
    }
    else {
        Get-PeerImageName -EnvironmentVariable "HTTP3_NGTCP2_IMAGE" -DefaultImage "ghcr.io/ngtcp2/ngtcp2-interop:latest"
    }

    $containerName = "incursa-http3-external-$peerName-server-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
    $peerLogRoot = Join-Path $script:LogsRoot "$peerName-server"
    New-Item -ItemType Directory -Force -Path $peerLogRoot | Out-Null
    $peerStdoutPath = Join-Path $ArtifactDirectory "peer-server.stdout.log"
    $peerStderrPath = Join-Path $ArtifactDirectory "peer-server.stderr.log"
    $peerStartPath = Join-Path $ArtifactDirectory "peer-server-start.stdout.log"
    $peerStartErrorPath = Join-Path $ArtifactDirectory "peer-server-start.stderr.log"

    if ($peerName -eq "quiche") {
        $quicheServerCommand = "mkdir -p /logs/qlog /logs/sslkeylog && quiche-server --listen 0.0.0.0:4433 --cert /certs/cert.pem --key /certs/priv.key --root /www --http-version HTTP/3"
        $serverArgs = @(
            "run", "-d",
            "--name", $containerName,
            "--network", $script:Http3ExternalDockerNetworkName,
            "-v", "${wwwRoot}:/www:ro",
            "-v", "${certRoot}:/certs:ro",
            "-v", "${peerLogRoot}:/logs",
            "-e", "QLOGDIR=/logs/qlog",
            "-e", "SSLKEYLOGFILE=/logs/sslkeylog/keys.log",
            "--entrypoint", "/bin/sh",
            $peerImage,
            "-lc",
            $quicheServerCommand
        )
        $serverCommandLine = "docker $($serverArgs -join ' ')"
    }
    else {
        $ngtcp2ServerCommand = "mkdir -p /logs/qlog /logs/sslkeylog && /usr/local/bin/wsslserver --htdocs=/www --qlog-dir=/logs/qlog --no-http-dump --timeout=15s --handshake-timeout=10s 0.0.0.0 4433 /certs/priv.key /certs/cert.pem"
        $serverArgs = @(
            "run", "-d",
            "--name", $containerName,
            "--network", $script:Http3ExternalDockerNetworkName,
            "-v", "${wwwRoot}:/www:ro",
            "-v", "${certRoot}:/certs:ro",
            "-v", "${peerLogRoot}:/logs",
            "-e", "QLOGDIR=/logs/qlog",
            "-e", "SSLKEYLOGFILE=/logs/sslkeylog/keys.log",
            "--entrypoint", "/bin/sh",
            $peerImage,
            "-lc",
            $ngtcp2ServerCommand
        )
        $serverCommandLine = "docker $($serverArgs -join ' ')"
    }

    $clientLogRoot = Join-Path $script:LogsRoot "incursa-client-peer-server"
    New-Item -ItemType Directory -Force -Path $clientLogRoot | Out-Null
    $clientUrl = "https://${containerName}:4433$Path"
    $clientArgs = @(
        "run", "--rm",
        "--network", $script:Http3ExternalDockerNetworkName,
        "-v", "${downloadsRoot}:/downloads",
        "-v", "${certRoot}:/certs:ro",
        "-v", "${clientLogRoot}:/logs",
        "-e", "QLOGDIR=/logs/qlog",
        "-e", "SSLKEYLOGFILE=/logs/sslkeylog/keys.log",
        "incursa-http3-external-interop-incursa-client:latest",
        $clientUrl,
        $DownloadPath,
        "--expect-status", "$ExpectedStatus"
    )
    $clientCommandLine = "docker $($clientArgs -join ' ')"
    Set-Content -LiteralPath $CommandPath -Value "$serverCommandLine`n$clientCommandLine"

    if ($PlanOnly) {
        New-Item -ItemType File -Force -Path $StdoutPath, $StderrPath, $peerStdoutPath, $peerStderrPath | Out-Null
        Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only" -ExitCode 0 -CommandLine "$serverCommandLine; $clientCommandLine"
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only: $serverCommandLine; $clientCommandLine" -Artifact $ArtifactDirectory
        return
    }

    & docker @serverArgs > $peerStartPath 2> $peerStartErrorPath
    $serverExitCode = $LASTEXITCODE
    if ($serverExitCode -ne 0) {
        Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "blocked" -Detail "peer server failed to start with exit code $serverExitCode" -ExitCode $serverExitCode -CommandLine "$serverCommandLine; $clientCommandLine"
        Write-Result -Target $Target -Scenario $Scenario -Status "blocked" -Detail "peer server failed to start with exit code $serverExitCode" -Artifact $ArtifactDirectory
        return
    }

    try {
        Start-Sleep -Seconds 2
        $isRunning = (& docker inspect --format "{{.State.Running}}" $containerName 2> $null).Trim()
        if ($isRunning -ne "true") {
            & docker logs $containerName > $peerStdoutPath 2> $peerStderrPath
            Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "blocked" -Detail "peer server exited before client run" -ExitCode $serverExitCode -CommandLine "$serverCommandLine; $clientCommandLine"
            Write-Result -Target $Target -Scenario $Scenario -Status "blocked" -Detail "peer server exited before client run" -Artifact $ArtifactDirectory
            return
        }

        & docker @clientArgs > $StdoutPath 2> $StderrPath
        $clientExitCode = $LASTEXITCODE
        & docker logs $containerName > $peerStdoutPath 2> $peerStderrPath

        $stderrText = if (Test-Path -LiteralPath $StderrPath) {
            Get-Content -LiteralPath $StderrPath -Raw
        }
        else {
            ""
        }

        if ($stderrText -match "handshake timed out|handshake timeout") {
            Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "fail" -Detail "handshake timeout" -ExitCode $clientExitCode -CommandLine "$serverCommandLine; $clientCommandLine"
            Write-Result -Target $Target -Scenario $Scenario -Status "fail" -Detail "handshake timeout" -Artifact $ArtifactDirectory
        }
        elseif ($clientExitCode -eq 0) {
            Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "pass" -Detail "exit code 0" -ExitCode 0 -CommandLine "$serverCommandLine; $clientCommandLine"
            Write-Result -Target $Target -Scenario $Scenario -Status "pass" -Detail "exit code 0" -Artifact $ArtifactDirectory
        }
        else {
            Write-Http3Summary -ArtifactDirectory $ArtifactDirectory -Target $Target -Scenario $Scenario -Status "fail" -Detail "exit code $clientExitCode" -ExitCode $clientExitCode -CommandLine "$serverCommandLine; $clientCommandLine"
            Write-Result -Target $Target -Scenario $Scenario -Status "fail" -Detail "exit code $clientExitCode" -Artifact $ArtifactDirectory
        }
    }
    finally {
        & docker rm -f $containerName > $null 2> $null
    }
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
    $artifactDirectory = New-ScenarioArtifactDirectory -Target $Target -Scenario $Scenario
    $safeName = "$Target-$Scenario".Replace("/", "-")
    $stdoutPath = Join-Path $artifactDirectory "stdout.log"
    $stderrPath = Join-Path $artifactDirectory "stderr.log"
    $commandPath = Join-Path $artifactDirectory "command.txt"
    $downloadPath = "/downloads/$safeName.out"

    if ($Target -eq "incursa-client__incursa-server" -and $Scenario -eq "multiple-concurrent-get") {
        Invoke-IncursaConcurrentGetScenario `
            -Target $Target `
            -Scenario $Scenario `
            -ArtifactDirectory $artifactDirectory `
            -CommandPath $commandPath `
            -StdoutPath $stdoutPath `
            -StderrPath $stderrPath
        return
    }

    if ($Target -eq "incursa-client__incursa-server") {
        $args = @(
            "run", "--rm", "--no-deps", "incursa-client",
            "https://incursa-server:4433$path",
            $downloadPath,
            "--expect-status", "$expectedStatus"
        )

        if ($Scenario -eq "many-headers") {
            $args += @("--expect-header-count-at-least", "66")
        }

        if ($Scenario -eq "request-cancellation") {
            $args += @("--cancel-after-ms", "150")
        }
    }
    elseif ($Target -eq "curl__incursa-server") {
        if ($expectedStatus -eq 200) {
            $args = @(
                "run", "--rm", "--no-deps", "curl",
                "--http3-only", "--max-time", "15", "--insecure", "--silent", "--show-error", "--fail",
                "--output", $downloadPath,
                "https://incursa-server:4433$path"
            )
        }
        else {
            $args = @(
                "run", "--rm", "--no-deps", "curl",
                "--http3-only", "--max-time", "15", "--insecure", "--silent", "--show-error",
                "--output", $downloadPath,
                "--write-out", "%{http_code}",
                "https://incursa-server:4433$path"
            )
        }
    }
    elseif ($Target -eq "aioquic-client__incursa-server") {
        $args = @(
            "run", "--rm", "--no-deps", "aioquic",
            "/usr/local/bin/aioquic-http3-client",
            "https://incursa-server:4433$path",
            $downloadPath,
            "--expect-status", "$expectedStatus"
        )

        if ($Scenario -eq "many-headers") {
            $args += @("--expect-header-count-at-least", "66")
        }
    }
    elseif ($Target -eq "quiche-client__incursa-server") {
        $quicheContainerName = "incursa-http3-external-interop-quiche-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
        $quicheDumpDirectory = "/downloads/$safeName"
        $quicheImage = Get-PeerImageName -EnvironmentVariable "HTTP3_QUICHE_IMAGE" -DefaultImage "cloudflare/quiche:latest"
        $quicheCommand = "mkdir -p $quicheDumpDirectory /logs/qlog /logs/sslkeylog && quiche-client --http-version HTTP/3 --no-verify --connect-to $script:Http3ExternalServerConnectTo --dump-responses $quicheDumpDirectory --dump-json --max-json-payload 0 https://incursa-server:4433$path"
        $args = @(
            "run",
            "--name", $quicheContainerName,
            "--network", $script:Http3ExternalDockerNetworkName,
            "-e", "QLOGDIR=/logs/qlog",
            "-e", "SSLKEYLOGFILE=/logs/sslkeylog/keys.log",
            "--entrypoint", "/bin/sh",
            $quicheImage,
            "-lc",
            $quicheCommand
        )
    }
    elseif ($Target -eq "ngtcp2-client__incursa-server") {
        $ngtcp2ContainerName = "incursa-http3-external-interop-ngtcp2-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
        $ngtcp2Image = if ([string]::IsNullOrWhiteSpace($env:HTTP3_NGTCP2_IMAGE)) { "ghcr.io/ngtcp2/ngtcp2-interop:latest" } else { $env:HTTP3_NGTCP2_IMAGE }
        $ngtcp2LogRoot = Join-Path $script:LogsRoot "ngtcp2"
        New-Item -ItemType Directory -Force -Path $ngtcp2LogRoot | Out-Null
        $ngtcp2Command = "mkdir -p /logs/qlog /logs/sslkeylog && wsslclient --download=/downloads --exit-on-all-streams-close --timeout=15s --handshake-timeout=10s --no-http-dump --qlog-dir=/logs/qlog incursa-server 4433 https://incursa-server:4433$path"
        $args = @(
            "run", "--rm",
            "--name", $ngtcp2ContainerName,
            "--network", $script:Http3ExternalDockerNetworkName,
            "-v", "${wwwRoot}:/www:ro",
            "-v", "${downloadsRoot}:/downloads",
            "-v", "${certRoot}:/certs:ro",
            "-v", "${ngtcp2LogRoot}:/logs",
            "-e", "QLOGDIR=/logs/qlog",
            "-e", "SSLKEYLOGFILE=/logs/sslkeylog/keys.log",
            "--entrypoint", "/bin/sh",
            $ngtcp2Image,
            "-lc",
            $ngtcp2Command
        )
    }
    elseif ($Target -eq "incursa-client__aioquic-server") {
        $args = @("run", "--rm", "--no-deps")

        if (-not [string]::IsNullOrWhiteSpace($env:AIOQUIC_HTTP3_DEBUG)) {
            $args += @("-e", "AIOQUIC_HTTP3_DEBUG=$env:AIOQUIC_HTTP3_DEBUG")
        }

        $args += @(
            "incursa-client",
            "https://aioquic-server:4433$path",
            $downloadPath,
            "--expect-status", "$expectedStatus"
        )

        if ($Scenario -eq "many-headers") {
            $args += @("--expect-header-count-at-least", "66")
        }

    }
    elseif ($Target -eq "incursa-client__quiche-server" -or $Target -eq "incursa-client__ngtcp2-server") {
        Invoke-IncursaClientPeerServerScenario `
            -Target $Target `
            -Scenario $Scenario `
            -Path $path `
            -ExpectedStatus $expectedStatus `
            -ArtifactDirectory $artifactDirectory `
            -CommandPath $commandPath `
            -StdoutPath $stdoutPath `
            -StderrPath $stderrPath `
            -DownloadPath $downloadPath
        return
    }
    else {
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "target command is not wired"
        return
    }

    if ($Target -eq "quiche-client__incursa-server") {
        $commandLine = "docker run --name $quicheContainerName --network $script:Http3ExternalDockerNetworkName -e QLOGDIR=/logs/qlog -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log --entrypoint /bin/sh $quicheImage -lc `"$quicheCommand`""
    }
    elseif ($Target -eq "ngtcp2-client__incursa-server") {
        $commandLine = "docker run --rm --name $ngtcp2ContainerName --network $script:Http3ExternalDockerNetworkName -v `"$(${wwwRoot}):/www:ro`" -v `"$(${downloadsRoot}):/downloads`" -v `"$(${certRoot}):/certs:ro`" -v `"$(${ngtcp2LogRoot}):/logs`" -e QLOGDIR=/logs/qlog -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log --entrypoint /bin/sh $ngtcp2Image -lc `"$ngtcp2Command`""
    }
    else {
        $commandLine = "docker compose --file `"$script:ComposeFilePath`" $($args -join ' ')"
    }

    if ($PlanOnly) {
        Set-Content -LiteralPath $commandPath -Value $commandLine
        New-Item -ItemType File -Force -Path $stdoutPath, $stderrPath | Out-Null
        Write-Http3Summary -ArtifactDirectory $artifactDirectory -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only" -ExitCode 0 -CommandLine $commandLine
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "plan-only: $commandLine" -Artifact $artifactDirectory
        return
    }

    Set-Content -LiteralPath $commandPath -Value $commandLine
    if ($Target -eq "quiche-client__incursa-server") {
        & docker @args > $stdoutPath 2> $stderrPath
    }
    elseif ($Target -eq "ngtcp2-client__incursa-server") {
        & docker @args > $stdoutPath 2> $stderrPath
    }
    else {
        & docker compose --file $script:ComposeFilePath @args > $stdoutPath 2> $stderrPath
    }
    $exitCode = $LASTEXITCODE
    $stderrText = if (Test-Path -LiteralPath $stderrPath) {
        Get-Content -LiteralPath $stderrPath -Raw
    }
    else {
        ""
    }

    if ($Target -eq "quiche-client__incursa-server") {
        $quicheContainerId = $quicheContainerName
        $quicheDownloadRoot = Join-Path $artifactDirectory "quiche-downloads"
        $quicheLogRoot = Join-Path $script:LogsRoot "quiche"
        New-Item -ItemType Directory -Force -Path $quicheDownloadRoot, $quicheLogRoot | Out-Null
        try {
            & docker cp "${quicheContainerId}:/downloads/$safeName" $quicheDownloadRoot | Out-Null
            $dumpedFile = Get-ChildItem -LiteralPath $quicheDownloadRoot -File -Recurse | Select-Object -First 1
            if ($null -ne $dumpedFile) {
                Copy-Item -LiteralPath $dumpedFile.FullName -Destination $downloadPath -Force
            }

            & docker cp "${quicheContainerId}:/logs/qlog" (Join-Path $quicheLogRoot "qlog") | Out-Null
            & docker cp "${quicheContainerId}:/logs/sslkeylog" (Join-Path $quicheLogRoot "sslkeylog") | Out-Null
        }
        catch {
            # Keep the scenario result from the client exit code; artifact copy is best-effort.
        }
        finally {
            & docker rm -f $quicheContainerId | Out-Null
        }
    }

    if ($stderrText -match "ERR_HANDSHAKE_TIMEOUT|handshake timed out|handshake timeout") {
        Write-Http3Summary -ArtifactDirectory $artifactDirectory -Target $Target -Scenario $Scenario -Status "fail" -Detail "handshake timeout" -ExitCode $exitCode -CommandLine $commandLine
        Write-Result -Target $Target -Scenario $Scenario -Status "fail" -Detail "handshake timeout" -Artifact $artifactDirectory
    }
    elseif ($exitCode -eq 0) {
        Write-Http3Summary -ArtifactDirectory $artifactDirectory -Target $Target -Scenario $Scenario -Status "pass" -Detail "exit code 0" -ExitCode $exitCode -CommandLine $commandLine
        Write-Result -Target $Target -Scenario $Scenario -Status "pass" -Detail "exit code 0" -Artifact $artifactDirectory
    }
    elseif ($Target -eq "curl__incursa-server" -and
        (Test-Path -LiteralPath $stderrPath) -and
        ($stderrText -match "option .*--http3|--http3-only.*unknown|unsupported protocol|the installed libcurl version doesn't support this")) {
        $detail = "curl image does not support HTTP/3; set HTTP3_CURL_IMAGE to a curl build with --http3-only support"
        Write-Http3Summary -ArtifactDirectory $artifactDirectory -Target $Target -Scenario $Scenario -Status "skip" -Detail $detail -ExitCode $exitCode -CommandLine $commandLine
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail $detail -Artifact $artifactDirectory
    }
    else {
        Write-Http3Summary -ArtifactDirectory $artifactDirectory -Target $Target -Scenario $Scenario -Status "fail" -Detail "exit code $exitCode" -ExitCode $exitCode -CommandLine $commandLine
        Write-Result -Target $Target -Scenario $Scenario -Status "fail" -Detail "exit code $exitCode" -Artifact $artifactDirectory
    }
}

$repoRoot = Resolve-RepoRoot
$Targets = Normalize-MatrixValues $Targets
$Scenarios = Normalize-MatrixValues $Scenarios
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
$script:LogsRoot = Join-Path $script:RunRoot "logs"
$script:ScenarioRoot = Join-Path $script:RunRoot "scenarios"
$script:PcapRoot = Join-Path $script:RunRoot "pcaps"
$script:ResultsPath = Join-Path $script:RunRoot "results.jsonl"
$reportPath = Join-Path $script:RunRoot "report.md"
$peerToolManifestPath = Join-Path $script:RunRoot "peer-tool-manifest.json"

New-Item -ItemType Directory -Force -Path $script:RunRoot, $downloadsRoot, $script:LogsRoot, $script:ScenarioRoot, $script:PcapRoot | Out-Null
New-Fixtures -WwwRoot $wwwRoot
if (-not $PlanOnly) {
    New-Certificate -CertRoot $certRoot
}

$env:HTTP3_INTEROP_WWW = $wwwRoot
$env:HTTP3_INTEROP_DOWNLOADS = $downloadsRoot
$env:HTTP3_INTEROP_CERTS = $certRoot
$env:HTTP3_INTEROP_LOGS = $script:LogsRoot

if (-not $PlanOnly) {
    if (-not $SkipBuild) {
        $buildExitCode = Invoke-DockerCompose -Arguments @("build", "incursa-server", "incursa-client", "aioquic")
        if ($buildExitCode -ne 0) {
            throw "docker compose build failed with exit code $buildExitCode."
        }
    }

    $upArgs = @("up", "--detach")
    $upArgs += "incursa-server"
    if ($Targets -contains "incursa-client__aioquic-server") {
        $upArgs += "aioquic-server"
    }

        $upExitCode = Invoke-DockerCompose -Arguments $upArgs
        if ($upExitCode -ne 0) {
            throw "docker compose up failed with exit code $upExitCode."
        }

        Start-Sleep -Seconds 3
        $script:Http3ExternalServerConnectTo = Get-ServerConnectToAddress
        Invoke-EndpointPreflight
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
        & docker compose --file $script:ComposeFilePath logs --no-color incursa-server > (Join-Path $script:RunRoot "server.stdout.log") 2> (Join-Path $script:RunRoot "server.stderr.log")
        if ($Targets -contains "incursa-client__aioquic-server") {
            & docker compose --file $script:ComposeFilePath logs --no-color aioquic-server > (Join-Path $script:RunRoot "aioquic-server.stdout.log") 2> (Join-Path $script:RunRoot "aioquic-server.stderr.log")
            Invoke-DockerCompose -Arguments @("--profile", "peers", "stop", "aioquic-server") | Out-Null
            Invoke-DockerCompose -Arguments @("--profile", "peers", "rm", "--force", "aioquic-server") | Out-Null
        }

        Invoke-DockerCompose -Arguments @("down", "--remove-orphans") | Out-Null
    }
}

Copy-PcapArtifacts
Write-PeerToolManifest -Path $peerToolManifestPath
python (Join-Path $PSScriptRoot "parse-http3-results.py") $script:ResultsPath --output $reportPath
$udpReportPath = Join-Path $script:RunRoot "udp-reachability-report.md"
Write-UdpReachabilityReport -ReportPath $udpReportPath
Write-Host "Results: $script:ResultsPath"
Write-Host "Report:  $reportPath"
Write-Host "UDP:     $udpReportPath"
Write-Host "Tools:   $peerToolManifestPath"
