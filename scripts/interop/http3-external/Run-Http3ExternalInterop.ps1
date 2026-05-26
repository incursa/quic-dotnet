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

    if ($Target -eq "incursa-client__incursa-server" -and $Scenario -in $incursaScenarios) {
        return ""
    }

    if ($Target -eq "curl__incursa-server" -and $Scenario -in $curlScenarios) {
        return ""
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
        $quicheCommand = "mkdir -p $quicheDumpDirectory /logs/qlog /logs/sslkeylog && quiche-client --http-version HTTP/3 --no-verify --connect-to $script:Http3ExternalServerConnectTo --dump-responses $quicheDumpDirectory --dump-json --max-json-payload 0 https://incursa-server:4433$path"
        $args = @(
            "run",
            "--name", $quicheContainerName,
            "--network", $script:Http3ExternalDockerNetworkName,
            "-e", "QLOGDIR=/logs/qlog",
            "-e", "SSLKEYLOGFILE=/logs/sslkeylog/keys.log",
            "--entrypoint", "/bin/sh",
            "cloudflare/quiche:latest",
            "-lc",
            $quicheCommand
        )
    }
    elseif ($Target -eq "ngtcp2-client__incursa-server") {
        $ngtcp2Command = "mkdir -p /logs/qlog && wsslclient --download=/downloads --exit-on-all-streams-close --timeout=15s --handshake-timeout=10s --no-http-dump --qlog-dir=/logs/qlog incursa-server 4433 https://incursa-server:4433$path"
        $args = @(
            "run", "--rm", "--no-deps", "ngtcp2",
            "/bin/sh",
            "-lc",
            $ngtcp2Command
        )
    }
    elseif ($Target -eq "incursa-client__aioquic-server") {
        $args = @(
            "run", "--rm", "--no-deps", "incursa-client",
            "https://aioquic-server:4433$path",
            $downloadPath,
            "--expect-status", "$expectedStatus"
        )

        if ($Scenario -eq "many-headers") {
            $args += @("--expect-header-count-at-least", "66")
        }
    }
    else {
        Write-Result -Target $Target -Scenario $Scenario -Status "skip" -Detail "target command is not wired"
        return
    }

    if ($Target -eq "quiche-client__incursa-server") {
        $commandLine = "docker run --name $quicheContainerName --network $script:Http3ExternalDockerNetworkName -e QLOGDIR=/logs/qlog -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log --entrypoint /bin/sh cloudflare/quiche:latest -lc `"$quicheCommand`""
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
python (Join-Path $PSScriptRoot "parse-http3-results.py") $script:ResultsPath --output $reportPath
$udpReportPath = Join-Path $script:RunRoot "udp-reachability-report.md"
Write-UdpReachabilityReport -ReportPath $udpReportPath
Write-Host "Results: $script:ResultsPath"
Write-Host "Report:  $reportPath"
Write-Host "UDP:     $udpReportPath"
