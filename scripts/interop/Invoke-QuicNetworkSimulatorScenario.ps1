[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,

    [string]$SimulatorRoot,

    [ValidateSet("SIM-QUIC-BASE-0001", "SIM-QUIC-LOSS-0001")]
    [string]$ScenarioId = "SIM-QUIC-BASE-0001",

    [string]$ArtifactsRoot,

    [string]$RunId,

    [string]$DropsToClient = "",

    [string]$DropsToServer = "",

    [string]$Client = "",

    [string]$Server = "",

    [string]$ClientParams = "",

    [string]$ServerParams = "",

    [switch]$Execute,

    [Alias("PlanOnly")]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }

    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function ConvertTo-ScenarioJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Scenario
    )

    return ($Scenario | ConvertTo-Json -Depth 12)
}

function New-ScenarioDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScenarioId,

        [string]$DropsToClient,

        [string]$DropsToServer
    )

    if ($ScenarioId -eq "SIM-QUIC-LOSS-0001" -and
        [string]::IsNullOrWhiteSpace($DropsToClient) -and
        [string]::IsNullOrWhiteSpace($DropsToServer)) {
        throw "SIM-QUIC-LOSS-0001 requires -DropsToClient, -DropsToServer, or both so deterministic loss evidence is explicit."
    }

    if ($ScenarioId -eq "SIM-QUIC-BASE-0001") {
        $parameters = @("--delay=15ms", "--bandwidth=10Mbps", "--queue=25")
        return [ordered]@{
            scenario_id = "SIM-QUIC-BASE-0001"
            classification = "correctness"
            upstream_profile = "simple-p2p"
            upstream_reference = "sim/scenarios/simple-p2p/README.md"
            parameters = $parameters
            local_role = "both"
            peer_shape = "same implementation"
            mapped_requirement_ids = @("REQ-QUIC-INT-0026", "REQ-QUIC-INT-0010")
            expected_observable_behavior = "One ordered transfer completes through the simulator and the harness exits honestly after byte delivery and EOF."
            evidence_required = @(
                "scenario-summary.json",
                "invocation.txt",
                "simulator.stdout.log",
                "simulator.stderr.log",
                "artifact-tree.txt",
                "upstream simulator source reference or pinned commit/path",
                "endpoint logs, runner report, qlog, and packet capture when later integrated"
            )
            status = "implemented"
            promotion_rule = "Promotes only the baseline transfer-under-simulator proof for REQ-QUIC-INT-0010 after linked verification records passing runtime evidence."
            simulator_command = "simple-p2p $($parameters -join ' ')"
        }
    }

    $parameters = @("--delay=15ms", "--bandwidth=10Mbps", "--queue=25")
    if (-not [string]::IsNullOrWhiteSpace($DropsToClient)) {
        $parameters += "--drops_to_client=$DropsToClient"
    }

    if (-not [string]::IsNullOrWhiteSpace($DropsToServer)) {
        $parameters += "--drops_to_server=$DropsToServer"
    }

    return [ordered]@{
        scenario_id = "SIM-QUIC-LOSS-0001"
        classification = "correctness"
        upstream_profile = "droplist"
        upstream_reference = "sim/scenarios/droplist/README.md"
        parameters = $parameters
        local_role = "both"
        peer_shape = "same implementation"
        mapped_requirement_ids = @(
            "REQ-QUIC-RFC9002-S3-0009",
            "REQ-QUIC-RFC9002-S3-0010",
            "REQ-QUIC-RFC9002-S6P2-0001",
            "RFC9002-S6-2-4-P1-R01",
            "RFC9002-S6-2-4-P1-S2-R01"
        )
        expected_observable_behavior = "Reliable data is acknowledged or declared lost, retransmitted in a new ack-eliciting packet, and the bounded transfer completes. Droplist indexes are bottleneck-link IP packet indexes, not QUIC packet numbers."
        evidence_required = @(
            "scenario-summary.json",
            "invocation.txt",
            "simulator.stdout.log",
            "simulator.stderr.log",
            "artifact-tree.txt",
            "droplist material",
            "packet trace or runner packet analysis",
            "qlog loss/probe markers when available",
            "summary showing retransmission rather than duplicate accounting"
        )
        status = "implemented"
        promotion_rule = "Promotes only the mapped deterministic-loss requirements after linked verification records the affected QUIC packet, retransmission evidence, and passing transfer result."
        simulator_command = "droplist $($parameters -join ' ')"
    }
}

function Write-Plan {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Scenario,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$SimulatorRoot,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactsRoot,

        [Parameter(Mandatory = $true)]
        [string]$RunRoot,

        [Parameter(Mandatory = $true)]
        [bool]$Execute,

        [Parameter(Mandatory = $true)]
        [bool]$DryRun
    )

    Write-Host "Network simulator scenario plan."
    Write-Host "Repo root: $RepoRoot"
    Write-Host "Simulator root: $SimulatorRoot"
    Write-Host "Scenario id: $($Scenario.scenario_id)"
    Write-Host "Classification: $($Scenario.classification)"
    Write-Host "Upstream profile: $($Scenario.upstream_profile)"
    Write-Host "Upstream reference: $($Scenario.upstream_reference)"
    Write-Host "Parameters: $($Scenario.parameters -join ' ')"
    Write-Host "Local role: $($Scenario.local_role)"
    Write-Host "Peer shape: $($Scenario.peer_shape)"
    Write-Host "Mapped requirements: $($Scenario.mapped_requirement_ids -join ',')"
    Write-Host "Expected observable behavior: $($Scenario.expected_observable_behavior)"
    Write-Host "Promotion rule: $($Scenario.promotion_rule)"
    Write-Host "Simulator command: $($Scenario.simulator_command)"
    Write-Host "Execute: $Execute"
    Write-Host "Client: $(if ([string]::IsNullOrWhiteSpace($Client)) { '(not supplied)' } else { $Client })"
    Write-Host "Server: $(if ([string]::IsNullOrWhiteSpace($Server)) { '(not supplied)' } else { $Server })"
    Write-Host "Client params: $ClientParams"
    Write-Host "Server params: $ServerParams"
    Write-Host "Compose file: $(Join-Path $SimulatorRoot 'docker-compose.yml')"
    Write-Host "Compose command: docker compose --file docker-compose.yml up --build --force-recreate --abort-on-container-exit"
    Write-Host "Artifact root: $ArtifactsRoot"
    Write-Host "Run root: $RunRoot"
    Write-Host "Scenario summary: $(Join-Path $RunRoot 'scenario-summary.json')"
    Write-Host "Invocation log: $(Join-Path $RunRoot 'invocation.txt')"
    Write-Host "Simulator stdout: $(Join-Path $RunRoot 'simulator.stdout.log')"
    Write-Host "Simulator stderr: $(Join-Path $RunRoot 'simulator.stderr.log')"
    Write-Host "Artifact tree: $(Join-Path $RunRoot 'artifact-tree.txt')"

    if ($DryRun) {
        Write-Host "Plan-only mode completed without simulator checkout validation or simulator launch."
    } elseif (-not $Execute) {
        Write-Host "Evidence-only mode will validate the simulator checkout shape and preserve the compose invocation plan without launching Docker."
    }
}

function Write-ArtifactTree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunRoot
    )

    $entries = Get-ChildItem -LiteralPath $RunRoot -Force -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            $_.FullName.Substring($RunRoot.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        }

    Write-Utf8File -Path (Join-Path $RunRoot "artifact-tree.txt") -Content (($entries -join [Environment]::NewLine) + [Environment]::NewLine)
}

function Copy-SimulatorLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SimulatorRoot,

        [Parameter(Mandatory = $true)]
        [string]$RunRoot
    )

    $sourceLogsRoot = Join-Path $SimulatorRoot "logs"
    if (-not (Test-Path -LiteralPath $sourceLogsRoot -PathType Container)) {
        return
    }

    $destinationLogsRoot = Join-Path $RunRoot "simulator-logs"
    if (Test-Path -LiteralPath $destinationLogsRoot) {
        Remove-Item -LiteralPath $destinationLogsRoot -Recurse -Force
    }

    Copy-DirectoryTreeWithExcludes `
        -SourceRoot $sourceLogsRoot `
        -DestinationRoot $destinationLogsRoot `
        -ExcludedDirectoryNames @()
}

function Resolve-DockerExecutable {
    $docker = Get-Command "docker" -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
        return $null
    }

    return $docker.Source
}

function Copy-DirectoryTreeWithExcludes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,

        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [string[]]$ExcludedDirectoryNames
    )

    $sourceDirectory = [System.IO.DirectoryInfo]::new($SourceRoot)
    if (-not $sourceDirectory.Exists) {
        throw "Source directory '$SourceRoot' does not exist."
    }

    $sourceFullName = $sourceDirectory.FullName.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)

    $excludedDirectories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ExcludedDirectoryNames) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            [void]$excludedDirectories.Add($name)
        }
    }

    $directories = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $directories.Push($sourceDirectory)

    while ($directories.Count -gt 0) {
        $currentDirectory = $directories.Pop()
        $relativePath = ''
        if ($currentDirectory.FullName.Length -gt $sourceFullName.Length) {
            $relativePath = $currentDirectory.FullName.Substring($sourceFullName.Length).TrimStart(
                [System.IO.Path]::DirectorySeparatorChar,
                [System.IO.Path]::AltDirectorySeparatorChar)
        }

        $relativeSegments = $relativePath.Split(
            [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
            [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($relativeSegments | Where-Object { $excludedDirectories.Contains($_) }) {
            continue
        }

        $destinationDirectory = if ([string]::IsNullOrEmpty($relativePath)) {
            $DestinationRoot
        }
        else {
            Join-Path $DestinationRoot $relativePath
        }

        [System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null

        foreach ($childDirectory in $currentDirectory.GetDirectories()) {
            if ($excludedDirectories.Contains($childDirectory.Name)) {
                continue
            }

            $directories.Push($childDirectory)
        }

        foreach ($file in $currentDirectory.GetFiles()) {
            $destinationPath = Join-Path $destinationDirectory $file.Name
            $destinationParent = Split-Path -Parent $destinationPath
            if (-not [string]::IsNullOrEmpty($destinationParent)) {
                [System.IO.Directory]::CreateDirectory($destinationParent) | Out-Null
            }

            $file.CopyTo($destinationPath, $true) | Out-Null
        }
    }
}

function ConvertTo-ComposePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Resolve-FullPath -Path $Path).Replace('\', '/')
}

function New-TlsMaterial {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificateRoot
    )

    [System.IO.Directory]::CreateDirectory($CertificateRoot) | Out-Null

    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=server4",
            $key,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)

        $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $sanBuilder.AddDnsName("server")
        $sanBuilder.AddDnsName("server4")
        $sanBuilder.AddDnsName("server6")
        $sanBuilder.AddDnsName("server46")
        $request.CertificateExtensions.Add($sanBuilder.Build())

        $notBefore = [System.DateTimeOffset]::UtcNow.AddMinutes(-5)
        $notAfter = $notBefore.AddDays(10)
        $certificate = $request.CreateSelfSigned($notBefore, $notAfter)
        try {
            Write-Utf8File -Path (Join-Path $CertificateRoot "cert.pem") -Content $certificate.ExportCertificatePem()
            Write-Utf8File -Path (Join-Path $CertificateRoot "priv.key") -Content $key.ExportPkcs8PrivateKeyPem()
        }
        finally {
            $certificate.Dispose()
        }
    }
    finally {
        $key.Dispose()
    }
}

function New-IncursaEndpointStaging {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$RunRoot,

        [Parameter(Mandatory = $true)]
        [string]$RunId
    )

    $dockerfilePath = Join-Path $RepoRoot "src\Incursa.Quic.InteropHarness\Dockerfile"
    if (-not (Test-Path -LiteralPath $dockerfilePath -PathType Leaf)) {
        throw "Harness Dockerfile was not found: $dockerfilePath"
    }

    $stagingRoot = Join-Path $RunRoot "staged-endpoints"
    $contextRoot = Join-Path $stagingRoot "incursa-quic"
    $repoCopyRoot = Join-Path $contextRoot "quic-dotnet"
    $wwwRoot = Join-Path $RunRoot "www"
    $downloadsRoot = Join-Path $RunRoot "downloads"
    $certsRoot = Join-Path $RunRoot "certs"
    $composeOverridePath = Join-Path $RunRoot "incursa-endpoints.compose.yml"

    $stagingExcludes = @(
        '.git',
        '.artifacts',
        '.config',
        '.dotnet-home',
        '.workbench',
        'BenchmarkDotNet.Artifacts',
        'bdn',
        'StrykerOutput',
        'artifacts',
        'bin',
        'obj',
        '.vs',
        'TestResults',
        'node_modules'
    )

    Copy-DirectoryTreeWithExcludes `
        -SourceRoot $RepoRoot `
        -DestinationRoot $repoCopyRoot `
        -ExcludedDirectoryNames $stagingExcludes

    Copy-Item -LiteralPath $dockerfilePath -Destination (Join-Path $contextRoot "Dockerfile") -Force

    @"
**/.git
**/.artifacts
**/.config
**/.dotnet-home
**/.workbench
**/BenchmarkDotNet.Artifacts
**/bdn
**/bin
**/obj
**/artifacts
**/StrykerOutput
**/TestResults
**/.vs
**/.idea
**/*.user
**/*.suo
"@ | Set-Content -LiteralPath (Join-Path $contextRoot ".dockerignore")

    [System.IO.Directory]::CreateDirectory($wwwRoot) | Out-Null
    [System.IO.Directory]::CreateDirectory($downloadsRoot) | Out-Null
    Write-Utf8File -Path (Join-Path $wwwRoot "10000.txt") -Content (('incursa-quic-network-simulator-baseline' + [Environment]::NewLine) * 250)
    New-TlsMaterial -CertificateRoot $certsRoot

    $contextPath = ConvertTo-ComposePath -Path $contextRoot
    $certsPath = ConvertTo-ComposePath -Path $certsRoot
    $wwwPath = ConvertTo-ComposePath -Path $wwwRoot
    $downloadsPath = ConvertTo-ComposePath -Path $downloadsRoot
    $safeRunId = ($RunId -replace '[^A-Za-z0-9_.-]', '-').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($safeRunId)) {
        $safeRunId = "run"
    }

    Write-Utf8File -Path $composeOverridePath -Content @"
services:
  client:
    build:
      context: "$contextPath"
      dockerfile: "Dockerfile"
    image: "incursa-quic-network-simulator-client-$safeRunId"
    environment:
      - TESTCASE=transfer
      - REQUESTS=https://server4/10000.txt
      - QLOGDIR=/logs/qlog
    volumes:
      - "${certsPath}:/certs"
      - "${wwwPath}:/www"
      - "${downloadsPath}:/downloads"
  server:
    build:
      context: "$contextPath"
      dockerfile: "Dockerfile"
    image: "incursa-quic-network-simulator-server-$safeRunId"
    environment:
      - TESTCASE=transfer
      - REQUESTS=
      - QLOGDIR=/logs/qlog
    volumes:
      - "${certsPath}:/certs"
      - "${wwwPath}:/www"
"@

    return [ordered]@{
        client = "incursa-client"
        server = "incursa-server"
        context_root = $contextRoot
        repo_copy_root = $repoCopyRoot
        compose_override = $composeOverridePath
        www_root = $wwwRoot
        downloads_root = $downloadsRoot
        certs_root = $certsRoot
        request_uri = "https://server4/10000.txt"
    }
}

function Write-ScenarioEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunRoot,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioSummaryPath,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath,

        [Parameter(Mandatory = $true)]
        [object]$Summary,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Stdout,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Stderr
    )

    Write-Utf8File -Path $ScenarioSummaryPath -Content (ConvertTo-ScenarioJson -Scenario $Summary)
    Write-Utf8File -Path $StdoutPath -Content $Stdout
    Write-Utf8File -Path $StderrPath -Content $Stderr
    Write-ArtifactTree -RunRoot $RunRoot
}

$resolvedRepoRoot = Resolve-FullPath -Path $RepoRoot
if ([string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
    $ArtifactsRoot = Join-Path $resolvedRepoRoot "artifacts\network-simulator"
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssZ")
}

$resolvedArtifactsRoot = Resolve-FullPath -Path $ArtifactsRoot
$scenario = New-ScenarioDefinition -ScenarioId $ScenarioId -DropsToClient $DropsToClient -DropsToServer $DropsToServer
$runRoot = Join-Path (Join-Path $resolvedArtifactsRoot $scenario.scenario_id) $RunId
$resolvedSimulatorRoot = if ([string]::IsNullOrWhiteSpace($SimulatorRoot)) { "(not supplied)" } else { Resolve-FullPath -Path $SimulatorRoot }

Write-Plan `
    -Scenario $scenario `
    -RepoRoot $resolvedRepoRoot `
    -SimulatorRoot $resolvedSimulatorRoot `
    -ArtifactsRoot $resolvedArtifactsRoot `
    -RunRoot $runRoot `
    -Execute ([bool]$Execute) `
    -DryRun ([bool]$DryRun)

if ($DryRun) {
    exit 0
}

[System.IO.Directory]::CreateDirectory($runRoot) | Out-Null

$scenarioSummaryPath = Join-Path $runRoot "scenario-summary.json"
$invocationPath = Join-Path $runRoot "invocation.txt"
$stdoutPath = Join-Path $runRoot "simulator.stdout.log"
$stderrPath = Join-Path $runRoot "simulator.stderr.log"
$composeFile = Join-Path $resolvedSimulatorRoot "docker-compose.yml"
$composeOverridePathToUse = ""
$endpointStaging = $null

$summary = [ordered]@{
    scenario = $scenario
    repo_root = $resolvedRepoRoot
    simulator_root = $resolvedSimulatorRoot
    run_root = $runRoot
    execute_requested = [bool]$Execute
    client = $Client
    server = $Server
    client_params = $ClientParams
    server_params = $ServerParams
    status = "running"
    promotion_result = "not-promoted"
    started_utc = [DateTimeOffset]::UtcNow.ToString("O")
}

function Write-InvocationLog {
    $composeCommand = if ([string]::IsNullOrWhiteSpace($composeOverridePathToUse)) {
        "docker compose --file docker-compose.yml up --build --force-recreate --abort-on-container-exit"
    }
    else {
        "docker compose --file docker-compose.yml --file $composeOverridePathToUse up --build --force-recreate --abort-on-container-exit"
    }

    Write-Utf8File -Path $invocationPath -Content (@(
        "RepoRoot: $resolvedRepoRoot",
        "SimulatorRoot: $resolvedSimulatorRoot",
        "ScenarioId: $($scenario.scenario_id)",
        "ScenarioCommand: $($scenario.simulator_command)",
        "Execute: $([bool]$Execute)",
        "Client: $Client",
        "Server: $Server",
        "ClientParams: $ClientParams",
        "ServerParams: $ServerParams",
        "ComposeFile: $composeFile",
        "ComposeOverride: $composeOverridePathToUse",
        "ComposeCommand: $composeCommand",
        "SimulatorLogs: $(Join-Path $runRoot 'simulator-logs')",
        "ScenarioSummary: $scenarioSummaryPath",
        "SimulatorStdout: $stdoutPath",
        "SimulatorStderr: $stderrPath",
        "ArtifactTree: $(Join-Path $runRoot 'artifact-tree.txt')"
    ) -join [Environment]::NewLine)
}

Write-InvocationLog

function Complete-PreflightFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $summary.status = "preflight-failed"
    $summary.exit_code = 1
    $summary.finished_utc = [DateTimeOffset]::UtcNow.ToString("O")
    $summary.observed_result = $Message

    Write-ScenarioEvidence `
        -RunRoot $runRoot `
        -ScenarioSummaryPath $scenarioSummaryPath `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath `
        -Summary $summary `
        -Stdout "" `
        -Stderr ($Message + [Environment]::NewLine)

    throw $Message
}

if ([string]::IsNullOrWhiteSpace($SimulatorRoot)) {
    Complete-PreflightFailure -Message "-SimulatorRoot is required when not running with -DryRun."
}

if (-not (Test-Path -LiteralPath $resolvedSimulatorRoot -PathType Container)) {
    Complete-PreflightFailure -Message "Simulator root does not exist: $resolvedSimulatorRoot"
}

if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    Complete-PreflightFailure -Message "Simulator docker-compose file was not found: $composeFile"
}

if (-not $Execute) {
    $summary.status = "execution-not-requested"
    $summary.exit_code = 0
    $summary.finished_utc = [DateTimeOffset]::UtcNow.ToString("O")
    $summary.observed_result = "Scenario metadata and docker compose invocation plan were preserved. Simulator execution was not requested, so no requirement behavior is promoted."

    Write-ScenarioEvidence `
        -RunRoot $runRoot `
        -ScenarioSummaryPath $scenarioSummaryPath `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath `
        -Summary $summary `
        -Stdout "" `
        -Stderr ""

    exit 0
}

$usesManagedEndpointStaging = [string]::IsNullOrWhiteSpace($Client) -and [string]::IsNullOrWhiteSpace($Server)
if ($usesManagedEndpointStaging) {
    try {
        $endpointStaging = New-IncursaEndpointStaging -RepoRoot $resolvedRepoRoot -RunRoot $runRoot -RunId $RunId
        $Client = $endpointStaging.client
        $Server = $endpointStaging.server
        $composeOverridePathToUse = $endpointStaging.compose_override
        $summary.client = $Client
        $summary.server = $Server
        $summary.endpoint_staging = $endpointStaging
        Write-InvocationLog
    }
    catch {
        Complete-PreflightFailure -Message "Managed Incursa endpoint staging failed: $($_.Exception.Message)"
    }
}
elseif ([string]::IsNullOrWhiteSpace($Client)) {
    Complete-PreflightFailure -Message "-Client is required when -Execute is supplied without managed endpoint staging."
}

if ([string]::IsNullOrWhiteSpace($Server)) {
    Complete-PreflightFailure -Message "-Server is required when -Execute is supplied without managed endpoint staging."
}

$clientRoot = Join-Path $resolvedSimulatorRoot $Client
$serverRoot = Join-Path $resolvedSimulatorRoot $Server

if (-not $usesManagedEndpointStaging -and -not (Test-Path -LiteralPath $clientRoot -PathType Container)) {
    Complete-PreflightFailure -Message "Client endpoint directory was not found: $clientRoot"
}

if (-not $usesManagedEndpointStaging -and -not (Test-Path -LiteralPath $serverRoot -PathType Container)) {
    Complete-PreflightFailure -Message "Server endpoint directory was not found: $serverRoot"
}

$docker = Resolve-DockerExecutable
if ([string]::IsNullOrWhiteSpace($docker)) {
    Complete-PreflightFailure -Message "docker is required to launch the upstream simulator docker-compose model."
}

$processStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
$processStartInfo.FileName = $docker
$processStartInfo.WorkingDirectory = $resolvedSimulatorRoot
$processStartInfo.UseShellExecute = $false
$processStartInfo.RedirectStandardOutput = $true
$processStartInfo.RedirectStandardError = $true
$processStartInfo.CreateNoWindow = $true
$processStartInfo.ArgumentList.Add("compose")
$processStartInfo.ArgumentList.Add("--file")
$processStartInfo.ArgumentList.Add("docker-compose.yml")
if (-not [string]::IsNullOrWhiteSpace($composeOverridePathToUse)) {
    $processStartInfo.ArgumentList.Add("--file")
    $processStartInfo.ArgumentList.Add($composeOverridePathToUse)
}
$processStartInfo.ArgumentList.Add("up")
$processStartInfo.ArgumentList.Add("--build")
$processStartInfo.ArgumentList.Add("--force-recreate")
$processStartInfo.ArgumentList.Add("--abort-on-container-exit")
$processStartInfo.Environment["CLIENT"] = $Client
$processStartInfo.Environment["SERVER"] = $Server
$processStartInfo.Environment["CLIENT_PARAMS"] = $ClientParams
$processStartInfo.Environment["SERVER_PARAMS"] = $ServerParams
$processStartInfo.Environment["SCENARIO"] = $scenario.simulator_command

$process = [System.Diagnostics.Process]::Start($processStartInfo)
if ($null -eq $process) {
    Complete-PreflightFailure -Message "Unable to start the simulator docker compose process."
}

$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()

$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()

$summary.status = if ($process.ExitCode -eq 0) { "evidence-preserved" } else { "simulator-failed" }
$summary.exit_code = $process.ExitCode
$summary.finished_utc = [DateTimeOffset]::UtcNow.ToString("O")
$summary.observed_result = if ($process.ExitCode -eq 0) {
    "Docker compose exited successfully and minimum helper evidence was preserved. Requirement promotion still requires linked runtime evidence for the expected observable behavior."
} else {
    "Docker compose failed; preserved stdout, stderr, invocation metadata, and scenario summary for triage."
}

Write-ScenarioEvidence `
    -RunRoot $runRoot `
    -ScenarioSummaryPath $scenarioSummaryPath `
    -StdoutPath $stdoutPath `
    -StderrPath $stderrPath `
    -Summary $summary `
    -Stdout $stdout `
    -Stderr $stderr

try {
    Copy-SimulatorLogs -SimulatorRoot $resolvedSimulatorRoot -RunRoot $runRoot
}
catch {
    Write-Warning "Unable to preserve simulator logs: $($_.Exception.Message)"
}

Write-ArtifactTree -RunRoot $runRoot

exit $process.ExitCode
