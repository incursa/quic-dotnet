[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",

    [string] $OutputRoot = ".artifacts\protocol-lab\readiness",

    [string] $RunId = "protocol-lab-readiness-$((Get-Date -AsUTC).ToString('yyyyMMddTHHmmssZ'))",

    [string] $Http3RunnerArtifactRoot,

    [switch] $SkipPackageBuild,

    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-RepoRoot {
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    if (-not (Test-Path -LiteralPath (Join-Path $candidate "Incursa.Quic.slnx"))) {
        throw "Could not locate quic-dotnet repository root from '$PSScriptRoot'."
    }

    return $candidate
}

function Format-CommandLine {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $escaped = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argument
        }
    }

    "$FileName $($escaped -join ' ')"
}

function Invoke-PackageBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [Parameter(Mandatory = $true)]
        [string] $ProtocolLabRoot,

        [Parameter(Mandatory = $true)]
        [string] $PackageTarget,

        [Parameter(Mandatory = $true)]
        [string] $PackageVersion,

        [Parameter(Mandatory = $true)]
        [bool] $IsDryRun
    )

    $scriptPath = Join-Path $RepoRoot "eng\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1"
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $scriptPath,
        "-PackageTarget",
        $PackageTarget,
        "-ProtocolLabRoot",
        $ProtocolLabRoot,
        "-PackageVersion",
        $PackageVersion,
        "-Force"
    )

    $command = Format-CommandLine -FileName "pwsh" -Arguments $arguments
    if ($IsDryRun) {
        return [ordered]@{
            packageTarget = $PackageTarget
            packageVersion = $PackageVersion
            command = $command
            skipped = $true
            skipReason = "DryRun"
        }
    }

    Push-Location $RepoRoot
    try {
        $packageJson = & pwsh @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Package build failed for $PackageTarget with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    $packageResult = $packageJson | ConvertFrom-Json
    return [ordered]@{
        packageTarget = $PackageTarget
        packageId = [string]$packageResult.packageId
        packageVersion = [string]$packageResult.packageVersion
        path = [string]$packageResult.path
        sha256 = [string]$packageResult.sha256
        command = $command
        skipped = $false
    }
}

function Get-PackageBuildCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [Parameter(Mandatory = $true)]
        [string] $ProtocolLabRoot,

        [Parameter(Mandatory = $true)]
        [string] $PackageTarget,

        [Parameter(Mandatory = $true)]
        [string] $PackageVersion
    )

    $scriptPath = Join-Path $RepoRoot "eng\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1"
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $scriptPath,
        "-PackageTarget",
        $PackageTarget,
        "-ProtocolLabRoot",
        $ProtocolLabRoot,
        "-PackageVersion",
        $PackageVersion,
        "-Force"
    )

    return Format-CommandLine -FileName "pwsh" -Arguments $arguments
}

function Find-LatestHttp3RunnerArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepoRoot
    )

    $defaultRoot = Join-Path $RepoRoot ".artifacts\interop-runner\http3-local-live-current"
    if (-not (Test-Path -LiteralPath $defaultRoot -PathType Container)) {
        return $null
    }

    return Get-ChildItem -LiteralPath $defaultRoot -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "runner-report.json") } |
        Sort-Object Name -Descending |
        Select-Object -First 1
}

function Read-Http3RunnerEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ArtifactRoot
    )

    $reportPath = Join-Path $ArtifactRoot "runner-report.json"
    if (-not (Test-Path -LiteralPath $reportPath)) {
        return [ordered]@{
            artifactRoot = $ArtifactRoot
            present = $false
            blocker = "runner-report.json was not found"
        }
    }

    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $reportHash = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $results = @($report.results | ForEach-Object { @($_) } | ForEach-Object { $_ })
    $http3Result = $results |
        Where-Object { [string]$_.name -eq "http3" -or [string]$_.abbr -eq "3" } |
        Select-Object -First 1

    return [ordered]@{
        artifactRoot = [System.IO.Path]::GetFullPath($ArtifactRoot)
        present = $true
        reportPath = [System.IO.Path]::GetFullPath($reportPath)
        reportSha256 = $reportHash
        result = if ($null -eq $http3Result) { "unknown" } else { [string]$http3Result.result }
        startTime = [double]$report.start_time
        endTime = [double]$report.end_time
        servers = @($report.servers)
        clients = @($report.clients)
    }
}

function Add-Line {
    param(
        [System.Collections.Generic.List[string]] $Lines,

        [AllowEmptyString()]
        [string] $Line
    )

    $Lines.Add($Line) | Out-Null
}

$repoRoot = Get-RepoRoot
$resolvedOutputRoot = Resolve-FullPath -Path $OutputRoot -BasePath $repoRoot
$runRoot = Join-Path $resolvedOutputRoot $RunId
$resolvedProtocolLabRoot = Resolve-FullPath -Path $ProtocolLabRoot -BasePath $repoRoot
$protocolLabBenchmarkScript = Join-Path $resolvedProtocolLabRoot "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"

if (-not (Test-Path -LiteralPath $resolvedProtocolLabRoot -PathType Container)) {
    throw "ProtocolLab root was not found: $resolvedProtocolLabRoot"
}

New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

$gitCommit = (& git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitCommit)) {
    $gitCommit = "unknown"
}
else {
    $gitCommit = $gitCommit.Trim()
}

$gitStatus = @(& git -C $repoRoot status --porcelain 2>$null)
$gitState = if ($LASTEXITCODE -ne 0) {
    "unknown"
}
elseif ($gitStatus.Count -eq 0) {
    "clean"
}
else {
    "dirty"
}

$http3PackageVersion = "$RunId-http3"
$rawQuicPackageVersion = "$RunId-raw-quic"
$packageEvidence = @()
if ($SkipPackageBuild) {
    $packageEvidence += [ordered]@{
        packageTarget = "Http3"
        packageVersion = $http3PackageVersion
        command = Get-PackageBuildCommand -RepoRoot $repoRoot -ProtocolLabRoot $resolvedProtocolLabRoot -PackageTarget "Http3" -PackageVersion $http3PackageVersion
        skipped = $true
        skipReason = "SkipPackageBuild"
    }
    $packageEvidence += [ordered]@{
        packageTarget = "RawQuic"
        packageVersion = $rawQuicPackageVersion
        command = Get-PackageBuildCommand -RepoRoot $repoRoot -ProtocolLabRoot $resolvedProtocolLabRoot -PackageTarget "RawQuic" -PackageVersion $rawQuicPackageVersion
        skipped = $true
        skipReason = "SkipPackageBuild"
    }
}
else {
    $packageEvidence += Invoke-PackageBuild -RepoRoot $repoRoot -ProtocolLabRoot $resolvedProtocolLabRoot -PackageTarget "Http3" -PackageVersion $http3PackageVersion -IsDryRun:$DryRun
    $packageEvidence += Invoke-PackageBuild -RepoRoot $repoRoot -ProtocolLabRoot $resolvedProtocolLabRoot -PackageTarget "RawQuic" -PackageVersion $rawQuicPackageVersion -IsDryRun:$DryRun
}

if ([string]::IsNullOrWhiteSpace($Http3RunnerArtifactRoot)) {
    $latestRunnerArtifact = Find-LatestHttp3RunnerArtifact -RepoRoot $repoRoot
    $Http3RunnerArtifactRoot = if ($null -eq $latestRunnerArtifact) { "" } else { $latestRunnerArtifact.FullName }
}

$http3RunnerEvidence = if ([string]::IsNullOrWhiteSpace($Http3RunnerArtifactRoot)) {
    [ordered]@{
        present = $false
        blocker = "No HTTP/3 local runner artifact was found under .artifacts/interop-runner/http3-local-live-current."
    }
}
else {
    Read-Http3RunnerEvidence -ArtifactRoot (Resolve-FullPath -Path $Http3RunnerArtifactRoot -BasePath $repoRoot)
}

$performanceCommands = @(
    [ordered]@{
        name = "Raw QUIC multiplex smoke"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 -Lane Smoke -Surface RawQuicMultiplex"
        mode = "local-source-reference"
        publishable = $false
    },
    [ordered]@{
        name = "Raw QUIC duplex smoke"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 -Lane Smoke -Surface RawQuicDuplex"
        mode = "local-source-reference"
        publishable = $false
    },
    [ordered]@{
        name = "Raw QUIC multiplex confidence"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 -Lane Confidence -Surface RawQuicMultiplex"
        mode = "local-source-reference"
        publishable = $false
    },
    [ordered]@{
        name = "Package-backed HTTP/3 rack lab smoke"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\eng\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1 -ProtocolLabRoot $resolvedProtocolLabRoot -ControllerUri http://10.10.99.176:5088 -PackageTarget Http3 -SuiteId h3-local-v1 -ScenarioId http3.payload.bytes.64kb -Protocol h3 -LoadProfileId smoke"
        mode = "package-backed-controller"
        publishable = $false
    },
    [ordered]@{
        name = "Package-backed raw QUIC rack lab smoke"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\eng\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1 -ProtocolLabRoot $resolvedProtocolLabRoot -ControllerUri http://10.10.99.176:5088 -PackageTarget RawQuic -SuiteId quic-transport-v1-comparison -ScenarioId quic.transport.multiplex.100x64kb,quic.transport.duplex-streams -Protocol quic -LoadProfileId smoke"
        mode = "package-backed-controller"
        publishable = $false
    }
)

$protocolLabPrerequisites = [ordered]@{
    root = $resolvedProtocolLabRoot
    benchmarkSetScript = [ordered]@{
        path = $protocolLabBenchmarkScript
        present = Test-Path -LiteralPath $protocolLabBenchmarkScript -PathType Leaf
        requiredFor = "source-reference ProtocolLab performance lane"
    }
}

$externalBlockers = @(
    [ordered]@{
        area = "live DNSSEC chain validation"
        requiredCondition = "real validating resolver, configured trust anchor or platform trust policy, and live signed DNS data"
    },
    [ordered]@{
        area = "DNS provider publication"
        requiredCondition = "provider credentials, authoritative zone ownership, DNSSEC key access, and signing policy"
    },
    [ordered]@{
        area = "IKEv2/IPsec session integration"
        requiredCondition = "real IKEv2 stack, IPsec session authority, and credential policy"
    },
    [ordered]@{
        area = "host resolver application"
        requiredCondition = "OS resolver APIs, administrative privileges, rollback policy, and operator approval for mutation"
    },
    [ordered]@{
        area = "DHCP and Router Advertisement emission"
        requiredCondition = "privileged DHCP/RA/ND infrastructure, live network segment, and rollback/maintenance window decision"
    },
    [ordered]@{
        area = "live encrypted DNS establishment"
        requiredCondition = "reachable DoT/DoQ/DoH endpoints, certificate policy, TLS policy, QUIC policy, and failure-handling decision"
    }
)

$manifest = [ordered]@{
    schemaVersion = "quic-dotnet-protocol-lab-readiness-v1"
    runId = $RunId
    createdUtc = (Get-Date -AsUTC).ToString("o")
    repoRoot = $repoRoot
    protocolLabRoot = $resolvedProtocolLabRoot
    git = [ordered]@{
        commit = $gitCommit
        state = $gitState
        statusPorcelain = @($gitStatus)
    }
    packageEvidence = @($packageEvidence)
    http3RunnerEvidence = $http3RunnerEvidence
    protocolLabPrerequisites = $protocolLabPrerequisites
    performanceCommands = $performanceCommands
    localMode = [ordered]@{
        description = "Local source-reference and smoke lanes are developer/regression evidence only."
        proofCommands = @(
            "dotnet build Incursa.Quic.slnx -c Release",
            "dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --filter FullyQualifiedName~ProtocolLabPackageTemplateTests",
            "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-SpecTraceJson.ps1 -Profiles core",
            "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\spec-trace\Generate-QuicRequirementCoverageTriage.ps1"
        )
    }
    liveMode = [ordered]@{
        description = "Live integration runs require the listed external credentials, authorities, endpoints, privileges, or operator decisions."
        externalBlockers = $externalBlockers
    }
}

$manifestPath = Join-Path $runRoot "readiness-manifest.json"
$summaryPath = Join-Path $runRoot "README.md"
$manifest | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$summary = New-Object System.Collections.Generic.List[string]
Add-Line $summary "# QUIC.NET ProtocolLab Readiness Evidence"
Add-Line $summary ""
Add-Line $summary "- Run ID: ``$RunId``"
Add-Line $summary "- Created UTC: ``$($manifest.createdUtc)``"
Add-Line $summary "- Git commit: ``$gitCommit``"
Add-Line $summary "- Git state: ``$gitState``"
Add-Line $summary "- Manifest: ``$manifestPath``"
Add-Line $summary ""
Add-Line $summary "## Package Evidence"
Add-Line $summary ""
foreach ($package in $packageEvidence) {
    if ($package.skipped) {
        Add-Line $summary "- ``$($package.packageTarget)``: skipped (``$($package.skipReason)``), planned version ``$($package.packageVersion)``."
        if ($package.command) {
            Add-Line $summary "  - Command: ``$($package.command)``"
        }
        continue
    }

    Add-Line $summary "- ``$($package.packageId)`` version ``$($package.packageVersion)``"
    Add-Line $summary "  - Path: ``$($package.path)``"
    Add-Line $summary "  - SHA-256: ``$($package.sha256)``"
    Add-Line $summary "  - Command: ``$($package.command)``"
}

Add-Line $summary ""
Add-Line $summary "## HTTP/3 Runner Evidence"
Add-Line $summary ""
if ($http3RunnerEvidence.present) {
    Add-Line $summary "- Artifact root: ``$($http3RunnerEvidence.artifactRoot)``"
    Add-Line $summary "- Report: ``$($http3RunnerEvidence.reportPath)``"
    Add-Line $summary "- Report SHA-256: ``$($http3RunnerEvidence.reportSha256)``"
    Add-Line $summary "- Result: ``$($http3RunnerEvidence.result)``"
    Add-Line $summary "- Servers: ``$(@($http3RunnerEvidence.servers) -join ', ')``"
    Add-Line $summary "- Clients: ``$(@($http3RunnerEvidence.clients) -join ', ')``"
}
else {
    Add-Line $summary "- Blocked: $($http3RunnerEvidence.blocker)"
}

Add-Line $summary ""
Add-Line $summary "## Performance And Controller Commands"
Add-Line $summary ""
Add-Line $summary "- ProtocolLab benchmark set script: ``$($protocolLabPrerequisites.benchmarkSetScript.path)``"
Add-Line $summary "- ProtocolLab benchmark set script present: ``$($protocolLabPrerequisites.benchmarkSetScript.present)``"
Add-Line $summary ""
foreach ($command in $performanceCommands) {
    Add-Line $summary "- $($command.name): ``$($command.command)``"
    Add-Line $summary "  - Mode: ``$($command.mode)``"
    Add-Line $summary "  - Publishable: ``$($command.publishable)``"
}

Add-Line $summary ""
Add-Line $summary "## External Integration Blockers"
Add-Line $summary ""
foreach ($blocker in $externalBlockers) {
    Add-Line $summary "- $($blocker.area): $($blocker.requiredCondition)."
}

Add-Line $summary ""
Add-Line $summary "## Local/Live Separation"
Add-Line $summary ""
Add-Line $summary "- Local fake/planner/adapter seams can be validated with repo-local tests, SpecTrace validation, generated triage, BenchmarkDotNet smoke, package smoke, and source-reference ProtocolLab loops."
Add-Line $summary "- Live provider/platform execution must not be reported as complete until the matching credential, host, endpoint, privilege, network infrastructure, or operator decision is present and recorded."

Set-Content -LiteralPath $summaryPath -Value $summary -Encoding utf8

[ordered]@{
    runRoot = $runRoot
    manifestPath = $manifestPath
    summaryPath = $summaryPath
    packageEvidence = @($packageEvidence)
    http3RunnerEvidence = $http3RunnerEvidence
} | ConvertTo-Json -Depth 32
