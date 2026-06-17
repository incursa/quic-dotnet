[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",

    [string] $ProtocolLabExecutionRoot,

    [string] $OutputRoot = ".artifacts\protocol-lab\readiness",

    [string] $RunId = "protocol-lab-readiness-$((Get-Date -AsUTC).ToString('yyyyMMddTHHmmssZ'))",

    [string] $Http3RunnerArtifactRoot,

    [string[]] $ProtocolLabRunRoot = @(),

    [int] $MinimumPublishableRepetitions = 3,

    [double] $LocalMaxRelativeRange = 0.25,

    [double] $PublishableMaxRelativeRange = 0.05,

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

function Resolve-ProtocolLabExecutionRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ContractRoot,

        [string] $RequestedExecutionRoot,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($RequestedExecutionRoot)) {
        $candidates.Add((Resolve-FullPath -Path $RequestedExecutionRoot -BasePath $BasePath)) | Out-Null
    }

    $environmentRoot = [Environment]::GetEnvironmentVariable("PROTOCOL_LAB_EXECUTION_ROOT")
    if (-not [string]::IsNullOrWhiteSpace($environmentRoot)) {
        $candidates.Add((Resolve-FullPath -Path $environmentRoot -BasePath $BasePath)) | Out-Null
    }

    $candidates.Add($ContractRoot) | Out-Null
    $candidates.Add((Join-Path (Split-Path -Parent $ContractRoot) "protocol-lab-internal")) | Out-Null

    $checked = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $resolvedCandidate = [System.IO.Path]::GetFullPath($candidate)
        if ($checked.Contains($resolvedCandidate)) {
            continue
        }

        $checked.Add($resolvedCandidate) | Out-Null
        $benchmarkScript = Join-Path $resolvedCandidate "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"
        $solutionPath = Join-Path $resolvedCandidate "Incursa.ProtocolLab.sln"
        if ((Test-Path -LiteralPath $benchmarkScript -PathType Leaf) -and
            (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
            return $resolvedCandidate
        }
    }

    return $null
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

function Get-ObjectValue {
    param(
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    if ($null -eq $property.Value) {
        return $Default
    }

    return $property.Value
}

function Invoke-OptionalCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [string[]] $Arguments = @(),

        [string] $WorkingDirectory
    )

    try {
        if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            $output = & $FileName @Arguments 2>$null
        }
        else {
            $output = & $FileName @Arguments 2>$null
        }

        if ($LASTEXITCODE -ne 0) {
            return $null
        }

        return (@($output) -join "`n").Trim()
    }
    catch {
        return $null
    }
}

function Get-RepositoryIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [ordered]@{
            name = $Name
            path = $Path
            present = $false
        }
    }

    $commit = (& git -C $Path rev-parse HEAD 2>$null)
    $status = @(& git -C $Path status --porcelain 2>$null)
    return [ordered]@{
        name = $Name
        path = [System.IO.Path]::GetFullPath($Path)
        present = $true
        commit = if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($commit)) { $commit.Trim() } else { "unknown" }
        state = if ($status.Count -eq 0) { "clean" } else { "dirty" }
        statusPorcelain = @($status)
    }
}

function Get-HostEnvironmentSnapshot {
    $dotnetVersion = Invoke-OptionalCommand -FileName "dotnet" -Arguments @("--version")
    $dockerVersion = Invoke-OptionalCommand -FileName "docker" -Arguments @("--version")

    return [ordered]@{
        hostName = [Environment]::MachineName
        operatingSystem = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        frameworkDescription = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
        processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        operatingSystemArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        processorCount = [Environment]::ProcessorCount
        is64BitProcess = [Environment]::Is64BitProcess
        dotnetVersion = $dotnetVersion
        dockerVersion = $dockerVersion
        captureUtc = (Get-Date -AsUTC).ToString("o")
    }
}

function Get-ChecksumInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RootPath
    )

    if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        return @()
    }

    $resolvedRoot = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $prefixLength = $resolvedRoot.Length + 1
    $files = Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse |
        Sort-Object FullName

    return @($files | ForEach-Object {
            $relativePath = if ($_.FullName.Length -gt $prefixLength) { $_.FullName.Substring($prefixLength) } else { $_.Name }
            [ordered]@{
                relativePath = $relativePath.Replace("\", "/")
                path = $_.FullName
                length = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        })
}

function Get-ReadinessEvidenceClass {
    param($Aggregate)

    $loadToolCategory = [string](Get-ObjectValue -InputObject $Aggregate -Name "loadToolCategory" -Default "")
    $targetExecutionMode = [string](Get-ObjectValue -InputObject $Aggregate -Name "targetExecutionMode" -Default "")
    $executionProfile = [string](Get-ObjectValue -InputObject $Aggregate -Name "executionProfile" -Default "")
    $evidence = Get-ObjectValue -InputObject $Aggregate -Name "evidence"
    $reportedClass = [string](Get-ObjectValue -InputObject $evidence -Name "evidenceClass" -Default "")
    $warnings = @(
        @(Get-ObjectValue -InputObject $Aggregate -Name "warnings" -Default @())
        @(Get-ObjectValue -InputObject $evidence -Name "comparabilityWarnings" -Default @())
        @(Get-ObjectValue -InputObject $evidence -Name "evidenceReasons" -Default @())
    ) | ForEach-Object { [string]$_ }

    $hasLocalWarning = $warnings |
        Where-Object {
            $_ -match "localhost|shared-host|single-machine|managed-lab|local-dev|load-tool-not-docker|no-cpu-isolation|no-network-isolation"
        } |
        Select-Object -First 1

    if ($reportedClass -eq "publishable") {
        return "publishable"
    }

    if (-not [string]::IsNullOrWhiteSpace($hasLocalWarning) -or
        $reportedClass -eq "local-lab" -or
        $loadToolCategory -eq "managed-lab" -or
        $executionProfile -match "local") {
        return "local-lab"
    }

    if ($loadToolCategory -eq "external-reference" -and $targetExecutionMode -eq "external") {
        return "external-reference"
    }

    return "isolated-local"
}

function Get-MetricGate {
    param(
        $Aggregate,

        [Parameter(Mandatory = $true)]
        [string] $MetricName
    )

    $metric = Get-ObjectValue -InputObject $Aggregate -Name $MetricName
    if ($null -eq $metric) {
        return [ordered]@{
            metric = $MetricName
            present = $false
        }
    }

    $median = [double](Get-ObjectValue -InputObject $metric -Name "median" -Default 0)
    $best = [double](Get-ObjectValue -InputObject $metric -Name "best" -Default $median)
    $worst = [double](Get-ObjectValue -InputObject $metric -Name "worst" -Default $median)
    $relativeRange = if ($median -gt 0) { [Math]::Abs($best - $worst) / $median } else { $null }

    return [ordered]@{
        metric = $MetricName
        present = $true
        median = $median
        best = $best
        worst = $worst
        relativeRange = $relativeRange
    }
}

function Get-QualityGate {
    param(
        $Aggregate,

        [Parameter(Mandatory = $true)]
        [int] $MinimumPublishableRepetitions,

        [Parameter(Mandatory = $true)]
        [double] $LocalMaxRelativeRange,

        [Parameter(Mandatory = $true)]
        [double] $PublishableMaxRelativeRange
    )

    $validation = Get-ObjectValue -InputObject $Aggregate -Name "validation"
    $failedValidation = [int](Get-ObjectValue -InputObject $validation -Name "failed" -Default 0)
    $infraFailures = [int](Get-ObjectValue -InputObject $validation -Name "infrastructureFailure" -Default 0)
    $failedRequests = [int](Get-ObjectValue -InputObject $Aggregate -Name "failedRequests" -Default 0)
    $timeoutRequests = [int](Get-ObjectValue -InputObject $Aggregate -Name "timeoutRequests" -Default 0)
    $repetitions = [int](Get-ObjectValue -InputObject $Aggregate -Name "repetitions" -Default 0)
    $metricGates = @(
        Get-MetricGate -Aggregate $Aggregate -MetricName "requestsPerSecond"
        Get-MetricGate -Aggregate $Aggregate -MetricName "latencyMeanMs"
        Get-MetricGate -Aggregate $Aggregate -MetricName "throughputBytesPerSecond"
    )
    $presentMetricGates = @($metricGates | Where-Object { $_.present -and $null -ne $_.relativeRange })
    $maxRelativeRange = if ($presentMetricGates.Count -eq 0) {
        $null
    }
    else {
        (@($presentMetricGates | ForEach-Object { [double]$_.relativeRange }) | Measure-Object -Maximum).Maximum
    }

    $localStatus = "passed"
    $failureClass = "none"
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($failedValidation -gt 0 -or $infraFailures -gt 0) {
        $localStatus = "failed"
        $failureClass = "validation-or-infrastructure-failure"
        $reasons.Add("validation-or-infrastructure-failure") | Out-Null
    }
    if ($failedRequests -gt 0 -or $timeoutRequests -gt 0) {
        $localStatus = "failed"
        $failureClass = "request-failures-or-timeouts"
        $reasons.Add("request-failures-or-timeouts") | Out-Null
    }
    if ($repetitions -lt 2) {
        $localStatus = "warning"
        if ($failureClass -eq "none") {
            $failureClass = "insufficient-local-repetitions"
        }
        $reasons.Add("insufficient-local-repetitions") | Out-Null
    }
    elseif ($null -ne $maxRelativeRange -and $maxRelativeRange -gt $LocalMaxRelativeRange) {
        $localStatus = "failed"
        $failureClass = "local-variance-threshold-exceeded"
        $reasons.Add("local-variance-threshold-exceeded") | Out-Null
    }

    $publishableStatus = "blocked"
    $publishableBlockers = New-Object System.Collections.Generic.List[string]
    if ($repetitions -lt $MinimumPublishableRepetitions) {
        $publishableBlockers.Add("repeat-count-below-publishable-minimum") | Out-Null
    }
    if ($failedValidation -gt 0 -or $infraFailures -gt 0 -or $failedRequests -gt 0 -or $timeoutRequests -gt 0) {
        $publishableBlockers.Add("accepted-benchmark-failures-present") | Out-Null
    }
    if ($null -eq $maxRelativeRange -or $maxRelativeRange -gt $PublishableMaxRelativeRange) {
        $publishableBlockers.Add("publishable-variance-threshold-not-met") | Out-Null
    }

    return [ordered]@{
        localStatus = $localStatus
        failureClass = $failureClass
        reasons = @($reasons)
        repetitions = $repetitions
        minimumPublishableRepetitions = $MinimumPublishableRepetitions
        maxRelativeRange = $maxRelativeRange
        localMaxRelativeRange = $LocalMaxRelativeRange
        publishableMaxRelativeRange = $PublishableMaxRelativeRange
        metricGates = @($metricGates)
        publishableStatus = $publishableStatus
        publishableBlockers = @($publishableBlockers)
    }
}

function Test-AnyTextMatch {
    param(
        [AllowNull()]
        $Values,

        [Parameter(Mandatory = $true)]
        [string] $Pattern
    )

    foreach ($value in @($Values)) {
        if ([string]$value -match $Pattern) {
            return $true
        }
    }

    return $false
}

function New-BlockerDetail {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Code,

        [Parameter(Mandatory = $true)]
        [string] $Reason,

        [Parameter(Mandatory = $true)]
        [string] $LocalActionability
    )

    return [ordered]@{
        code = $Code
        reason = $Reason
        localActionability = $LocalActionability
    }
}

function Get-EnvironmentGateAssessment {
    param($Cell)

    $evidence = Get-ObjectValue -InputObject $Cell -Name "evidence"
    $warnings = @(
        @(Get-ObjectValue -InputObject $Cell -Name "warnings" -Default @())
        @(Get-ObjectValue -InputObject $evidence -Name "comparabilityWarnings" -Default @())
        @(Get-ObjectValue -InputObject $evidence -Name "evidenceReasons" -Default @())
    ) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $executionProfile = [string](Get-ObjectValue -InputObject $Cell -Name "executionProfile" -Default "")
    $targetExecutionMode = [string](Get-ObjectValue -InputObject $Cell -Name "targetExecutionMode" -Default "")
    $loadToolMode = [string](Get-ObjectValue -InputObject $Cell -Name "loadToolMode" -Default "")
    $loadToolCategory = [string](Get-ObjectValue -InputObject $Cell -Name "loadToolCategory" -Default "")
    $targetMetricsCaptured = [int](Get-ObjectValue -InputObject $Cell -Name "targetProcessMetricsCapturedCount" -Default 0) +
        [int](Get-ObjectValue -InputObject $Cell -Name "targetDockerMetricsCapturedCount" -Default 0)
    $targetMetricsMissing = [int](Get-ObjectValue -InputObject $Cell -Name "targetProcessMetricsMissingCount" -Default 0) +
        [int](Get-ObjectValue -InputObject $Cell -Name "targetDockerMetricsMissingCount" -Default 0)
    $loadToolMetricsCaptured = [int](Get-ObjectValue -InputObject $Cell -Name "loadToolDockerMetricsCapturedCount" -Default 0)
    $loadToolMetricsMissing = [int](Get-ObjectValue -InputObject $Cell -Name "loadToolDockerMetricsMissingCount" -Default 0)
    $targetMetricWarnings = @($warnings | Where-Object { $_ -match "target-process|target-resource|Target process metrics|adapter-derived" })
    $loadSaturationWarnings = @(
        @(Get-ObjectValue -InputObject $Cell -Name "saturationWarnings" -Default @())
        @($warnings | Where-Object { $_ -match "load-generator|saturation|overload|connection-pressure" })
    ) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

    $isLoopbackOrSameHost = Test-AnyTextMatch -Values $warnings -Pattern "localhost|127\.0\.0\.1|single-machine|shared-host|same local environment"
    $hostClassification = if ($isLoopbackOrSameHost) {
        "same-host-loopback"
    }
    elseif ($executionProfile -match "local" -or $targetExecutionMode -eq "process") {
        "local-process"
    }
    else {
        "unknown-or-separated"
    }

    $blockerDetails = New-Object System.Collections.ArrayList
    if ($isLoopbackOrSameHost) {
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "same-host-loopback-target-and-load-generator" `
                    -Reason "The target URL/control plane uses localhost or the aggregate reports a single-machine/shared-host run." `
                    -LocalActionability "Needs separate SUT/load-generator resources or an equivalent isolated lab topology.")) | Out-Null
    }

    $cpuIsolationStatus = "unknown"
    $cpuIsolationReasons = New-Object System.Collections.Generic.List[string]
    if (Test-AnyTextMatch -Values $warnings -Pattern "no-cpu-isolation") {
        $cpuIsolationStatus = "not-proven"
        $cpuIsolationReasons.Add("Aggregate reports no-cpu-isolation.") | Out-Null
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "cpu-isolation-unattested-local-process" `
                    -Reason "The run did not record cpuset/container CPU limits, bare-metal reservation policy, or equivalent CPU isolation attestation." `
                    -LocalActionability "Needs privileged host/container configuration or an operator attestation captured with the run.")) | Out-Null
    }

    $networkIsolationStatus = "unknown"
    $networkIsolationReasons = New-Object System.Collections.Generic.List[string]
    if (Test-AnyTextMatch -Values $warnings -Pattern "no-network-isolation|localhost|127\.0\.0\.1|single-machine|shared-host|same local environment") {
        $networkIsolationStatus = "not-proven"
        $networkIsolationReasons.Add("Aggregate reports localhost/shared-host execution or no-network-isolation.") | Out-Null
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "network-isolation-unattested-loopback" `
                    -Reason "The run did not record a separated physical/virtual network path; loopback or same-host execution is present." `
                    -LocalActionability "Needs a separated lab network path, NIC/virtual-network metadata, and no loopback target URL.")) | Out-Null
    }

    $targetResourceStatus = if ($targetMetricsCaptured -gt 0) {
        if (Test-AnyTextMatch -Values $targetMetricWarnings -Pattern "adapter-derived") { "adapter-derived" } else { "captured" }
    }
    else {
        "missing"
    }
    $targetUnavailableReasons = @()
    if ($targetResourceStatus -eq "missing") {
        $targetUnavailableReasons = @(
            "No target process or target container resource samples were recorded in aggregate-results.json.",
            "Adapter-backed or externally managed targets need adapter-derived metrics, direct process sampling, or container metrics."
        )
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "target-resource-metrics-missing" `
                    -Reason "The aggregate reports zero captured target process/container metric repetitions." `
                    -LocalActionability "Locally actionable by capturing adapter process metrics, direct process metrics, or target container stats.")) | Out-Null
    }

    $loadGeneratorStatus = if ($loadToolMetricsCaptured -gt 0) {
        if (Test-AnyTextMatch -Values $loadSaturationWarnings -Pattern "saturation-not-detected") { "not-saturated" } else { "telemetry-captured" }
    }
    elseif ($loadToolMode -eq "process" -and -not (Test-AnyTextMatch -Values $loadSaturationWarnings -Pattern "overload|connection-pressure")) {
        "process-heuristic-only"
    }
    else {
        "not-proven"
    }
    $loadUnavailableReasons = @()
    if ($loadGeneratorStatus -ne "not-saturated" -and $loadGeneratorStatus -ne "telemetry-captured") {
        $loadUnavailableReasons = @(
            "The selected load tool mode is '$loadToolMode' with category '$loadToolCategory'.",
            "No load-generator CPU/memory samples were recorded, so saturation cannot be ruled out from telemetry."
        )
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "load-generator-process-telemetry-unavailable" `
                    -Reason "The load generator ran without captured CPU/memory telemetry; stderr heuristics are not enough for isolated-local proof." `
                    -LocalActionability "Needs docker stats, process sampling, or another retained load-generator telemetry source.")) | Out-Null
    }

    $isolatedLocalBlockers = @($blockerDetails | ForEach-Object { $_.code } | Sort-Object -Unique)
    return [ordered]@{
        hostClassification = [ordered]@{
            status = $hostClassification
            executionProfile = $executionProfile
            targetExecutionMode = $targetExecutionMode
            loadToolMode = $loadToolMode
            loadToolCategory = $loadToolCategory
        }
        cpuIsolation = [ordered]@{
            status = $cpuIsolationStatus
            reasons = @($cpuIsolationReasons)
        }
        networkIsolation = [ordered]@{
            status = $networkIsolationStatus
            reasons = @($networkIsolationReasons)
        }
        targetResourceMetrics = [ordered]@{
            status = $targetResourceStatus
            capturedCount = $targetMetricsCaptured
            missingCount = $targetMetricsMissing
            warnings = @($targetMetricWarnings | Sort-Object -Unique)
            unavailableReasons = @($targetUnavailableReasons)
        }
        loadGeneratorSaturation = [ordered]@{
            status = $loadGeneratorStatus
            dockerMetricsCapturedCount = $loadToolMetricsCaptured
            dockerMetricsMissingCount = $loadToolMetricsMissing
            warnings = @($loadSaturationWarnings)
            unavailableReasons = @($loadUnavailableReasons)
        }
        isolatedLocalGate = [ordered]@{
            status = if ($isolatedLocalBlockers.Count -eq 0) { "passed" } else { "blocked" }
            blockers = @($isolatedLocalBlockers)
            blockerDetails = @($blockerDetails)
        }
    }
}

function Read-ProtocolLabRunReadiness {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RunRoot,

        [Parameter(Mandatory = $true)]
        [int] $MinimumPublishableRepetitions,

        [Parameter(Mandatory = $true)]
        [double] $LocalMaxRelativeRange,

        [Parameter(Mandatory = $true)]
        [double] $PublishableMaxRelativeRange
    )

    $resolvedRunRoot = [System.IO.Path]::GetFullPath($RunRoot)
    $aggregatePath = Join-Path $resolvedRunRoot "aggregate-results.json"
    if (-not (Test-Path -LiteralPath $aggregatePath -PathType Leaf)) {
        return [ordered]@{
            runRoot = $resolvedRunRoot
            present = $false
            blocker = "aggregate-results.json was not found"
        }
    }

    $aggregate = Get-Content -LiteralPath $aggregatePath -Raw | ConvertFrom-Json
    $aggregates = @($aggregate.aggregates | ForEach-Object { $_ })
    $cellReadiness = @()
    foreach ($cell in $aggregates) {
        $evidenceClass = Get-ReadinessEvidenceClass -Aggregate $cell
        $environmentGates = Get-EnvironmentGateAssessment -Cell $cell
        $qualityGate = Get-QualityGate `
            -Aggregate $cell `
            -MinimumPublishableRepetitions $MinimumPublishableRepetitions `
            -LocalMaxRelativeRange $LocalMaxRelativeRange `
            -PublishableMaxRelativeRange $PublishableMaxRelativeRange

        $publishableBlockers = New-Object System.Collections.Generic.List[string]
        foreach ($blocker in @($qualityGate.publishableBlockers)) {
            $publishableBlockers.Add($blocker) | Out-Null
        }
        if ($evidenceClass -ne "publishable") {
            $publishableBlockers.Add("evidence-class-is-$evidenceClass") | Out-Null
        }
        foreach ($blocker in @($environmentGates.isolatedLocalGate.blockers)) {
            $publishableBlockers.Add([string]$blocker) | Out-Null
        }
        foreach ($warning in @($cell.warnings)) {
            $text = [string]$warning
            if ($text -match "localhost|single-machine|shared-host") {
                $publishableBlockers.Add("same-host-loopback-target-and-load-generator") | Out-Null
            }
            elseif ($text -match "no-cpu-isolation") {
                $publishableBlockers.Add("cpu-isolation-unattested-local-process") | Out-Null
            }
            elseif ($text -match "no-network-isolation") {
                $publishableBlockers.Add("network-isolation-unattested-loopback") | Out-Null
            }
            elseif ($text -match "no-load-generator-saturation-check|load-generator-cpu-not-captured") {
                $publishableBlockers.Add("load-generator-process-telemetry-unavailable") | Out-Null
            }
            elseif ($text -match "no-target-resource-metrics") {
                $publishableBlockers.Add("target-resource-metrics-missing") | Out-Null
            }
        }

        $cellReadiness += [ordered]@{
            implementationId = [string](Get-ObjectValue -InputObject $cell -Name "implementationId" -Default "")
            scenarioId = [string](Get-ObjectValue -InputObject $cell -Name "scenarioId" -Default "")
            protocol = [string](Get-ObjectValue -InputObject $cell -Name "protocol" -Default "")
            loadProfileId = [string](Get-ObjectValue -InputObject $cell -Name "loadProfileId" -Default "")
            loadTool = [string](Get-ObjectValue -InputObject $cell -Name "loadTool" -Default "")
            loadToolCategory = [string](Get-ObjectValue -InputObject $cell -Name "loadToolCategory" -Default "")
            targetExecutionMode = [string](Get-ObjectValue -InputObject $cell -Name "targetExecutionMode" -Default "")
            evidenceClass = $evidenceClass
            protocolLabEvidenceClass = [string](Get-ObjectValue -InputObject (Get-ObjectValue -InputObject $cell -Name "evidence") -Name "evidenceClass" -Default "")
            comparabilityStatus = [string](Get-ObjectValue -InputObject (Get-ObjectValue -InputObject $cell -Name "evidence") -Name "comparabilityStatus" -Default "")
            environmentGates = $environmentGates
            qualityGate = $qualityGate
            publishability = [ordered]@{
                status = "blocked"
                blockers = @($publishableBlockers | Sort-Object -Unique)
                blockerDetails = @($environmentGates.isolatedLocalGate.blockerDetails)
            }
        }
    }

    $evidenceClasses = @($cellReadiness | ForEach-Object { $_.evidenceClass } | Sort-Object -Unique)
    $runEvidenceClass = if ($evidenceClasses -contains "local-lab") {
        "local-lab"
    }
    elseif ($evidenceClasses -contains "isolated-local") {
        "isolated-local"
    }
    elseif ($evidenceClasses -contains "external-reference") {
        "external-reference"
    }
    elseif ($evidenceClasses -contains "publishable") {
        "publishable"
    }
    else {
        "unknown"
    }

    $allBlockers = @($cellReadiness | ForEach-Object { @($_.publishability.blockers) } | Sort-Object -Unique)
    $checksumInventory = Get-ChecksumInventory -RootPath $resolvedRunRoot

    return [ordered]@{
        runRoot = $resolvedRunRoot
        present = $true
        runId = [string](Get-ObjectValue -InputObject $aggregate -Name "runId" -Default (Split-Path -Leaf $resolvedRunRoot))
        generatedAt = [string](Get-ObjectValue -InputObject $aggregate -Name "generatedAt" -Default "")
        aggregateResultsPath = $aggregatePath
        aggregateResultsSha256 = (Get-FileHash -LiteralPath $aggregatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        evidenceReportPath = Join-Path $resolvedRunRoot "evidence-report.json"
        summaryPath = Join-Path $resolvedRunRoot "summary.md"
        claimLevel = [string](Get-ObjectValue -InputObject $aggregate -Name "claimLevel" -Default "")
        protocolLabMetadata = Get-ObjectValue -InputObject $aggregate -Name "metadata"
        totals = Get-ObjectValue -InputObject $aggregate -Name "totals"
        evidenceClass = $runEvidenceClass
        evidenceClassesSeen = $evidenceClasses
        cellReadiness = @($cellReadiness)
        publishability = [ordered]@{
            status = if ($runEvidenceClass -eq "publishable" -and $allBlockers.Count -eq 0) { "publishable" } else { "blocked" }
            blockers = $allBlockers
        }
        checksumInventory = @($checksumInventory)
        checksumInventoryCount = @($checksumInventory).Count
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
$resolvedProtocolLabExecutionRoot = Resolve-ProtocolLabExecutionRoot -ContractRoot $resolvedProtocolLabRoot -RequestedExecutionRoot $ProtocolLabExecutionRoot -BasePath $repoRoot
$protocolLabBenchmarkRoot = if ([string]::IsNullOrWhiteSpace($resolvedProtocolLabExecutionRoot)) { $resolvedProtocolLabRoot } else { $resolvedProtocolLabExecutionRoot }
$protocolLabBenchmarkScript = Join-Path $protocolLabBenchmarkRoot "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"

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

$protocolLabRunEvidence = @()
foreach ($runRootInput in @($ProtocolLabRunRoot)) {
    if ([string]::IsNullOrWhiteSpace($runRootInput)) {
        continue
    }

    $protocolLabRunEvidence += Read-ProtocolLabRunReadiness `
        -RunRoot (Resolve-FullPath -Path $runRootInput -BasePath $repoRoot) `
        -MinimumPublishableRepetitions $MinimumPublishableRepetitions `
        -LocalMaxRelativeRange $LocalMaxRelativeRange `
        -PublishableMaxRelativeRange $PublishableMaxRelativeRange
}

$readinessEvidenceClasses = @($protocolLabRunEvidence |
        Where-Object { $_.present } |
        ForEach-Object { $_.evidenceClass } |
        Sort-Object -Unique)
$overallEvidenceClass = if ($readinessEvidenceClasses -contains "local-lab") {
    "local-lab"
}
elseif ($readinessEvidenceClasses -contains "isolated-local") {
    "isolated-local"
}
elseif ($readinessEvidenceClasses -contains "external-reference") {
    "external-reference"
}
elseif ($readinessEvidenceClasses -contains "publishable") {
    "publishable"
}
else {
    "local-lab"
}

$publishabilityBlockers = New-Object System.Collections.Generic.List[string]
if ($protocolLabRunEvidence.Count -eq 0) {
    $publishabilityBlockers.Add("no-protocol-lab-run-roots-supplied") | Out-Null
}
foreach ($runEvidence in @($protocolLabRunEvidence)) {
    foreach ($blocker in @($runEvidence.publishability.blockers)) {
        $publishabilityBlockers.Add($blocker) | Out-Null
    }
}
if ($overallEvidenceClass -ne "publishable") {
    $publishabilityBlockers.Add("overall-evidence-class-is-$overallEvidenceClass") | Out-Null
}

$readinessQuality = [ordered]@{
    thresholds = [ordered]@{
        minimumPublishableRepetitions = $MinimumPublishableRepetitions
        localMaxRelativeRange = $LocalMaxRelativeRange
        publishableMaxRelativeRange = $PublishableMaxRelativeRange
    }
    runsEvaluated = @($protocolLabRunEvidence | Where-Object { $_.present }).Count
    evidenceClass = $overallEvidenceClass
    publishability = [ordered]@{
        status = if ($overallEvidenceClass -eq "publishable" -and $publishabilityBlockers.Count -eq 0) { "publishable" } else { "blocked" }
        blockers = @($publishabilityBlockers | Sort-Object -Unique)
    }
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

$publishableRunbook = [ordered]@{
    localRepeatabilityCommand = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 -UseProjectReferences -ProtocolLabRoot $resolvedProtocolLabRoot -ProtocolLabExecutionRoot $protocolLabBenchmarkRoot -Suite quic-transport-v1-comparison -Implementations incursa-raw-quic-adapter-v1 -Scenarios quic.transport.multiplex.100x64kb -DurationSeconds 15 -WarmupSeconds 5 -Repetitions $MinimumPublishableRepetitions -Connections 1 -StreamsPerConnection 1 -RunIdPrefix quic-local-repeat"
    externalReferenceCommandTemplate = "pwsh -NoProfile -ExecutionPolicy Bypass -File $protocolLabBenchmarkScript -WorkflowProfile Comparison -Suite quic-transport-v1-comparison -ImplementationIds <publishable-implementation-id> -ScenarioIds quic.transport.multiplex.100x64kb -Protocol quic -LoadProfileId local-comparison -RunIdPrefix quic-publishable-<yyyymmdd> -Output .artifacts\runs -Configuration Release -TargetMode external -BaseUrl <sut-endpoint-url> -DurationSeconds 30 -WarmupSeconds 10 -Repetitions $MinimumPublishableRepetitions -Connections 1 -StreamsPerConnection 1 -FailOnError"
    prerequisites = @(
        "separate SUT and load-generator hosts or equivalent isolated resources; no localhost or same-host client/server execution",
        "pinned implementation identity: git commits, package ids, package versions, package SHA-256 values, and source checkout state",
        "captured host metadata for SUT and load generator: CPU model/count, OS build, runtime version, memory, power profile, Docker/container details when used",
        "CPU and memory isolation notes for SUT and load generator, including cpuset/container limits or bare-metal reservation policy",
        "network isolation notes: physical or virtual network path, NIC details where available, no unrelated shared-host traffic, and no host.docker.internal rewrite",
        "external-reference load generator identity and version, plus load-generator CPU/saturation telemetry",
        "minimum repeated-run policy met with stable medians and relative range at or below the publishable threshold",
        "artifact retention with checksum inventory for aggregate-results.json, evidence-report.json, telemetry-bundle.json, run.json, summary.md, and per-cell raw logs",
        "explicit caveats and blockers recorded before any public claim is made"
    )
}

$protocolLabPrerequisites = [ordered]@{
    contractRoot = $resolvedProtocolLabRoot
    executionRoot = $resolvedProtocolLabExecutionRoot
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
    schemaVersion = "quic-dotnet-protocol-lab-readiness-v2"
    runId = $RunId
    createdUtc = (Get-Date -AsUTC).ToString("o")
    repoRoot = $repoRoot
    protocolLabRoot = $resolvedProtocolLabRoot
    protocolLabExecutionRoot = $resolvedProtocolLabExecutionRoot
    evidenceClassDefinitions = [ordered]@{
        "local-lab" = "Developer or rack-local validation where SUT and load generation share host, localhost, local Docker, managed load tools, or otherwise non-isolated resources."
        "isolated-local" = "Local/private lab run with stronger host or container controls, but without external-reference load generation and complete publishable provenance."
        "external-reference" = "Run using external-reference load tooling and separated target/load resources, but still missing one or more publishable artifact, attestation, repetition, or environment gates."
        "publishable" = "External-reference benchmark run with isolated resources, complete identity/environment metadata, retained checksum inventory, stable repeated runs, and no unresolved publishability blockers."
    }
    git = [ordered]@{
        commit = $gitCommit
        state = $gitState
        statusPorcelain = @($gitStatus)
    }
    repositoryIdentities = @(
        Get-RepositoryIdentity -Name "quic-dotnet" -Path $repoRoot
        Get-RepositoryIdentity -Name "protocol-lab" -Path $resolvedProtocolLabRoot
        Get-RepositoryIdentity -Name "protocol-lab-internal" -Path $resolvedProtocolLabExecutionRoot
    )
    hostEnvironment = Get-HostEnvironmentSnapshot
    packageEvidence = @($packageEvidence)
    http3RunnerEvidence = $http3RunnerEvidence
    protocolLabRuns = @($protocolLabRunEvidence)
    readinessQuality = $readinessQuality
    protocolLabPrerequisites = $protocolLabPrerequisites
    performanceCommands = $performanceCommands
    publishableRunbook = $publishableRunbook
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
Add-Line $summary "## Evidence Classification"
Add-Line $summary ""
Add-Line $summary "- Overall evidence class: ``$($readinessQuality.evidenceClass)``"
Add-Line $summary "- Publishability status: ``$($readinessQuality.publishability.status)``"
Add-Line $summary "- Runs evaluated: ``$($readinessQuality.runsEvaluated)``"
Add-Line $summary "- Minimum publishable repetitions: ``$MinimumPublishableRepetitions``"
Add-Line $summary "- Local max relative range: ``$LocalMaxRelativeRange``"
Add-Line $summary "- Publishable max relative range: ``$PublishableMaxRelativeRange``"
if (@($readinessQuality.publishability.blockers).Count -gt 0) {
    Add-Line $summary ""
    Add-Line $summary "Publishability blockers:"
    foreach ($blocker in @($readinessQuality.publishability.blockers)) {
        Add-Line $summary "- ``$blocker``"
    }
}
Add-Line $summary ""
Add-Line $summary "Evidence classes:"
foreach ($definition in $manifest.evidenceClassDefinitions.GetEnumerator()) {
    Add-Line $summary "- ``$($definition.Key)``: $($definition.Value)"
}
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
Add-Line $summary "## ProtocolLab Run Readiness"
Add-Line $summary ""
if ($protocolLabRunEvidence.Count -eq 0) {
    Add-Line $summary "- No ProtocolLab run roots were supplied with ``-ProtocolLabRunRoot``."
}
foreach ($runEvidence in @($protocolLabRunEvidence)) {
    if (-not $runEvidence.present) {
        Add-Line $summary "- ``$($runEvidence.runRoot)``: blocked ($($runEvidence.blocker))."
        continue
    }

    Add-Line $summary "- ``$($runEvidence.runId)``"
    Add-Line $summary "  - Run root: ``$($runEvidence.runRoot)``"
    Add-Line $summary "  - Evidence class: ``$($runEvidence.evidenceClass)``"
    Add-Line $summary "  - Claim level: ``$($runEvidence.claimLevel)``"
    Add-Line $summary "  - Aggregate SHA-256: ``$($runEvidence.aggregateResultsSha256)``"
    Add-Line $summary "  - Checksum inventory entries: ``$($runEvidence.checksumInventoryCount)``"
    Add-Line $summary "  - Publishability: ``$($runEvidence.publishability.status)``"
    foreach ($cell in @($runEvidence.cellReadiness)) {
        Add-Line $summary "  - Cell ``$($cell.implementationId)`` / ``$($cell.scenarioId)`` / ``$($cell.protocol)``"
        Add-Line $summary "    - Load tool: ``$($cell.loadTool)`` (``$($cell.loadToolCategory)``)"
        Add-Line $summary "    - Evidence: ``$($cell.evidenceClass)``; comparability: ``$($cell.comparabilityStatus)``"
        Add-Line $summary "    - Local quality: ``$($cell.qualityGate.localStatus)``; failure class: ``$($cell.qualityGate.failureClass)``; repetitions: ``$($cell.qualityGate.repetitions)``"
        if ($null -ne $cell.qualityGate.maxRelativeRange) {
            Add-Line $summary "    - Max relative range: ``$([Math]::Round([double]$cell.qualityGate.maxRelativeRange, 6))``"
        }
        if (@($cell.publishability.blockers).Count -gt 0) {
            Add-Line $summary "    - Publishability blockers: ``$(@($cell.publishability.blockers) -join ', ')``"
        }
        Add-Line $summary "    - Host classification: ``$($cell.environmentGates.hostClassification.status)``"
        Add-Line $summary "    - CPU isolation: ``$($cell.environmentGates.cpuIsolation.status)``"
        Add-Line $summary "    - Network isolation: ``$($cell.environmentGates.networkIsolation.status)``"
        Add-Line $summary "    - Target resource metrics: ``$($cell.environmentGates.targetResourceMetrics.status)`` (captured ``$($cell.environmentGates.targetResourceMetrics.capturedCount)``, missing ``$($cell.environmentGates.targetResourceMetrics.missingCount)``)"
        Add-Line $summary "    - Load-generator saturation: ``$($cell.environmentGates.loadGeneratorSaturation.status)``"
        if (@($cell.environmentGates.isolatedLocalGate.blockers).Count -gt 0) {
            Add-Line $summary "    - Isolated-local blockers: ``$(@($cell.environmentGates.isolatedLocalGate.blockers) -join ', ')``"
        }
    }
}

Add-Line $summary ""
Add-Line $summary "## Performance And Controller Commands"
Add-Line $summary ""
Add-Line $summary "- ProtocolLab contract root: ``$($protocolLabPrerequisites.contractRoot)``"
Add-Line $summary "- ProtocolLab execution root: ``$($protocolLabPrerequisites.executionRoot)``"
Add-Line $summary "- ProtocolLab benchmark set script: ``$($protocolLabPrerequisites.benchmarkSetScript.path)``"
Add-Line $summary "- ProtocolLab benchmark set script present: ``$($protocolLabPrerequisites.benchmarkSetScript.present)``"
Add-Line $summary ""
foreach ($command in $performanceCommands) {
    Add-Line $summary "- $($command.name): ``$($command.command)``"
    Add-Line $summary "  - Mode: ``$($command.mode)``"
    Add-Line $summary "  - Publishable: ``$($command.publishable)``"
}

Add-Line $summary ""
Add-Line $summary "## Publishable Collection Runbook"
Add-Line $summary ""
Add-Line $summary "Local repeatability command:"
Add-Line $summary ""
Add-Line $summary '```powershell'
Add-Line $summary $publishableRunbook.localRepeatabilityCommand
Add-Line $summary '```'
Add-Line $summary ""
Add-Line $summary "External-reference command template:"
Add-Line $summary ""
Add-Line $summary '```powershell'
Add-Line $summary $publishableRunbook.externalReferenceCommandTemplate
Add-Line $summary '```'
Add-Line $summary ""
Add-Line $summary "Prerequisites:"
foreach ($prerequisite in @($publishableRunbook.prerequisites)) {
    Add-Line $summary "- $prerequisite."
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
