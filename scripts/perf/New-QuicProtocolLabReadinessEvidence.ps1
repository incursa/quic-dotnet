[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",

    [string] $ProtocolLabExecutionRoot,

    [string] $ComponentPackageDirectory,

    [string[]] $ComponentPackage = @(),

    [string] $OutputRoot = ".artifacts\protocol-lab\readiness",

    [string] $RunId = "protocol-lab-readiness-$((Get-Date -AsUTC).ToString('yyyyMMddTHHmmssZ'))",

    [string] $Http3RunnerArtifactRoot,

    [string[]] $ProtocolLabRunRoot = @(),

    [string] $LabControllerEvidencePath,

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

    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
        $dictionaryValue = $InputObject[$Name]
        if ($null -eq $dictionaryValue) {
            return $Default
        }

        return $dictionaryValue
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

function Resolve-ComponentPackageDirectory {
    param(
        [string] $RequestedDirectory,

        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [Parameter(Mandatory = $true)]
        [string] $ProtocolLabRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedDirectory)) {
        return Resolve-FullPath -Path $RequestedDirectory -BasePath $RepoRoot
    }

    $environmentDirectory = [Environment]::GetEnvironmentVariable("PROTOCOL_LAB_COMPONENT_PACKAGE_DIRECTORY")
    if (-not [string]::IsNullOrWhiteSpace($environmentDirectory)) {
        return Resolve-FullPath -Path $environmentDirectory -BasePath $RepoRoot
    }

    $siblingDirectory = Join-Path (Split-Path -Parent $ProtocolLabRoot) "protocol-lab-components\artifacts\packages"
    if (Test-Path -LiteralPath $siblingDirectory -PathType Container) {
        return [System.IO.Path]::GetFullPath($siblingDirectory)
    }

    return ""
}

function Get-ComponentPackageSelectors {
    param([string[]] $Selectors)

    return @(
        foreach ($selector in @($Selectors)) {
            foreach ($entry in @([string]$selector -split ",")) {
                $trimmed = $entry.Trim()
                if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                    $trimmed
                }
            }
        }
    )
}

function Get-ComponentPackageManifest {
    param([Parameter(Mandatory = $true)][string] $PackagePath)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        $entry = $archive.GetEntry("protocol-lab-package.json")
        if ($null -eq $entry) {
            return $null
        }

        $reader = [System.IO.StreamReader]::new($entry.Open())
        try {
            return ($reader.ReadToEnd() | ConvertFrom-Json)
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-ComponentPackageEvidence {
    param(
        [string] $Directory,

        [string[]] $Selectors
    )

    if ([string]::IsNullOrWhiteSpace($Directory)) {
        return [ordered]@{
            directory = ""
            present = $false
            packages = @()
            blocker = "No component package directory was supplied and no default directory was found."
        }
    }

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return [ordered]@{
            directory = $Directory
            present = $false
            packages = @()
            blocker = "Component package directory was not found."
        }
    }

    $packageSelectors = @(Get-ComponentPackageSelectors -Selectors $Selectors)
    $archives = if ($packageSelectors.Count -gt 0) {
        foreach ($selector in $packageSelectors) {
            $candidate = if ([System.IO.Path]::IsPathRooted($selector)) { $selector } else { Join-Path $Directory $selector }
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                Get-Item -LiteralPath $candidate
            }
            else {
                Get-ChildItem -LiteralPath $Directory -File -Filter "*.plabpkg" |
                    Where-Object { $_.BaseName -like "$selector*" -or $_.Name -like "$selector*" }
            }
        }
    }
    else {
        Get-ChildItem -LiteralPath $Directory -File -Filter "*.plabpkg"
    }

    $packages = @(
        foreach ($archive in @($archives | Sort-Object FullName -Unique)) {
            $manifest = Get-ComponentPackageManifest -PackagePath $archive.FullName
            [ordered]@{
                packageId = if ($null -eq $manifest) { [System.IO.Path]::GetFileNameWithoutExtension($archive.Name) } else { [string]$manifest.packageId }
                packageVersion = if ($null -eq $manifest) { "" } else { [string]$manifest.packageVersion }
                kind = if ($null -eq $manifest) { "" } else { [string]$manifest.kind }
                path = $archive.FullName
                length = $archive.Length
                sha256 = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                entryManifests = if ($null -eq $manifest) { @() } else { @($manifest.entryManifests | ForEach-Object { [string]$_ }) }
            }
        }
    )

    return [ordered]@{
        directory = $Directory
        present = $true
        selectedPackages = @($packageSelectors)
        packageCount = $packages.Count
        packages = @($packages)
        blocker = if ($packages.Count -eq 0) { "No .plabpkg archives matched the selected component package inputs." } else { "" }
    }
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

function Read-JsonFileOrNull {
    param([string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Get-LabNodeLabel {
    param(
        [AllowNull()]
        $Node,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    $labels = Get-ObjectValue -InputObject $Node -Name "labels"
    if ($null -eq $labels) {
        $capabilities = Get-ObjectValue -InputObject $Node -Name "capabilities"
        $labels = Get-ObjectValue -InputObject $capabilities -Name "labels"
    }

    if ($null -eq $labels) {
        return ""
    }

    return [string](Get-ObjectValue -InputObject $labels -Name $Name -Default "")
}

function Get-LabNodeName {
    param(
        [AllowNull()]
        $Node
    )

    foreach ($propertyName in @("nodeId", "id", "name", "displayName")) {
        $value = [string](Get-ObjectValue -InputObject $Node -Name $propertyName -Default "")
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return "unknown"
}

function Test-LabNodeReady {
    param(
        [AllowNull()]
        $Node
    )

    $ready = Get-ObjectValue -InputObject $Node -Name "ready"
    if ($ready -is [bool]) {
        return $ready
    }

    foreach ($propertyName in @("status", "state")) {
        $value = [string](Get-ObjectValue -InputObject $Node -Name $propertyName -Default "")
        if ($value -eq "Ready" -or $value -eq "ready") {
            return $true
        }
    }

    return $false
}

function Read-LabControllerEvidence {
    param([string] $Path)

    $emptySummary = [ordered]@{
        nodeCount = 0
        readyNodeCount = 0
        sutNodes = @()
        loadNodes = @()
        benchmarkAddresses = @()
        physicalHostLabels = @()
        separateRolesAvailable = $false
        samePhysicalHostObserved = $false
        isolatedPairPreview = [ordered]@{
            present = $false
            canSubmit = $false
            roles = @()
            blockers = @()
        }
        blockers = @()
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [ordered]@{
            present = $false
            path = ""
            sha256 = ""
            blocker = "LabControllerEvidencePath was not supplied"
            summary = $emptySummary
        }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{
            present = $false
            path = [System.IO.Path]::GetFullPath($Path)
            sha256 = ""
            blocker = "Lab controller evidence file was not found"
            summary = $emptySummary
        }
    }

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $document = Read-JsonFileOrNull -Path $resolvedPath
    if ($null -eq $document) {
        return [ordered]@{
            present = $false
            path = $resolvedPath
            sha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
            blocker = "Lab controller evidence file could not be parsed as JSON"
            summary = $emptySummary
        }
    }

    $rawNodes = Get-ObjectValue -InputObject $document -Name "nodes" -Default @()
    $nodes = @($rawNodes | ForEach-Object { $_ })
    $nodeFacts = @(
        foreach ($node in $nodes) {
            $nodeName = Get-LabNodeName -Node $node
            [ordered]@{
                nodeId = $nodeName
                ready = Test-LabNodeReady -Node $node
                role = Get-LabNodeLabel -Node $node -Name "role"
                workerKind = Get-LabNodeLabel -Node $node -Name "workerKind"
                host = Get-LabNodeLabel -Node $node -Name "host"
                evidenceTier = Get-LabNodeLabel -Node $node -Name "evidenceTier"
                benchmarkAddress = Get-LabNodeLabel -Node $node -Name "benchmarkAddress"
            }
        }
    )

    $sutNodes = @($nodeFacts | Where-Object { $_.role -eq "sut" } | ForEach-Object { $_.nodeId })
    $loadNodes = @($nodeFacts | Where-Object { $_.role -eq "load" } | ForEach-Object { $_.nodeId })
    $sutHostLabels = @($nodeFacts | Where-Object { $_.role -eq "sut" -and -not [string]::IsNullOrWhiteSpace($_.host) } | ForEach-Object { $_.host } | Select-Object -Unique)
    $loadHostLabels = @($nodeFacts | Where-Object { $_.role -eq "load" -and -not [string]::IsNullOrWhiteSpace($_.host) } | ForEach-Object { $_.host } | Select-Object -Unique)
    $sharedHostLabels = @($sutHostLabels | Where-Object { $loadHostLabels -contains $_ })
    $benchmarkAddresses = @($nodeFacts | Where-Object { -not [string]::IsNullOrWhiteSpace($_.benchmarkAddress) } | ForEach-Object { $_.benchmarkAddress } | Select-Object -Unique)

    $preview = Get-ObjectValue -InputObject $document -Name "isolatedPairPreview"
    $previewRoles = @()
    $previewBlockers = @()
    $previewCanSubmit = $false
    $previewPresent = $false
    if ($null -ne $preview) {
        $previewPresent = $true
        $previewCanSubmitValue = Get-ObjectValue -InputObject $preview -Name "canSubmit" -Default $false
        if ($previewCanSubmitValue -is [bool]) {
            $previewCanSubmit = $previewCanSubmitValue
        }

        $previewBlockers = @((Get-ObjectValue -InputObject $preview -Name "blockers" -Default @()) | ForEach-Object { [string]$_ })
        $previewRoles = @(
            (Get-ObjectValue -InputObject $preview -Name "roles" -Default @()) | ForEach-Object {
                $matchedNodeIds = @((Get-ObjectValue -InputObject $_ -Name "matchedNodeIds" -Default @()) | ForEach-Object { [string]$_ })
                [ordered]@{
                    name = [string](Get-ObjectValue -InputObject $_ -Name "name" -Default (Get-ObjectValue -InputObject $_ -Name "role" -Default ""))
                    matchedNodeIds = $matchedNodeIds
                    matchedNodeCount = $matchedNodeIds.Count
                }
            }
        )
    }

    $blockers = New-Object System.Collections.Generic.List[string]
    if ($sutNodes.Count -eq 0) {
        $blockers.Add("no-ready-sut-worker-observed") | Out-Null
    }

    if ($loadNodes.Count -eq 0) {
        $blockers.Add("no-ready-load-worker-observed") | Out-Null
    }

    if ($sharedHostLabels.Count -gt 0) {
        $blockers.Add("physical-host-isolation-unattested:$($sharedHostLabels -join ',')") | Out-Null
    }

    if ($previewPresent -and -not $previewCanSubmit) {
        $blockers.Add("isolated-pair-preview-not-submittable") | Out-Null
    }

    return [ordered]@{
        present = $true
        path = $resolvedPath
        sha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        capturedUtc = [string](Get-ObjectValue -InputObject $document -Name "capturedUtc" -Default "")
        controllerUrl = [string](Get-ObjectValue -InputObject $document -Name "controllerUrl" -Default "")
        blocker = ""
        summary = [ordered]@{
            nodeCount = $nodeFacts.Count
            readyNodeCount = @($nodeFacts | Where-Object { $_.ready }).Count
            sutNodes = $sutNodes
            loadNodes = $loadNodes
            benchmarkAddresses = $benchmarkAddresses
            physicalHostLabels = @($nodeFacts | Where-Object { -not [string]::IsNullOrWhiteSpace($_.host) } | ForEach-Object { $_.host } | Select-Object -Unique)
            separateRolesAvailable = ($sutNodes.Count -gt 0 -and $loadNodes.Count -gt 0)
            samePhysicalHostObserved = ($sharedHostLabels.Count -gt 0)
            isolatedPairPreview = [ordered]@{
                present = $previewPresent
                canSubmit = $previewCanSubmit
                roles = $previewRoles
                blockers = $previewBlockers
            }
            blockers = @($blockers)
        }
    }
}

function Test-LoopbackHost {
    param([string] $HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) {
        return $false
    }

    $normalized = $HostName.Trim().Trim("[", "]").ToLowerInvariant()
    if ($normalized -eq "localhost" -or $normalized -eq "::1" -or $normalized -match "^127\.") {
        return $true
    }

    $address = [System.Net.IPAddress]::None
    if ([System.Net.IPAddress]::TryParse($normalized, [ref]$address)) {
        return [System.Net.IPAddress]::IsLoopback($address)
    }

    return $false
}

function Get-UrlHost {
    param([string] $Url)

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return ""
    }

    try {
        return ([Uri]$Url).Host
    }
    catch {
        return ""
    }
}

function Get-HostAddressFamily {
    param([string] $HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) {
        return "unknown"
    }

    $normalized = $HostName.Trim().Trim("[", "]")
    $address = [System.Net.IPAddress]::None
    if ([System.Net.IPAddress]::TryParse($normalized, [ref]$address)) {
        if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return "ipv4"
        }

        if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return "ipv6"
        }
    }

    return "dns"
}

function Get-CellArtifactFacts {
    param(
        [string] $RunRoot,

        [AllowNull()]
        $Cell
    )

    $cellDirectory = ""
    $qlogDirectory = [string](Get-ObjectValue -InputObject $Cell -Name "qlogDirectory" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($qlogDirectory)) {
        $cellDirectory = Split-Path -Parent $qlogDirectory
    }

    if ([string]::IsNullOrWhiteSpace($cellDirectory)) {
        $artifact = @((Get-ObjectValue -InputObject $Cell -Name "loadToolProcessMetricsArtifacts" -Default @())) | Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace([string]$artifact) -and -not [string]::IsNullOrWhiteSpace($RunRoot)) {
            $cellDirectory = Split-Path -Parent (Join-Path $RunRoot ([string]$artifact))
        }
    }

    $targetExecution = $null
    $loadToolExecution = $null
    $adapterEndpoints = $null
    $sourceArtifacts = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($cellDirectory) -and (Test-Path -LiteralPath $cellDirectory -PathType Container)) {
        $targetExecutionPath = Join-Path $cellDirectory "target-execution.json"
        $loadToolExecutionPath = Join-Path $cellDirectory "load-tool-execution.json"
        $adapterEndpointsPath = Join-Path $cellDirectory "adapter-endpoints.json"
        $targetExecution = Read-JsonFileOrNull -Path $targetExecutionPath
        $loadToolExecution = Read-JsonFileOrNull -Path $loadToolExecutionPath
        $adapterEndpoints = Read-JsonFileOrNull -Path $adapterEndpointsPath
        foreach ($path in @($targetExecutionPath, $loadToolExecutionPath, $adapterEndpointsPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $sourceArtifacts.Add($path) | Out-Null
            }
        }
    }

    $endpoint = @((Get-ObjectValue -InputObject $adapterEndpoints -Name "endpoints" -Default @())) | Select-Object -First 1
    $targetUrl = [string](Get-ObjectValue -InputObject $targetExecution -Name "targetEffectiveBaseUrl" -Default "")
    if ([string]::IsNullOrWhiteSpace($targetUrl)) {
        $targetUrl = [string](Get-ObjectValue -InputObject $Cell -Name "targetEffectiveBaseUrl" -Default "")
    }

    $loadToolEffectiveUrl = [string](Get-ObjectValue -InputObject $loadToolExecution -Name "effectiveUrl" -Default "")
    $loadToolRequestedUrl = [string](Get-ObjectValue -InputObject $loadToolExecution -Name "requestedUrl" -Default "")
    $endpointHost = [string](Get-ObjectValue -InputObject $endpoint -Name "host" -Default (Get-UrlHost -Url $targetUrl))
    $loadToolUrlHost = Get-UrlHost -Url $loadToolEffectiveUrl
    if ([string]::IsNullOrWhiteSpace($loadToolUrlHost)) {
        $loadToolUrlHost = Get-UrlHost -Url $loadToolRequestedUrl
    }

    return [ordered]@{
        cellDirectory = $cellDirectory
        sourceArtifacts = @($sourceArtifacts)
        target = [ordered]@{
            effectiveBaseUrl = $targetUrl
            endpointHost = $endpointHost
            endpointPort = Get-ObjectValue -InputObject $endpoint -Name "port"
            endpointScheme = Get-ObjectValue -InputObject $endpoint -Name "scheme"
            endpointNetworkMode = Get-ObjectValue -InputObject $endpoint -Name "networkMode"
            endpointBindMode = Get-ObjectValue -InputObject $endpoint -Name "bindMode"
            addressFamily = Get-HostAddressFamily -HostName $endpointHost
            isLoopback = (Test-LoopbackHost -HostName $endpointHost)
            diagnosticProcessId = Get-ObjectValue -InputObject $Cell -Name "diagnosticProcessId"
        }
        loadGenerator = [ordered]@{
            effectiveUrl = $loadToolEffectiveUrl
            requestedUrl = $loadToolRequestedUrl
            urlHost = $loadToolUrlHost
            addressFamily = Get-HostAddressFamily -HostName $loadToolUrlHost
            isLoopbackUrl = (Test-LoopbackHost -HostName $loadToolUrlHost)
            executablePath = Get-ObjectValue -InputObject $loadToolExecution -Name "executablePath"
            workingDirectory = Get-ObjectValue -InputObject $loadToolExecution -Name "workingDirectory"
            processIds = @((Get-ObjectValue -InputObject $Cell -Name "loadToolProcessMetricsSummaries" -Default @()) |
                ForEach-Object { Get-ObjectValue -InputObject $_ -Name "processId" } |
                Where-Object { $null -ne $_ })
        }
    }
}

function Get-EnvironmentGateAssessment {
    param(
        $Cell,

        [string] $RunRoot,

        [AllowNull()]
        $RunMetadata
    )

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
    $loadToolDockerMetricsCaptured = [int](Get-ObjectValue -InputObject $Cell -Name "loadToolDockerMetricsCapturedCount" -Default 0)
    $loadToolDockerMetricsMissing = [int](Get-ObjectValue -InputObject $Cell -Name "loadToolDockerMetricsMissingCount" -Default 0)
    $loadToolProcessMetricsCaptured = [int](Get-ObjectValue -InputObject $Cell -Name "loadToolProcessMetricsCapturedCount" -Default 0)
    $loadToolProcessMetricsMissing = [int](Get-ObjectValue -InputObject $Cell -Name "loadToolProcessMetricsMissingCount" -Default 0)
    $loadToolMetricsCaptured = $loadToolDockerMetricsCaptured + $loadToolProcessMetricsCaptured
    $loadToolMetricsMissing = $loadToolDockerMetricsMissing + $loadToolProcessMetricsMissing
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
                    -Reason "This is a hard local-lab classifier: the target and load generator use loopback, localhost, or the same host resources." `
                    -LocalActionability "Not clearable on this same-host run. Rerun with a non-loopback SUT endpoint and a separate load-generator host, VM, or container topology with retained route/NIC metadata.")) | Out-Null
    }

    $cpuIsolationStatus = "unknown"
    $cpuIsolationReasons = New-Object System.Collections.Generic.List[string]
    if (Test-AnyTextMatch -Values $warnings -Pattern "no-cpu-isolation") {
        $cpuIsolationStatus = "not-proven"
        $cpuIsolationReasons.Add("Aggregate reports no-cpu-isolation; no cpuset, processor-group, CPU affinity, container CPU limit, or operator reservation attestation was retained with this run.") | Out-Null
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "cpu-isolation-unattested-local-process" `
                    -Reason "The run did not record cpuset/container CPU limits, processor affinity, processor-group placement, bare-metal reservation policy, or equivalent CPU isolation attestation." `
                    -LocalActionability "Requires a new run with retained CPU isolation metadata, such as Docker cpuset/cpus, process affinity and processor group, or an operator-attested reserved host.")) | Out-Null
    }

    $networkIsolationStatus = "unknown"
    $networkIsolationReasons = New-Object System.Collections.Generic.List[string]
    if (Test-AnyTextMatch -Values $warnings -Pattern "no-network-isolation|localhost|127\.0\.0\.1|single-machine|shared-host|same local environment") {
        $networkIsolationStatus = "not-proven"
        $networkIsolationReasons.Add("Aggregate reports localhost/shared-host execution, loopback routing, or no-network-isolation.") | Out-Null
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "network-isolation-unattested-loopback" `
                    -Reason "The run did not record a separated physical or virtual network path; loopback or same-host routing is present." `
                    -LocalActionability "Requires a new run whose effective load-tool URL is not localhost/127.0.0.1 and whose manifest retains route, NIC, virtual switch, or container-network metadata.")) | Out-Null
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

    $loadGeneratorStatus = if ($loadToolDockerMetricsCaptured -gt 0) {
        if (Test-AnyTextMatch -Values $loadSaturationWarnings -Pattern "saturation-not-detected") { "not-saturated" } else { "telemetry-captured" }
    }
    elseif ($loadToolProcessMetricsCaptured -gt 0) {
        "process-telemetry-captured"
    }
    elseif ($loadToolMode -eq "process" -and -not (Test-AnyTextMatch -Values $loadSaturationWarnings -Pattern "overload|connection-pressure")) {
        "process-heuristic-only"
    }
    else {
        "not-proven"
    }
    $loadUnavailableReasons = @()
    if ($loadGeneratorStatus -ne "not-saturated" -and $loadGeneratorStatus -ne "telemetry-captured" -and $loadGeneratorStatus -ne "process-telemetry-captured") {
        $loadUnavailableReasons = @(
            "The selected load tool mode is '$loadToolMode' with category '$loadToolCategory'.",
            "No load-generator Docker metrics or process metrics were recorded, so saturation cannot be ruled out from retained telemetry."
        )
        $blockerDetails.Add((New-BlockerDetail `
                    -Code "load-generator-process-telemetry-unavailable" `
                    -Reason "The load generator ran without retained Docker stats or process CPU/memory snapshots; stderr heuristics are not enough for isolated-local proof." `
                    -LocalActionability "Rerun with load-generator Docker stats or process-mode load-generator telemetry retained in aggregate-results.json.")) | Out-Null
    }

    $artifactFacts = Get-CellArtifactFacts -RunRoot $RunRoot -Cell $Cell
    $runHostName = [string](Get-ObjectValue -InputObject $RunMetadata -Name "hostName" -Default "")
    $runProcessorCount = Get-ObjectValue -InputObject $RunMetadata -Name "processorCount"
    $artifactTargetFacts = Get-ObjectValue -InputObject $artifactFacts -Name "target"
    $artifactLoadGeneratorFacts = Get-ObjectValue -InputObject $artifactFacts -Name "loadGenerator"
    $targetEndpointIsLoopback = [bool](Get-ObjectValue -InputObject $artifactTargetFacts -Name "isLoopback" -Default $false)
    $loadToolUrlIsLoopback = [bool](Get-ObjectValue -InputObject $artifactLoadGeneratorFacts -Name "isLoopbackUrl" -Default $false)
    $targetProcessIds = @((Get-ObjectValue -InputObject $artifactTargetFacts -Name "diagnosticProcessId") | Where-Object { $null -ne $_ })
    $loadGeneratorProcessIds = @((Get-ObjectValue -InputObject $artifactLoadGeneratorFacts -Name "processIds" -Default @()) | Where-Object { $null -ne $_ })
    $targetHostIdentity = if ($targetExecutionMode -eq "process" -or $targetEndpointIsLoopback) { $runHostName } else { "unknown" }
    $loadGeneratorHostIdentity = if ($loadToolMode -eq "process" -or $loadToolUrlIsLoopback) { $runHostName } else { "unknown" }
    $separateHostObserved = -not [string]::IsNullOrWhiteSpace($targetHostIdentity) -and
        -not [string]::IsNullOrWhiteSpace($loadGeneratorHostIdentity) -and
        $targetHostIdentity -ne "unknown" -and
        $loadGeneratorHostIdentity -ne "unknown" -and
        -not [string]::Equals($targetHostIdentity, $loadGeneratorHostIdentity, [StringComparison]::OrdinalIgnoreCase)
    $sameProcessNamespace = $targetExecutionMode -eq "process" -and $loadToolMode -eq "process"
    $placementStatus = if ($separateHostObserved) {
        "separate-host-observed"
    }
    elseif ($sameProcessNamespace -or $isLoopbackOrSameHost -or $targetEndpointIsLoopback -or $loadToolUrlIsLoopback) {
        "same-host-observed"
    }
    else {
        "unknown"
    }

    $nonLoopbackNetworkObserved = -not $targetEndpointIsLoopback -and -not $loadToolUrlIsLoopback -and -not $isLoopbackOrSameHost -and
        -not [string]::IsNullOrWhiteSpace([string](Get-ObjectValue -InputObject $artifactTargetFacts -Name "endpointHost" -Default ""))
    $networkPathStatus = if ($targetEndpointIsLoopback -or $loadToolUrlIsLoopback -or $isLoopbackOrSameHost) {
        "loopback-observed"
    }
    elseif ($nonLoopbackNetworkObserved) {
        "non-loopback-observed"
    }
    else {
        "unknown"
    }

    $targetTelemetryStatus = if ($targetMetricsCaptured -gt 0) { if ($targetResourceStatus -eq "adapter-derived") { "captured-adapter-derived" } else { "captured" } } else { "missing" }
    $loadGeneratorTelemetryStatus = if ($loadToolMetricsCaptured -gt 0) { $loadGeneratorStatus } else { "missing" }
    $cpuAttestationStatus = if ($cpuIsolationStatus -eq "not-proven") { "not-attested" } else { "unknown" }
    $networkAttestationStatus = if ($networkIsolationStatus -eq "not-proven") { "not-attested" } else { "unknown" }
    $placementAttestationStatus = if ($placementStatus -eq "same-host-observed") { "not-attested" } elseif ($placementStatus -eq "separate-host-observed") { "observed-not-attested" } else { "unknown" }

    $isolatedLocalRequirements = @(
        [ordered]@{
            requirement = "separate-target-and-load-generator-host"
            status = if ($separateHostObserved) { "satisfied" } else { "blocked" }
            blocker = if ($separateHostObserved) { $null } else { "same-host-loopback-target-and-load-generator" }
            upgradeInstruction = "Run the SUT on a separate host, VM, or isolated container host from the load generator and retain both host identities in the run artifacts."
        },
        [ordered]@{
            requirement = "non-loopback-network-path"
            status = if ($nonLoopbackNetworkObserved) { "satisfied" } else { "blocked" }
            blocker = if ($nonLoopbackNetworkObserved) { $null } else { "network-isolation-unattested-loopback" }
            upgradeInstruction = "Use a non-localhost SUT URL and retain endpoint, route, NIC, virtual switch, or container-network metadata showing that traffic did not use loopback or host.docker.internal."
        },
        [ordered]@{
            requirement = "cpu-isolation-or-reservation-attestation"
            status = if ($cpuAttestationStatus -eq "attested") { "satisfied" } else { "blocked" }
            blocker = if ($cpuAttestationStatus -eq "attested") { $null } else { "cpu-isolation-unattested-local-process" }
            upgradeInstruction = "Retain CPU isolation evidence for target and load-generator resources: cpuset/cpus, processor affinity and processor group, VM vCPU reservation, or an operator-attested reserved host policy."
        },
        [ordered]@{
            requirement = "target-resource-telemetry-retained"
            status = if ($targetMetricsCaptured -gt 0) { "satisfied" } else { "blocked" }
            blocker = if ($targetMetricsCaptured -gt 0) { $null } else { "target-resource-metrics-missing" }
            upgradeInstruction = "Retain target process, adapter-derived endpoint, or target container CPU/memory telemetry for every repetition."
        },
        [ordered]@{
            requirement = "load-generator-telemetry-retained"
            status = if ($loadToolMetricsCaptured -gt 0) { "satisfied" } else { "blocked" }
            blocker = if ($loadToolMetricsCaptured -gt 0) { $null } else { "load-generator-process-telemetry-unavailable" }
            upgradeInstruction = "Retain load-generator process or container CPU/memory telemetry for every repetition so saturation can be assessed from artifacts."
        },
        [ordered]@{
            requirement = "isolated-local-evidence-class"
            status = if ($placementStatus -ne "same-host-observed" -and $nonLoopbackNetworkObserved -and $cpuAttestationStatus -eq "attested") { "satisfied" } else { "blocked" }
            blocker = if ($placementStatus -ne "same-host-observed" -and $nonLoopbackNetworkObserved -and $cpuAttestationStatus -eq "attested") { $null } else { "evidence-class-remains-local-lab" }
            upgradeInstruction = "After the topology and attestation gates are satisfied, rerun the readiness proof against the new ProtocolLab run root; keep the evidence class local-lab until those artifacts exist."
        }
    )

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
        measuredTopology = [ordered]@{
            hostCpuTopology = [ordered]@{
                status = if ($null -ne $runProcessorCount) { "measured" } else { "unavailable" }
                hostName = $runHostName
                processorCount = $runProcessorCount
                source = "aggregate-results.metadata"
                attestationStatus = $cpuAttestationStatus
            }
            processPlacement = [ordered]@{
                status = $placementStatus
                targetHostIdentity = $targetHostIdentity
                loadGeneratorHostIdentity = $loadGeneratorHostIdentity
                targetExecutionMode = $targetExecutionMode
                loadToolMode = $loadToolMode
                targetProcessIds = @($targetProcessIds)
                loadGeneratorProcessIds = @($loadGeneratorProcessIds)
                separateHostObserved = $separateHostObserved
                sameProcessNamespaceObserved = $sameProcessNamespace
                attestationStatus = $placementAttestationStatus
            }
            networkPath = [ordered]@{
                status = $networkPathStatus
                targetEffectiveBaseUrl = Get-ObjectValue -InputObject $artifactTargetFacts -Name "effectiveBaseUrl"
                loadGeneratorEffectiveUrl = Get-ObjectValue -InputObject $artifactLoadGeneratorFacts -Name "effectiveUrl"
                targetEndpointHost = Get-ObjectValue -InputObject $artifactTargetFacts -Name "endpointHost"
                loadGeneratorUrlHost = Get-ObjectValue -InputObject $artifactLoadGeneratorFacts -Name "urlHost"
                targetAddressFamily = Get-ObjectValue -InputObject $artifactTargetFacts -Name "addressFamily"
                loadGeneratorAddressFamily = Get-ObjectValue -InputObject $artifactLoadGeneratorFacts -Name "addressFamily"
                targetEndpointIsLoopback = $targetEndpointIsLoopback
                loadGeneratorUrlIsLoopback = $loadToolUrlIsLoopback
                nonLoopbackNetworkObserved = $nonLoopbackNetworkObserved
                sourceArtifacts = @((Get-ObjectValue -InputObject $artifactFacts -Name "sourceArtifacts" -Default @()))
                attestationStatus = $networkAttestationStatus
            }
        }
        attestations = [ordered]@{
            cpuIsolation = [ordered]@{
                status = $cpuAttestationStatus
                distinction = "Host CPU topology can be measured without proving exclusive CPU isolation, affinity, processor-group placement, container CPU limits, or host reservation."
                requiredEvidence = @("target CPU affinity/cpuset/cpus or VM vCPU reservation", "load-generator CPU affinity/cpuset/cpus or VM vCPU reservation", "operator attestation when bare-metal reservation is used")
            }
            networkIsolation = [ordered]@{
                status = $networkAttestationStatus
                distinction = "A reachable endpoint and a passing local benchmark do not prove a separated network path when loopback or same-host routing is present."
                requiredEvidence = @("non-loopback SUT endpoint", "route/NIC/virtual-switch/container-network metadata", "absence of localhost, 127.0.0.1, ::1, and host.docker.internal rewrites")
            }
            hostPlacement = [ordered]@{
                status = $placementAttestationStatus
                distinction = "Process ids prove local process execution, not separate target/load-generator host placement."
                requiredEvidence = @("target host identity", "load-generator host identity", "evidence that the identities are different or resources are otherwise isolated")
            }
            evidenceClass = [ordered]@{
                current = Get-ReadinessEvidenceClass -Aggregate $Cell
                requiredForIsolatedLocal = "isolated-local"
                status = if ($placementStatus -ne "same-host-observed" -and $nonLoopbackNetworkObserved -and $cpuAttestationStatus -eq "attested") { "satisfied" } else { "blocked" }
            }
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
            dockerMetricsCapturedCount = $loadToolDockerMetricsCaptured
            dockerMetricsMissingCount = $loadToolDockerMetricsMissing
            processMetricsCapturedCount = $loadToolProcessMetricsCaptured
            processMetricsMissingCount = $loadToolProcessMetricsMissing
            capturedCount = $loadToolMetricsCaptured
            missingCount = $loadToolMetricsMissing
            warnings = @($loadSaturationWarnings)
            unavailableReasons = @($loadUnavailableReasons)
        }
        isolatedLocalGate = [ordered]@{
            status = if ($isolatedLocalBlockers.Count -eq 0) { "passed" } else { "blocked" }
            blockers = @($isolatedLocalBlockers)
            blockerDetails = @($blockerDetails)
        }
        isolatedLocalRequirements = @($isolatedLocalRequirements)
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
            evidenceClass = "unknown"
            evidenceClassesSeen = @()
            cellReadiness = @()
            publishability = [ordered]@{
                status = "blocked"
                blockers = @("aggregate-results-json-missing")
            }
            checksumInventory = @()
            checksumInventoryCount = 0
        }
    }

    $aggregate = Get-Content -LiteralPath $aggregatePath -Raw | ConvertFrom-Json
    $aggregates = @($aggregate.aggregates | ForEach-Object { $_ })
    $cellReadiness = @()
    foreach ($cell in $aggregates) {
        $evidenceClass = Get-ReadinessEvidenceClass -Aggregate $cell
        $environmentGates = Get-EnvironmentGateAssessment -Cell $cell -RunRoot $resolvedRunRoot -RunMetadata (Get-ObjectValue -InputObject $aggregate -Name "metadata")
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
            elseif (($text -match "no-load-generator-saturation-check|load-generator-cpu-not-captured") -and
                $environmentGates.loadGeneratorSaturation.status -ne "process-telemetry-captured" -and
                $environmentGates.loadGeneratorSaturation.status -ne "telemetry-captured" -and
                $environmentGates.loadGeneratorSaturation.status -ne "not-saturated") {
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
$resolvedComponentPackageDirectory = Resolve-ComponentPackageDirectory -RequestedDirectory $ComponentPackageDirectory -RepoRoot $repoRoot -ProtocolLabRoot $resolvedProtocolLabRoot
$componentPackageEvidence = Get-ComponentPackageEvidence -Directory $resolvedComponentPackageDirectory -Selectors $ComponentPackage
$componentPackageArgumentSuffix = if (-not [string]::IsNullOrWhiteSpace($resolvedComponentPackageDirectory)) {
    " -ComponentPackageDirectory $resolvedComponentPackageDirectory"
}
else {
    ""
}
if (@($ComponentPackage).Count -gt 0) {
    $componentPackageArgumentSuffix += " -ComponentPackage $($ComponentPackage -join ',')"
}
$readinessComponentPackageArgumentSuffix = if (-not [string]::IsNullOrWhiteSpace($resolvedComponentPackageDirectory)) {
    " -ComponentPackageDirectory $resolvedComponentPackageDirectory"
}
else {
    ""
}
if (@($ComponentPackage).Count -gt 0) {
    $readinessComponentPackageArgumentSuffix += " -ComponentPackage $($ComponentPackage -join ',')"
}

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

$labControllerEvidence = Read-LabControllerEvidence -Path $LabControllerEvidencePath

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
        name = "Raw QUIC stream-throughput smoke"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 -Lane Smoke -Surface RawQuicStreamThroughput -CaptureCounters"
        mode = "local-source-reference"
        publishable = $false
    },
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
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\eng\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1 -ProtocolLabRoot $resolvedProtocolLabRoot -ProtocolLabExecutionRoot $resolvedProtocolLabExecutionRoot -ControllerUri http://10.10.99.176:5088 -PackageTarget Http3 -SuiteId h3-local-v1 -ScenarioId http3.payload.bytes.1kb -Protocol h3 -LoadProfileId smoke"
        mode = "package-backed-controller"
        publishable = $false
    },
    [ordered]@{
        name = "Package-backed raw QUIC rack lab smoke"
        command = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\eng\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1 -ProtocolLabRoot $resolvedProtocolLabRoot -ProtocolLabExecutionRoot $resolvedProtocolLabExecutionRoot -ControllerUri http://10.10.99.176:5088 -PackageTarget RawQuic -SuiteId quic-transport-v1-comparison -ScenarioId quic.transport.stream-throughput.1mb -Protocol quic -LoadProfileId smoke"
        mode = "package-backed-controller"
        publishable = $false
    }
)

$publishableRunbook = [ordered]@{
    localRepeatabilityCommand = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 -UseProjectReferences -ProtocolLabRoot $resolvedProtocolLabRoot -ProtocolLabExecutionRoot $protocolLabBenchmarkRoot$componentPackageArgumentSuffix -Suite raw-quic-transport-v1-smoke -Implementations quic-dotnet-raw-dev -Scenarios quic.transport.stream-throughput.1mb -DurationSeconds 15 -WarmupSeconds 5 -Repetitions $MinimumPublishableRepetitions -Connections 1 -StreamsPerConnection 1 -RunIdPrefix quic-local-repeat"
    isolatedLocalCommandTemplate = "pwsh -NoProfile -ExecutionPolicy Bypass -File $protocolLabBenchmarkScript -WorkflowProfile Comparison -Suite raw-quic-transport-v1-smoke -ImplementationIds <isolated-local-implementation-id> -ScenarioIds quic.transport.stream-throughput.1mb -Protocol quic -LoadProfileId local-comparison$componentPackageArgumentSuffix -RunIdPrefix quic-isolated-local-<yyyymmdd> -Output .artifacts\runs -Configuration Release -TargetMode external -BaseUrl <non-loopback-sut-endpoint-url> -DurationSeconds 30 -WarmupSeconds 10 -Repetitions $MinimumPublishableRepetitions -Connections 1 -StreamsPerConnection 1 -FailOnError"
    readinessProofCommandTemplate = "pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicProtocolLabReadinessEvidence.ps1 -ProtocolLabRoot $resolvedProtocolLabRoot -ProtocolLabExecutionRoot $resolvedProtocolLabExecutionRoot$readinessComponentPackageArgumentSuffix -ProtocolLabRunRoot <new-isolated-local-run-root> -RunId protocol-lab-readiness-isolated-local-<yyyymmddTHHmmssZ> -SkipPackageBuild"
    isolatedLocalUpgradeRequirements = @(
        "run the SUT and load generator on separate hosts, VMs, or isolated container hosts and retain both host identities",
        "use a non-loopback SUT endpoint; do not use localhost, 127.0.0.1, ::1, or host.docker.internal",
        "retain CPU isolation or reservation evidence for both sides: cpuset/cpus, processor affinity and processor group, VM vCPU reservation, or an operator-attested reserved-host policy",
        "retain target resource telemetry for every repetition, either direct process/container metrics or adapter-derived endpoint metrics when direct sampling is impossible",
        "retain load-generator process/container telemetry for every repetition and record saturation warnings",
        "rerun New-QuicProtocolLabReadinessEvidence.ps1 against the new run root; keep the evidence class local-lab until these artifacts are present"
    )
    externalReferenceCommandTemplate = "pwsh -NoProfile -ExecutionPolicy Bypass -File $protocolLabBenchmarkScript -WorkflowProfile Comparison -Suite raw-quic-transport-v1-smoke -ImplementationIds <publishable-implementation-id> -ScenarioIds quic.transport.stream-throughput.1mb -Protocol quic -LoadProfileId local-comparison$componentPackageArgumentSuffix -RunIdPrefix quic-publishable-<yyyymmdd> -Output .artifacts\runs -Configuration Release -TargetMode external -BaseUrl <sut-endpoint-url> -DurationSeconds 30 -WarmupSeconds 10 -Repetitions $MinimumPublishableRepetitions -Connections 1 -StreamsPerConnection 1 -FailOnError"
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
    componentPackageDirectory = $resolvedComponentPackageDirectory
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
    componentPackageEvidence = $componentPackageEvidence
    http3RunnerEvidence = $http3RunnerEvidence
    labControllerEvidence = $labControllerEvidence
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
Add-Line $summary "## Lab Controller Topology Evidence"
Add-Line $summary ""
Add-Line $summary "- Present: ``$($labControllerEvidence.present)``"
if ($labControllerEvidence.present) {
    Add-Line $summary "- Controller: ``$($labControllerEvidence.controllerUrl)``"
    Add-Line $summary "- Snapshot path: ``$($labControllerEvidence.path)``"
    Add-Line $summary "- Snapshot SHA-256: ``$($labControllerEvidence.sha256)``"
    Add-Line $summary "- Ready nodes: ``$($labControllerEvidence.summary.readyNodeCount)`` / ``$($labControllerEvidence.summary.nodeCount)``"
    Add-Line $summary "- SUT nodes: ``$(@($labControllerEvidence.summary.sutNodes) -join ', ')``"
    Add-Line $summary "- Load nodes: ``$(@($labControllerEvidence.summary.loadNodes) -join ', ')``"
    Add-Line $summary "- Benchmark addresses: ``$(@($labControllerEvidence.summary.benchmarkAddresses) -join ', ')``"
    Add-Line $summary "- Physical host labels: ``$(@($labControllerEvidence.summary.physicalHostLabels) -join ', ')``"
    Add-Line $summary "- Separate roles available: ``$($labControllerEvidence.summary.separateRolesAvailable)``"
    Add-Line $summary "- Same physical host observed: ``$($labControllerEvidence.summary.samePhysicalHostObserved)``"
    Add-Line $summary "- Isolated-pair preview can submit: ``$($labControllerEvidence.summary.isolatedPairPreview.canSubmit)``"
    if (@($labControllerEvidence.summary.blockers).Count -gt 0) {
        Add-Line $summary ""
        Add-Line $summary "Topology blockers:"
        foreach ($blocker in @($labControllerEvidence.summary.blockers)) {
            Add-Line $summary "- ``$blocker``"
        }
    }
}
else {
    Add-Line $summary "- Blocker: $($labControllerEvidence.blocker)"
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
Add-Line $summary "## Component Package Evidence"
Add-Line $summary ""
Add-Line $summary "- Directory: ``$($componentPackageEvidence.directory)``"
Add-Line $summary "- Present: ``$($componentPackageEvidence.present)``"
if (-not [string]::IsNullOrWhiteSpace([string]$componentPackageEvidence.blocker)) {
    Add-Line $summary "- Blocker: $($componentPackageEvidence.blocker)"
}
foreach ($package in @($componentPackageEvidence.packages)) {
    Add-Line $summary "- ``$($package.packageId)`` version ``$($package.packageVersion)``"
    Add-Line $summary "  - Kind: ``$($package.kind)``"
    Add-Line $summary "  - Path: ``$($package.path)``"
    Add-Line $summary "  - SHA-256: ``$($package.sha256)``"
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
        Add-Line $summary "    - Measured CPU topology: host ``$($cell.environmentGates.measuredTopology.hostCpuTopology.hostName)``, processors ``$($cell.environmentGates.measuredTopology.hostCpuTopology.processorCount)``, attestation ``$($cell.environmentGates.measuredTopology.hostCpuTopology.attestationStatus)``"
        Add-Line $summary "    - Placement topology: ``$($cell.environmentGates.measuredTopology.processPlacement.status)``; target host ``$($cell.environmentGates.measuredTopology.processPlacement.targetHostIdentity)``; load-generator host ``$($cell.environmentGates.measuredTopology.processPlacement.loadGeneratorHostIdentity)``"
        Add-Line $summary "    - Network topology: ``$($cell.environmentGates.measuredTopology.networkPath.status)``; target host ``$($cell.environmentGates.measuredTopology.networkPath.targetEndpointHost)`` (``$($cell.environmentGates.measuredTopology.networkPath.targetAddressFamily)``); load-generator URL host ``$($cell.environmentGates.measuredTopology.networkPath.loadGeneratorUrlHost)``"
        Add-Line $summary "    - Target resource metrics: ``$($cell.environmentGates.targetResourceMetrics.status)`` (captured ``$($cell.environmentGates.targetResourceMetrics.capturedCount)``, missing ``$($cell.environmentGates.targetResourceMetrics.missingCount)``)"
        Add-Line $summary "    - Load-generator saturation: ``$($cell.environmentGates.loadGeneratorSaturation.status)``"
        Add-Line $summary "    - Attestation gates: CPU ``$($cell.environmentGates.attestations.cpuIsolation.status)``, network ``$($cell.environmentGates.attestations.networkIsolation.status)``, placement ``$($cell.environmentGates.attestations.hostPlacement.status)``"
        if (@($cell.environmentGates.isolatedLocalGate.blockers).Count -gt 0) {
            Add-Line $summary "    - Isolated-local blockers: ``$(@($cell.environmentGates.isolatedLocalGate.blockers) -join ', ')``"
        }
        foreach ($requirement in @($cell.environmentGates.isolatedLocalRequirements)) {
            Add-Line $summary "      - ``$($requirement.requirement)``: ``$($requirement.status)``; $($requirement.upgradeInstruction)"
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
Add-Line $summary "## Isolated-Local Upgrade Runbook"
Add-Line $summary ""
Add-Line $summary "Isolated-local command template:"
Add-Line $summary ""
Add-Line $summary '```powershell'
Add-Line $summary $publishableRunbook.isolatedLocalCommandTemplate
Add-Line $summary '```'
Add-Line $summary ""
Add-Line $summary "Rerun readiness proof after collecting the new ProtocolLab run:"
Add-Line $summary ""
Add-Line $summary '```powershell'
Add-Line $summary $publishableRunbook.readinessProofCommandTemplate
Add-Line $summary '```'
Add-Line $summary ""
Add-Line $summary "Upgrade requirements:"
foreach ($requirement in @($publishableRunbook.isolatedLocalUpgradeRequirements)) {
    Add-Line $summary "- $requirement."
}

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
