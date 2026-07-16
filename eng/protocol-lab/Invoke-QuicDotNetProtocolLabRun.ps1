[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ControllerUri,

    [ValidateSet("Http3", "RawQuic")]
    [string] $PackageTarget = "Http3",

    [string] $ProtocolLabRoot = "../protocol-lab",

    [string] $ProtocolLabExecutionRoot,

    [string] $Project,

    [string] $Configuration = "Release",

    [string[]] $RuntimeIdentifier = @("linux-x64"),

    [string] $SuiteId = "h3-local-v1",

    [string[]] $ScenarioId = @("http3.payload.bytes.1kb"),

    [string] $Protocol = "h3",

    [string] $TestExecutorId,

    [string] $LoadProfileId = "smoke",

    [int] $Repetitions,

    [switch] $CaptureCounters,

    [switch] $CaptureTrace,

    [string[]] $RequiredCapability,

    [string[]] $PackageReference = @(),

    [switch] $UsePackageReferenceOnly,

    [string] $RawQuicTestExecutorRuntimeIdentifier = "linux-x64",

    [switch] $BinaryBackedRawQuicTestExecutor,

    [int] $TimeoutSeconds = 1800,

    [switch] $NoWait
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PathOrThrow {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description was not found: $Path"
    }

    return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
}

function Resolve-OptionalProtocolLabExecutionRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ContractRoot,

        [string] $RequestedExecutionRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedExecutionRoot)) {
        return Resolve-PathOrThrow -Path $RequestedExecutionRoot -Description "ProtocolLab execution root"
    }

    $environmentRoot = [Environment]::GetEnvironmentVariable("PROTOCOL_LAB_EXECUTION_ROOT")
    if (-not [string]::IsNullOrWhiteSpace($environmentRoot) -and (Test-Path -LiteralPath $environmentRoot)) {
        return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $environmentRoot).Path)
    }

    $siblingInternalRoot = Join-Path (Split-Path -Parent $ContractRoot) "protocol-lab-internal"
    if (Test-Path -LiteralPath $siblingInternalRoot) {
        return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $siblingInternalRoot).Path)
    }

    return $ContractRoot
}

function Get-PackageTargetConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Target
    )

    switch ($Target) {
        "Http3" {
            return [pscustomobject]@{
                DefaultProject = "samples/Incursa.Http3.Samples.TechEmpower/Incursa.Http3.Samples.TechEmpower.csproj"
                ImplementationId = "quic-dotnet-dev"
                SuiteId = "h3-local-v1"
                ScenarioIds = @("http3.payload.bytes.1kb")
                SupportedSuiteIds = @("h3-local-v1", "h3-large-body-v1")
                SupportedScenarioIds = @("http3.payload.bytes.1kb", "http3.payload.bytes.64kb", "http3.payload.bytes.1mb", "http3.payload.stream.100x16kb")
                SupportedLoadProfileIds = @("smoke", "local-regression", "local-comparison", "h3-small-payload-c32", "h3-small-payload-c128")
                Protocol = "h3"
                TestExecutorId = "managed-httpclient-h3-load"
                RequiredCapabilities = @()
                SupportedCapabilities = @("httpPlaintext", "httpJson", "httpBytes", "httpStreaming")
            }
        }
        "RawQuic" {
            return [pscustomobject]@{
                DefaultProject = "eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj"
                ImplementationId = "quic-dotnet-raw-dev"
                SuiteId = "quic-transport-v1-comparison"
                ScenarioIds = @("quic.transport.handshake-cold", "quic.transport.latency.echo-1kb", "quic.transport.connection-churn", "quic.transport.stream-throughput.1mb", "quic.transport.multiplex.100x64kb", "quic.transport.stream-limits.100x64kb", "quic.transport.duplex-streams", "quic.transport.duplex-streams-peer-matrix")
                SupportedSuiteIds = @("quic-transport-v1-comparison")
                SupportedScenarioIds = @("quic.transport.handshake-cold", "quic.transport.latency.echo-1kb", "quic.transport.connection-churn", "quic.transport.stream-throughput.1mb", "quic.transport.multiplex.100x64kb", "quic.transport.stream-limits.100x64kb", "quic.transport.duplex-streams", "quic.transport.duplex-streams-peer-matrix")
                SupportedLoadProfileIds = @()
                Protocol = "quic"
                TestExecutorId = "quic-go-raw-load"
                RequiredCapabilities = @("quicTransport", "quicStreams")
                SupportedCapabilities = @("quicTransport", "quicStreams", "quicMultiplexing", "quicDuplex")
            }
        }
        default {
            throw "Unsupported package target '$Target'."
        }
    }
}

function Assert-RunSelection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Target,

        [Parameter(Mandatory = $true)]
        [pscustomobject] $TargetConfig,

        [Parameter(Mandatory = $true)]
        [string] $SuiteId,

        [Parameter(Mandatory = $true)]
        [string[]] $ScenarioIds,

        [Parameter(Mandatory = $true)]
        [string] $LoadProfileId,

        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [string] $TestExecutorId,

        [string[]] $RequiredCapabilities = @()
    )

    if (-not [string]::Equals($Protocol, $TargetConfig.Protocol, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Target package target only supports protocol '$($TargetConfig.Protocol)'. It must not route through the managed H3 helper or another ProtocolLab lane."
    }

    $supportedSuiteIds = if ($TargetConfig.PSObject.Properties.Name -contains "SupportedSuiteIds") {
        @($TargetConfig.SupportedSuiteIds)
    }
    else {
        @($TargetConfig.SuiteId)
    }
    if ($supportedSuiteIds -notcontains $SuiteId) {
        throw "$Target package target only supports suite(s): $($supportedSuiteIds -join ', ')."
    }

    if (-not [string]::Equals($TestExecutorId, $TargetConfig.TestExecutorId, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Target package target only supports test executor '$($TargetConfig.TestExecutorId)'. It must not route through another ProtocolLab lane."
    }

    $supportedScenarioIds = @($TargetConfig.SupportedScenarioIds)
    $unsupportedScenarioIds = @($ScenarioIds | Where-Object { $supportedScenarioIds -notcontains $_ })
    if ($unsupportedScenarioIds.Count -gt 0) {
        throw "$Target package target scenario(s) are not declared by the package template: $($unsupportedScenarioIds -join ', ')."
    }

    $supportedLoadProfileIds = @($TargetConfig.SupportedLoadProfileIds)
    if ($supportedLoadProfileIds.Count -gt 0 -and $supportedLoadProfileIds -notcontains $LoadProfileId) {
        throw "$Target package target load profile '$LoadProfileId' is not declared by the package template. Supported profiles: $($supportedLoadProfileIds -join ', ')."
    }

    $supportedCapabilities = @($TargetConfig.SupportedCapabilities)
    $unsupportedCapabilities = @($RequiredCapabilities | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            $supportedCapabilities -notcontains $_
        })
    if ($unsupportedCapabilities.Count -gt 0) {
        throw "$Target package target capability requirement(s) are not declared by the package template: $($unsupportedCapabilities -join ', ')."
    }
}

$targetConfig = Get-PackageTargetConfig -Target $PackageTarget
$requiredCapabilityWasSpecified = $PSBoundParameters.ContainsKey("RequiredCapability")
if ([string]::IsNullOrWhiteSpace($Project)) {
    $Project = $targetConfig.DefaultProject
}
if ($PackageTarget -eq "RawQuic" -and -not $PSBoundParameters.ContainsKey("RuntimeIdentifier")) {
    $RuntimeIdentifier = @("linux-x64", "win-x64")
}
if (-not $PSBoundParameters.ContainsKey("SuiteId")) {
    $SuiteId = $targetConfig.SuiteId
}
if (-not $PSBoundParameters.ContainsKey("ScenarioId")) {
    $ScenarioId = $targetConfig.ScenarioIds
}
if (-not $PSBoundParameters.ContainsKey("Protocol")) {
    $Protocol = $targetConfig.Protocol
}
if (-not $PSBoundParameters.ContainsKey("TestExecutorId")) {
    $TestExecutorId = $targetConfig.TestExecutorId
}
if (-not $PSBoundParameters.ContainsKey("RequiredCapability")) {
    $RequiredCapability = @()
}
if ($PSBoundParameters.ContainsKey("Repetitions") -and $Repetitions -lt 1) {
    throw "Repetitions must be greater than zero when specified."
}
if ($UsePackageReferenceOnly -and $PackageReference.Count -eq 0) {
    throw "UsePackageReferenceOnly requires at least one -PackageReference entry."
}

Assert-RunSelection `
    -Target $PackageTarget `
    -TargetConfig $targetConfig `
    -SuiteId $SuiteId `
    -ScenarioIds $ScenarioId `
    -LoadProfileId $LoadProfileId `
    -Protocol $Protocol `
    -TestExecutorId $TestExecutorId `
    -RequiredCapabilities $RequiredCapability

$protocolLabRootFullPath = Resolve-PathOrThrow -Path $ProtocolLabRoot -Description "ProtocolLab root"
$protocolLabExecutionRootFullPath = Resolve-OptionalProtocolLabExecutionRoot `
    -ContractRoot $protocolLabRootFullPath `
    -RequestedExecutionRoot $ProtocolLabExecutionRoot

$rawComponentPackageBuilder = Join-Path $protocolLabExecutionRootFullPath "scripts/lab/New-ProtocolLabRawQuicComponentPackages.ps1"
$rawComponentPackageBuilderExists = Test-Path -LiteralPath $rawComponentPackageBuilder -PathType Leaf

$h3ComponentPackageBuilder = Join-Path $protocolLabExecutionRootFullPath "scripts/lab/New-ProtocolLabH3ComponentPackages.ps1"
$h3ComponentPackageBuilderExists = Test-Path -LiteralPath $h3ComponentPackageBuilder -PathType Leaf
if ($PackageTarget -eq "RawQuic" -and -not $rawComponentPackageBuilderExists -and $PackageReference.Count -eq 0) {
    throw "ProtocolLab raw QUIC component package builder was not found: $rawComponentPackageBuilder. Package-backed raw QUIC jobs require package-provided scenario and test-executor inventory; pass -PackageReference entries as 'packageId|packageVersion|sha256' or set -ProtocolLabExecutionRoot to protocol-lab-internal."
}

if ($PackageTarget -eq "Http3" -and -not $h3ComponentPackageBuilderExists -and $PackageReference.Count -eq 0) {
    throw "ProtocolLab H3 component package builder was not found: $h3ComponentPackageBuilder. Package-backed H3 jobs require package-provided scenario and test-executor inventory; pass -PackageReference entries as 'packageId|packageVersion|sha256' or set -ProtocolLabExecutionRoot to protocol-lab-internal."
}

function ConvertTo-LabPackageReference {
    param([Parameter(Mandatory = $true)] $Metadata)

    return [ordered]@{
        packageId = [string]$Metadata.packageId
        packageVersion = [string]$Metadata.packageVersion
        sha256 = [string]$Metadata.sha256
    }
}

function ConvertFrom-PackageReferenceString {
    param([Parameter(Mandatory = $true)][string] $Reference)

    $parts = $Reference.Split('|', 3, [StringSplitOptions]::TrimEntries)
    if ($parts.Length -ne 3 -or
        [string]::IsNullOrWhiteSpace($parts[0]) -or
        [string]::IsNullOrWhiteSpace($parts[1]) -or
        [string]::IsNullOrWhiteSpace($parts[2])) {
        throw "Package reference '$Reference' must use 'packageId|packageVersion|sha256'."
    }

    return [ordered]@{
        packageId = $parts[0]
        packageVersion = $parts[1]
        sha256 = $parts[2].ToLowerInvariant()
    }
}

function Upload-LabPackage {
    param(
        [Parameter(Mandatory = $true)][string] $ControllerUri,
        [Parameter(Mandatory = $true)][string] $Path
    )

    Add-Type -AssemblyName System.Net.Http
    $resolved = Resolve-PathOrThrow -Path $Path -Description "Lab package"
    $client = [System.Net.Http.HttpClient]::new()
    $form = [System.Net.Http.MultipartFormDataContent]::new()
    $stream = [System.IO.File]::OpenRead($resolved)
    try {
        $fileContent = [System.Net.Http.StreamContent]::new($stream)
        $form.Add($fileContent, "file", [System.IO.Path]::GetFileName($resolved))
        $response = $client.PostAsync("$ControllerUri/api/lab/packages", $form).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "Package upload failed with HTTP $([int]$response.StatusCode): $body"
        }

        return $body | ConvertFrom-Json
    }
    finally {
        $stream.Dispose()
        $form.Dispose()
        $client.Dispose()
    }
}

function Invoke-ControllerJson {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][string] $Method,
        [object] $Body
    )

    $parameters = @{
        Uri = $Uri
        Method = $Method
    }
    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = ($Body | ConvertTo-Json -Depth 32)
    }

    return Invoke-RestMethod @parameters
}

function Wait-LabJob {
    param(
        [Parameter(Mandatory = $true)][string] $ControllerUri,
        [Parameter(Mandatory = $true)][string] $JobId,
        [Parameter(Mandatory = $true)][int] $TimeoutSeconds
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $job = Invoke-ControllerJson -Uri "$ControllerUri/api/lab/jobs/$JobId" -Method "GET"
        if (@("Completed", "Failed", "Cancelled") -contains [string]$job.status) {
            return $job
        }

        Start-Sleep -Seconds 5
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting for lab job '$JobId' after $TimeoutSeconds seconds."
}

$packageResult = $null
if (-not $UsePackageReferenceOnly) {
    $packageResultJson = & (Join-Path $PSScriptRoot "New-QuicDotNetProtocolLabPackage.ps1") `
        -PackageTarget $PackageTarget `
        -ProtocolLabRoot $protocolLabRootFullPath `
        -Project $Project `
        -Configuration $Configuration `
        -RuntimeIdentifier $RuntimeIdentifier `
        -AllowDirtySource `
        -Force

    $packageResult = $packageResultJson | ConvertFrom-Json
}
$resultRoot = Join-Path (Get-Location) "artifacts/protocol-lab/results"
New-Item -ItemType Directory -Force -Path $resultRoot | Out-Null

$componentPackageResult = $null
$componentPackageReferences = @()
$componentPackagePaths = @()
if (-not $UsePackageReferenceOnly -and $PackageTarget -eq "RawQuic" -and $rawComponentPackageBuilderExists) {
    $componentOutputRoot = Join-Path (Get-Location) "artifacts/protocol-lab/component-packages/$($packageResult.packageVersion)"
    $componentArgs = @(
        "-NoLogo",
        "-NoProfile",
        "-File",
        $rawComponentPackageBuilder,
        "-PackageVersion",
        $packageResult.packageVersion,
        "-OutputRoot",
        $componentOutputRoot,
        "-TestExecutorRuntimeIdentifier",
        $RawQuicTestExecutorRuntimeIdentifier,
        "-Force"
    )

    if (-not $BinaryBackedRawQuicTestExecutor) {
        $componentArgs += "-SourceBackedTestExecutor"
    }

    $componentPackageResultJson = & pwsh @componentArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Raw QUIC component package creation failed."
    }

    $componentPackageResult = $componentPackageResultJson | ConvertFrom-Json
    $componentPackageReferences = @($componentPackageResult.packageReferences)
    $componentPackagePaths = @(
        [string]$componentPackageResult.testExecutorPackage.path,
        [string]$componentPackageResult.scenarioPackage.path
    )
}
elseif (-not $UsePackageReferenceOnly -and $PackageTarget -eq "Http3" -and $h3ComponentPackageBuilderExists) {
    $componentOutputRoot = Join-Path (Get-Location) "artifacts/protocol-lab/component-packages/$($packageResult.packageVersion)"
    $componentArgs = @(
        "-NoLogo",
        "-NoProfile",
        "-File",
        $h3ComponentPackageBuilder,
        "-PackageVersion",
        $packageResult.packageVersion,
        "-OutputRoot",
        $componentOutputRoot,
        "-SuiteId",
        $SuiteId,
        "-ScenarioId",
        ($ScenarioId -join ",")
    ) + @(
        "-Force"
    )

    $componentPackageResultJson = & pwsh @componentArgs
    $componentPackageResult = $componentPackageResultJson | ConvertFrom-Json
    $componentPackageReferences = @($componentPackageResult.packageReferences)
    $componentPackagePaths = @(
        [string]$componentPackageResult.testExecutorPackage.path,
        [string]$componentPackageResult.scenarioPackage.path
    )
}

$artifactPath = Join-Path $resultRoot "latest.zip"
$uploadedPackages = @()
if (-not $UsePackageReferenceOnly) {
    $uploadedPackages += Upload-LabPackage -ControllerUri $ControllerUri -Path $packageResult.path
    foreach ($componentPackagePath in $componentPackagePaths) {
        $uploadedPackages += Upload-LabPackage -ControllerUri $ControllerUri -Path $componentPackagePath
    }
}

$allPackageReferences = @()
$allPackageReferences += @($uploadedPackages | ForEach-Object { ConvertTo-LabPackageReference -Metadata $_ })
$allPackageReferences += @($PackageReference | ForEach-Object { ConvertFrom-PackageReferenceString -Reference $_ })

$requiredCapabilities = @()
if ($requiredCapabilityWasSpecified) {
    $requiredCapabilities = @($RequiredCapability | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
            [ordered]@{
                name = $_
                value = "true"
            }
        })
}

$runIdPrefix = "$($targetConfig.ImplementationId)-$((Get-Date -AsUTC -Format 'yyyyMMddTHHmmssZ'))"
$jobRequest = [ordered]@{
    suiteIds = @($SuiteId)
    implementationIds = @($targetConfig.ImplementationId)
    scenarioIds = @($ScenarioId)
    protocols = @($Protocol)
    testExecutorIds = @($TestExecutorId)
    loadProfileId = $LoadProfileId
    runIdPrefix = $runIdPrefix
    maxAttempts = 1
    packages = $allPackageReferences
    requiredCapabilities = $requiredCapabilities
    extensions = [ordered]@{}
}
if ($PSBoundParameters.ContainsKey("Repetitions")) {
    $jobRequest.repetitions = $Repetitions
}
if ($CaptureCounters) {
    $jobRequest.extensions.captureCounters = $true
}
if ($CaptureTrace) {
    $jobRequest.extensions.captureTrace = $true
}

$submittedJob = Invoke-ControllerJson -Uri "$ControllerUri/api/lab/jobs" -Method "POST" -Body $jobRequest
$jobResult = if ($NoWait) {
    $submittedJob
}
else {
    Wait-LabJob -ControllerUri $ControllerUri -JobId $submittedJob.jobId -TimeoutSeconds $TimeoutSeconds
}

$jobResultJson = $jobResult | ConvertTo-Json -Depth 32
$jobResultPath = Join-Path $resultRoot "$($jobResult.jobId).json"
$jobResultJson | Set-Content -LiteralPath $jobResultPath

[ordered]@{
    package = $packageResult
    componentPackages = $componentPackageResult
    componentPackageReferences = $componentPackageReferences
    packageReferences = $PackageReference
    protocolLabRoot = $protocolLabRootFullPath
    protocolLabExecutionRoot = $protocolLabExecutionRootFullPath
    uploadedPackages = $uploadedPackages
    artifactOutputPath = $artifactPath
    job = $jobResult
    jobResultPath = $jobResultPath
    repetitions = $(if ($PSBoundParameters.ContainsKey("Repetitions")) { $Repetitions } else { $null })
} | ConvertTo-Json -Depth 32
