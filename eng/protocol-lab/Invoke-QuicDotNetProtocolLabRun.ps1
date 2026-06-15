[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ControllerUri,

    [ValidateSet("Http3", "RawQuic")]
    [string] $PackageTarget = "Http3",

    [string] $ProtocolLabRoot = "../protocol-lab",

    [string] $Project,

    [string] $Configuration = "Release",

    [string[]] $RuntimeIdentifier = @("linux-x64"),

    [string] $SuiteId = "h3-local-v1",

    [string[]] $ScenarioId = @("http3.payload.bytes.64kb"),

    [string] $Protocol = "h3",

    [string] $TestExecutorId,

    [string] $LoadProfileId = "smoke",

    [string[]] $RequiredCapability,

    [string[]] $PackageReference = @(),

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
                ScenarioIds = @("http3.payload.bytes.64kb")
                SupportedSuiteIds = @("h3-local-v1", "h3-large-body-v1")
                SupportedScenarioIds = @("http3.payload.bytes.64kb", "http3.payload.bytes.1mb")
                Protocol = "h3"
                TestExecutorId = "managed-httpclient-h3-load"
                RequiredCapabilities = @()
                SupportedCapabilities = @("httpPlaintext", "httpJson", "httpBytes")
            }
        }
        "RawQuic" {
            return [pscustomobject]@{
                DefaultProject = "eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj"
                ImplementationId = "quic-dotnet-raw-dev"
                SuiteId = "quic-transport-v1-comparison"
                ScenarioIds = @("quic.transport.multiplex.100x64kb", "quic.transport.duplex-streams")
                SupportedSuiteIds = @("quic-transport-v1-comparison")
                SupportedScenarioIds = @("quic.transport.multiplex.100x64kb", "quic.transport.duplex-streams")
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
    $RequiredCapability = $targetConfig.RequiredCapabilities
}

Assert-RunSelection `
    -Target $PackageTarget `
    -TargetConfig $targetConfig `
    -SuiteId $SuiteId `
    -ScenarioIds $ScenarioId `
    -Protocol $Protocol `
    -TestExecutorId $TestExecutorId `
    -RequiredCapabilities $RequiredCapability

$protocolLabRootFullPath = Resolve-PathOrThrow -Path $ProtocolLabRoot -Description "ProtocolLab root"
$submitScript = Join-Path $protocolLabRootFullPath "scripts/lab/Submit-ProtocolLabPackageRun.ps1"
if (-not (Test-Path -LiteralPath $submitScript -PathType Leaf)) {
    throw "ProtocolLab submit script was not found: $submitScript"
}

$rawComponentPackageBuilder = Join-Path $protocolLabRootFullPath "scripts/lab/New-ProtocolLabRawQuicComponentPackages.ps1"
if ($PackageTarget -eq "RawQuic" -and -not (Test-Path -LiteralPath $rawComponentPackageBuilder -PathType Leaf)) {
    throw "ProtocolLab raw QUIC component package builder was not found: $rawComponentPackageBuilder"
}

$h3ComponentPackageBuilder = Join-Path $protocolLabRootFullPath "scripts/lab/New-ProtocolLabH3ComponentPackages.ps1"
if ($PackageTarget -eq "Http3" -and [string]::Equals($SuiteId, "h3-large-body-v1", [StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path -LiteralPath $h3ComponentPackageBuilder -PathType Leaf)) {
    throw "ProtocolLab H3 component package builder was not found: $h3ComponentPackageBuilder"
}

$packageResultJson = & pwsh -NoLogo -NoProfile -File (Join-Path $PSScriptRoot "New-QuicDotNetProtocolLabPackage.ps1") `
    -PackageTarget $PackageTarget `
    -ProtocolLabRoot $protocolLabRootFullPath `
    -Project $Project `
    -Configuration $Configuration `
    -RuntimeIdentifier $RuntimeIdentifier `
    -Force

$packageResult = $packageResultJson | ConvertFrom-Json
$resultRoot = Join-Path (Get-Location) "artifacts/protocol-lab/results"
New-Item -ItemType Directory -Force -Path $resultRoot | Out-Null

$componentPackageResult = $null
$componentPackageReferences = @()
$componentPackagePaths = @()
if ($PackageTarget -eq "RawQuic") {
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
        throw "H3 component package creation failed."
    }

    $componentPackageResult = $componentPackageResultJson | ConvertFrom-Json
    $componentPackageReferences = @($componentPackageResult.packageReferences)
    $componentPackagePaths = @(
        [string]$componentPackageResult.testExecutorPackage.path,
        [string]$componentPackageResult.scenarioPackage.path
    )
}
elseif ($PackageTarget -eq "Http3" -and [string]::Equals($SuiteId, "h3-large-body-v1", [StringComparison]::OrdinalIgnoreCase)) {
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
$submitParameters = @{
    ControllerUri = $ControllerUri
    PackagePath = $packageResult.path
    ImplementationId = $targetConfig.ImplementationId
    TestExecutorId = $TestExecutorId
    SuiteId = $SuiteId
    ScenarioId = $ScenarioId
    Protocol = $Protocol
    LoadProfileId = $LoadProfileId
    TimeoutSeconds = $TimeoutSeconds
    ArtifactOutputPath = $artifactPath
}

$allPackageReferences = @($PackageReference)
if ($componentPackagePaths.Count -gt 0) {
    $submitParameters.Add("AdditionalPackagePath", $componentPackagePaths)
}

if ($allPackageReferences.Count -gt 0) {
    $submitParameters.Add("PackageReference", $allPackageReferences)
}

$requiredCapabilities = @($RequiredCapability)
if ($requiredCapabilities.Count -gt 0) {
    $submitParameters.Add("RequiredCapability", $requiredCapabilities)
}

if ($NoWait) {
    $submitParameters.Add("NoWait", $true)
}

$jobResultJson = & $submitScript @submitParameters
$jobResult = $jobResultJson | ConvertFrom-Json
$jobResultPath = Join-Path $resultRoot "$($jobResult.jobId).json"
$jobResultJson | Set-Content -LiteralPath $jobResultPath

[ordered]@{
    package = $packageResult
    componentPackages = $componentPackageResult
    componentPackageReferences = $componentPackageReferences
    packageReferences = $PackageReference
    job = $jobResult
    jobResultPath = $jobResultPath
} | ConvertTo-Json -Depth 32
