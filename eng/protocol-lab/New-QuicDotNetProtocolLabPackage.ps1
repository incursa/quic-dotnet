[CmdletBinding()]
param(
    [ValidateSet("Http3", "RawQuic")]
    [string] $PackageTarget = "Http3",

    [string] $ProtocolLabRoot = "../protocol-lab",

    [string] $Project,

    [string] $Configuration = "Release",

    [string[]] $RuntimeIdentifier = @("linux-x64"),

    [string] $PackageVersion,

    [ValidateSet("", "legacy_current", "immediate", "read_dominant_batch", "shadow")]
    [string] $AdaptiveRuntimeReceiveCreditPolicy = "",

    [string] $OutputPath,

    [string] $WorkRoot,

    [switch] $Force,

    [switch] $NoRestore,

    [switch] $AllowDirtySource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-GitValue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [Parameter(Mandatory = $true)]
        [string] $Description,

        [switch] $AllowEmpty
    )

    $output = & git -C $RepositoryRoot @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read $Description from the quic-dotnet repository."
    }

    $value = ($output | Out-String).Trim()
    if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($value)) {
        throw "Git returned an empty $Description for the quic-dotnet repository."
    }

    return $value
}

function Get-DefaultPackageVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [bool] $SourceClean
    )

    $timestamp = Get-Date -AsUTC -Format "yyyyMMddTHHmmssZ"
    $shortSha = "nogit"
    $dirty = if ($SourceClean) { "clean" } else { "dirty" }

    try {
        $shortSha = (git -C $RepositoryRoot rev-parse --short HEAD 2>$null).Trim()
    }
    catch {
        $shortSha = "nogit"
        $dirty = "unknown"
    }

    return "dev-$timestamp-$shortSha-$dirty"
}

function Get-PackageSourceScope {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Target
    )

    $common = @(
        "Directory.Build.props",
        "Directory.Packages.props",
        "global.json",
        "NuGet.config",
        "eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1"
    )

    if ($Target -eq "RawQuic") {
        return $common + @(
            "eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic",
            "eng/protocol-lab/servers/IncursaRawQuicServer",
            "eng/protocol-lab/templates/raw-quic",
            "src/Incursa.Quic"
        )
    }

    return $common + @(
        "eng/protocol-lab/templates/protocol-lab-package.json",
        "eng/protocol-lab/templates/protocol-lab.internal.json",
        "eng/protocol-lab/templates/implementations",
        "eng/protocol-lab/templates/scripts",
        "samples/Incursa.Http3.Samples.TechEmpower",
        "src/Incursa.Quic",
        "src/Incursa.Quic.Http3",
        "src/Incursa.Qpack"
    )
}

function Get-OptionalToolVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return $null
    }

    $output = & $command.Source @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    return (($output -join "`n").Trim())
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Value,

        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $json = $Value | ConvertTo-Json -Depth 32
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function New-DeterministicZipArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SourceRoot,

        [Parameter(Mandatory = $true)]
        [string] $DestinationPath
    )

    $fixedTimestamp = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $archiveStream = [System.IO.File]::Open(
        $DestinationPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $archiveStream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $true,
            [System.Text.UTF8Encoding]::new($false))
        try {
            $files = @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force | Sort-Object {
                    [System.IO.Path]::GetRelativePath($SourceRoot, $_.FullName).Replace('\', '/')
                })
            foreach ($file in $files) {
                $entryName = [System.IO.Path]::GetRelativePath($SourceRoot, $file.FullName).Replace('\', '/')
                $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                $entryStream = $entry.Open()
                $sourceStream = [System.IO.File]::OpenRead($file.FullName)
                try {
                    $sourceStream.CopyTo($entryStream)
                }
                finally {
                    $sourceStream.Dispose()
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $archiveStream.Dispose()
    }
}

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

function Assert-PathUnderRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Root,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootFullPath = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)

    if ([string]::Equals($fullPath, $rootFullPath, [StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    $rootPrefix = $rootFullPath + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must resolve under the quic-dotnet root: $Path"
    }
}

function Get-PackageTargetConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Target
    )

    switch ($Target) {
        "Http3" {
            return [pscustomobject]@{
                PackageId = "quic-dotnet-dev"
                DefaultProject = "samples/Incursa.Http3.Samples.TechEmpower/Incursa.Http3.Samples.TechEmpower.csproj"
                TemplateRoot = Join-Path $PSScriptRoot "templates"
                UseIncursaQuicSourceRoot = $false
                UseProtocolLabContracts = $false
                RawServerProject = $null
                SelfContained = $false
                RequiresDotNet = $true
                RequiresPwsh = $true
                RequiresBash = $true
            }
        }
        "RawQuic" {
            return [pscustomobject]@{
                PackageId = "quic-dotnet-raw-dev"
                DefaultProject = "eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj"
                TemplateRoot = Join-Path (Join-Path $PSScriptRoot "templates") "raw-quic"
                UseIncursaQuicSourceRoot = $true
                UseProtocolLabContracts = $false
                RawServerProject = "eng/protocol-lab/servers/IncursaRawQuicServer/IncursaRawQuicServer.csproj"
                SelfContained = $false
                RequiresDotNet = $true
                RequiresPwsh = $true
                RequiresBash = $false
            }
        }
        default {
            throw "Unsupported package target '$Target'."
        }
    }
}

function Get-ProtocolLabEnvironmentKey {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RuntimeIdentifier
    )

    switch ($RuntimeIdentifier) {
        "linux-x64" { return "linux/x64" }
        "win-x64" { return "windows/x64" }
        default {
            throw "RuntimeIdentifier '$RuntimeIdentifier' does not have a ProtocolLab package environment mapping."
        }
    }
}

function Resolve-ProjectPathOrThrow {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Description,

        [Parameter(Mandatory = $true)]
        [string] $RepoRoot
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return Resolve-PathOrThrow -Path $Path -Description $Description
    }

    $candidate = Join-Path $RepoRoot $Path
    if (Test-Path -LiteralPath $candidate) {
        return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $candidate).Path)
    }

    throw "$Description was not found under the quic-dotnet root: $Path"
}

function Test-NoRestoreRuntimeAssetFailure {
    param(
        [string] $LogText,
        [string] $RuntimeIdentifier
    )

    if ([string]::IsNullOrWhiteSpace($LogText)) {
        return $false
    }

    $normalizedLog = $LogText.ToLowerInvariant()
    $normalizedRuntime = $RuntimeIdentifier.ToLowerInvariant()

    return $normalizedLog.Contains("netsdk1047") -or
        ($normalizedLog.Contains("project.assets.json") -and $normalizedLog.Contains($normalizedRuntime))
}

function Invoke-DotNetPublish {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProjectPath,

        [Parameter(Mandatory = $true)]
        [string] $RuntimeIdentifier,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath,

        [Parameter(Mandatory = $true)]
        [bool] $SelfContained,

        [string[]] $Properties = @()
    )

    $publishArgs = @(
        "publish",
        $ProjectPath,
        "-c",
        $Configuration,
        "-r",
        $RuntimeIdentifier,
        "--self-contained",
        $SelfContained.ToString().ToLowerInvariant(),
        "-o",
        $OutputPath
    ) + $Properties

    if ($NoRestore) {
        $publishArgs += "--no-restore"
    }

    $publishLog = & dotnet @publishArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $publishText = ($publishLog | Out-String)
        $publishLog | Write-Error -ErrorAction Continue
        if ($NoRestore -and (Test-NoRestoreRuntimeAssetFailure -LogText $publishText -RuntimeIdentifier $RuntimeIdentifier)) {
            throw "dotnet publish failed for runtime identifier '$RuntimeIdentifier' because restore assets are missing for that RID. Rerun the package build once without -NoRestore, then use -NoRestore again after restore succeeds."
        }

        throw "dotnet publish failed for runtime identifier '$RuntimeIdentifier'."
    }
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$targetConfig = Get-PackageTargetConfig -Target $PackageTarget
if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy) -and $PackageTarget -ne "RawQuic") {
    throw "AdaptiveRuntimeReceiveCreditPolicy is supported only for the RawQuic package target."
}
if ([string]::IsNullOrWhiteSpace($Project)) {
    $Project = $targetConfig.DefaultProject
}

if ($PackageTarget -eq "RawQuic" -and -not $PSBoundParameters.ContainsKey("RuntimeIdentifier")) {
    $RuntimeIdentifier = @("linux-x64", "win-x64")
}

$projectFullPath = Resolve-ProjectPathOrThrow -Path $Project -Description "ProtocolLab package project" -RepoRoot $repoRoot
Assert-PathUnderRoot -Path $projectFullPath -Root $repoRoot -Description "ProtocolLab package project"

$protocolLabRootFullPath = Resolve-PathOrThrow -Path $ProtocolLabRoot -Description "ProtocolLab root"
$sourceRepository = Invoke-GitValue -RepositoryRoot $repoRoot -Arguments @("remote", "get-url", "origin") -Description "source repository"
$sourceCommit = Invoke-GitValue -RepositoryRoot $repoRoot -Arguments @("rev-parse", "HEAD") -Description "source commit"
$sourceCommitTimestamp = Invoke-GitValue -RepositoryRoot $repoRoot -Arguments @("show", "-s", "--format=%cI", "HEAD") -Description "source commit timestamp"
$projectSourceDirectory = [System.IO.Path]::GetRelativePath($repoRoot, (Split-Path -Parent $projectFullPath)).Replace('\', '/')
$sourceScope = @((Get-PackageSourceScope -Target $PackageTarget) + @($projectSourceDirectory) | Sort-Object -Unique)
$sourceStatusArguments = @("status", "--porcelain=v1", "--untracked-files=normal", "--") + $sourceScope
$sourceStatus = Invoke-GitValue `
    -RepositoryRoot $repoRoot `
    -Arguments $sourceStatusArguments `
    -Description "package source status" `
    -AllowEmpty
$sourceClean = [string]::IsNullOrWhiteSpace($sourceStatus)
if (-not $sourceClean -and -not $AllowDirtySource) {
    throw "ProtocolLab package inputs are dirty. Commit the package source slice or pass -AllowDirtySource for diagnostic-only output.`n$sourceStatus"
}

if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
    $PackageVersion = Get-DefaultPackageVersion -RepositoryRoot $repoRoot -SourceClean $sourceClean
}

$resolvedWorkRoot = if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    Join-Path $repoRoot "artifacts/protocol-lab"
}
elseif ([System.IO.Path]::IsPathRooted($WorkRoot)) {
    [System.IO.Path]::GetFullPath($WorkRoot)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $WorkRoot))
}
$stageRoot = Join-Path $resolvedWorkRoot "package-source/$($targetConfig.PackageId)/$PackageVersion"
$publishRoot = Join-Path $resolvedWorkRoot "publish/$($targetConfig.PackageId)/$PackageVersion"
$templateRoot = $targetConfig.TemplateRoot
if (-not (Test-Path -LiteralPath $templateRoot -PathType Container)) {
    throw "Package target template root was not found: $templateRoot"
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $resolvedWorkRoot "packages/$($targetConfig.PackageId).$PackageVersion.plabpkg"
}

Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $publishRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null

Copy-Item -LiteralPath (Join-Path $templateRoot "protocol-lab-package.json") -Destination (Join-Path $stageRoot "protocol-lab-package.json")
Copy-Item -LiteralPath (Join-Path $templateRoot "protocol-lab.internal.json") -Destination (Join-Path $stageRoot "protocol-lab.internal.json")
Copy-Item -LiteralPath (Join-Path $templateRoot "implementations") -Destination (Join-Path $stageRoot "implementations") -Recurse
$scriptsRoot = Join-Path $templateRoot "scripts"
if (Test-Path -LiteralPath $scriptsRoot -PathType Container) {
    Copy-Item -LiteralPath $scriptsRoot -Destination (Join-Path $stageRoot "scripts") -Recurse
}

if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy)) {
    $implementationManifestPath = Join-Path $stageRoot "implementations/quic-dotnet-raw-dev.yaml"
    $implementationText = Get-Content -LiteralPath $implementationManifestPath -Raw
    $environmentAnchorPattern = '(?m)^(  ASPNETCORE_URLS: http://127\.0\.0\.1:53591)(\r?)$'
    $environmentAnchorMatches = [regex]::Matches($implementationText, $environmentAnchorPattern)
    if ($environmentAnchorMatches.Count -ne 1) {
        throw "Raw QUIC package implementation manifest must contain exactly one ASPNETCORE_URLS environment anchor."
    }

    $environmentReplacement = '$1$2' + "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY: $AdaptiveRuntimeReceiveCreditPolicy"
    $implementationText = [regex]::Replace(
        $implementationText,
        $environmentAnchorPattern,
        $environmentReplacement,
        [System.Text.RegularExpressions.RegexOptions]::None,
        [TimeSpan]::FromSeconds(1))
    [System.IO.File]::WriteAllText(
        $implementationManifestPath,
        $implementationText,
        [System.Text.UTF8Encoding]::new($false))
}

$manifestPath = Join-Path $stageRoot "protocol-lab-package.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$manifest.packageVersion = $PackageVersion
$manifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $manifestPath
$executionManifestPath = Join-Path $stageRoot "protocol-lab.internal.json"

$requestedEnvironmentKeys = foreach ($rid in $RuntimeIdentifier) {
    Get-ProtocolLabEnvironmentKey -RuntimeIdentifier $rid
}

$executionManifest = Get-Content -LiteralPath $executionManifestPath -Raw | ConvertFrom-Json
$executionManifest.sourceRepository = $sourceRepository
$executionManifest.sourceCommit = $sourceCommit
$executionManifest.environments = @(
    $executionManifest.environments | Where-Object {
        $requestedEnvironmentKeys -contains "$($_.os)/$($_.arch)"
    }
)
$executionManifest.dependencies.requiresDotNet = [bool]$targetConfig.RequiresDotNet
$executionManifest.dependencies.requiresPwsh = [bool]$targetConfig.RequiresPwsh
$executionManifest.dependencies.requiresBash = [bool]($targetConfig.RequiresBash -and ($requestedEnvironmentKeys -contains "linux/x64"))
$executionManifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $executionManifestPath

foreach ($rid in $RuntimeIdentifier) {
    $publishOutput = Join-Path (Join-Path $publishRoot $rid) "entrypoint"
    $publishProperties = @()
    if ($targetConfig.UseIncursaQuicSourceRoot) {
        $publishProperties += "/p:IncursaQuicSourceRoot=$repoRoot"
    }
    if ($targetConfig.UseProtocolLabContracts) {
        $publishProperties += "/p:ProtocolLabRoot=$protocolLabRootFullPath"
    }

    Invoke-DotNetPublish -ProjectPath $projectFullPath -RuntimeIdentifier $rid -OutputPath $publishOutput -SelfContained $targetConfig.SelfContained -Properties $publishProperties

    $binOutput = Join-Path $stageRoot "bin/$rid"
    New-Item -ItemType Directory -Force -Path $binOutput | Out-Null
    Get-ChildItem -LiteralPath $publishOutput -Force | Copy-Item -Destination $binOutput -Recurse -Force

    if (-not [string]::IsNullOrWhiteSpace($targetConfig.RawServerProject)) {
        Get-ChildItem -LiteralPath $binOutput -Filter "IncursaRawQuicServer*" -File -ErrorAction SilentlyContinue |
            Remove-Item -Force

        $rawServerProjectFullPath = Resolve-ProjectPathOrThrow `
            -Path $targetConfig.RawServerProject `
            -Description "Raw QUIC server project" `
            -RepoRoot $repoRoot
        Assert-PathUnderRoot -Path $rawServerProjectFullPath -Root $repoRoot -Description "Raw QUIC server project"

        $rawServerPublishOutput = Join-Path (Join-Path $publishRoot $rid) "raw-server"
        Invoke-DotNetPublish -ProjectPath $rawServerProjectFullPath -RuntimeIdentifier $rid -OutputPath $rawServerPublishOutput -SelfContained $targetConfig.SelfContained -Properties $publishProperties

        $rawServerBinOutput = Join-Path $binOutput "servers/IncursaRawQuicServer"
        New-Item -ItemType Directory -Force -Path $rawServerBinOutput | Out-Null
        Get-ChildItem -LiteralPath $rawServerPublishOutput -Force | Copy-Item -Destination $rawServerBinOutput -Recurse -Force
    }
}

if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output package already exists: $OutputPath. Use -Force to overwrite it."
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

$build = [ordered]@{
    configuration = $Configuration
    runtimeIdentifier = ($RuntimeIdentifier -join "+")
    runtimeIdentifiers = @($RuntimeIdentifier)
    operatingSystem = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    powershell = $PSVersionTable.PSVersion.ToString()
    dotnet = Get-OptionalToolVersion -Name "dotnet" -Arguments @("--version")
}
$source = [ordered]@{
    repository = $sourceRepository
    commitSha = $sourceCommit
    workingTreeClean = $sourceClean
    dirtyState = if ($sourceClean) { "clean" } else { "dirty" }
    dirtyEntries = if ($sourceClean) { @() } else { @($sourceStatus -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ }) }
    componentPath = if ($PackageTarget -eq "RawQuic") { "src/Incursa.Quic" } else { "samples/Incursa.Http3.Samples.TechEmpower" }
    scopedPaths = $sourceScope
}
$embeddedProvenance = [ordered]@{
    schemaVersion = "protocol-lab.package-build-provenance.v1"
    generatedAtUtc = ([DateTimeOffset]::Parse($sourceCommitTimestamp)).ToUniversalTime().ToString("O")
    timestampBasis = "source-commit"
    parityEligible = $sourceClean
    source = $source
    build = $build
    package = [ordered]@{
        packageId = $targetConfig.PackageId
        packageVersion = $PackageVersion
        packageTarget = $PackageTarget
        adaptiveRuntimeReceiveCreditPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy)) { $null } else { $AdaptiveRuntimeReceiveCreditPolicy }
    }
}
Write-JsonFile -Value $embeddedProvenance -Path (Join-Path $stageRoot "package-build-provenance.json")

Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
New-DeterministicZipArchive -SourceRoot $stageRoot -DestinationPath $OutputPath

$sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
$attestationPath = "$OutputPath.build-attestation.json"
$attestation = [ordered]@{
    schemaVersion = "protocol-lab.package-build-attestation.v1"
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    parityEligible = $sourceClean
    source = $source
    build = $build
    package = [ordered]@{
        packageId = $targetConfig.PackageId
        packageVersion = $PackageVersion
        packageTarget = $PackageTarget
        adaptiveRuntimeReceiveCreditPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy)) { $null } else { $AdaptiveRuntimeReceiveCreditPolicy }
        sha256 = $sha256
        materializationPath = [System.IO.Path]::GetFullPath($OutputPath)
        buildAttestationPath = [System.IO.Path]::GetFullPath($attestationPath)
        immutableIdentity = "$($targetConfig.PackageId)@$PackageVersion#$sha256"
    }
    claimBoundary = if ($sourceClean) {
        "This attestation identifies an immutable package built from the recorded clean package-input scope."
    }
    else {
        "Diagnostic-only dirty-source build. This artifact is not eligible for source/package parity or publication."
    }
}
Remove-Item -LiteralPath $attestationPath -Force -ErrorAction SilentlyContinue
Write-JsonFile -Value $attestation -Path $attestationPath

[pscustomobject]@{
    path = [System.IO.Path]::GetFullPath($OutputPath)
    packageId = $targetConfig.PackageId
    packageVersion = $PackageVersion
    adaptiveRuntimeReceiveCreditPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy)) { $null } else { $AdaptiveRuntimeReceiveCreditPolicy }
    workRoot = $resolvedWorkRoot
    sha256 = $sha256
    buildAttestationPath = [System.IO.Path]::GetFullPath($attestationPath)
    parityEligible = $sourceClean
    sourceCommit = $sourceCommit
} | ConvertTo-Json -Depth 8
