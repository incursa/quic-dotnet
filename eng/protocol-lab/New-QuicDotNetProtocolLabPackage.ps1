[CmdletBinding()]
param(
    [ValidateSet("Http3", "RawQuic")]
    [string] $PackageTarget = "Http3",

    [string] $ProtocolLabRoot = "../protocol-lab",

    [string] $Project,

    [string] $Configuration = "Release",

    [string[]] $RuntimeIdentifier = @("linux-x64"),

    [string] $PackageVersion,

    [string] $OutputPath,

    [switch] $Force,

    [switch] $NoRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DefaultPackageVersion {
    $timestamp = Get-Date -AsUTC -Format "yyyyMMddTHHmmssZ"
    $shortSha = "nogit"
    $dirty = "unknown"

    try {
        $shortSha = (git rev-parse --short HEAD 2>$null).Trim()
        $status = @(git status --porcelain 2>$null)
        $dirty = if ($status.Count -gt 0) { "dirty" } else { "clean" }
    }
    catch {
        $shortSha = "nogit"
        $dirty = "unknown"
    }

    return "dev-$timestamp-$shortSha-$dirty"
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
        $publishLog | Write-Error
        if ($NoRestore -and (Test-NoRestoreRuntimeAssetFailure -LogText $publishText -RuntimeIdentifier $RuntimeIdentifier)) {
            throw "dotnet publish failed for runtime identifier '$RuntimeIdentifier' because restore assets are missing for that RID. Rerun the package build once without -NoRestore, then use -NoRestore again after restore succeeds."
        }

        throw "dotnet publish failed for runtime identifier '$RuntimeIdentifier'."
    }
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$targetConfig = Get-PackageTargetConfig -Target $PackageTarget
if ([string]::IsNullOrWhiteSpace($Project)) {
    $Project = $targetConfig.DefaultProject
}

if ($PackageTarget -eq "RawQuic" -and -not $PSBoundParameters.ContainsKey("RuntimeIdentifier")) {
    $RuntimeIdentifier = @("linux-x64", "win-x64")
}

$projectFullPath = Resolve-ProjectPathOrThrow -Path $Project -Description "ProtocolLab package project" -RepoRoot $repoRoot
Assert-PathUnderRoot -Path $projectFullPath -Root $repoRoot -Description "ProtocolLab package project"

$protocolLabRootFullPath = Resolve-PathOrThrow -Path $ProtocolLabRoot -Description "ProtocolLab root"

if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
    $PackageVersion = Get-DefaultPackageVersion
}

$stageRoot = Join-Path $repoRoot "artifacts/protocol-lab/package-source/$($targetConfig.PackageId)/$PackageVersion"
$publishRoot = Join-Path $repoRoot "artifacts/protocol-lab/publish/$($targetConfig.PackageId)/$PackageVersion"
$templateRoot = $targetConfig.TemplateRoot
if (-not (Test-Path -LiteralPath $templateRoot -PathType Container)) {
    throw "Package target template root was not found: $templateRoot"
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repoRoot "artifacts/protocol-lab/packages/$($targetConfig.PackageId).$PackageVersion.plabpkg"
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

$manifestPath = Join-Path $stageRoot "protocol-lab-package.json"
(Get-Content -LiteralPath $manifestPath -Raw).Replace("__PACKAGE_VERSION__", $PackageVersion) |
    Set-Content -LiteralPath $manifestPath -NoNewline
$executionManifestPath = Join-Path $stageRoot "protocol-lab.internal.json"

$requestedEnvironmentKeys = foreach ($rid in $RuntimeIdentifier) {
    Get-ProtocolLabEnvironmentKey -RuntimeIdentifier $rid
}

$executionManifest = Get-Content -LiteralPath $executionManifestPath -Raw | ConvertFrom-Json
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

Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $stageRoot "*") -DestinationPath $OutputPath -Force

$sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    path = [System.IO.Path]::GetFullPath($OutputPath)
    packageId = $targetConfig.PackageId
    packageVersion = $PackageVersion
    sha256 = $sha256
} | ConvertTo-Json -Depth 8
