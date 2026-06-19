[CmdletBinding()]
param(
    [string]$ArtifactsRoot = ".artifacts/tools",
    [string]$Version = "v0.1.13",
    [switch]$Force,
    [switch]$PassThruJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Get-H3SpecAssetName {
    if ($IsWindows -or $IsLinux) {
        return "h3spec-linux-x86_64"
    }

    if ($IsMacOS -and [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64) {
        return "h3spec-mac-arm64"
    }

    throw "No h3spec release asset is known for this platform. Use -H3SpecExecutable on Run-H3Spec.ps1 to provide a local wrapper."
}

function Save-H3SpecAsset {
    param(
        [string]$DestinationPath,
        [string]$AssetName,
        [string]$VersionToFetch
    )

    if ((Test-Path -LiteralPath $DestinationPath) -and -not $Force) {
        return
    }

    $downloadUrl = "https://github.com/kazu-yamamoto/h3spec/releases/download/$VersionToFetch/$AssetName"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $DestinationPath
}

function Write-DockerWrapper {
    param(
        [string]$ToolRoot,
        [string]$AssetName
    )

    $wrapperPath = Join-Path $ToolRoot "Invoke-H3SpecDocker.ps1"
    @"
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = `$true)]
    [string[]]`$H3SpecArguments = @()
)

Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

`$toolRoot = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$binaryPath = Join-Path `$toolRoot "$AssetName"
if (-not (Test-Path -LiteralPath `$binaryPath -PathType Leaf)) {
    throw "h3spec binary was not found: `$binaryPath"
}

if (`$null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required to run the acquired Linux h3spec binary on this platform."
}

`$dockerArguments = @(
    "run",
    "--rm",
    "-v",
    "`${toolRoot}:/tools:ro",
    "ubuntu:24.04",
    "/bin/sh",
    "-lc",
    'exec /tools/$AssetName "`$@"',
    "h3spec"
)
`$dockerArguments += `$H3SpecArguments

& docker @dockerArguments
exit `$LASTEXITCODE
"@ | Set-Content -LiteralPath $wrapperPath -NoNewline

    return $wrapperPath
}

$repoRoot = Resolve-RepoRoot
$assetName = Get-H3SpecAssetName
$toolRoot = Join-Path (Join-Path $repoRoot $ArtifactsRoot) "h3spec-$Version"
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null

$binaryPath = Join-Path $toolRoot $assetName
Save-H3SpecAsset -DestinationPath $binaryPath -AssetName $assetName -VersionToFetch $Version

$usesDockerWrapper = $IsWindows -or $IsLinux
if ($usesDockerWrapper) {
    $wrapperPath = Write-DockerWrapper -ToolRoot $toolRoot -AssetName $assetName
    $executable = "pwsh"
    $prefixArguments = @("-NoProfile", "-File", $wrapperPath)
    $recommendedHostName = if ($IsWindows -or $IsMacOS) { "host.docker.internal" } else { "127.0.0.1" }
}
else {
    if ($IsMacOS -or $IsLinux) {
        & chmod +x $binaryPath
        if ($LASTEXITCODE -ne 0) {
            throw "chmod failed for $binaryPath."
        }
    }

    $executable = $binaryPath
    $prefixArguments = @()
    $recommendedHostName = "127.0.0.1"
}

$manifest = [ordered]@{
    tool = "h3spec"
    version = $Version
    asset = $assetName
    toolRoot = $toolRoot
    binary = $binaryPath
    executable = $executable
    prefixArguments = $prefixArguments
    usesDockerWrapper = [bool]$usesDockerWrapper
    recommendedHostName = $recommendedHostName
    acquiredUtc = (Get-Date).ToUniversalTime().ToString("o")
}

$manifestPath = Join-Path $toolRoot "h3spec-tool.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath

if ($PassThruJson) {
    $manifest | ConvertTo-Json -Depth 8
}
else {
    Write-Host "h3spec tool manifest: $manifestPath"
    Write-Host "Run-H3Spec executable: $executable"
    if ($prefixArguments.Count -gt 0) {
        Write-Host "Run-H3Spec prefix args: $($prefixArguments -join ' ')"
    }
}
