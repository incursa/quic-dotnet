[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $PackagePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $PackageVersion,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ProtocolLabInternalRoot,

    [string] $ArtifactsRoot = "artifacts/release/package-backed-raw-quic-conformance"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description was not found: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string] $Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-DotNetOrThrow {
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments,

        [Parameter(Mandatory)]
        [string] $Description
    )

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$packageFullPath = Resolve-ExistingPath -Path $PackagePath -Description "Incursa.Quic candidate package"
$internalRoot = Resolve-ExistingPath -Path $ProtocolLabInternalRoot -Description "ProtocolLab internal checkout"
$artifactsFullPath = if ([System.IO.Path]::IsPathRooted($ArtifactsRoot)) {
    [System.IO.Path]::GetFullPath($ArtifactsRoot)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ArtifactsRoot))
}

if ([System.IO.Path]::GetExtension($packageFullPath) -ne ".nupkg") {
    throw "Candidate package must be a .nupkg file: $packageFullPath"
}

if (-not [string]::IsNullOrWhiteSpace($env:PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT)) {
    throw "PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT must be unset for package-backed conformance."
}

$expectedPackageFileName = "Incursa.Quic.$PackageVersion.nupkg"
if (-not [string]::Equals((Split-Path -Leaf $packageFullPath), $expectedPackageFileName, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Candidate package file must be '$expectedPackageFileName' to prove the requested package identity."
}

$serverProject = Resolve-ExistingPath -Path (Join-Path $internalRoot "servers\\IncursaRawQuicServer\\IncursaRawQuicServer.csproj") -Description "Raw QUIC server project"
$adapterProject = Resolve-ExistingPath -Path (Join-Path $internalRoot "src\\Incursa.ProtocolLab.Adapters.IncursaRawQuic\\Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj") -Description "Raw QUIC adapter project"
$testProject = Resolve-ExistingPath -Path (Join-Path $internalRoot "tests\\Incursa.ProtocolLab.Tests\\Incursa.ProtocolLab.Tests.csproj") -Description "ProtocolLab internal test project"

New-Item -ItemType Directory -Force -Path $artifactsFullPath | Out-Null
$candidateFeed = Join-Path $artifactsFullPath "nuget-feed"
New-Item -ItemType Directory -Force -Path $candidateFeed | Out-Null
$candidatePackagePath = Join-Path $candidateFeed $expectedPackageFileName
Copy-Item -LiteralPath $packageFullPath -Destination $candidatePackagePath -Force

$nugetConfigPath = Join-Path $artifactsFullPath "candidate.NuGet.config"
$escapedCandidateFeed = [Security.SecurityElement]::Escape($candidateFeed)
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="candidate" value="$escapedCandidateFeed" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="candidate">
      <package pattern="Incursa.Quic" />
    </packageSource>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content -LiteralPath $nugetConfigPath -Encoding utf8NoBOM

Invoke-DotNetOrThrow -Description "Raw QUIC server restore" -Arguments @(
    "restore", $serverProject, "--configfile", $nugetConfigPath, "--force-evaluate", "-p:IncursaQuicVersion=$PackageVersion"
)
Invoke-DotNetOrThrow -Description "Raw QUIC adapter restore" -Arguments @(
    "restore", $adapterProject, "--configfile", $nugetConfigPath, "--force-evaluate", "-p:IncursaQuicVersion=$PackageVersion"
)
Invoke-DotNetOrThrow -Description "ProtocolLab internal conformance test restore" -Arguments @(
    "restore", $testProject, "--configfile", $nugetConfigPath, "--force-evaluate", "-p:IncursaQuicVersion=$PackageVersion"
)
Invoke-DotNetOrThrow -Description "Raw QUIC server build" -Arguments @(
    "build", $serverProject, "-c", "Debug", "--no-restore", "-p:IncursaQuicVersion=$PackageVersion"
)
Invoke-DotNetOrThrow -Description "Raw QUIC adapter build" -Arguments @(
    "build", $adapterProject, "-c", "Debug", "--no-restore", "-p:IncursaQuicVersion=$PackageVersion"
)
Invoke-DotNetOrThrow -Description "ProtocolLab internal conformance test build" -Arguments @(
    "build", $testProject, "-c", "Debug", "--no-restore", "-p:IncursaQuicVersion=$PackageVersion"
)

$serverOutputDirectory = Split-Path -Parent $serverProject
$serverDepsPath = Resolve-ExistingPath -Path (Join-Path $serverOutputDirectory "bin\\Debug\\net10.0\\IncursaRawQuicServer.deps.json") -Description "Raw QUIC server dependency manifest"
$serverQuicDllPath = Resolve-ExistingPath -Path (Join-Path $serverOutputDirectory "bin\\Debug\\net10.0\\Incursa.Quic.dll") -Description "Raw QUIC server Incursa.Quic binary"
$serverDepsText = Get-Content -LiteralPath $serverDepsPath -Raw
if (-not $serverDepsText.Contains("Incursa.Quic/$PackageVersion", [StringComparison]::Ordinal)) {
    throw "Raw QUIC server dependency manifest does not resolve Incursa.Quic/$PackageVersion."
}

$packageDllPath = Join-Path $artifactsFullPath "Incursa.Quic.package.dll"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($candidatePackagePath)
try {
    $packageDllEntry = $archive.GetEntry("lib/net10.0/Incursa.Quic.dll")
    if ($null -eq $packageDllEntry) {
        throw "Candidate package does not contain lib/net10.0/Incursa.Quic.dll."
    }

    $input = $packageDllEntry.Open()
    try {
        $output = [System.IO.File]::Open($packageDllPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            $input.CopyTo($output)
        }
        finally {
            $output.Dispose()
        }
    }
    finally {
        $input.Dispose()
    }
}
finally {
    $archive.Dispose()
}

$packageDllSha256 = Get-FileSha256 -Path $packageDllPath
$serverDllSha256 = Get-FileSha256 -Path $serverQuicDllPath
if (-not [string]::Equals($packageDllSha256, $serverDllSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Raw QUIC server binary hash does not match the candidate package binary."
}

$trxPath = Join-Path $artifactsFullPath "package-backed-raw-quic-conformance.trx"
$filter = "FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_writes_exact_deterministic_download_payload|FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_echoes_slow_reader_stream_work_concurrently"
Invoke-DotNetOrThrow -Description "Package-backed Raw QUIC conformance" -Arguments @(
    "test", $testProject, "-c", "Debug", "--no-build", "--no-restore", "--disable-build-servers", "--nologo",
    "--results-directory", $artifactsFullPath, "--logger", "trx;LogFileName=package-backed-raw-quic-conformance.trx", "--filter", $filter
)

[xml]$trx = Get-Content -LiteralPath $trxPath -Raw
$counters = $trx.TestRun.ResultSummary.Counters
$total = [int]$counters.total
$passed = [int]$counters.passed
$failed = [int]$counters.failed
if ($total -ne 5 -or $passed -ne 5 -or $failed -ne 0) {
    throw "Package-backed Raw QUIC conformance expected 5 passing tests with zero failures; observed total=$total passed=$passed failed=$failed."
}

$summaryPath = Join-Path $artifactsFullPath "package-backed-raw-quic-conformance.json"
[ordered]@{
    schemaVersion = "incursa.quic.package-backed-raw-quic-conformance.v1"
    package = [ordered]@{
        id = "Incursa.Quic"
        version = $PackageVersion
        path = $candidatePackagePath
        sha256 = Get-FileSha256 -Path $candidatePackagePath
        assemblySha256 = $packageDllSha256
    }
    server = [ordered]@{
        dependencyManifestPath = $serverDepsPath
        binaryPath = $serverQuicDllPath
        binarySha256 = $serverDllSha256
    }
    sourceRootOverride = [ordered]@{
        environmentVariable = "PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT"
        present = $false
    }
    tests = [ordered]@{
        filter = $filter
        total = $total
        passed = $passed
        failed = $failed
        trxPath = $trxPath
        trxSha256 = Get-FileSha256 -Path $trxPath
    }
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding utf8NoBOM

Get-Content -LiteralPath $summaryPath -Raw
