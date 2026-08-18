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

    [ValidateSet("", "legacy_current", "conservative", "observe_only", "shadow")]
    [string] $AdaptiveRuntimeApplicationSendTurnPolicy = "",

    [ValidateSet("", "legacy_current", "single_datagram")]
    [string] $AdaptiveRuntimeQueuedSendBurstPolicy = "",

    [ValidatePattern("^$|^[0-9a-f]{64}$")]
    [string] $AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256 = "",

    [ValidateSet("", "legacy_current", "single_fragment")]
    [string] $AdaptiveRuntimeOversizedWriteAdmissionPolicy = "",

    [ValidateSet("", "legacy_current", "single_eligible")]
    [string] $AdaptiveRuntimeApplicationSendBatchPolicy = "",

    [ValidateSet("", "legacy_current", "memory_conservative")]
    [string] $AdaptiveRuntimeBufferCopyPolicy = "",

    [ValidatePattern("^$|^[0-9a-f]{64}$")]
    [string] $AdaptiveRuntimeAdmissionPerformanceManifestContentSha256 = "",

    [ValidateSet("", "legacy_current", "prompt", "observe_only", "shadow")]
    [string] $AdaptiveRuntimePacketFlushCadencePolicy = "",

    [ValidateSet("", "legacy_current", "single_segment", "observe_only", "shadow")]
    [string] $AdaptiveRuntimeReceiveDeliveryQuantumPolicy = "",

    [ValidateSet("", "legacy_current", "bounded_power_of_two_choices", "observe_only", "shadow")]
    [string] $AdaptiveRuntimeConnectionShardPlacementPolicy = "",

    [ValidateSet("", "legacy_current", "segmented_batch", "ordinary_datagrams", "observe_only", "shadow")]
    [string] $AdaptiveRuntimeApplicationDatagramBatchTransportPolicy = "",

    [ValidateSet("", "legacy_current", "cubic", "observe_only", "shadow")]
    [string] $AdaptiveRuntimeCongestionPacingProfilePolicy = "",

    [switch] $RawQuicDebugLogging,

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

function Get-AdmissionPerformancePackagePathCell {
    param(
        [Parameter(Mandatory = $true)]
        [string] $OversizedWriteAdmissionPolicy,

        [Parameter(Mandatory = $true)]
        [string] $ApplicationSendBatchPolicy,

        [Parameter(Mandatory = $true)]
        [string] $BufferCopyPolicy,

        [string] $ManifestContentSha256
    )

    $pilotManifestContentSha256 =
        "257b31f3f93c6a34e14066b2c5d77bfc15ab5f2cfe54603b8d9244eb93fb7fd9"
    $balancedManifestContentSha256 =
        "005f39814881cbfff70b8d283b1ee5a8e0c430496db5b30141d2208e4aed024a"
    $selectedManifestContentSha256 = if (
        [string]::IsNullOrWhiteSpace($ManifestContentSha256)
    ) {
        $pilotManifestContentSha256
    }
    else {
        $ManifestContentSha256
    }
    if ($selectedManifestContentSha256 -notin @(
        $pilotManifestContentSha256,
        $balancedManifestContentSha256
    )) {
        throw "Admission-performance package path requires a reviewed pilot or balanced manifest hash."
    }

    $tupleKey = "$OversizedWriteAdmissionPolicy|$ApplicationSendBatchPolicy|$BufferCopyPolicy"
    $cell = switch ($tupleKey) {
        "legacy_current|legacy_current|legacy_current" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a0"
                cellContentSha256 = "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28"
            }
        }
        "legacy_current|legacy_current|memory_conservative" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a1"
                cellContentSha256 = "c41ed6674829898c3dc4e9af34cca11d159c07642c267a893b9d7097c3cc4f25"
            }
        }
        "legacy_current|single_eligible|legacy_current" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a2"
                cellContentSha256 = "68c4112be72f82a9eb11b8a6dcf0594542337960c85bcc5f7386d91a172341db"
            }
        }
        "legacy_current|single_eligible|memory_conservative" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a3"
                cellContentSha256 = "1b7b63f5d53d39416d999b4bda0cc0c80e8817a535ceed9bc91e36aa12bcc2b1"
            }
        }
        "single_fragment|legacy_current|legacy_current" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a4"
                cellContentSha256 = "99c02f1b21aaef38b13b996a8e25d31b1e78d1f6927433470dd743ddc3a37598"
            }
        }
        "single_fragment|legacy_current|memory_conservative" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a5"
                cellContentSha256 = "e3635faeb1b2435fc40487bd1cc5060f822624607c2c2202b78d1c1894041b2a"
            }
        }
        "single_fragment|single_eligible|legacy_current" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a6"
                cellContentSha256 = "ac2a8d830612027da8f85d90d6bf9624c344078ae0067dd9fca3b8e7c6ae6fd1"
            }
        }
        "single_fragment|single_eligible|memory_conservative" {
            [ordered]@{
                campaignId = "campaign.send_admission_composition.performance.v1"
                cellId = "cell.send_admission_composition.correctness.a7"
                cellContentSha256 = "281b32fd62406993adbffb6c6717e8a73d8ced29524b8f0a82b2d470cbda409f"
            }
        }
        default {
            throw "Admission-performance package path requires one of the reviewed A0-A7 tuples."
        }
    }
    if (
        $selectedManifestContentSha256 -eq
            $pilotManifestContentSha256 -and
        $cell.cellId -notin @(
            "cell.send_admission_composition.correctness.a0",
            "cell.send_admission_composition.correctness.a3",
            "cell.send_admission_composition.correctness.a4",
            "cell.send_admission_composition.correctness.a7"
        )
    ) {
        throw "Admission-performance pilot package path requires one of the reviewed A0, A3, A4, or A7 tuples."
    }
    $cell.manifestContentSha256 = $selectedManifestContentSha256
    return $cell
}

function Get-QueuedSendPerformancePackagePathCell {
    param(
        [Parameter(Mandatory = $true)]
        [string] $QueuedSendBurstPolicy,

        [Parameter(Mandatory = $true)]
        [string] $ManifestContentSha256
    )

    # The exact reviewed manifest and cell hashes are intentionally centralized here.
    # Package construction cannot authorize an arbitrary caller-supplied identity.
    $reviewedManifestContentSha256 =
        "2ad809ecdb882f000c38d00c97f69604cbb3e004186535fd2348800e7c8a27ab"
    if ($ManifestContentSha256 -ne $reviewedManifestContentSha256) {
        throw "Queued-send performance package path requires the exact reviewed manifest hash."
    }

    $cell = switch ($QueuedSendBurstPolicy) {
        "legacy_current" {
            [ordered]@{
                campaignId = "campaign.queued_send_burst_budget.performance.v1"
                cellId = "cell.queued_send_burst_budget.performance.q0"
                cellContentSha256 = "b2911df4e1782b6f1636d37bf50f0dd5e59dbbb9164ec3154b667034c43fb3e9"
            }
        }
        "single_datagram" {
            [ordered]@{
                campaignId = "campaign.queued_send_burst_budget.performance.v1"
                cellId = "cell.queued_send_burst_budget.performance.q1"
                cellContentSha256 = "2f4a7a36c0d52aeae801a979e91335347693db5ec8665715497d068fb02cdc2a"
            }
        }
        default {
            throw "Queued-send performance package path requires the reviewed q0 or q1 policy value."
        }
    }

    $cell.manifestContentSha256 = $ManifestContentSha256
    return $cell
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
        "linux-arm64" { return "linux/arm64" }
        "win-x64" { return "windows/x64" }
        "osx-arm64" { return "macos/arm64" }
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
if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendTurnPolicy) -and $PackageTarget -ne "RawQuic") {
    throw "AdaptiveRuntimeApplicationSendTurnPolicy is supported only for the RawQuic package target."
}
if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy) -and $PackageTarget -ne "RawQuic") {
    throw "AdaptiveRuntimeQueuedSendBurstPolicy is supported only for the RawQuic package target."
}
if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy) -and $PackageTarget -ne "RawQuic") {
    throw "AdaptiveRuntimeOversizedWriteAdmissionPolicy is supported only for the RawQuic package target."
}
if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy) -and $PackageTarget -ne "RawQuic") {
    throw "AdaptiveRuntimeApplicationSendBatchPolicy is supported only for the RawQuic package target."
}
if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy) -and $PackageTarget -ne "RawQuic") {
    throw "AdaptiveRuntimeBufferCopyPolicy is supported only for the RawQuic package target."
}
if ($RawQuicDebugLogging -and $PackageTarget -ne "RawQuic") {
    throw "RawQuicDebugLogging is supported only for the RawQuic package target."
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

$queuedSendPerformancePathRequested =
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256)
$admissionPerformancePathRequested = -not $queuedSendPerformancePathRequested -and (
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy))
if ($queuedSendPerformancePathRequested) {
    if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy) -or
        [string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256)) {
        throw "Queued-send performance package path requires the queued-send policy and exact manifest hash together."
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeAdmissionPerformanceManifestContentSha256)) {
        throw "Admission-performance and queued-send performance package-path authorizations are mutually exclusive."
    }

    $adjacentPolicyValues = @(
        $AdaptiveRuntimeReceiveCreditPolicy,
        $AdaptiveRuntimeApplicationSendTurnPolicy,
        $AdaptiveRuntimeOversizedWriteAdmissionPolicy,
        $AdaptiveRuntimeApplicationSendBatchPolicy,
        $AdaptiveRuntimeBufferCopyPolicy,
        $AdaptiveRuntimePacketFlushCadencePolicy,
        $AdaptiveRuntimeReceiveDeliveryQuantumPolicy,
        $AdaptiveRuntimeConnectionShardPlacementPolicy,
        $AdaptiveRuntimeApplicationDatagramBatchTransportPolicy,
        $AdaptiveRuntimeCongestionPacingProfilePolicy)
    if (@($adjacentPolicyValues | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne "legacy_current"
            }).Count -ne 0) {
        throw "Queued-send performance package path requires every adjacent adaptive-runtime policy to be legacy_current or unset."
    }
}
if ($admissionPerformancePathRequested) {
    if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy) -or
        [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy) -or
        [string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy)) {
        throw "Admission-performance package path requires oversized admission, application-send batch, and buffer-copy policies together."
    }
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

$adaptiveRuntimeEnvironmentRequested =
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendTurnPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimePacketFlushCadencePolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveDeliveryQuantumPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeConnectionShardPlacementPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationDatagramBatchTransportPolicy) -or
    -not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeCongestionPacingProfilePolicy) -or
    $RawQuicDebugLogging
$admissionPerformanceCell = $null
if ($admissionPerformancePathRequested) {
    $admissionPerformanceCell = Get-AdmissionPerformancePackagePathCell `
        -OversizedWriteAdmissionPolicy $AdaptiveRuntimeOversizedWriteAdmissionPolicy `
        -ApplicationSendBatchPolicy $AdaptiveRuntimeApplicationSendBatchPolicy `
        -BufferCopyPolicy $AdaptiveRuntimeBufferCopyPolicy `
        -ManifestContentSha256 $AdaptiveRuntimeAdmissionPerformanceManifestContentSha256
}
$queuedSendPerformanceCell = $null
if ($queuedSendPerformancePathRequested) {
    $queuedSendPerformanceCell = Get-QueuedSendPerformancePackagePathCell `
        -QueuedSendBurstPolicy $AdaptiveRuntimeQueuedSendBurstPolicy `
        -ManifestContentSha256 $AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256
}
if ($adaptiveRuntimeEnvironmentRequested) {
    $implementationManifestPath = Join-Path $stageRoot "implementations/quic-dotnet-raw-dev.yaml"
    $implementationText = Get-Content -LiteralPath $implementationManifestPath -Raw
    $environmentAnchorPattern = '(?m)^(  ASPNETCORE_URLS: http://127\.0\.0\.1:53591)(\r?)$'
    $environmentAnchorMatches = [regex]::Matches($implementationText, $environmentAnchorPattern)
    if ($environmentAnchorMatches.Count -ne 1) {
        throw "Raw QUIC package implementation manifest must contain exactly one ASPNETCORE_URLS environment anchor."
    }

    $environmentReplacement = '$1$2'
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveCreditPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY: $AdaptiveRuntimeReceiveCreditPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendTurnPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY: $AdaptiveRuntimeApplicationSendTurnPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_BURST_POLICY: $AdaptiveRuntimeQueuedSendBurstPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_OVERSIZED_WRITE_ADMISSION_POLICY: $AdaptiveRuntimeOversizedWriteAdmissionPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_BATCH_POLICY: $AdaptiveRuntimeApplicationSendBatchPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_BUFFER_COPY_POLICY: $AdaptiveRuntimeBufferCopyPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimePacketFlushCadencePolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_PACKET_FLUSH_CADENCE_POLICY: $AdaptiveRuntimePacketFlushCadencePolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeReceiveDeliveryQuantumPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_DELIVERY_QUANTUM_POLICY: $AdaptiveRuntimeReceiveDeliveryQuantumPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeConnectionShardPlacementPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_CONNECTION_SHARD_PLACEMENT_POLICY: $AdaptiveRuntimeConnectionShardPlacementPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationDatagramBatchTransportPolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_DATAGRAM_BATCH_TRANSPORT_POLICY: $AdaptiveRuntimeApplicationDatagramBatchTransportPolicy"
    }
    if (-not [string]::IsNullOrWhiteSpace($AdaptiveRuntimeCongestionPacingProfilePolicy)) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_CONGESTION_PACING_PROFILE_POLICY: $AdaptiveRuntimeCongestionPacingProfilePolicy"
    }
    if ($RawQuicDebugLogging) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG: 1"
    }
    if ($admissionPerformanceCell -ne $null) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_EVIDENCE_MODE: bounded_aggregate"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CAMPAIGN_ID: $($admissionPerformanceCell.campaignId)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_MANIFEST_CONTENT_SHA256: $($admissionPerformanceCell.manifestContentSha256)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CELL_ID: $($admissionPerformanceCell.cellId)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CELL_CONTENT_SHA256: $($admissionPerformanceCell.cellContentSha256)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_OVERSIZED_WRITE_ADMISSION_POLICY: $AdaptiveRuntimeOversizedWriteAdmissionPolicy"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_APPLICATION_SEND_BATCH_POLICY: $AdaptiveRuntimeApplicationSendBatchPolicy"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_BUFFER_COPY_POLICY: $AdaptiveRuntimeBufferCopyPolicy"
    }
    if ($queuedSendPerformanceCell -ne $null) {
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_EVIDENCE_MODE: bounded_aggregate"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_PERFORMANCE_CAMPAIGN_ID: $($queuedSendPerformanceCell.campaignId)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_PERFORMANCE_MANIFEST_CONTENT_SHA256: $($queuedSendPerformanceCell.manifestContentSha256)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_PERFORMANCE_CELL_ID: $($queuedSendPerformanceCell.cellId)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_PERFORMANCE_CELL_CONTENT_SHA256: $($queuedSendPerformanceCell.cellContentSha256)"
        $environmentReplacement += "`n  PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_PERFORMANCE_QUEUED_SEND_BURST_POLICY: $AdaptiveRuntimeQueuedSendBurstPolicy"
    }
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
        adaptiveRuntimeApplicationSendTurnPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendTurnPolicy)) { $null } else { $AdaptiveRuntimeApplicationSendTurnPolicy }
        adaptiveRuntimeQueuedSendBurstPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy)) { $null } else { $AdaptiveRuntimeQueuedSendBurstPolicy }
        queuedSendPerformancePackagePathSelected = [bool]$queuedSendPerformancePathRequested
        queuedSendPerformanceCampaignId = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.campaignId }
        queuedSendPerformanceManifestContentSha256 = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.manifestContentSha256 }
        queuedSendPerformanceCellId = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.cellId }
        queuedSendPerformanceCellContentSha256 = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.cellContentSha256 }
        admissionPerformancePackagePathSelected = [bool]$admissionPerformancePathRequested
        admissionPerformanceCampaignId = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.campaignId }
        admissionPerformanceManifestContentSha256 = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.manifestContentSha256 }
        admissionPerformanceCellId = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.cellId }
        admissionPerformanceCellContentSha256 = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.cellContentSha256 }
        admissionPerformanceOversizedWriteAdmissionPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy)) { $null } else { $AdaptiveRuntimeOversizedWriteAdmissionPolicy }
        admissionPerformanceApplicationSendBatchPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy)) { $null } else { $AdaptiveRuntimeApplicationSendBatchPolicy }
        admissionPerformanceBufferCopyPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy)) { $null } else { $AdaptiveRuntimeBufferCopyPolicy }
        rawQuicDebugLogging = [bool]$RawQuicDebugLogging
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
        adaptiveRuntimeApplicationSendTurnPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendTurnPolicy)) { $null } else { $AdaptiveRuntimeApplicationSendTurnPolicy }
        adaptiveRuntimeQueuedSendBurstPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy)) { $null } else { $AdaptiveRuntimeQueuedSendBurstPolicy }
        queuedSendPerformancePackagePathSelected = [bool]$queuedSendPerformancePathRequested
        queuedSendPerformanceCampaignId = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.campaignId }
        queuedSendPerformanceManifestContentSha256 = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.manifestContentSha256 }
        queuedSendPerformanceCellId = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.cellId }
        queuedSendPerformanceCellContentSha256 = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.cellContentSha256 }
        admissionPerformancePackagePathSelected = [bool]$admissionPerformancePathRequested
        admissionPerformanceCampaignId = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.campaignId }
        admissionPerformanceManifestContentSha256 = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.manifestContentSha256 }
        admissionPerformanceCellId = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.cellId }
        admissionPerformanceCellContentSha256 = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.cellContentSha256 }
        admissionPerformanceOversizedWriteAdmissionPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy)) { $null } else { $AdaptiveRuntimeOversizedWriteAdmissionPolicy }
        admissionPerformanceApplicationSendBatchPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy)) { $null } else { $AdaptiveRuntimeApplicationSendBatchPolicy }
        admissionPerformanceBufferCopyPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy)) { $null } else { $AdaptiveRuntimeBufferCopyPolicy }
        rawQuicDebugLogging = [bool]$RawQuicDebugLogging
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
    adaptiveRuntimeApplicationSendTurnPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendTurnPolicy)) { $null } else { $AdaptiveRuntimeApplicationSendTurnPolicy }
    adaptiveRuntimeQueuedSendBurstPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeQueuedSendBurstPolicy)) { $null } else { $AdaptiveRuntimeQueuedSendBurstPolicy }
    queuedSendPerformancePackagePathSelected = [bool]$queuedSendPerformancePathRequested
    queuedSendPerformanceCampaignId = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.campaignId }
    queuedSendPerformanceManifestContentSha256 = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.manifestContentSha256 }
    queuedSendPerformanceCellId = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.cellId }
    queuedSendPerformanceCellContentSha256 = if ($queuedSendPerformanceCell -eq $null) { $null } else { $queuedSendPerformanceCell.cellContentSha256 }
    admissionPerformancePackagePathSelected = [bool]$admissionPerformancePathRequested
    admissionPerformanceCampaignId = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.campaignId }
    admissionPerformanceManifestContentSha256 = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.manifestContentSha256 }
    admissionPerformanceCellId = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.cellId }
    admissionPerformanceCellContentSha256 = if ($admissionPerformanceCell -eq $null) { $null } else { $admissionPerformanceCell.cellContentSha256 }
    admissionPerformanceOversizedWriteAdmissionPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeOversizedWriteAdmissionPolicy)) { $null } else { $AdaptiveRuntimeOversizedWriteAdmissionPolicy }
    admissionPerformanceApplicationSendBatchPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeApplicationSendBatchPolicy)) { $null } else { $AdaptiveRuntimeApplicationSendBatchPolicy }
    admissionPerformanceBufferCopyPolicy = if ([string]::IsNullOrWhiteSpace($AdaptiveRuntimeBufferCopyPolicy)) { $null } else { $AdaptiveRuntimeBufferCopyPolicy }
    rawQuicDebugLogging = [bool]$RawQuicDebugLogging
    workRoot = $resolvedWorkRoot
    sha256 = $sha256
    buildAttestationPath = [System.IO.Path]::GetFullPath($attestationPath)
    parityEligible = $sourceClean
    sourceCommit = $sourceCommit
} | ConvertTo-Json -Depth 8
