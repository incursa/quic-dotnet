[CmdletBinding()]
param(
    [string]$RootPath = (Join-Path $PSScriptRoot '..\..'),
    [string[]]$Scope,
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'SpecTraceMigration.Common.ps1')

$repoRoot = Get-SpecTraceMigrationRepoRoot -RootPath $RootPath
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $timestamp = Get-Date -Format 'yyyyMMddTHHmmss'
    $OutputRoot = Join-Path $repoRoot "artifacts/spec-trace-json-migration/backups/$timestamp"
}

$cueExecutable = $null
$artifactPaths = @(Get-SpecTraceCanonicalSourceArtifactPaths -RepoRoot $repoRoot -Scope $Scope)
if ($artifactPaths.Count -eq 0) {
    throw 'No canonical SpecTrace artifacts were found for backup.'
}

if ($artifactPaths | Where-Object { [System.IO.Path]::GetExtension($_).Equals('.cue', [System.StringComparison]::OrdinalIgnoreCase) }) {
    $cueExecutable = Get-CueExecutablePath -RepoRoot $repoRoot
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$manifestArtifacts = New-Object System.Collections.Generic.List[object]

foreach ($artifactPath in $artifactPaths) {
    $sourceRelativePath = Get-RepoRelativePath -RepoRoot $repoRoot -Path $artifactPath
    $sourceExtension = [System.IO.Path]::GetExtension($artifactPath).ToLowerInvariant()
    $canonicalRelativePath = [System.IO.Path]::ChangeExtension($sourceRelativePath, '.json').Replace('\', '/')
    $destinationPath = Join-Path $OutputRoot $sourceRelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destinationPath) | Out-Null
    Copy-Item -LiteralPath $artifactPath -Destination $destinationPath -Force

    $markdownCompanion = if ($sourceExtension -eq '.md') { $artifactPath } else { [System.IO.Path]::ChangeExtension($artifactPath, '.md') }
    if ((Test-Path -LiteralPath $markdownCompanion) -and $markdownCompanion -ne $artifactPath) {
        $markdownRelativePath = Get-RepoRelativePath -RepoRoot $repoRoot -Path $markdownCompanion
        $markdownDestinationPath = Join-Path $OutputRoot $markdownRelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $markdownDestinationPath) | Out-Null
        Copy-Item -LiteralPath $markdownCompanion -Destination $markdownDestinationPath -Force
    }

    $artifact = Import-SpecTraceArtifactFromPath -RepoRoot $repoRoot -Path $artifactPath -CueExecutable $cueExecutable
    $snapshot = New-ComparableArtifactSnapshot -Artifact $artifact -RepoRelativePath $canonicalRelativePath
    $snapshot['source_path'] = $sourceRelativePath
    $snapshot['source_format'] = $sourceExtension.TrimStart('.')
    $manifestArtifacts.Add($snapshot)
}

$manifest = [ordered]@{
    created_utc = (Get-Date).ToUniversalTime().ToString('o')
    repo_root   = $repoRoot
    artifacts   = $manifestArtifacts.ToArray()
}

$manifestPath = Join-Path $OutputRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $manifestPath
Write-Output $OutputRoot
