[CmdletBinding()]
param(
    [string]$RootPath = (Join-Path $PSScriptRoot '..\..'),
    [Parameter(Mandatory)]
    [string]$BackupPath,
    [string[]]$Scope,
    [string]$SchemaUri = 'https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'SpecTraceMigration.Common.ps1')

$repoRoot = Get-SpecTraceMigrationRepoRoot -RootPath $RootPath
$resolvedBackupPath = if ([System.IO.Path]::IsPathRooted($BackupPath)) { $BackupPath } else { Join-Path $repoRoot $BackupPath }
$manifestPath = Join-Path $resolvedBackupPath 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Could not find migration manifest at '$manifestPath'."
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
$scopePrefixes = @($Scope | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        $_.Trim().Replace('\', '/').TrimStart('/').TrimEnd('/')
    })

$mismatches = New-Object System.Collections.Generic.List[string]
foreach ($expectedSnapshot in @($manifest['artifacts'])) {
    $relativePath = $expectedSnapshot['path']
    if ($scopePrefixes.Count -gt 0 -and -not ($scopePrefixes | Where-Object { $relativePath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
        continue
    }

    $jsonPath = Join-Path $repoRoot $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $jsonPath)) {
        $mismatches.Add("Missing migrated artifact '$relativePath'.")
        continue
    }

    $artifact = Import-JsonArtifact -JsonPath $jsonPath
    $actualSnapshot = New-ComparableArtifactSnapshot -Artifact $artifact -RepoRelativePath $relativePath -SchemaUri $SchemaUri
    $expectedArtifact = [ordered]@{}
    foreach ($key in $expectedSnapshot.Keys) {
        if ($key -in @('source_path', 'source_format')) {
            continue
        }

        if ($key -eq 'path') {
            continue
        }

        $expectedArtifact[$key] = $expectedSnapshot[$key]
    }

    $comparableExpectedSnapshot = New-ComparableArtifactSnapshot -Artifact $expectedArtifact -RepoRelativePath $relativePath -SchemaUri $SchemaUri

    foreach ($mismatch in (Compare-ArtifactSnapshots -Expected $comparableExpectedSnapshot -Actual $actualSnapshot)) {
        $mismatches.Add($mismatch)
    }
}

if ($mismatches.Count -gt 0) {
    throw "SpecTrace JSON migration parity failed:`n$($mismatches -join [Environment]::NewLine)"
}

& (Join-Path $repoRoot 'scripts\Validate-SpecTraceJson.ps1') -RepoRoot $repoRoot -Profiles core -SchemaUri $SchemaUri

& (Join-Path $repoRoot 'scripts\Assert-No-SpecTraceCue.ps1') -RepoRoot $repoRoot
if ($LASTEXITCODE -ne 0) {
    throw 'Residual .cue assertion failed.'
}

Write-Output "SpecTrace JSON migration parity succeeded for $(@($manifest['artifacts']).Count) artifact snapshot(s)."
