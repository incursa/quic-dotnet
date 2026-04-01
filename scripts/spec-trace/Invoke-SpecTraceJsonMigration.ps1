[CmdletBinding()]
param(
    [string]$RootPath = (Join-Path $PSScriptRoot '..\..'),
    [string[]]$Scope,
    [string]$BackupOutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath $RootPath).Path
$backupPath = & (Join-Path $PSScriptRoot 'Backup-SpecTraceCanonicalArtifacts.ps1') -RootPath $repoRoot -Scope $Scope -OutputRoot $BackupOutputRoot
& (Join-Path $PSScriptRoot 'Convert-SpecTraceCueToJson.ps1') -RootPath $repoRoot -Scope $Scope -DeleteCue
& (Join-Path $PSScriptRoot 'Align-SpecTraceJsonToPublishedSchema.ps1') -RootPath $repoRoot -Scope $Scope
& (Join-Path $PSScriptRoot 'Test-SpecTraceJsonMigration.ps1') -RootPath $repoRoot -Scope $Scope -BackupPath $backupPath

Write-Output $backupPath
