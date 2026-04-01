[CmdletBinding()]
param(
    [string]$RootPath = (Join-Path $PSScriptRoot '..\..'),
    [string[]]$Scope,
    [switch]$DeleteCue
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'SpecTraceMigration.Common.ps1')

$repoRoot = Get-SpecTraceMigrationRepoRoot -RootPath $RootPath
$cueExecutable = Get-CueExecutablePath -RepoRoot $repoRoot
$cuePaths = @(Get-SpecTraceCanonicalCueArtifactPaths -RepoRoot $repoRoot -Scope $Scope)
if ($cuePaths.Count -eq 0) {
    throw 'No canonical .cue artifacts were found to convert.'
}

foreach ($cuePath in $cuePaths) {
    $artifact = Export-CueArtifact -RepoRoot $repoRoot -CuePath $cuePath -CueExecutable $cueExecutable
    $jsonPath = [System.IO.Path]::ChangeExtension($cuePath, '.json')
    Write-ArtifactJson -Artifact $artifact -JsonPath $jsonPath

    if ($DeleteCue) {
        Remove-Item -LiteralPath $cuePath -Force
    }
}

Write-Output "Wrote $($cuePaths.Count) canonical JSON artifact(s) from sibling .cue files."
