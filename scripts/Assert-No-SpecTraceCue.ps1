[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot '..')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ignoredSegments = @(
    '.git',
    '.tools',
    '.vs',
    'artifacts',
    'bin',
    'obj',
    'node_modules'
)

$cueFiles = @(Get-ChildItem -LiteralPath $resolvedRepoRoot -Recurse -File -Filter '*.cue' |
    Where-Object {
        $relativePath = [System.IO.Path]::GetRelativePath($resolvedRepoRoot, $_.FullName)
        foreach ($segment in ($relativePath -split '[\\/]')) {
            if ($ignoredSegments -contains $segment) {
                return $false
            }
        }

        return $true
    } |
    Sort-Object FullName)

if ($cueFiles.Count -gt 0) {
    $paths = $cueFiles | ForEach-Object { [System.IO.Path]::GetRelativePath($resolvedRepoRoot, $_.FullName).Replace('\', '/') }
    throw "Found remaining SpecTrace .cue files:`n$($paths -join [Environment]::NewLine)"
}

Write-Output "No SpecTrace .cue files found under '$resolvedRepoRoot'."
