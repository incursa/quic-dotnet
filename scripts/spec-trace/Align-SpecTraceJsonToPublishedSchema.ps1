[CmdletBinding()]
param(
    [string]$RootPath = (Join-Path $PSScriptRoot '..\..'),
    [string[]]$Scope,
    [string]$SchemaUri = 'https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json',
    [switch]$SkipTemplates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'SpecTraceMigration.Common.ps1')

$repoRoot = Get-SpecTraceMigrationRepoRoot -RootPath $RootPath
$jsonPaths = New-Object System.Collections.Generic.List[string]

foreach ($jsonPath in @(Get-SpecTraceCanonicalJsonArtifactPaths -RepoRoot $repoRoot -Scope $Scope)) {
    if (-not $jsonPaths.Contains($jsonPath)) {
        $jsonPaths.Add($jsonPath)
    }
}

if (-not $SkipTemplates) {
    $templateRoot = Join-Path $repoRoot 'specs\templates'
    if (Test-Path -LiteralPath $templateRoot) {
        foreach ($templatePath in @(Get-ChildItem -LiteralPath $templateRoot -Filter '*.json' -File | Select-Object -ExpandProperty FullName)) {
            if (-not $jsonPaths.Contains($templatePath)) {
                $jsonPaths.Add($templatePath)
            }
        }
    }
}

if ($jsonPaths.Count -eq 0) {
    throw 'No canonical SpecTrace JSON artifacts or templates were found to align.'
}

$updatedCount = 0
foreach ($jsonPath in $jsonPaths) {
    $artifact = Import-JsonArtifact -JsonPath $jsonPath
    $publishedArtifact = Convert-LegacyArtifactToPublishedSchema -Artifact $artifact -SchemaUri $SchemaUri

    $currentJson = Get-ComparableArtifactString -Value (Get-Content -LiteralPath $jsonPath -Raw)
    $publishedJson = Get-ComparableArtifactString -Value ((($publishedArtifact | ConvertTo-Json -Depth 100).TrimEnd()) + [Environment]::NewLine)
    if ($currentJson -eq $publishedJson) {
        continue
    }

    Write-ArtifactJson -Artifact $publishedArtifact -JsonPath $jsonPath
    $updatedCount++
}

Write-Output "Aligned $updatedCount of $($jsonPaths.Count) SpecTrace JSON artifact/template file(s) to the published schema."
