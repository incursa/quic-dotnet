[CmdletBinding()]
param(
    [string] $OutputRoot = ".artifacts\perf-closeout",

    [string] $RunId = "quic-performance-closeout-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [string] $RuntimeChangeSummary = "",

    [string[]] $RequirementArtifact = @(),

    [string[]] $FocusedTestCommand = @(),

    [string[]] $RequirementHomeTestCommand = @(),

    [string[]] $FullTestCommand = @(),

    [string] $SpecTraceValidationCommand = "pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles core",

    [string] $KnownSpecTraceBacklogNote = "No new SpecTrace validation backlog was identified for this performance slice.",

    [string[]] $ProtocolLabArtifactPath = @(),

    [string[]] $PerformanceArtifactPath = @(),

    [string[]] $CorrectnessNote = @(),

    [string[]] $PerformanceNote = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-RepoRoot {
    $candidate = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $candidate "Incursa.Quic.slnx"))) {
        throw "Could not locate quic-dotnet repository root from '$PSScriptRoot'."
    }

    return [System.IO.Path]::GetFullPath($candidate)
}

function Invoke-Git {
    param([string[]] $Arguments)

    $output = & git @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed: $output"
    }

    return @($output)
}

function New-ArtifactReference {
    param(
        [string] $Path,

        [string] $RepositoryRoot
    )

    $resolvedPath = Resolve-FullPath -Path $Path -BasePath $RepositoryRoot
    $exists = Test-Path -LiteralPath $resolvedPath
    $hash = $null
    $kind = "missing"

    if ($exists) {
        if (Test-Path -LiteralPath $resolvedPath -PathType Leaf) {
            $kind = "file"
            $hash = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        else {
            $kind = "directory"
        }
    }

    return [ordered]@{
        inputPath = $Path
        resolvedPath = $resolvedPath
        exists = [bool]$exists
        kind = $kind
        sha256 = $hash
    }
}

function Add-Line {
    param(
        [System.Collections.Generic.List[string]] $Lines,

        [string] $Line = ""
    )

    $Lines.Add($Line) | Out-Null
}

$repoRoot = Get-RepoRoot
$resolvedOutputRoot = Resolve-FullPath -Path $OutputRoot -BasePath $repoRoot
$runRoot = Join-Path $resolvedOutputRoot $RunId
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

$gitCommit = (Invoke-Git @("-C", $repoRoot, "rev-parse", "HEAD"))[0]
$gitStatus = @(Invoke-Git @("-C", $repoRoot, "status", "--short"))
$changedFiles = @(Invoke-Git @("-C", $repoRoot, "diff", "--name-only", "HEAD", "--"))

$requirementArtifacts = @($RequirementArtifact | ForEach-Object {
    New-ArtifactReference -Path $_ -RepositoryRoot $repoRoot
})
$protocolLabArtifacts = @($ProtocolLabArtifactPath | ForEach-Object {
    New-ArtifactReference -Path $_ -RepositoryRoot $repoRoot
})
$performanceArtifacts = @($PerformanceArtifactPath | ForEach-Object {
    New-ArtifactReference -Path $_ -RepositoryRoot $repoRoot
})

$document = [ordered]@{
    schemaVersion = "incursa.quic.performance-closeout.v1"
    generatedAtUtc = ([DateTime]::UtcNow).ToString("O", [Globalization.CultureInfo]::InvariantCulture)
    runId = $RunId
    repositoryRoot = $repoRoot
    runtimeChangeSummary = $RuntimeChangeSummary
    git = [ordered]@{
        commit = $gitCommit
        statusShort = $gitStatus
        changedFiles = $changedFiles
        worktreeClean = [bool]($gitStatus.Count -eq 0)
    }
    correctnessEvidence = [ordered]@{
        requirementArtifacts = $requirementArtifacts
        focusedTestCommands = @($FocusedTestCommand)
        requirementHomeTestCommands = @($RequirementHomeTestCommand)
        fullTestCommands = @($FullTestCommand)
        specTraceValidationCommand = $SpecTraceValidationCommand
        knownSpecTraceBacklogNote = $KnownSpecTraceBacklogNote
        notes = @($CorrectnessNote)
    }
    performanceEvidence = [ordered]@{
        protocolLabArtifacts = $protocolLabArtifacts
        localPerformanceArtifacts = $performanceArtifacts
        notes = @($PerformanceNote)
    }
}

$jsonPath = Join-Path $runRoot "performance-closeout.json"
$markdownPath = Join-Path $runRoot "performance-closeout.md"
$document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding utf8NoBOM

$lines = New-Object System.Collections.Generic.List[string]
Add-Line $lines "# QUIC Performance Closeout"
Add-Line $lines
Add-Line $lines "- Run ID: ``$RunId``"
Add-Line $lines "- Git commit: ``$gitCommit``"
Add-Line $lines "- Worktree clean: ``$($gitStatus.Count -eq 0)``"
Add-Line $lines "- Runtime change summary: $RuntimeChangeSummary"
Add-Line $lines "- Machine summary: ``$jsonPath``"
Add-Line $lines
Add-Line $lines "## Diff Hygiene"
if ($gitStatus.Count -eq 0) {
    Add-Line $lines "- No uncommitted changes were present when this closeout was generated."
}
else {
    foreach ($entry in $gitStatus) {
        Add-Line $lines "- ``$entry``"
    }
}
Add-Line $lines
Add-Line $lines "## Correctness Evidence"
Add-Line $lines "- SpecTrace validation command: ``$SpecTraceValidationCommand``"
Add-Line $lines "- Known SpecTrace backlog: $KnownSpecTraceBacklogNote"
foreach ($command in @($FocusedTestCommand)) {
    Add-Line $lines "- Focused test: ``$command``"
}
foreach ($command in @($RequirementHomeTestCommand)) {
    Add-Line $lines "- Requirement-home test: ``$command``"
}
foreach ($command in @($FullTestCommand)) {
    Add-Line $lines "- Full test: ``$command``"
}
foreach ($artifact in @($requirementArtifacts)) {
    Add-Line $lines "- Requirement/spec artifact: ``$($artifact.resolvedPath)`` exists ``$($artifact.exists)``"
}
foreach ($note in @($CorrectnessNote)) {
    Add-Line $lines "- Note: $note"
}
Add-Line $lines
Add-Line $lines "## Performance Evidence"
foreach ($artifact in @($protocolLabArtifacts)) {
    Add-Line $lines "- ProtocolLab artifact: ``$($artifact.resolvedPath)`` exists ``$($artifact.exists)``"
}
foreach ($artifact in @($performanceArtifacts)) {
    Add-Line $lines "- Local performance artifact: ``$($artifact.resolvedPath)`` exists ``$($artifact.exists)``"
}
foreach ($note in @($PerformanceNote)) {
    Add-Line $lines "- Note: $note"
}

Set-Content -LiteralPath $markdownPath -Value $lines -Encoding utf8NoBOM
Write-Host "Performance closeout: $markdownPath" -ForegroundColor Green
