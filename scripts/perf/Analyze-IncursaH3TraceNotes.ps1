[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ArtifactRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
    throw "Artifact root was not found: $ArtifactRoot"
}

$resolvedRoot = (Resolve-Path -LiteralPath $ArtifactRoot).Path
$notesPath = Join-Path $resolvedRoot "analysis-notes.md"
$files = Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
        "- ``$($_.FullName)`` ($($_.Length) bytes)"
    }

$traceFiles = Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Filter "*.nettrace" -ErrorAction SilentlyContinue
$counterFiles = Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Filter "counters.raw.*" -ErrorAction SilentlyContinue

$content = [System.Collections.Generic.List[string]]::new()
$content.Add("# Incursa H3 P1 Artifact Notes")
$content.Add("")
$content.Add("Artifact root: ``$resolvedRoot``")
$content.Add("")
$content.Add("## Files")
$content.Add("")
foreach ($file in $files) {
    $content.Add($file)
}

$content.Add("")
$content.Add("## Trace Review")
$content.Add("")
if ($traceFiles) {
    $content.Add("Open ``.nettrace`` files with Visual Studio, PerfView, or speedscope conversion tooling. Start with CPU stacks under Incursa.Quic, Incursa.Quic.Http3, and Incursa.Qpack.")
}
else {
    $content.Add("No ``.nettrace`` files were found in this artifact root.")
}

$content.Add("")
$content.Add("## Counter Review")
$content.Add("")
if ($counterFiles) {
    $content.Add("Review raw ``System.Runtime`` counter files directly. Treat generated summaries as convenience only.")
}
else {
    $content.Add("No raw counter files were found in this artifact root.")
}

$content.Add("")
$content.Add("## Reminder")
$content.Add("")
$content.Add("These notes are an index only. They do not prove a bottleneck by themselves.")

Set-Content -Path $notesPath -Value $content
Get-Content -Path $notesPath
