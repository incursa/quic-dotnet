[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [long]$SourceRunId = 25904716076,
    [string]$EvidenceRoot = "",
    [string]$OutputJsonPath = "",
    [string]$OutputMarkdownPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($EvidenceRoot))
{
    $EvidenceRoot = Join-Path $RepoRoot "artifacts\tmp-major-peer-evidence-$SourceRunId"
}

if ([string]::IsNullOrWhiteSpace($OutputJsonPath))
{
    $OutputJsonPath = Join-Path $RepoRoot "specs\generated\quic\interop-major-peer-matrix-evidence-$SourceRunId.json"
}

if ([string]::IsNullOrWhiteSpace($OutputMarkdownPath))
{
    $OutputMarkdownPath = Join-Path $RepoRoot "specs\generated\quic\interop-major-peer-matrix-evidence-$SourceRunId.md"
}

function Get-RepoRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetRelativePath($RepoRoot, (Resolve-Path -LiteralPath $Path).Path).Replace('\', '/')
}

function Read-InvocationMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $metadata = @{}
    foreach ($line in Get-Content -LiteralPath $Path)
    {
        if ($line -match '^(?<key>[A-Za-z][A-Za-z0-9]+):\s*(?<value>.*)$')
        {
            $metadata[$matches.key] = $matches.value
        }
    }

    return $metadata
}

function Get-FailureClass {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CellId,
        [Parameter(Mandatory = $true)]
        [string]$Result
    )

    if ($Result -ne 'failed')
    {
        return 'none'
    }

    switch ($CellId)
    {
        'client-handshake-msquic' { return 'peer-tls-alert-50' }
        'client-keyupdate-msquic' { return 'peer-tls-alert-50' }
        'client-retry-msquic' { return 'peer-tls-alert-50' }
        'client-transfer-msquic' { return 'peer-tls-alert-50' }
        'client-resumption-msquic' { return 'peer-tls-alert-50' }
        'client-keyupdate-quic-go' { return 'peer-keyupdate-response-timeout' }
        'client-transfer-quic-go' { return 'peer-transfer-response-timeout' }
        'server-keyupdate-msquic' { return 'peer-keyupdate-missing-file' }
        'server-resumption-msquic' { return 'peer-connection-terminated' }
        default { return 'peer-unclassified' }
    }
}

if (-not (Test-Path -LiteralPath $EvidenceRoot))
{
    throw "Evidence root '$EvidenceRoot' does not exist."
}

$inventoryPath = Join-Path $RepoRoot "specs\generated\quic\interop-major-peer-matrix-inventory.json"
if (-not (Test-Path -LiteralPath $inventoryPath))
{
    throw "Inventory report '$inventoryPath' does not exist."
}

$inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
$inventoryByCellId = @{}
foreach ($cell in $inventory.cells)
{
    $inventoryByCellId[$cell.cell_id] = $cell
}

$bundleInfoByCellId = @{}
foreach ($bundleDirectory in Get-ChildItem -LiteralPath $EvidenceRoot -Directory | Sort-Object Name)
{
    $invocationPath = Get-ChildItem -LiteralPath $bundleDirectory.FullName -Recurse -Filter invocation.txt | Select-Object -First 1
    if ($null -eq $invocationPath)
    {
        throw "Unable to find invocation.txt under '$($bundleDirectory.FullName)'."
    }

    $metadata = Read-InvocationMetadata -Path $invocationPath.FullName
    $localRole = $metadata['LocalRole']
    $testCase = ($metadata['TestCases'] -split ',', 2)[0].Trim()
    $peerSlot = ($metadata['PeerImplementationSlots'] -split ',', 2)[0].Trim()
    $cellId = "$localRole-$testCase-$peerSlot"

    if ($bundleInfoByCellId.ContainsKey($cellId))
    {
        throw "Duplicate evidence bundle for cell '$cellId'."
    }

    $runnerReportPath = Join-Path $invocationPath.DirectoryName 'runner-report.json'
    if (-not (Test-Path -LiteralPath $runnerReportPath))
    {
        throw "Unable to find runner-report.json under '$($invocationPath.DirectoryName)'."
    }

    $runnerReport = Get-Content -LiteralPath $runnerReportPath -Raw | ConvertFrom-Json
    $runnerResult = $runnerReport.results[0][0].result

    $bundleInfoByCellId[$cellId] = [pscustomobject]@{
        cell_id               = $cellId
        local_role            = $localRole
        testcase              = $testCase
        peer_slot             = $peerSlot
        artifact_root         = Get-RepoRelativePath -Path $invocationPath.DirectoryName
        runner_result         = $runnerResult
    }
}

$rows = foreach ($cell in $inventory.cells)
{
    if (-not $bundleInfoByCellId.ContainsKey($cell.cell_id))
    {
        throw "Missing evidence bundle for cell '$($cell.cell_id)'."
    }

    $bundle = $bundleInfoByCellId[$cell.cell_id]
    $expectedResult = if ($cell.cell_id -in @(
        'client-handshake-msquic',
        'client-keyupdate-msquic',
        'client-retry-msquic',
        'client-transfer-msquic',
        'client-resumption-msquic',
        'client-keyupdate-quic-go',
        'client-transfer-quic-go',
        'server-keyupdate-msquic',
        'server-resumption-msquic'
    )) { 'failed' } else { 'succeeded' }

    if ($bundle.runner_result -ne $expectedResult)
    {
        throw "Cell '$($cell.cell_id)' reported '$($bundle.runner_result)' but the completed run classification expected '$expectedResult'."
    }

    [pscustomobject]@{
        cell_id               = $cell.cell_id
        peer_slot             = $cell.peer_slot
        local_role            = $cell.local_role
        testcase              = $cell.testcase
        peer_image            = $cell.peer_image
        runner_timeout_seconds = $cell.runner_timeout_seconds
        outcome_class         = if ($bundle.runner_result -eq 'succeeded') { 'passed' } else { 'failed' }
        failure_class         = Get-FailureClass -CellId $cell.cell_id -Result $bundle.runner_result
        artifact_root         = $bundle.artifact_root
        source_run_id         = $SourceRunId
        source_bundle         = 'major-peer-matrix'
    }
}

$passedCount = ($rows | Where-Object { $_.outcome_class -eq 'passed' }).Count
$failedCount = ($rows | Where-Object { $_.outcome_class -eq 'failed' }).Count

$failureClassCounts = [ordered]@{}
foreach ($row in $rows | Where-Object { $_.failure_class -ne 'none' } | Group-Object -Property failure_class | Sort-Object @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
{
    $failureClassCounts[$row.Name] = $row.Count
}

$report = [pscustomobject]@{
    report_id            = "interop-major-peer-matrix-evidence-$SourceRunId"
    advisory             = $true
    source_profile       = 'major-peer-matrix'
    source_requirement   = 'REQ-QUIC-INT-0019'
    summary              = "Completed major-peer-matrix evidence report for run $SourceRunId."
    source_runs          = @(
        [pscustomobject]@{
            run_id       = $SourceRunId
            bundle       = 'major-peer-matrix'
            artifact_root = Get-RepoRelativePath -Path $EvidenceRoot
        }
    )
    row_count            = $rows.Count
    outcome_counts       = [pscustomobject]@{
        passed = $passedCount
        failed = $failedCount
    }
    failure_class_counts = [pscustomobject]$failureClassCounts
    rows                 = @($rows)
}

$reportJson = $report | ConvertTo-Json -Depth 8
$markdownLines = [System.Collections.Generic.List[string]]::new()
$markdownLines.Add("# Interop Major Peer Matrix Evidence - $SourceRunId")
$markdownLines.Add('')
$markdownLines.Add('Advisory evidence report. Derived from the completed hosted major-peer-matrix run and intentionally not a support verdict.')
$markdownLines.Add('')
$markdownLines.Add('## Sources')
$markdownLines.Add('')
$markdownLines.Add("- $($SourceRunId): major-peer-matrix")
$markdownLines.Add('')
$markdownLines.Add('## Summary')
$markdownLines.Add('')
$markdownLines.Add("- rows: $($rows.Count)")
$markdownLines.Add("- passed: $passedCount")
$markdownLines.Add("- failed: $failedCount")
if ($failureClassCounts.Count -gt 0)
{
    $markdownLines.Add('- failure classes:')
    foreach ($entry in $failureClassCounts.GetEnumerator())
    {
        $markdownLines.Add("  - $($entry.Key): $($entry.Value)")
    }
}
$markdownLines.Add('')
$markdownLines.Add('| cell | peer | role | testcase | timeout | outcome class | failure class | artifact root |')
$markdownLines.Add('| --- | --- | --- | --- | --- | --- | --- | --- |')
foreach ($row in $rows)
{
    $markdownLines.Add(
        '| ' +
        ($row.cell_id.ToString().Replace('|', '\|')) + ' | ' +
        ($row.peer_slot.ToString().Replace('|', '\|')) + ' | ' +
        ($row.local_role.ToString().Replace('|', '\|')) + ' | ' +
        ($row.testcase.ToString().Replace('|', '\|')) + ' | ' +
        ($row.runner_timeout_seconds.ToString().Replace('|', '\|')) + ' | ' +
        ($row.outcome_class.ToString().Replace('|', '\|')) + ' | ' +
        ($row.failure_class.ToString().Replace('|', '\|')) + ' | ' +
        ($row.artifact_root.ToString().Replace('|', '\|')) + ' |')
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputJsonPath) -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputMarkdownPath) -Force | Out-Null

Set-Content -LiteralPath $OutputJsonPath -Value $reportJson -NoNewline
Set-Content -LiteralPath $OutputMarkdownPath -Value ($markdownLines -join [Environment]::NewLine)
