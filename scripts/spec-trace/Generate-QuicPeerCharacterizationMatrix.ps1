[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$OutputJsonPath = "",
    [string]$OutputMarkdownPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputJsonPath))
{
    $OutputJsonPath = Join-Path $RepoRoot "specs\generated\quic\interop-peer-characterization-matrix-pilot.json"
}

if ([string]::IsNullOrWhiteSpace($OutputMarkdownPath))
{
    $OutputMarkdownPath = Join-Path $RepoRoot "specs\generated\quic\interop-peer-characterization-matrix-pilot.md"
}

function Get-PeerCharacterizationSeedRows {
    @(
        [pscustomobject]@{
            peer_slot     = 'neqo'
            local_role    = 'server'
            testcase      = 'connectionmigration'
            outcome_class = 'failed'
            failure_class = 'peer-acked-unsent-packet'
            artifact_root = 'artifacts/tmp-run-25891504134/20260514-232809159-server-nginx'
            source_run_id = 25891504134
            source_bundle = 'connectionmigration-server-proof'
        }
        [pscustomobject]@{
            peer_slot     = 'quic-go'
            local_role    = 'server'
            testcase      = 'connectionmigration'
            outcome_class = 'failed'
            failure_class = 'peer-zero-length-dcid-cid-retirement'
            artifact_root = 'artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-quic-go-blocked-25882671754/20260514-200548260-server-neqo'
            source_run_id = 25882671754
            source_bundle = 'connectionmigration-server-proof-blocked'
        }
        [pscustomobject]@{
            peer_slot     = 'msquic'
            local_role    = 'server'
            testcase      = 'connectionmigration'
            outcome_class = 'failed'
            failure_class = 'peer-packet-layer-missing'
            artifact_root = 'artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-msquic-blocked-25882671754/20260514-200543902-server-neqo'
            source_run_id = 25882671754
            source_bundle = 'connectionmigration-server-proof-blocked'
        }
        [pscustomobject]@{
            peer_slot     = 'ngtcp2'
            local_role    = 'server'
            testcase      = 'connectionmigration'
            outcome_class = 'failed'
            failure_class = 'peer-transfer-size-mismatch'
            artifact_root = 'artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-ngtcp2-blocked-25882671754/20260514-200540179-server-neqo'
            source_run_id = 25882671754
            source_bundle = 'connectionmigration-server-proof-blocked'
        }
    )
}

function Format-MarkdownCell {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value)
    {
        return ''
    }

    return ([string]$Value).Replace('|', '\|')
}

$rows = @(Get-PeerCharacterizationSeedRows)
$sourceRuns = @(
    [pscustomobject]@{
        run_id       = 25891504134
        bundle       = 'connectionmigration-server-proof'
        artifact_root = 'artifacts/tmp-run-25891504134/20260514-232809159-server-nginx'
    }
    [pscustomobject]@{
        run_id       = 25882671754
        bundle       = 'connectionmigration-server-proof-blocked'
        artifact_root = 'artifacts/tmp-run-25882671754'
    }
)

$report = [pscustomobject]@{
    report_id      = 'interop-peer-characterization-matrix-pilot'
    advisory       = $true
    summary        = 'Seed report for mixed connectionmigration evidence and the blocked peer comparison lane.'
    source_runs    = $sourceRuns
    row_count      = $rows.Count
    rows           = $rows
}

$reportJson = $report | ConvertTo-Json -Depth 8
$markdownLines = [System.Collections.Generic.List[string]]::new()
$markdownLines.Add('# Interop Peer Characterization Matrix Pilot')
$markdownLines.Add('')
$markdownLines.Add('Advisory seed report. Derived from preserved hosted bundles and intentionally not a support verdict.')
$markdownLines.Add('')
$markdownLines.Add('## Sources')
$markdownLines.Add('')
$markdownLines.Add('- `25891504134`: `connectionmigration-server-proof`')
$markdownLines.Add('- `25882671754`: `connectionmigration-server-proof-blocked`')
$markdownLines.Add('')
$markdownLines.Add('| peer | role | testcase | outcome class | failure class | artifact root |')
$markdownLines.Add('| --- | --- | --- | --- | --- | --- |')
foreach ($row in $rows)
{
    $markdownLines.Add(
        '| ' +
        (Format-MarkdownCell $row.peer_slot) + ' | ' +
        (Format-MarkdownCell $row.local_role) + ' | ' +
        (Format-MarkdownCell $row.testcase) + ' | ' +
        (Format-MarkdownCell $row.outcome_class) + ' | ' +
        (Format-MarkdownCell $row.failure_class) + ' | ' +
        (Format-MarkdownCell $row.artifact_root) + ' |')
}

Set-Content -LiteralPath $OutputJsonPath -Value $reportJson -NoNewline
Set-Content -LiteralPath $OutputMarkdownPath -Value ($markdownLines -join [Environment]::NewLine)
