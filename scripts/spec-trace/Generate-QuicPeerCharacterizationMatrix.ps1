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

function Get-RepoRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetRelativePath($RepoRoot, (Resolve-Path -LiteralPath $Path).Path).Replace('\', '/')
}

function Get-MajorPeerEvidenceRows {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($row in $report.rows)
    {
        [pscustomobject]@{
            peer_slot     = $row.peer_slot
            local_role    = $row.local_role
            testcase      = $row.testcase
            outcome_class = $row.outcome_class
            failure_class = $row.failure_class
            artifact_root = $row.artifact_root
            source_run_id = $report.source_runs[0].run_id
            source_bundle = $report.source_profile
        }
    }
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

$seedRows = @(Get-PeerCharacterizationSeedRows)
$majorPeerEvidencePath = Join-Path $RepoRoot "specs\generated\quic\interop-major-peer-matrix-evidence-$SourceRunId.json"
if (-not (Test-Path -LiteralPath $majorPeerEvidencePath))
{
    throw "Major-peer evidence report '$majorPeerEvidencePath' does not exist."
}

$rows = @(
    $seedRows
    Get-MajorPeerEvidenceRows -Path $majorPeerEvidencePath
)
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
    [pscustomobject]@{
        run_id       = $SourceRunId
        bundle       = 'major-peer-matrix'
        artifact_root = Get-RepoRelativePath -Path $EvidenceRoot
    }
)

$report = [pscustomobject]@{
    report_id      = 'interop-peer-characterization-matrix-pilot'
    advisory       = $true
    summary        = 'Refreshed advisory report `interop-peer-characterization-matrix-pilot` for mixed connectionmigration and major-peer evidence.'
    source_runs    = $sourceRuns
    row_count      = $rows.Count
    rows           = $rows
}

$reportJson = $report | ConvertTo-Json -Depth 8
$markdownLines = [System.Collections.Generic.List[string]]::new()
$markdownLines.Add('# Interop Peer Characterization Matrix Pilot')
$markdownLines.Add('')
$markdownLines.Add('Advisory report `interop-peer-characterization-matrix-pilot`. Derived from preserved hosted bundles and the completed major-peer evidence, and intentionally not a support verdict.')
$markdownLines.Add('')
$markdownLines.Add('## Sources')
$markdownLines.Add('')
$markdownLines.Add('- `25891504134`: `connectionmigration-server-proof`')
$markdownLines.Add('- `25882671754`: `connectionmigration-server-proof-blocked`')
$markdownLines.Add('- `' + $SourceRunId + '`: `major-peer-matrix`')
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
