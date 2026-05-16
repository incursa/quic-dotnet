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
    $OutputJsonPath = Join-Path $RepoRoot "specs\generated\quic\interop-major-peer-matrix-inventory.json"
}

if ([string]::IsNullOrWhiteSpace($OutputMarkdownPath))
{
    $OutputMarkdownPath = Join-Path $RepoRoot "specs\generated\quic\interop-major-peer-matrix-inventory.md"
}

function Get-MajorPeerMatrixCells {
    @(
        [pscustomobject]@{ cell_id = 'client-handshake-quic-go'; local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'handshake'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'server-handshake-quic-go'; local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'handshake'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'client-retry-quic-go';      local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'retry'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'server-retry-quic-go';      local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'retry'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'client-transfer-quic-go';   local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'transfer'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'server-transfer-quic-go';   local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'transfer'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'client-keyupdate-quic-go';  local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'keyupdate'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'server-keyupdate-quic-go';  local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'keyupdate'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'client-resumption-quic-go'; local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'resumption'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'server-resumption-quic-go'; local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'quic-go'; peer_image = 'martenseemann/quic-go-interop:latest'; testcase = 'resumption'; runner_timeout_seconds = 180 }

        [pscustomobject]@{ cell_id = 'client-handshake-msquic';   local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'handshake'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'server-handshake-msquic';   local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'handshake'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'client-retry-msquic';       local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'retry'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'server-retry-msquic';       local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'retry'; runner_timeout_seconds = 0 }
        [pscustomobject]@{ cell_id = 'client-transfer-msquic';    local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'transfer'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'server-transfer-msquic';    local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'transfer'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'client-keyupdate-msquic';   local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'keyupdate'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'server-keyupdate-msquic';   local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'keyupdate'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'client-resumption-msquic';  local_role = 'client'; implementation_slot = 'chrome'; peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'resumption'; runner_timeout_seconds = 180 }
        [pscustomobject]@{ cell_id = 'server-resumption-msquic';  local_role = 'server'; implementation_slot = 'nginx';  peer_slot = 'msquic'; peer_image = 'ghcr.io/microsoft/msquic/qns:main'; testcase = 'resumption'; runner_timeout_seconds = 180 }
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

$cells = @(Get-MajorPeerMatrixCells)

$report = [pscustomobject]@{
    report_id      = 'interop-major-peer-matrix-inventory'
    advisory       = $true
    source_profile = 'major-peer-matrix'
    source_requirement = 'REQ-QUIC-INT-0019'
    summary        = 'Advisory inventory for the currently executable non-HTTP/3 major-peer matrix cells.'
    cell_count     = $cells.Count
    cells          = @(
        foreach ($cell in $cells)
        {
            [pscustomobject]@{
                cell_id               = $cell.cell_id
                local_role            = $cell.local_role
                implementation_slot   = $cell.implementation_slot
                peer_slot             = $cell.peer_slot
                peer_image            = $cell.peer_image
                testcase              = $cell.testcase
                runner_timeout_seconds = $cell.runner_timeout_seconds
                execution_state       = 'planned'
                target_artifact_root  = "artifacts/interop-runner/$($cell.cell_id)"
            }
        }
    )
}

$reportJson = $report | ConvertTo-Json -Depth 8
$markdownLines = [System.Collections.Generic.List[string]]::new()
$markdownLines.Add('# Interop Major Peer Matrix Inventory')
$markdownLines.Add('')
$markdownLines.Add('Advisory inventory only. The cells are the manually dispatched major-peer matrix shape owned by `REQ-QUIC-INT-0019`; this report does not claim execution evidence.')
$markdownLines.Add('')
$markdownLines.Add('## Profile')
$markdownLines.Add('')
$markdownLines.Add('- `major-peer-matrix`')
$markdownLines.Add('- peers: `quic-go`, `msquic`')
$markdownLines.Add('- roles: `client`, `server`')
$markdownLines.Add('- testcases: `handshake`, `retry`, `transfer`, `keyupdate`, `resumption`')
$markdownLines.Add('')
$markdownLines.Add('| cell | role | peer | testcase | timeout | execution state | target artifact root |')
$markdownLines.Add('| --- | --- | --- | --- | --- | --- | --- |')
foreach ($cell in $report.cells)
{
    $markdownLines.Add(
        '| ' +
        (Format-MarkdownCell $cell.cell_id) + ' | ' +
        (Format-MarkdownCell $cell.local_role) + ' | ' +
        (Format-MarkdownCell $cell.peer_slot) + ' | ' +
        (Format-MarkdownCell $cell.testcase) + ' | ' +
        (Format-MarkdownCell $cell.runner_timeout_seconds) + ' | ' +
        (Format-MarkdownCell $cell.execution_state) + ' | ' +
        (Format-MarkdownCell $cell.target_artifact_root) + ' |')
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputJsonPath) -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputMarkdownPath) -Force | Out-Null

Set-Content -LiteralPath $OutputJsonPath -Value $reportJson -NoNewline
Set-Content -LiteralPath $OutputMarkdownPath -Value ($markdownLines -join [Environment]::NewLine)
