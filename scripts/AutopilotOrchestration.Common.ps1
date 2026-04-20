Set-StrictMode -Version Latest

function Get-AutopilotReconciliationDisposition {
    param(
        [string]$State = "",
        [string]$CommitSha = "",
        [string]$TestsSummary = "",
        [bool]$WorktreeClean = $false
    )

    $mergeReady = $false
    if (
        $State -in @("pause_manual", "complete") -and
        -not [string]::IsNullOrWhiteSpace($CommitSha) -and
        $WorktreeClean -and
        -not [string]::IsNullOrWhiteSpace($TestsSummary) -and
        $TestsSummary -notmatch '(?i)\bfailed\b|\bexit=\s*[1-9]\d*\b' -and
        $TestsSummary -match '(?i)\bpassed\b'
    ) {
        $mergeReady = $true
    }

    $terminalState = $State
    if ($mergeReady -and $State -eq "pause_manual") {
        $terminalState = "complete"
    }

    return [pscustomobject]@{
        TerminalState            = $terminalState
        ReconcileAction          = if ($mergeReady) { "merge" } else { "" }
        MergeReady               = $mergeReady
        NormalizedFromPauseManual = ($State -eq "pause_manual" -and $terminalState -eq "complete")
    }
}
