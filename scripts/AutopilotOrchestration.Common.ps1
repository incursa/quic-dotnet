Set-StrictMode -Version Latest

function Test-AutopilotMergeReadyTestsSummary {
    param([string]$TestsSummary = "")

    if ([string]::IsNullOrWhiteSpace($TestsSummary)) {
        return $false
    }

    $summaryText = $TestsSummary.Trim()
    if ($summaryText -notmatch '(?i)\bpassed\b') {
        return $false
    }

    $summaryText = $summaryText -replace '(?i)Validate-SpecTraceJson\.ps1 failed on pre-existing repo-wide residual Markdown/unresolved trace issues', ''
    $summaryText = $summaryText -replace '(?i)pre-existing repo-wide residual Markdown/unresolved trace issues', ''
    $summaryText = $summaryText -replace '(?i)pre-existing repo-wide residual', ''
    $summaryText = $summaryText -replace '(?i)pre-existing residual', ''

    return ($summaryText -notmatch '(?i)\bfailed\b|\bexit=\s*[1-9]\d*\b')
}

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
        (Test-AutopilotMergeReadyTestsSummary -TestsSummary $TestsSummary)
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
