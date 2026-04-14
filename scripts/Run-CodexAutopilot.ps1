param(
    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory,

    [string]$InitialPrompt = "",

    [string]$InitialPromptFile = "",

    [string]$OutputDirectory = "",

    [string]$CodexCommand = "codex",

    [string]$Sandbox = "danger-full-access",

    [string]$Model = "gpt-5.4-mini",

    [string]$ReasoningEffort = "xhigh",

    [int]$MaxIterations = 12,

    [int]$MaxRescueAttemptsPerTurn = 1,

    [int]$MaxConsecutiveNoProgressTurns = 2,

    [switch]$AutoCommitIfDirty,

    [string]$FallbackCommitMessagePrefix = "Codex autopilot",

    [switch]$SkipGitChecks,

    [int]$HeartbeatMinutes = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-ExceptionDetail {
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

    $messages = New-Object System.Collections.Generic.List[string]
    $current = $Exception

    while ($null -ne $current) {
        if (-not [string]::IsNullOrWhiteSpace($current.Message)) {
            $messages.Add($current.Message.Trim())
        }

        $current = $current.InnerException
    }

    if ($messages.Count -eq 0) {
        return $Exception.ToString()
    }

    return ($messages -join " | Inner: ")
}

function Test-IsWindows {
    return $env:OS -eq "Windows_NT"
}

function Resolve-CodexCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    if (-not (Test-IsWindows) -or $Command -ne "codex") {
        return $Command
    }

    foreach ($candidate in @("codex.cmd", "codex.exe")) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    throw "Unable to resolve a runnable Codex executable. Looked for codex.cmd and codex.exe on PATH."
}

function Write-LogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Line
    )

    [System.IO.File]::AppendAllText($Path, $Line + [Environment]::NewLine)
}

function Write-CodexStreamLine {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("stdout", "stderr", "heartbeat", "info")]
        [string]$StreamName,

        [AllowEmptyString()]
        [Parameter(Mandatory = $true)]
        [string]$Line,

        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$TranscriptPath
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        return
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $prefixed = "[$timestamp][$StreamName] $Line"
    Write-LogLine -Path $LogPath -Line $prefixed
    Write-LogLine -Path $TranscriptPath -Line $prefixed

    $summary = $Line
    $color = switch ($StreamName) {
        "stdout" { "Cyan" }
        "stderr" { "DarkYellow" }
        "heartbeat" { "DarkGray" }
        default { "Gray" }
    }

    if ($StreamName -eq "stdout" -and $Line.StartsWith("{")) {
        try {
            $event = $Line | ConvertFrom-Json -ErrorAction Stop

            switch ($event.type) {
                "thread.started" {
                    if ($event.PSObject.Properties.Name -contains "thread_id" -and -not [string]::IsNullOrWhiteSpace([string]$event.thread_id)) {
                        $summary = "Codex thread started ($($event.thread_id))"
                    }
                    else {
                        $summary = "Codex thread started"
                    }
                }
                "turn.started" {
                    $summary = "Codex turn started"
                }
                "item.completed" {
                    if ($null -ne $event.item -and $event.item.PSObject.Properties.Name -contains "type") {
                        if ($event.item.type -eq "agent_message" -and $event.item.PSObject.Properties.Name -contains "text") {
                            $messageText = [string]$event.item.text
                            $messageText = ($messageText -replace '\s+', ' ').Trim()
                            if ($messageText.Length -gt 160) {
                                $messageText = $messageText.Substring(0, 157) + "..."
                            }

                            $summary = "Codex message: $messageText"
                        }
                        else {
                            $summary = "Codex item completed ($($event.item.type))"
                        }
                    }
                    else {
                        $summary = "Codex item completed"
                    }
                }
                "turn.completed" {
                    if ($null -ne $event.usage) {
                        $inputTokens = if ($event.usage.PSObject.Properties.Name -contains "input_tokens") { $event.usage.input_tokens } else { $null }
                        $outputTokens = if ($event.usage.PSObject.Properties.Name -contains "output_tokens") { $event.usage.output_tokens } else { $null }
                        if ($null -ne $inputTokens -or $null -ne $outputTokens) {
                            $summary = "Codex turn completed (input=$inputTokens, output=$outputTokens)"
                        }
                        else {
                            $summary = "Codex turn completed"
                        }
                    }
                    else {
                        $summary = "Codex turn completed"
                    }
                }
                default {
                    $summary = "Codex event: $($event.type)"
                }
            }
        }
        catch {
            $summary = $Line
        }
    }
    elseif ($StreamName -eq "stderr") {
        $summary = "Codex stderr: $summary"
    }

    $summary = ($summary -replace '\s+', ' ').Trim()
    if ($summary.Length -gt 220) {
        $summary = $summary.Substring(0, 217) + "..."
    }

    Write-Host "  $summary" -ForegroundColor $color
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [string]$WorkingDirectory = ""
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $psi.WorkingDirectory = $WorkingDirectory
    }

    foreach ($arg in $ArgumentList) {
        [void]$psi.ArgumentList.Add($arg)
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

function Test-GitAvailable {
    $git = Get-Command -Name git -ErrorAction SilentlyContinue
    return $null -ne $git
}

function Get-GitSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $branch = ""
    $status = ""
    $recent = ""

    $branchResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "rev-parse", "--abbrev-ref", "HEAD")
    if ($branchResult.ExitCode -eq 0) {
        $branch = $branchResult.StdOut.Trim()
    }

    $statusResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "status", "--short", "--branch")
    if ($statusResult.ExitCode -eq 0) {
        $status = $statusResult.StdOut.TrimEnd()
    }

    $recentResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "log", "--oneline", "-n", "8")
    if ($recentResult.ExitCode -eq 0) {
        $recent = $recentResult.StdOut.TrimEnd()
    }

    $headResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "rev-parse", "HEAD")
    $head = if ($headResult.ExitCode -eq 0) { $headResult.StdOut.Trim() } else { "" }

    return [pscustomobject]@{
        Branch     = $branch
        Status     = $status
        RecentLog  = $recent
        Head       = $head
        IsClean    = [string]::IsNullOrWhiteSpace(($status -replace '^##.*(?:\r?\n)?', ''))
    }
}

function Get-GitDiffSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $result = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "status", "--short")
    if ($result.ExitCode -ne 0) {
        return ""
    }

    return $result.StdOut.TrimEnd()
}

function Invoke-GitCommitIfDirty {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$TranscriptPath
    )

    $statusBefore = Get-GitDiffSummary -RepositoryRoot $RepositoryRoot
    if ([string]::IsNullOrWhiteSpace($statusBefore)) {
        return [pscustomobject]@{
            Changed = $false
            Commit  = ""
            Message = $Message
        }
    }

    Write-LogLine -Path $TranscriptPath -Line "[git] Dirty worktree detected. Attempting automatic commit."

    $addResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "add", "-A")
    if ($addResult.ExitCode -ne 0) {
        throw "git add failed: $($addResult.StdErr.Trim())"
    }

    $commitArgs = @("-C", $RepositoryRoot, "commit", "-m", $Message)
    $commitResult = Invoke-NativeCapture -FilePath "git" -ArgumentList $commitArgs

    if ($commitResult.ExitCode -ne 0) {
        $stderr = ($commitResult.StdErr + "`n" + $commitResult.StdOut).Trim()
        if ($stderr -match "gpg|sign|signing") {
            Write-LogLine -Path $TranscriptPath -Line "[git] Commit signing blocked the commit. Retrying with --no-gpg-sign."
            $commitResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "commit", "--no-gpg-sign", "-m", $Message)
        }
    }

    if ($commitResult.ExitCode -ne 0) {
        $stderr = ($commitResult.StdErr + "`n" + $commitResult.StdOut).Trim()
        throw "git commit failed: $stderr"
    }

    $headResult = Invoke-NativeCapture -FilePath "git" -ArgumentList @("-C", $RepositoryRoot, "rev-parse", "HEAD")
    if ($headResult.ExitCode -ne 0) {
        throw "git rev-parse HEAD failed after commit."
    }

    return [pscustomobject]@{
        Changed = $true
        Commit  = $headResult.StdOut.Trim()
        Message = $Message
    }
}

function Get-MissionText {
    param(
        [string]$InlinePrompt,
        [string]$PromptFile
    )

    $parts = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($InlinePrompt)) {
        $parts.Add($InlinePrompt.Trim())
    }

    if (-not [string]::IsNullOrWhiteSpace($PromptFile)) {
        $resolved = Resolve-ExistingPath -Path $PromptFile
        $fileText = Get-Content -LiteralPath $resolved -Raw
        if (-not [string]::IsNullOrWhiteSpace($fileText)) {
            $parts.Add($fileText.Trim())
        }
    }

    if ($parts.Count -eq 0) {
        throw "Provide either -InitialPrompt or -InitialPromptFile."
    }

    $separator = [Environment]::NewLine + [Environment]::NewLine
    return ($parts -join $separator)
}

function Convert-HistoryToText {
    param(
        [object[]]$History = @()
    )

    if ($null -eq $History -or $History.Count -eq 0) {
        return "(none yet)"
    }

    $lines = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $History) {
        $lines.Add("Turn $($entry.Turn) [$($entry.Mode)] -> state=$($entry.State), confidence=$($entry.Confidence), commit=$($entry.CommitSha), summary=$($entry.Summary)")
    }

    return ($lines -join [Environment]::NewLine)
}

function New-AutopilotPrompt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mission,

        [Parameter(Mandatory = $true)]
        [int]$Iteration,

        [Parameter(Mandatory = $true)]
        [string]$GitContext,

        [Parameter(Mandatory = $true)]
        [string]$HistoryText,

        [Parameter(Mandatory = $true)]
        [bool]$RescueMode,

        [string]$PriorResultText = ""
    )

    $rescueInstructions = if ($RescueMode) {
@"
You previously reported that you were stuck or needed manual review.
Before stopping, do one broader repo-local investigation pass:
- inspect adjacent requirements, tests, generated reports, and nearby code
- look for a closely related bounded task that can honestly advance the mission without human intervention
- if no such task exists, stop cleanly with state=pause_manual and explain why
"@
    }
    else {
        "This is a normal autonomous turn."
    }

    $priorResultSection = if ([string]::IsNullOrWhiteSpace($PriorResultText)) {
        "(none)"
    }
    else {
        $trimmed = $PriorResultText.Trim()
        if ($trimmed.Length -gt 4000) {
            $trimmed = $trimmed.Substring(0, 4000) + "..."
        }
        $trimmed
    }

    return @"
You are running inside an unattended Codex autopilot loop for a local repository.

Primary mission:
$Mission

Core operating rules:
- Inspect the CURRENT repo state each turn and choose the single highest-priority bounded task that best advances the mission.
- Prefer one solid slice per turn over broad churn.
- Keep runtime/code work, proof/test work, and trace/design work clearly separated.
- If you make useful changes, run the most relevant checks you can, then create a local git commit.
- If commit signing blocks the commit, retry with --no-gpg-sign.
- Do not leave useful code changes uncommitted.
- Do not widen public support claims unless the runtime really earns them.
- If you are blocked, try one broader repo-local search for adjacent progress before asking for manual intervention.
- Assume the repo state is more authoritative than your memory of earlier turns.

Terminal states you may return:
- continue: useful progress made and another autonomous turn is worthwhile
- complete: the current mission is complete or the next work should be explicitly replanned by a human
- pause_manual: manual review / human decision / external information is genuinely required
- stuck: you could not make safe progress this turn

You MUST end your final response with these exact markers and one JSON object:
BEGIN_AUTOPILOT_RESULT
{
  "state": "continue|complete|pause_manual|stuck",
  "summary": "short plain-English summary",
  "next_step": "what should happen next",
  "broaden_search_worthwhile": true,
  "manual_reason": "reason if manual review is needed, otherwise empty string",
  "commit_sha": "commit sha if one was created, otherwise empty string",
  "commit_message": "commit subject if one was created, otherwise empty string",
  "tests": "concise test/check summary",
  "dirty_worktree": false,
  "confidence": "high|medium|low"
}
END_AUTOPILOT_RESULT

Turn number: $Iteration
Mode: $(if ($RescueMode) { "rescue" } else { "normal" })

Repo snapshot:
$GitContext

Prior turn summaries:
$HistoryText

Most recent full final response from prior turn:
$priorResultSection

$rescueInstructions

Before you finish:
- If you changed files, commit them locally.
- If no files changed, say so explicitly.
- Do not commit temp output files or logs outside the repo.
- Make the JSON block valid and easy to parse.
"@
}

function Invoke-CodexTurn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CodexExecutable,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$PromptText,

        [Parameter(Mandatory = $true)]
        [string]$ResultPath,

        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$TranscriptPath,

        [Parameter(Mandatory = $true)]
        [string]$Sandbox,

        [Parameter(Mandatory = $true)]
        [string]$Model,

        [Parameter(Mandatory = $true)]
        [string]$ReasoningEffort,

        [Parameter(Mandatory = $true)]
        [int]$HeartbeatMinutes
    )

    $startTime = Get-Date
    $process = $null
    $stdoutDone = $false
    $stderrDone = $false
    $stdoutTask = $null
    $stderrTask = $null
    $nextHeartbeatAt = $startTime.AddMinutes($HeartbeatMinutes)

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $CodexExecutable
        $psi.WorkingDirectory = $WorkingDirectory
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        [void]$psi.ArgumentList.Add("exec")
        [void]$psi.ArgumentList.Add("--json")
        [void]$psi.ArgumentList.Add("--output-last-message")
        [void]$psi.ArgumentList.Add($ResultPath)
        [void]$psi.ArgumentList.Add("--sandbox")
        [void]$psi.ArgumentList.Add($Sandbox)
        [void]$psi.ArgumentList.Add("--model")
        [void]$psi.ArgumentList.Add($Model)
        [void]$psi.ArgumentList.Add("--config")
        [void]$psi.ArgumentList.Add("model_reasoning_effort=""$ReasoningEffort""")

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi

        [void]$process.Start()
        $process.StandardInput.Write($PromptText)
        $process.StandardInput.Close()

        $stdoutTask = $process.StandardOutput.ReadLineAsync()
        $stderrTask = $process.StandardError.ReadLineAsync()

        while ($true) {
            $delayTask = [System.Threading.Tasks.Task]::Delay(250)
            $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]

            if (-not $stdoutDone) {
                [void]$tasks.Add([System.Threading.Tasks.Task]$stdoutTask)
            }

            if (-not $stderrDone) {
                [void]$tasks.Add([System.Threading.Tasks.Task]$stderrTask)
            }

            [void]$tasks.Add($delayTask)

            $completed = [System.Threading.Tasks.Task]::WhenAny($tasks.ToArray()).GetAwaiter().GetResult()

            if ($completed -eq $delayTask) {
                $now = Get-Date
                if ($now -ge $nextHeartbeatAt) {
                    $elapsed = $now - $startTime
                    $elapsedText = $elapsed.ToString("hh\:mm\:ss")
                    Write-CodexStreamLine -StreamName "heartbeat" -Line "Codex still running after $elapsedText" -LogPath $LogPath -TranscriptPath $TranscriptPath
                    $nextHeartbeatAt = $now.AddMinutes($HeartbeatMinutes)
                }

                if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                    break
                }

                continue
            }

            if (-not $stdoutDone -and $completed -eq $stdoutTask) {
                $line = $stdoutTask.GetAwaiter().GetResult()
                if ($null -eq $line) {
                    $stdoutDone = $true
                }
                else {
                    Write-CodexStreamLine -StreamName "stdout" -Line $line -LogPath $LogPath -TranscriptPath $TranscriptPath
                    $nextHeartbeatAt = (Get-Date).AddMinutes($HeartbeatMinutes)
                }

                if (-not $stdoutDone) {
                    $stdoutTask = $process.StandardOutput.ReadLineAsync()
                }
            }
            elseif (-not $stderrDone -and $completed -eq $stderrTask) {
                $line = $stderrTask.GetAwaiter().GetResult()
                if ($null -eq $line) {
                    $stderrDone = $true
                }
                else {
                    Write-CodexStreamLine -StreamName "stderr" -Line $line -LogPath $LogPath -TranscriptPath $TranscriptPath
                    $nextHeartbeatAt = (Get-Date).AddMinutes($HeartbeatMinutes)
                }

                if (-not $stderrDone) {
                    $stderrTask = $process.StandardError.ReadLineAsync()
                }
            }

            if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                break
            }
        }

        $process.WaitForExit()
        $duration = (Get-Date) - $startTime
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Seconds  = [math]::Round($duration.TotalSeconds, 2)
        }
    }
    finally {
        if ($null -ne $process) {
            try { $process.Dispose() } catch { }
        }
    }
}

function Try-ParseAutopilotResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $patterns = @(
        'BEGIN_AUTOPILOT_RESULT\s*(\{.*?\})\s*END_AUTOPILOT_RESULT',
        '```json\s*(\{.*?\})\s*```',
        '(\{\s*"state"\s*:.*\})'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($match.Success) {
            $jsonText = $match.Groups[1].Value.Trim()
            try {
                return $jsonText | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
            }
        }
    }

    return $null
}

try {
    $workRoot = Resolve-ExistingPath -Path $WorkingDirectory
    $codexExecutable = Resolve-CodexCommand -Command $CodexCommand
    $mission = Get-MissionText -InlinePrompt $InitialPrompt -PromptFile $InitialPromptFile

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $repoName = [System.IO.Path]::GetFileName($workRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
        $timeStamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $parent = [System.IO.Path]::GetDirectoryName($workRoot)
        $defaultOutput = Join-Path $parent ("_" + $repoName + "-codex-autopilot-" + $timeStamp)
        $outputRoot = Ensure-Directory -Path $defaultOutput
    }
    else {
        $outputRoot = Ensure-Directory -Path $OutputDirectory
    }

    $promptsRoot = Ensure-Directory -Path (Join-Path $outputRoot "prompts")
    $resultsRoot = Ensure-Directory -Path (Join-Path $outputRoot "results")
    $logsRoot = Ensure-Directory -Path (Join-Path $outputRoot "logs")
    $transcriptPath = Join-Path $outputRoot "autopilot-transcript.log"
    $journalPath = Join-Path $outputRoot "autopilot-journal.jsonl"
    $summaryPath = Join-Path $outputRoot "autopilot-summary.csv"

    Write-LogLine -Path $transcriptPath -Line "=== Codex autopilot started at $((Get-Date).ToString('s')) ==="
    Write-LogLine -Path $transcriptPath -Line "WorkingDirectory=$workRoot"
    Write-LogLine -Path $transcriptPath -Line "OutputDirectory=$outputRoot"

    if (-not $SkipGitChecks) {
        if (-not (Test-GitAvailable)) {
            throw "git is required unless -SkipGitChecks is used."
        }
    }

    $history = New-Object System.Collections.Generic.List[object]
    $summary = New-Object System.Collections.Generic.List[object]
    $consecutiveNoProgress = 0
    $lastFullResultText = ""
    $stopReason = ""

    for ($iteration = 1; $iteration -le $MaxIterations; $iteration++) {
        $modes = @("normal")
        for ($rescueIndex = 1; $rescueIndex -le $MaxRescueAttemptsPerTurn; $rescueIndex++) {
            $modes += "rescue"
        }

        $completedTurn = $false
        $attemptNumber = 0

        foreach ($mode in $modes) {
            $attemptNumber++
            $rescueMode = $mode -eq "rescue"

            Write-Host ""
            Write-Host "Turn $iteration ($mode)" -ForegroundColor Green
            Write-LogLine -Path $transcriptPath -Line "=== Turn $iteration ($mode) ==="

            $gitSnapshot = if ($SkipGitChecks) {
                [pscustomobject]@{ Branch = "(skipped)"; Status = "(skipped)"; RecentLog = "(skipped)"; Head = ""; IsClean = $true }
            }
            else {
                Get-GitSnapshot -RepositoryRoot $workRoot
            }

            $gitContext = @"
Branch: $($gitSnapshot.Branch)
HEAD: $($gitSnapshot.Head)

Status:
$($gitSnapshot.Status)

Recent commits:
$($gitSnapshot.RecentLog)
"@

            $historyText = Convert-HistoryToText -History ($history.ToArray())
            $promptText = New-AutopilotPrompt -Mission $mission -Iteration $iteration -GitContext $gitContext -HistoryText $historyText -RescueMode:$rescueMode -PriorResultText $lastFullResultText

            $promptPath = Join-Path $promptsRoot ("turn-{0:D2}-{1}.prompt.md" -f $iteration, $mode)
            $resultPath = Join-Path $resultsRoot ("turn-{0:D2}-{1}.result.md" -f $iteration, $mode)
            $logPath = Join-Path $logsRoot ("turn-{0:D2}-{1}.log.txt" -f $iteration, $mode)

            Set-Content -LiteralPath $promptPath -Value $promptText -NoNewline

            $headBefore = if ($SkipGitChecks) { "" } else { (Get-GitSnapshot -RepositoryRoot $workRoot).Head }

            $run = Invoke-CodexTurn -CodexExecutable $codexExecutable -WorkingDirectory $workRoot -PromptText $promptText -ResultPath $resultPath -LogPath $logPath -TranscriptPath $transcriptPath -Sandbox $Sandbox -Model $Model -ReasoningEffort $ReasoningEffort -HeartbeatMinutes $HeartbeatMinutes

            if (-not (Test-Path -LiteralPath $resultPath)) {
                throw "Codex did not write a final result file: $resultPath"
            }

            $fullResultText = Get-Content -LiteralPath $resultPath -Raw
            $lastFullResultText = $fullResultText
            $decision = Try-ParseAutopilotResult -Text $fullResultText

            if ($null -eq $decision) {
                Write-Warning "Could not parse the autopilot JSON result for turn $iteration ($mode)."
                if ($rescueMode -or $MaxRescueAttemptsPerTurn -eq 0) {
                    $stopReason = "Could not parse Codex autopilot JSON result."
                    $completedTurn = $true
                    break
                }

                continue
            }

            $state = [string]$decision.state
            $summaryText = [string]$decision.summary
            $nextStep = [string]$decision.next_step
            $manualReason = [string]$decision.manual_reason
            $commitSha = [string]$decision.commit_sha
            $commitMessage = [string]$decision.commit_message
            $testsSummary = [string]$decision.tests
            $confidence = [string]$decision.confidence
            $broadenSearchWorthwhile = $false
            if ($decision.PSObject.Properties.Name -contains "broaden_search_worthwhile") {
                $broadenSearchWorthwhile = [bool]$decision.broaden_search_worthwhile
            }

            if (-not $SkipGitChecks) {
                $statusAfter = Get-GitSnapshot -RepositoryRoot $workRoot
                $headAfter = $statusAfter.Head
                $headChanged = -not [string]::Equals($headBefore, $headAfter, [System.StringComparison]::OrdinalIgnoreCase)

                if (-not $statusAfter.IsClean -and $AutoCommitIfDirty) {
                    $fallbackMessage = if (-not [string]::IsNullOrWhiteSpace($commitMessage)) {
                        $commitMessage
                    }
                    else {
                        "$FallbackCommitMessagePrefix turn $iteration"
                    }

                    $commitResult = Invoke-GitCommitIfDirty -RepositoryRoot $workRoot -Message $fallbackMessage -TranscriptPath $transcriptPath
                    if ($commitResult.Changed) {
                        $commitSha = $commitResult.Commit
                        $commitMessage = $commitResult.Message
                        $statusAfter = Get-GitSnapshot -RepositoryRoot $workRoot
                        $headAfter = $statusAfter.Head
                        $headChanged = $true
                    }
                }

                if (-not $statusAfter.IsClean -and ($state -in @("continue", "complete", "pause_manual", "stuck"))) {
                    Write-Warning "Worktree is still dirty after turn $iteration ($mode)."
                    if (-not $AutoCommitIfDirty) {
                        $manualReasonParts = New-Object System.Collections.Generic.List[string]
                        if (-not [string]::IsNullOrWhiteSpace($manualReason)) { [void]$manualReasonParts.Add($manualReason.Trim()) }
                        [void]$manualReasonParts.Add("Dirty worktree remains and -AutoCommitIfDirty was not enabled.")
                        $manualReason = ($manualReasonParts -join " ")
                        $state = "pause_manual"
                    }
                }

                if ($headChanged) {
                    $consecutiveNoProgress = 0
                }
                else {
                    $consecutiveNoProgress++
                }
            }
            else {
                $consecutiveNoProgress++
            }

            $historyEntry = [pscustomobject]@{
                Turn      = $iteration
                Mode      = $mode
                State     = $state
                Summary   = $summaryText
                NextStep  = $nextStep
                CommitSha = $commitSha
                Tests     = $testsSummary
                Confidence= $confidence
            }
            [void]$history.Add($historyEntry)

            $journalLine = [pscustomobject]@{
                timestamp   = (Get-Date).ToString("o")
                turn        = $iteration
                mode        = $mode
                state       = $state
                summary     = $summaryText
                next_step   = $nextStep
                manual_reason = $manualReason
                commit_sha  = $commitSha
                commit_message = $commitMessage
                tests       = $testsSummary
                confidence  = $confidence
                result_file = $resultPath
                log_file    = $logPath
                seconds     = $run.Seconds
                exit_code   = $run.ExitCode
            } | ConvertTo-Json -Compress
            Write-LogLine -Path $journalPath -Line $journalLine

            $summary.Add([pscustomobject]@{
                Turn         = $iteration
                Mode         = $mode
                State        = $state
                Summary      = $summaryText
                NextStep     = $nextStep
                ManualReason = $manualReason
                CommitSha    = $commitSha
                CommitMessage= $commitMessage
                Tests        = $testsSummary
                Confidence   = $confidence
                ExitCode     = $run.ExitCode
                Seconds      = $run.Seconds
                ResultFile   = $resultPath
                LogFile      = $logPath
            })

            Write-Host "  Decision: state=$state, confidence=$confidence" -ForegroundColor Green
            if (-not [string]::IsNullOrWhiteSpace($summaryText)) {
                Write-Host "  Summary: $summaryText" -ForegroundColor Gray
            }
            if (-not [string]::IsNullOrWhiteSpace($nextStep)) {
                Write-Host "  Next:    $nextStep" -ForegroundColor Gray
            }
            if (-not [string]::IsNullOrWhiteSpace($commitSha)) {
                Write-Host "  Commit:  $commitSha" -ForegroundColor Gray
            }

            switch ($state) {
                "continue" {
                    if ($consecutiveNoProgress -ge $MaxConsecutiveNoProgressTurns) {
                        $stopReason = "Stopped after $consecutiveNoProgress consecutive no-progress turns."
                        $completedTurn = $true
                        break
                    }

                    $completedTurn = $true
                    break
                }
                "complete" {
                    $stopReason = "Mission complete."
                    $completedTurn = $true
                    $iteration = $MaxIterations + 1
                    break
                }
                "pause_manual" {
                    if (-not $rescueMode -and $broadenSearchWorthwhile -and $MaxRescueAttemptsPerTurn -gt 0) {
                        Write-Host "  Codex requested broader search before manual review. Starting rescue attempt." -ForegroundColor Yellow
                        continue
                    }

                    $stopReason = if (-not [string]::IsNullOrWhiteSpace($manualReason)) { $manualReason } else { "Manual review requested." }
                    $completedTurn = $true
                    $iteration = $MaxIterations + 1
                    break
                }
                "stuck" {
                    if (-not $rescueMode -and $MaxRescueAttemptsPerTurn -gt 0) {
                        Write-Host "  Codex reported it is stuck. Starting rescue attempt." -ForegroundColor Yellow
                        continue
                    }

                    $stopReason = if (-not [string]::IsNullOrWhiteSpace($manualReason)) { $manualReason } else { "Codex reported it is stuck." }
                    $completedTurn = $true
                    $iteration = $MaxIterations + 1
                    break
                }
                default {
                    $stopReason = "Unexpected autopilot state '$state'."
                    $completedTurn = $true
                    $iteration = $MaxIterations + 1
                    break
                }
            }
        }

        if (-not $completedTurn) {
            $stopReason = "Turn $iteration exhausted all allowed attempts without a terminal decision."
            break
        }
    }

    $summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation

    Write-Host ""
    Write-Host "Autopilot finished." -ForegroundColor Green
    if (-not [string]::IsNullOrWhiteSpace($stopReason)) {
        Write-Host "Stop reason: $stopReason" -ForegroundColor Yellow
    }
    Write-Host "Working directory: $workRoot"
    Write-Host "Output directory:  $outputRoot"
    Write-Host "Transcript:        $transcriptPath"
    Write-Host "Journal:           $journalPath"
    Write-Host "Summary:           $summaryPath"
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
