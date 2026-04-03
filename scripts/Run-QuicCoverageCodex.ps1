param(
    [string]$RepoRoot = "C:\src\incursa\quic-dotnet",
    [string]$RequirementsRoot = "C:\src\incursa\quic-dotnet\specs\requirements\quic",
    [string]$TriagePath = "C:\src\incursa\quic-dotnet\specs\generated\quic\quic-requirement-coverage-triage.json",
    [string]$TriageScriptPath = "C:\src\incursa\quic-dotnet\scripts\spec-trace\Generate-QuicRequirementCoverageTriage.ps1",

    [string]$OutputDirectory = "C:\src\incursa\quic-dotnet\specs\codex_work\loop",
    [string]$CodexCommand = "codex",
    [string]$Sandbox = "workspace-write",
    [string]$Model = "gpt-5.4-mini",
    [string]$ReasoningEffort = "high",

    [int]$MaxIterations = 25,
    [int]$NoProgressLimit = 2,
    [int]$CooldownSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-ExceptionDetail {
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)

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
    param([Parameter(Mandatory = $true)][string]$Command)

    if (-not (Test-IsWindows) -or $Command -ne "codex") {
        return $Command
    }

    foreach ($candidate in @("codex.cmd", "codex.exe")) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved -and $resolved.CommandType -eq "Application" -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    throw "Unable to resolve a runnable Codex executable. Looked for codex.cmd and codex.exe on PATH."
}

function Write-CodexStreamLine {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("stdout", "stderr", "heartbeat")]
        [string]$StreamName,

        [AllowEmptyString()]
        [Parameter(Mandatory = $true)]
        [string]$Line,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        return
    }

    [System.IO.File]::AppendAllText($LogPath, "[$StreamName] $Line$([Environment]::NewLine)")

    $summary = ($Line -replace '\s+', ' ').Trim()
    if ($summary.Length -gt 220) {
        $summary = $summary.Substring(0, 217) + "..."
    }

    $color = switch ($StreamName) {
        "stdout"    { "Cyan" }
        "stderr"    { "DarkYellow" }
        "heartbeat" { "DarkGray" }
    }

    Write-Host "  $summary" -ForegroundColor $color
}

function Get-StateCount {
    param(
        [Parameter(Mandatory = $true)]$StateObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $StateObject) {
        return 0
    }

    if ($StateObject.PSObject.Properties.Name -contains $Name) {
        return [int]$StateObject.$Name
    }

    return 0
}

function Get-TriageSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    $byState = $json.summary.by_state

    $traceClean = Get-StateCount -StateObject $byState -Name "trace_clean"
    $missingXrefs = Get-StateCount -StateObject $byState -Name "covered_but_missing_xrefs"
    $proofTooBroad = Get-StateCount -StateObject $byState -Name "covered_but_proof_too_broad"
    $partial = Get-StateCount -StateObject $byState -Name "partially_covered"
    $uncoveredUnblocked = Get-StateCount -StateObject $byState -Name "uncovered_unblocked"
    $uncoveredBlocked = Get-StateCount -StateObject $byState -Name "uncovered_blocked"

    $fingerprint = "$traceClean|$missingXrefs|$proofTooBroad|$partial|$uncoveredUnblocked|$uncoveredBlocked"

    return [pscustomobject]@{
        TraceClean           = $traceClean
        MissingXrefs         = $missingXrefs
        ProofTooBroad        = $proofTooBroad
        Partial              = $partial
        UncoveredUnblocked   = $uncoveredUnblocked
        UncoveredBlocked     = $uncoveredBlocked
        Fingerprint          = $fingerprint
    }
}

function Format-TriageSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    return "trace_clean=$($Snapshot.TraceClean), missing_xrefs=$($Snapshot.MissingXrefs), proof_too_broad=$($Snapshot.ProofTooBroad), partially_covered=$($Snapshot.Partial), uncovered_unblocked=$($Snapshot.UncoveredUnblocked), uncovered_blocked=$($Snapshot.UncoveredBlocked)"
}

function Get-LoopDirective {
    param([string]$ResultText)

    if ([string]::IsNullOrWhiteSpace($ResultText)) {
        return [pscustomobject]@{
            LoopStatus = "Continue"
            StopReason = ""
        }
    }

    if ($ResultText -match '(?im)^\s*LoopStatus\s*:\s*(Stop|Continue)\s*$') {
        $status = $matches[1]
        $reason = ""

        if ($ResultText -match '(?im)^\s*StopReason\s*:\s*(.+?)\s*$') {
            $reason = $matches[1].Trim()
        }

        return [pscustomobject]@{
            LoopStatus = $status
            StopReason = $reason
        }
    }

    if ($ResultText -match '(?im)LOOP_STOP\s*:\s*(.+)') {
        return [pscustomobject]@{
            LoopStatus = "Stop"
            StopReason = $matches[1].Trim()
        }
    }

    return [pscustomobject]@{
        LoopStatus = "Continue"
        StopReason = ""
    }
}

function New-IterationPrompt {
    param(
        [Parameter(Mandatory = $true)][int]$Iteration,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RequirementsRoot,
        [Parameter(Mandatory = $true)][string]$TriagePath,
        [Parameter(Mandatory = $true)][string]$TriageScriptPath,
        [Parameter(Mandatory = $true)]$BeforeSnapshot
    )

    $commitTail = @"

Before you finish:
- If you made any changes, create a local git commit for the work completed.
- If commit signing blocks the commit, retry with --no-gpg-sign.
- Do not leave useful work uncommitted.
- Do not commit temp files or generated triage files.
- If no files changed, say so explicitly.
"@

    return @"
You are helping systematically improve requirement-level test coverage and traceability in the quic-dotnet repository.

Iteration: $Iteration

Repository:
- Repo root: $RepoRoot
- Requirements root: $RequirementsRoot
- Current triage JSON: $TriagePath
- Triage regeneration script: $TriageScriptPath

Current triage summary before this iteration:
- $(Format-TriageSnapshot -Snapshot $BeforeSnapshot)

Operating model:
- We are converting the repo from broad, haphazard coverage into a requirement-centered proof model.
- Each requirement should have a canonical requirement-home file/class under tests/Incursa.Quic.Tests/RequirementHomes/<RFC>/ when focused proof is added.
- Canonical ownership is strict:
  - one file/class = one owning requirement
  - tests inside a canonical home should prove only that owning requirement
  - do not add extra Requirement IDs inside canonical requirement homes
- Existing broad tests may remain as supplemental proof, but should not be the primary proof artifact once focused proof exists.
- Requirement spec JSON is the source of truth for expected coverage dimensions.
- Trait("Category", ...) is the current evidence tag source because CoverageType is not yet broadly adopted.
- Requirement-home scaffolds without executable tests do not count as proof.
- Broad transport/frame codec aggregation tests and methods associated with more than six requirements are still broad proof.

Backlog categories:
- trace_clean: leave alone unless there is an obvious metadata issue
- covered_but_missing_xrefs: metadata/x_test_ref repair first
- covered_but_proof_too_broad: narrow or split proof into requirement-owned homes
- partially_covered: add only the missing proof dimensions
- uncovered_unblocked: create new focused tests only where implementation exists
- uncovered_blocked: do not force these; leave blocked unless a real implementation path now exists

Selection priorities for THIS iteration:
1. metadata-only cleanup if it unlocks easy wins
2. partial clusters with clear missing dimensions
3. broad-proof clusters that can be narrowed with existing implementation
4. only then uncovered_unblocked requirements

Avoid these families unless the triage clearly shows a real implementation-backed path:
- connection close / draining families
- stateful stateless-reset acceptance / lifecycle families
- blocked RFC9001 TLS / security families

Bounded-slice rules:
- Do not do repo-wide sweeps when a bounded slice is possible.
- Prefer a small adjacent cluster, usually 1 to 6 nearby requirements.
- Use old broad tests only as reference, setup inspiration, or helper extraction source.
- Do not mechanically move broad tests into requirement homes.
- Do not invent behavior.
- Do not silently change product code to make tests pass.
- Only make very small, low-risk testability seams if absolutely necessary.
- Preserve compileability.

What you must do:
1. Read the current triage JSON first and treat it as the source of truth.
2. Identify the best next bounded slice under the rules above.
3. If there is no good eligible slice, do not force work. Stop cleanly.
4. If there is a good eligible slice:
   - execute exactly ONE bounded slice
   - keep the work tightly scoped
   - repair metadata first if applicable
   - otherwise add only missing proof dimensions for partials
   - otherwise narrow broad proof only where implementation clearly exists
   - otherwise add new focused tests only where implementation clearly exists
5. Run the smallest relevant test subset for touched files.
6. Regenerate the triage by running:
   pwsh -File "$TriageScriptPath"
7. Base your final report on the regenerated triage.

Required final output format:
## Decision
- Selected slice: <requirement ids or cluster name>
- Why this slice: <short reason>

## Files Changed
- ...

## Tests Run and Result
- ...

## Before/After State
- requirement id | before | after

## Loop Control
LoopStatus: Continue
StopReason: n/a

If there is no good eligible slice, use:
## Loop Control
LoopStatus: Stop
StopReason: <clear reason>

$commitTail
"@
}

function Invoke-CodexIteration {
    param(
        [Parameter(Mandatory = $true)][string]$CodexExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Model,
        [Parameter(Mandatory = $true)][string]$ReasoningEffort
    )

    $process = $null
    $stdoutDone = $false
    $stderrDone = $false
    $stdoutTask = $null
    $stderrTask = $null
    $startTime = Get-Date
    $nextHeartbeatAt = $startTime.AddMinutes(5)

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $CodexExecutable
        $psi.WorkingDirectory = $RepoRoot
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

        $process.StandardInput.Write($Prompt)
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
                    Write-CodexStreamLine -StreamName "heartbeat" -Line "Codex still running after $($elapsed.ToString('hh\:mm\:ss'))" -LogPath $LogPath
                    $nextHeartbeatAt = $now.AddMinutes(5)
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
                    Write-CodexStreamLine -StreamName "stdout" -Line $line -LogPath $LogPath
                    $nextHeartbeatAt = (Get-Date).AddMinutes(5)
                    $stdoutTask = $process.StandardOutput.ReadLineAsync()
                }
            }
            elseif (-not $stderrDone -and $completed -eq $stderrTask) {
                $line = $stderrTask.GetAwaiter().GetResult()

                if ($null -eq $line) {
                    $stderrDone = $true
                }
                else {
                    Write-CodexStreamLine -StreamName "stderr" -Line $line -LogPath $LogPath
                    $nextHeartbeatAt = (Get-Date).AddMinutes(5)
                    $stderrTask = $process.StandardError.ReadLineAsync()
                }
            }

            if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                break
            }
        }

        $process.WaitForExit()

        $endTime = Get-Date
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Seconds  = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
        }
    }
    finally {
        if ($null -ne $process) {
            try { $process.Dispose() } catch {}
        }
    }
}

try {
    $repoRoot = Resolve-ExistingPath -Path $RepoRoot
    $requirementsRoot = Resolve-ExistingPath -Path $RequirementsRoot
    $triagePath = Resolve-ExistingPath -Path $TriagePath
    $triageScriptPath = Resolve-ExistingPath -Path $TriageScriptPath
    $codexExecutable = Resolve-CodexCommand -Command $CodexCommand

    $outputRoot = Ensure-Directory -Path $OutputDirectory
    $resultsRoot = Ensure-Directory -Path (Join-Path $outputRoot "results")
    $logsRoot = Ensure-Directory -Path (Join-Path $outputRoot "logs")

    $summaryRows = New-Object System.Collections.Generic.List[object]
    $beforeSnapshot = Get-TriageSnapshot -Path $triagePath
    $noProgressCount = 0

    Write-Host ""
    Write-Host "Initial triage: $(Format-TriageSnapshot -Snapshot $beforeSnapshot)" -ForegroundColor Green

    for ($iteration = 1; $iteration -le $MaxIterations; $iteration++) {
        Write-Host ""
        Write-Host "=== Iteration $iteration / $MaxIterations ===" -ForegroundColor White

        $resultPath = Join-Path $resultsRoot ("iteration-{0:D3}.output.md" -f $iteration)
        $logPath = Join-Path $logsRoot ("iteration-{0:D3}.log.txt" -f $iteration)

        $prompt = New-IterationPrompt `
            -Iteration $iteration `
            -RepoRoot $repoRoot `
            -RequirementsRoot $requirementsRoot `
            -TriagePath $triagePath `
            -TriageScriptPath $triageScriptPath `
            -BeforeSnapshot $beforeSnapshot

        $run = $null
        $status = "Success"
        $stopNow = $false
        $stopReason = ""

        try {
            $run = Invoke-CodexIteration `
                -CodexExecutable $codexExecutable `
                -RepoRoot $repoRoot `
                -Prompt $prompt `
                -ResultPath $resultPath `
                -LogPath $logPath `
                -Sandbox $Sandbox `
                -Model $Model `
                -ReasoningEffort $ReasoningEffort

            if ($run.ExitCode -ne 0) {
                $status = "Failed"
                $stopNow = $true
                $stopReason = "Codex exited with code $($run.ExitCode)."
            }
        }
        catch {
            $status = "Exception"
            $detail = Get-ExceptionDetail -Exception $_.Exception
            [System.IO.File]::AppendAllText($logPath, "[exception] $($_ | Out-String)$([Environment]::NewLine)")
            $run = [pscustomobject]@{ ExitCode = -1; Seconds = 0 }
            $stopNow = $true
            $stopReason = "Exception while running Codex: $detail"
        }

        $afterSnapshot = Get-TriageSnapshot -Path $triagePath
        $resultText = if (Test-Path -LiteralPath $resultPath) { Get-Content -LiteralPath $resultPath -Raw } else { "" }
        $directive = Get-LoopDirective -ResultText $resultText

        $triageChanged = $afterSnapshot.Fingerprint -ne $beforeSnapshot.Fingerprint
        if ($triageChanged) {
            $noProgressCount = 0
        }
        else {
            $noProgressCount++
        }

        if (-not $stopNow -and $directive.LoopStatus -eq "Stop") {
            $stopNow = $true
            $stopReason = if ([string]::IsNullOrWhiteSpace($directive.StopReason)) {
                "Codex requested stop."
            }
            else {
                $directive.StopReason
            }
        }

        if (-not $stopNow -and $noProgressCount -ge $NoProgressLimit) {
            $stopNow = $true
            $stopReason = "Triage fingerprint did not change for $noProgressCount consecutive iteration(s)."
        }

        $summaryRows.Add([pscustomobject]@{
            Iteration         = $iteration
            Status            = $status
            ExitCode          = $run.ExitCode
            Seconds           = $run.Seconds
            Before            = (Format-TriageSnapshot -Snapshot $beforeSnapshot)
            After             = (Format-TriageSnapshot -Snapshot $afterSnapshot)
            TriageChanged     = $triageChanged
            NoProgressCount   = $noProgressCount
            ResultFile        = $resultPath
            LogFile           = $logPath
            LoopStatus        = $directive.LoopStatus
            StopReason        = $stopReason
        })

        Write-Host "Before: $(Format-TriageSnapshot -Snapshot $beforeSnapshot)" -ForegroundColor DarkGray
        Write-Host "After : $(Format-TriageSnapshot -Snapshot $afterSnapshot)" -ForegroundColor DarkGray

        if ($stopNow) {
            Write-Host ""
            Write-Warning "Stopping after iteration $iteration. $stopReason"
            break
        }

        $beforeSnapshot = $afterSnapshot

        if ($CooldownSeconds -gt 0 -and $iteration -lt $MaxIterations) {
            Start-Sleep -Seconds $CooldownSeconds
        }
    }

    $summaryPath = Join-Path $outputRoot "summary.csv"
    $summaryRows | Export-Csv -LiteralPath $summaryPath -NoTypeInformation

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
    Write-Host "Repo root:  $repoRoot"
    Write-Host "Triage:     $triagePath"
    Write-Host "Results:    $resultsRoot"
    Write-Host "Logs:       $logsRoot"
    Write-Host "Summary:    $summaryPath"
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
