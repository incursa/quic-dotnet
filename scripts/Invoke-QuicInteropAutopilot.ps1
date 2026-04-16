param(
    [ValidateSet("plan", "prepare", "run", "resume", "merge", "cleanup", "supervise", "smoke")]
    [string]$Mode = "plan",

    [string]$RepoRoot = "C:\src\incursa\quic-dotnet",

    [string]$RunnerScriptPath = "C:\src\incursa\quic-dotnet\scripts\Run-CodexAutopilot.ps1",

    [string]$MissionPromptFile = "C:\src\incursa\quic-dotnet\prompts\mission.md",

    [string]$WorktreeRoot = "C:\src\incursa\quic-dotnet.worktrees\interop-autopilot",

    [string]$StateDirectory = "C:\src\incursa\quic-dotnet\.artifacts\interop-autopilot",

    [string]$LaneId = "",

    [string]$TargetBranch = "main",

    [string]$CodexCommand = "codex",

    [string]$Sandbox = "danger-full-access",

    [string]$PlannerModel = "gpt-5.4",

    [string]$PlannerReasoningEffort = "xhigh",

    [string]$WorkerModel = "gpt-5.4-mini",

    [string]$WorkerReasoningEffort = "xhigh",

    [int]$WorkerMaxIterations = 4,

    [int]$WorkerMaxRescueAttemptsPerTurn = 1,

    [switch]$AutoMerge,

    [switch]$CleanupAfterMerge,

    [int]$SupervisorMaxCycles = 0,

    [int]$SupervisorPollIntervalSeconds = 300,

    [int]$SupervisorMaxIdleCycles = 12,

    [int]$SupervisorMaxIdleMinutes = 0,

    [switch]$Overnight,

    [switch]$Force
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

function Resolve-SupervisorSettings {
    param(
        [Parameter(Mandatory = $true)][hashtable]$BoundParameters,
        [Parameter(Mandatory = $true)][int]$PollIntervalSeconds,
        [Parameter(Mandatory = $true)][int]$MaxIdleCycles,
        [Parameter(Mandatory = $true)][int]$MaxIdleMinutes,
        [Parameter(Mandatory = $true)][int]$MaxCycles,
        [Parameter(Mandatory = $true)][bool]$UseOvernightPreset
    )

    $resolvedPollIntervalSeconds = $PollIntervalSeconds
    $resolvedMaxIdleCycles = $MaxIdleCycles
    $resolvedMaxIdleMinutes = $MaxIdleMinutes
    $resolvedMaxCycles = $MaxCycles

    if ($UseOvernightPreset) {
        if (-not $BoundParameters.ContainsKey("SupervisorPollIntervalSeconds")) {
            $resolvedPollIntervalSeconds = 300
        }

        if (-not $BoundParameters.ContainsKey("SupervisorMaxIdleCycles")) {
            $resolvedMaxIdleCycles = 96
        }

        if (-not $BoundParameters.ContainsKey("SupervisorMaxIdleMinutes")) {
            $resolvedMaxIdleMinutes = 600
        }

        if (-not $BoundParameters.ContainsKey("SupervisorMaxCycles")) {
            $resolvedMaxCycles = 128
        }
    }

    if ($resolvedPollIntervalSeconds -lt 1) {
        throw "-SupervisorPollIntervalSeconds must be at least 1."
    }

    if ($resolvedMaxIdleCycles -lt 0) {
        throw "-SupervisorMaxIdleCycles cannot be negative."
    }

    if ($resolvedMaxIdleMinutes -lt 0) {
        throw "-SupervisorMaxIdleMinutes cannot be negative."
    }

    if ($resolvedMaxCycles -lt 0) {
        throw "-SupervisorMaxCycles cannot be negative."
    }

    if ($resolvedMaxIdleCycles -eq 0 -and $resolvedMaxIdleMinutes -eq 0) {
        throw "Supervisor mode requires at least one idle limit. Set -SupervisorMaxIdleCycles or -SupervisorMaxIdleMinutes."
    }

    return [pscustomobject]@{
        PollIntervalSeconds = $resolvedPollIntervalSeconds
        MaxIdleCycles = $resolvedMaxIdleCycles
        MaxIdleMinutes = $resolvedMaxIdleMinutes
        MaxCycles = $resolvedMaxCycles
        UsesOvernightPreset = $UseOvernightPreset
    }
}

function Invoke-SupervisorCatalogRefresh {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$StateDirectory,
        [Parameter(Mandatory = $true)][string]$TargetBranch,
        [Parameter(Mandatory = $true)][string]$PlannerModel,
        [Parameter(Mandatory = $true)][string]$PlannerReasoningEffort,
        [Parameter(Mandatory = $true)][string]$WorkerModel,
        [Parameter(Mandatory = $true)][string]$WorkerReasoningEffort,
        [Parameter(Mandatory = $true)][string]$CatalogPath
    )

    $planCapture = Invoke-NativeCapture `
        -FilePath $PowerShellExecutable `
        -WorkingDirectory $RepoRoot `
        -ArgumentList @(
            "-NoProfile"
            "-ExecutionPolicy"
            "Bypass"
            "-File"
            $ScriptPath
            "-Mode"
            "plan"
            "-RepoRoot"
            $RepoRoot
            "-StateDirectory"
            $StateDirectory
            "-TargetBranch"
            $TargetBranch
            "-PlannerModel"
            $PlannerModel
            "-PlannerReasoningEffort"
            $PlannerReasoningEffort
            "-WorkerModel"
            $WorkerModel
            "-WorkerReasoningEffort"
            $WorkerReasoningEffort
        )

    if ($planCapture.ExitCode -ne 0) {
        throw "Supervisor catalog refresh failed: $($planCapture.StdErr.Trim())"
    }

    return Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json -Depth 100
}

function Get-SupervisorIdleOutcome {
    param(
        [Parameter(Mandatory = $true)][int]$IdleCycles,
        [AllowNull()]$IdleStartedAt,
        [Parameter(Mandatory = $true)][datetime]$Now,
        [Parameter(Mandatory = $true)]$Settings
    )

    $effectiveIdleStartedAt = if ($null -eq $IdleStartedAt) { $Now } else { [datetime]$IdleStartedAt }
    $nextIdleCycles = $IdleCycles + 1
    $elapsed = $Now - $effectiveIdleStartedAt

    $idleCycleLimitReached = $Settings.MaxIdleCycles -gt 0 -and $nextIdleCycles -gt $Settings.MaxIdleCycles
    $idleWallClockLimitReached = $Settings.MaxIdleMinutes -gt 0 -and $elapsed.TotalMinutes -ge $Settings.MaxIdleMinutes

    $reason = ""
    if ($idleCycleLimitReached) {
        $reason = "Supervisor reached the configured idle poll limit of $($Settings.MaxIdleCycles) after $nextIdleCycles empty polls."
    }
    elseif ($idleWallClockLimitReached) {
        $reason = "Supervisor reached the configured idle wall-clock limit of $($Settings.MaxIdleMinutes) minutes after $([math]::Round($elapsed.TotalMinutes, 1)) idle minutes."
    }
    else {
        $limitText = if ($Settings.MaxIdleCycles -gt 0) { "$nextIdleCycles/$($Settings.MaxIdleCycles)" } else { "$nextIdleCycles" }
        $reason = "No eligible lane is currently available. Idle poll $limitText; retrying after $($Settings.PollIntervalSeconds) seconds."
    }

    return [pscustomobject]@{
        IdleStartedAt = $effectiveIdleStartedAt
        IdleCycles = $nextIdleCycles
        Elapsed = $elapsed
        ShouldStop = ($idleCycleLimitReached -or $idleWallClockLimitReached)
        Reason = $reason
    }
}

function Get-SupervisorPollAction {
    param(
        [Parameter(Mandatory = $true)][bool]$HasActiveLane,
        [string]$RecommendedLaneId = "",
        [Parameter(Mandatory = $true)][int]$IdleCycles,
        [AllowNull()]$IdleStartedAt,
        [Parameter(Mandatory = $true)][datetime]$Now,
        [Parameter(Mandatory = $true)]$Settings
    )

    if ($HasActiveLane) {
        return [pscustomobject]@{
            Action = "resume"
            LaneId = ""
            ResetIdle = $true
            IdleCycles = 0
            IdleStartedAt = $null
            Reason = "An active lane is recorded and should be resumed or reconciled before planning another lane."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($RecommendedLaneId)) {
        return [pscustomobject]@{
            Action = "run"
            LaneId = $RecommendedLaneId
            ResetIdle = $true
            IdleCycles = 0
            IdleStartedAt = $null
            Reason = "An eligible lane is available and should start immediately."
        }
    }

    # Empty-queue polls are allowed to repeat for a bounded period so supervise mode can wait for
    # reconciliation, catalog changes, or newly eligible lanes without becoming an unbounded loop.
    $idleOutcome = Get-SupervisorIdleOutcome -IdleCycles $IdleCycles -IdleStartedAt $IdleStartedAt -Now $Now -Settings $Settings
    return [pscustomobject]@{
        Action = if ($idleOutcome.ShouldStop) { "stop_idle" } else { "sleep" }
        LaneId = ""
        ResetIdle = $false
        IdleCycles = $idleOutcome.IdleCycles
        IdleStartedAt = $idleOutcome.IdleStartedAt
        Reason = $idleOutcome.Reason
    }
}

function Assert-SupervisorCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-SupervisorSmokeValidation {
    param([Parameter(Mandatory = $true)]$DefaultSettings)

    $now = [datetime]::SpecifyKind([datetime]"2026-04-16T00:00:00", [System.DateTimeKind]::Utc)

    $emptyQueueAction = Get-SupervisorPollAction `
        -HasActiveLane:$false `
        -RecommendedLaneId "" `
        -IdleCycles 0 `
        -IdleStartedAt $null `
        -Now $now `
        -Settings ([pscustomobject]@{
            PollIntervalSeconds = 1
            MaxIdleCycles = 2
            MaxIdleMinutes = 0
            MaxCycles = 0
            UsesOvernightPreset = $false
        })
    Assert-SupervisorCondition -Condition ($emptyQueueAction.Action -eq "sleep") -Message "Expected an empty queue to sleep/retry before hitting the idle limit."

    $resumeAction = Get-SupervisorPollAction `
        -HasActiveLane:$true `
        -RecommendedLaneId "" `
        -IdleCycles 2 `
        -IdleStartedAt $now.AddMinutes(-10) `
        -Now $now `
        -Settings $DefaultSettings
    Assert-SupervisorCondition -Condition ($resumeAction.Action -eq "resume" -and $resumeAction.ResetIdle) -Message "Expected an active lane to resume and reset idle tracking."

    $followOnRunAction = Get-SupervisorPollAction `
        -HasActiveLane:$false `
        -RecommendedLaneId "trace-metadata-reconciliation" `
        -IdleCycles 1 `
        -IdleStartedAt $now.AddMinutes(-5) `
        -Now $now `
        -Settings $DefaultSettings
    Assert-SupervisorCondition -Condition ($followOnRunAction.Action -eq "run" -and $followOnRunAction.LaneId -eq "trace-metadata-reconciliation" -and $followOnRunAction.ResetIdle) -Message "Expected the next eligible lane to start after merge/cleanup clears the active lane."

    $idleLimitStopAction = Get-SupervisorPollAction `
        -HasActiveLane:$false `
        -RecommendedLaneId "" `
        -IdleCycles 1 `
        -IdleStartedAt $now.AddMinutes(-1) `
        -Now $now `
        -Settings ([pscustomobject]@{
            PollIntervalSeconds = 1
            MaxIdleCycles = 1
            MaxIdleMinutes = 0
            MaxCycles = 0
            UsesOvernightPreset = $false
        })
    Assert-SupervisorCondition -Condition ($idleLimitStopAction.Action -eq "stop_idle") -Message "Expected supervise mode to stop cleanly after the configured idle limit is exceeded."

    Write-Host "Supervisor smoke validation passed." -ForegroundColor Green
    Write-Host "  Empty queue sleeps and retries before exit."
    Write-Host "  Active lanes resume and reset idle tracking."
    Write-Host "  Post-merge cleanup can hand off to the next eligible lane."
    Write-Host "  Idle limits stop the loop cleanly."
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

function Resolve-CommandPath {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Candidates = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($Command)) {
        $resolved = Get-Command -Name $Command -ErrorAction SilentlyContinue
        if ($resolved -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    foreach ($candidate in $Candidates) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    throw "Unable to resolve a runnable command for '$Command'."
}

function Get-NormalizedStringList {
    param([AllowNull()][string[]]$Items = @())

    if ($null -eq $Items) {
        return @()
    }

    return @(
        $Items |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
    )
}

function Get-NormalizedPathPrefixList {
    param([AllowNull()][string[]]$Items = @())

    return @(
        Get-NormalizedStringList -Items $Items |
        ForEach-Object { ($_ -replace '\\', '/').TrimEnd('/') }
    )
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
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

function Get-CurrentPowerShellExecutable {
    $process = Get-Process -Id $PID -ErrorAction Stop
    if (-not [string]::IsNullOrWhiteSpace($process.Path)) {
        return $process.Path
    }

    if ($env:OS -eq "Windows_NT") {
        return "powershell.exe"
    }

    return "pwsh"
}

function Get-OpenGapIds {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $state = ""
    $gapIds = New-Object System.Collections.Generic.List[string]
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^## Open Gaps') {
            $state = "open"
            continue
        }

        if ($line -match '^## Closed Gaps') {
            break
        }

        if ($state -eq "open" -and $line -match '^- `([^`]+)`') {
            [void]$gapIds.Add($Matches[1])
        }
    }

    return @(Get-NormalizedStringList -Items $gapIds.ToArray())
}

function Get-OrchestrationState {
    param([Parameter(Mandatory = $true)][string]$StatePath)

    if (-not (Test-Path -LiteralPath $StatePath)) {
        return [pscustomobject]@{
            schema_version = 1
            last_updated = ""
            completed_lane_ids = @()
            pending_reconciliation_lane_ids = @()
            active_lane = $null
        }
    }

    return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -Depth 100
}

function Save-OrchestrationState {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)]$StateObject
    )

    $directory = Split-Path -Path $StatePath -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        Ensure-Directory -Path $directory | Out-Null
    }

    $StateObject.last_updated = (Get-Date).ToString("o")
    $StateObject.completed_lane_ids = @(Get-NormalizedStringList -Items $StateObject.completed_lane_ids)
    $StateObject.pending_reconciliation_lane_ids = @(Get-NormalizedStringList -Items $StateObject.pending_reconciliation_lane_ids)
    ($StateObject | ConvertTo-Json -Depth 100) | Set-Content -LiteralPath $StatePath -Encoding utf8
}

function Test-GitWorktreeExists {
    param([Parameter(Mandatory = $true)][string]$WorktreePath)

    if (-not (Test-Path -LiteralPath $WorktreePath)) {
        return $false
    }

    return Test-Path -LiteralPath (Join-Path -Path $WorktreePath -ChildPath ".git")
}

function Ensure-GitWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [Parameter(Mandatory = $true)][string]$BranchName,
        [Parameter(Mandatory = $true)][string]$BaseRef
    )

    if (Test-GitWorktreeExists -WorktreePath $WorktreePath) {
        return [pscustomobject]@{
            Created = $false
            WorktreePath = $WorktreePath
            BranchName = $BranchName
            BaseRef = $BaseRef
        }
    }

    $parent = Split-Path -Path $WorktreePath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Ensure-Directory -Path $parent | Out-Null
    }

    $branchExists = $false
    & $GitExecutable -C $RepoRoot show-ref --verify --quiet "refs/heads/$BranchName"
    if ($LASTEXITCODE -eq 0) {
        $branchExists = $true
    }

    if ($branchExists) {
        & $GitExecutable -C $RepoRoot worktree add $WorktreePath $BranchName | Out-Null
    }
    else {
        & $GitExecutable -C $RepoRoot worktree add -b $BranchName $WorktreePath $BaseRef | Out-Null
    }

    if ($LASTEXITCODE -ne 0) {
        throw "git worktree add failed for $WorktreePath ($BranchName)."
    }

    return [pscustomobject]@{
        Created = $true
        WorktreePath = $WorktreePath
        BranchName = $BranchName
        BaseRef = $BaseRef
    }
}

function Remove-GitWorktreeAndBranch {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [string]$BranchName = ""
    )

    if (Test-Path -LiteralPath $WorktreePath) {
        $worktreeRemoval = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepoRoot, "worktree", "remove", "--force", $WorktreePath)
        if ($worktreeRemoval.ExitCode -ne 0) {
            if ($worktreeRemoval.StdErr -notmatch "not a working tree") {
                try {
                    Remove-Item -LiteralPath $WorktreePath -Recurse -Force -ErrorAction Stop
                }
                catch {
                    throw "git worktree remove failed for $WorktreePath. $($worktreeRemoval.StdErr.Trim())"
                }
            }
            elseif (Test-Path -LiteralPath $WorktreePath) {
                try {
                    Remove-Item -LiteralPath $WorktreePath -Recurse -Force -ErrorAction Stop
                }
                catch {
                    throw "git worktree remove reported the path was not a working tree, and direct cleanup failed for $WorktreePath."
                }
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($BranchName)) {
        & $GitExecutable -C $RepoRoot show-ref --verify --quiet "refs/heads/$BranchName"
        if ($LASTEXITCODE -eq 0) {
            & $GitExecutable -C $RepoRoot branch -D $BranchName | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "git branch -D failed for $BranchName."
            }
        }
    }
}

function Remove-GitWorktreeOnly {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorktreePath
    )

    if (-not (Test-Path -LiteralPath $WorktreePath)) {
        return
    }

    $worktreeRemoval = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepoRoot, "worktree", "remove", "--force", $WorktreePath)
    if ($worktreeRemoval.ExitCode -ne 0) {
        if ($worktreeRemoval.StdErr -notmatch "not a working tree") {
            try {
                Remove-Item -LiteralPath $WorktreePath -Recurse -Force -ErrorAction Stop
            }
            catch {
                throw "git worktree remove failed for $WorktreePath. $($worktreeRemoval.StdErr.Trim())"
            }
        }
        elseif (Test-Path -LiteralPath $WorktreePath) {
            try {
                Remove-Item -LiteralPath $WorktreePath -Recurse -Force -ErrorAction Stop
            }
            catch {
                throw "git worktree remove reported the path was not a working tree, and direct cleanup failed for $WorktreePath."
            }
        }
    }
}

function Add-ExistingBranchWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [Parameter(Mandatory = $true)][string]$BranchName
    )

    if (Test-GitWorktreeExists -WorktreePath $WorktreePath) {
        return $WorktreePath
    }

    $parent = Split-Path -Path $WorktreePath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Ensure-Directory -Path $parent | Out-Null
    }

    & $GitExecutable -C $RepoRoot worktree add $WorktreePath $BranchName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "git worktree add failed for $WorktreePath ($BranchName)."
    }

    return $WorktreePath
}

function Get-GitHead {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$Ref = "HEAD"
    )

    $result = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepositoryRoot, "rev-parse", $Ref)
    if ($result.ExitCode -ne 0) {
        throw "git rev-parse failed for ${Ref}: $($result.StdErr.Trim())"
    }

    return $result.StdOut.Trim()
}

function Get-GitCurrentBranch {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $result = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepositoryRoot, "rev-parse", "--abbrev-ref", "HEAD")
    if ($result.ExitCode -ne 0) {
        throw "git rev-parse --abbrev-ref failed: $($result.StdErr.Trim())"
    }

    return $result.StdOut.Trim()
}

function Test-GitClean {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $result = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepositoryRoot, "status", "--porcelain")
    if ($result.ExitCode -ne 0) {
        throw "git status --porcelain failed: $($result.StdErr.Trim())"
    }

    return [string]::IsNullOrWhiteSpace($result.StdOut)
}

function Get-CommitRange {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$FromRef,
        [Parameter(Mandatory = $true)][string]$ToRef
    )

    $result = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepositoryRoot, "rev-list", "--reverse", "$FromRef..$ToRef")
    if ($result.ExitCode -ne 0) {
        throw "git rev-list failed: $($result.StdErr.Trim())"
    }

    return @(
        $result.StdOut -split '\r?\n' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Invoke-CommandBatch {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Commands,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $commands = @(Get-NormalizedStringList -Items $Commands)
    if ($commands.Count -eq 0) {
        return @()
    }

    $pwshExecutable = Get-CurrentPowerShellExecutable
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($commandText in $commands) {
        $argumentList = @("-NoProfile")
        if ($env:OS -eq "Windows_NT") {
            $argumentList += @("-ExecutionPolicy", "Bypass")
        }

        $argumentList += @("-Command", $commandText)
        $result = Invoke-NativeCapture -FilePath $pwshExecutable -ArgumentList $argumentList -WorkingDirectory $WorkingDirectory
        [void]$results.Add([pscustomobject]@{
            Label = $Label
            CommandText = $commandText
            ExitCode = $result.ExitCode
            StdOut = $result.StdOut
            StdErr = $result.StdErr
        })

        if ($result.ExitCode -ne 0) {
            break
        }
    }

    return $results.ToArray()
}

function Test-RequirementMatchesFamilies {
    param(
        [Parameter(Mandatory = $true)][string]$RequirementId,
        [AllowNull()][string[]]$RequirementFamilies = @()
    )

    $families = @(Get-NormalizedStringList -Items $RequirementFamilies)
    if ($families.Count -eq 0) {
        return $true
    }

    foreach ($family in $families) {
        if ($RequirementId.StartsWith($family, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-LaneRequirementSummary {
    param(
        [Parameter(Mandatory = $true)]$TriageJson,
        [AllowNull()][string[]]$RequirementFamilies = @()
    )

    $counts = @{}
    $total = 0

    foreach ($requirement in @($TriageJson.requirements)) {
        if ($null -eq $requirement) {
            continue
        }

        $requirementId = [string]$requirement.requirement_id
        if ([string]::IsNullOrWhiteSpace($requirementId)) {
            continue
        }

        if (-not (Test-RequirementMatchesFamilies -RequirementId $requirementId -RequirementFamilies $RequirementFamilies)) {
            continue
        }

        $state = [string]$requirement.state
        if ([string]::IsNullOrWhiteSpace($state)) {
            $state = "unknown"
        }

        if (-not $counts.ContainsKey($state)) {
            $counts[$state] = 0
        }

        $counts[$state]++
        $total++
    }

    return [pscustomobject]@{
        total = $total
        by_state = $counts
    }
}

function Get-LaneTemplateDefinitions {
    return @(
        [pscustomobject]@{
            lane_id = "interop-front-door-hardening"
            objective = "Harden the existing interop front door: local runner helper, preflight, artifact capture, and current INT support surfaces."
            priority = 1
            prerequisite_lane_ids = @()
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "scripts/interop",
                "src/Incursa.Quic.InteropHarness",
                "tests/Incursa.Quic.Tests/RequirementHomes/INT",
                "specs/requirements/quic/SPEC-QUIC-INT",
                "specs/architecture/quic/ARC-QUIC-INT",
                "specs/work-items/quic/WI-QUIC-INT",
                "specs/verification/quic/VER-QUIC-INT",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-INT")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_INT_0013|FullyQualifiedName~REQ_QUIC_INT_0014|FullyQualifiedName~REQ_QUIC_INT_0008|FullyQualifiedName~REQ_QUIC_INT_0002"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_INT_0013|FullyQualifiedName~REQ_QUIC_INT_0014|FullyQualifiedName~REQ_QUIC_INT_0008|FullyQualifiedName~REQ_QUIC_INT_0002"'
            )
            success_gates = @(
                "localhost preflight and current INT requirement homes stay green",
                "same-slot and split-role runner support becomes easier to exercise without widening support claims"
            )
            fail_gates = @(
                "only artifacts or specs/generated changed",
                "runner support claimed without fresh executable evidence"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "handshake-protected-packet-unlock"
            objective = "Close the remaining handshake and protected-packet seams that still block broader honest interop."
            priority = 2
            prerequisite_lane_ids = @("interop-front-door-hardening")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic",
                "src/Incursa.Quic.InteropHarness",
                "tests/Incursa.Quic.Tests/RequirementHomes/CRT",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9001",
                "tests/Incursa.Quic.Tests/RequirementHomes/INT",
                "specs/requirements/quic/SPEC-QUIC-CRT",
                "specs/requirements/quic/SPEC-QUIC-INT",
                "specs/architecture/quic/ARC-QUIC-CRT",
                "specs/architecture/quic/ARC-QUIC-INT",
                "specs/work-items/quic/WI-QUIC-CRT",
                "specs/work-items/quic/WI-QUIC-INT",
                "specs/verification/quic/VER-QUIC-CRT",
                "specs/verification/quic/VER-QUIC-INT",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @("specs/generated")
            requirement_families = @("REQ-QUIC-CRT-01", "REQ-QUIC-RFC9001", "REQ-QUIC-INT")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_CRT_01|FullyQualifiedName~REQ_QUIC_RFC9001_|FullyQualifiedName~REQ_QUIC_INT_0008|FullyQualifiedName~REQ_QUIC_INT_0011|FullyQualifiedName~REQ_QUIC_INT_0012"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_CRT_01|FullyQualifiedName~REQ_QUIC_INT_"'
            )
            success_gates = @(
                "touched CRT homes pass with existing handshake-path INT homes",
                "the next interop slice becomes reachable for real, not just on paper"
            )
            fail_gates = @(
                "work stays trace-only or helper-only",
                "the same handshake blocker remains after the lane finishes"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "runtime-backbone"
            objective = "Land the sender, ACK/retransmission, and timer/runtime backbone needed for honest interop expansion."
            priority = 3
            prerequisite_lane_ids = @("handshake-protected-packet-unlock")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic",
                "tests/Incursa.Quic.Tests/RequirementHomes/CRT",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9002",
                "specs/requirements/quic/SPEC-QUIC-CRT",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9002",
                "specs/architecture/quic/ARC-QUIC-CRT",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9002",
                "specs/work-items/quic/WI-QUIC-CRT",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9002",
                "specs/verification/quic/VER-QUIC-CRT",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9002",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-CRT", "REQ-QUIC-RFC9000", "REQ-QUIC-RFC9002")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_CRT_0105|FullyQualifiedName~REQ_QUIC_CRT_0117|FullyQualifiedName~REQ_QUIC_CRT_0122|FullyQualifiedName~REQ_QUIC_CRT_0141|FullyQualifiedName~REQ_QUIC_CRT_0142|FullyQualifiedName~REQ_QUIC_CRT_0145"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_CRT_0105|FullyQualifiedName~REQ_QUIC_CRT_0117|FullyQualifiedName~REQ_QUIC_CRT_0122|FullyQualifiedName~REQ_QUIC_CRT_0141|FullyQualifiedName~REQ_QUIC_CRT_0142|FullyQualifiedName~REQ_QUIC_CRT_0145"'
            )
            success_gates = @(
                "a named runtime blocker family shrinks",
                "real src and tests movement lands with executable proof"
            )
            fail_gates = @(
                "two commits in a row without runtime or tests movement",
                "proof-home splitting dominates the lane"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "interop-testcase-expansion"
            objective = "Expand one honest interop testcase or materially strengthen one existing testcase after the runtime prerequisites are merged."
            priority = 4
            prerequisite_lane_ids = @("runtime-backbone")
            blocking_gap_ids = @(
                "9000-19-retransmission-and-frame-reliability",
                "9000-02-stream-state",
                "9000-03-flow-control"
            )
            allowed_path_prefixes = @(
                "src/Incursa.Quic",
                "src/Incursa.Quic.InteropHarness",
                "tests/Incursa.Quic.Tests/RequirementHomes/INT",
                "tests/Incursa.Quic.Tests/RequirementHomes/CRT",
                "specs/requirements/quic/SPEC-QUIC-INT",
                "specs/requirements/quic/SPEC-QUIC-CRT",
                "specs/architecture/quic/ARC-QUIC-INT",
                "specs/architecture/quic/ARC-QUIC-CRT",
                "specs/work-items/quic/WI-QUIC-INT",
                "specs/work-items/quic/WI-QUIC-CRT",
                "specs/verification/quic/VER-QUIC-INT",
                "specs/verification/quic/VER-QUIC-CRT",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @("specs/generated")
            requirement_families = @("REQ-QUIC-INT", "REQ-QUIC-CRT")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_INT_|FullyQualifiedName~REQ_QUIC_CRT_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_INT_"'
            )
            success_gates = @(
                "one new or materially stronger testcase is supported honestly end to end",
                "unsupported paths still fail honestly"
            )
            fail_gates = @(
                "support is enabled only in routing or docs",
                "success is faked through relaxed checks or placeholder exits"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "stream-flow-partial-closeout"
            objective = "Close the remaining stream and flow-control partials that the runtime backbone has already unblocked."
            priority = 5
            prerequisite_lane_ids = @("runtime-backbone")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0003"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0003"'
            )
            success_gates = @(
                "selected partial families become trace-clean with requirement-home evidence"
            )
            fail_gates = @(
                "the work becomes helper-only proof churn",
                "the next items are still blocked by the same runtime absence"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "path-migration-cid-runtime"
            objective = "Unlock path validation, migration core, CID lifecycle, idle-close, and stateless-reset follow-ons after the transport core is ready."
            priority = 6
            prerequisite_lane_ids = @("runtime-backbone")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/CRT",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/requirements/quic/SPEC-QUIC-CRT",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-CRT",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-CRT",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-CRT",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000", "REQ-QUIC-CRT")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_|FullyQualifiedName~REQ_QUIC_CRT_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0007"'
            )
            success_gates = @(
                "at least one migration/path blocker family moves from blocked to active",
                "runtime ownership lands instead of only helper math"
            )
            fail_gates = @(
                "only RFC9000 proof reshaping occurs",
                "path or migration remains blocked by the same sender or timer gap"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "stream-send-reset-lifecycle"
            objective = "Close the send-side stream terminal and reset lifecycle rules that unblock the remaining RFC 9000 stream-state and reset-reliability slices."
            priority = 7
            prerequisite_lane_ids = @("runtime-backbone")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicStream",
                "src/Incursa.Quic/QuicConnectionStream",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S3P1-0013", "REQ-QUIC-RFC9000-S3P1-0014", "REQ-QUIC-RFC9000-S3P1-0015", "REQ-QUIC-RFC9000-S3P1-0016", "REQ-QUIC-RFC9000-S3P1-0017", "REQ-QUIC-RFC9000-S13P3-0011", "REQ-QUIC-RFC9000-S13P3-0012")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0013|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0014|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0016|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0017|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0011|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0012"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0013|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0014|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0016|FullyQualifiedName~REQ_QUIC_RFC9000_S3P1_0017|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0011|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0012"'
            )
            success_gates = @(
                "send-side terminal states become runtime-owned and requirement-home proven",
                "the lane closes real reset and terminal-stream behavior instead of only reshaping traces"
            )
            fail_gates = @(
                "work stays trace-only or helper-only",
                "the same S3P1 and S13P3 terminal/reset blocker remains after the lane finishes"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "control-frame-reliability"
            objective = "Close the remaining runtime-owned RFC 9000 control-frame reliability rules for PATH_RESPONSE, CID lifecycle, NEW_TOKEN, PING/PADDING, and HANDSHAKE_DONE."
            priority = 8
            prerequisite_lane_ids = @("runtime-backbone", "path-migration-cid-runtime")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicHandshakeDoneFrame.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicStream",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S13P3-0028", "REQ-QUIC-RFC9000-S13P3-0029", "REQ-QUIC-RFC9000-S13P3-0030", "REQ-QUIC-RFC9000-S13P3-0031", "REQ-QUIC-RFC9000-S13P3-0032", "REQ-QUIC-RFC9000-S13P3-0033")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0028|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0029|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0030|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0031|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0032|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0033"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0028|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0029|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0030|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0031|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0032|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0033"'
            )
            success_gates = @(
                "control-frame retransmission and no-repair ownership is runtime-backed and narrowly proven",
                "HANDSHAKE_DONE is handled as a control-frame reliability seam rather than a broader handshake umbrella"
            )
            fail_gates = @(
                "codec-only edits land without runtime resend ownership",
                "the lane widens into unrelated handshake or interop work"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "stream-stop-sending-read-abort"
            objective = "Close the remaining STOP_SENDING and read-abort coordination rules, including RESET_STREAM reliability after interruption or loss."
            priority = 9
            prerequisite_lane_ids = @("stream-send-reset-lifecycle")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicStopSendingFrame.cs",
                "src/Incursa.Quic/QuicResetStreamFrame.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S3P5", "REQ-QUIC-RFC9000-S13P3-0013")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P5_|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0013"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P5_|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0013"'
            )
            success_gates = @(
                "STOP_SENDING, read abort, and RESET_STREAM recovery rules are proven with focused requirement-home evidence",
                "the lane closes runtime interruption behavior instead of only adding surface helpers"
            )
            fail_gates = @(
                "the lane adds no proof for repeated STOP_SENDING or deferred reset behavior",
                "public API widening displaces the narrow runtime goal"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "stream-read-reset-disposition"
            objective = "Close read-side interruption, reset notification, and ResetRead acknowledgement behavior for receive-state stream transitions."
            priority = 10
            prerequisite_lane_ids = @("stream-stop-sending-read-abort")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicStream.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S3P2-0022", "REQ-QUIC-RFC9000-S3P2-0023")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P2_0022|FullyQualifiedName~REQ_QUIC_RFC9000_S3P2_0023"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P2_0022|FullyQualifiedName~REQ_QUIC_RFC9000_S3P2_0023"'
            )
            success_gates = @(
                "RESET_STREAM transitions and acknowledgement handling stay runtime-owned and narrowly proven",
                "the receive-side reset disposition closes without widening the send-side terminal guards"
            )
            fail_gates = @(
                "the lane turns into trace-only xref cleanup",
                "the same read-side reset blocker still remains after the lane finishes"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "stream-terminal-send-guards"
            objective = "Close the remaining terminal-state send guards and RESET_STREAM/STOP_SENDING admission rules that still block the stream-state follow-ons."
            priority = 11
            prerequisite_lane_ids = @("stream-read-reset-disposition")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicStream.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S3P3-0001", "REQ-QUIC-RFC9000-S3P3-0002", "REQ-QUIC-RFC9000-S3P3-0005")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P3_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S3P3_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S3P3_0005"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P3_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S3P3_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S3P3_0005"'
            )
            success_gates = @(
                "terminal send-state transitions reject STREAM, STREAM_DATA_BLOCKED, and RESET_STREAM once the send side is closed",
                "STOP_SENDING remains admitted only while the receive side still accepts it"
            )
            fail_gates = @(
                "the lane broadens into bidirectional composition before the send guards are proven",
                "the lane only shuffles traces instead of closing runtime behavior"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "stream-bidirectional-composition"
            objective = "Close bidirectional stream composition and the acknowledgement-gated closed-state mapping that remains after the send guards land."
            priority = 11
            prerequisite_lane_ids = @("stream-terminal-send-guards")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicStream.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S3P4-0001", "REQ-QUIC-RFC9000-S3P4-0002", "REQ-QUIC-RFC9000-S3P4-0003")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P4_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S3P4_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S3P4_0003"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S3P4_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S3P4_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S3P4_0003"'
            )
            success_gates = @(
                "bidirectional streams continue to be represented as a composite of sending and receiving parts",
                "the closed-state example mapping stays ack-gated without broadening into public API or interop work"
            )
            fail_gates = @(
                "the lane becomes a general stream-state sweep instead of a bidirectional composition slice",
                "the result is only trace reshaping without runtime-backed proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "final-size-and-credit-accounting"
            objective = "Close final-size immutability and connection-level credit accounting rules that gate the remaining stream and flow-control work."
            priority = 10
            prerequisite_lane_ids = @("stream-send-reset-lifecycle", "stream-stop-sending-read-abort")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S4P5-0002", "REQ-QUIC-RFC9000-S4P5-0004", "REQ-QUIC-RFC9000-S4P5-0005", "REQ-QUIC-RFC9000-S4P5-0006", "REQ-QUIC-RFC9000-S4P5-0007", "REQ-QUIC-RFC9000-S4P5-0008", "REQ-QUIC-RFC9000-S3P5-0003")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0005|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0006|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0007|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S3P5_0003"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0005|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0006|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0007|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S3P5_0003"'
            )
            success_gates = @(
                "final-size and connection credit accounting rules become trace-clean with positive and negative proof",
                "the lane removes a real blocker for downstream MAX_* and BLOCKED cadence work"
            )
            fail_gates = @(
                "work stays trace-only or never proves the error paths",
                "the same accounting blocker still prevents downstream flow-control lanes"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "credit-readvertisement-reliability"
            objective = "Close runtime-owned MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS re-advertisement reliability after reads, resets, and loss."
            priority = 11
            prerequisite_lane_ids = @("final-size-and-credit-accounting")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "src/Incursa.Quic/QuicMax",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S13P3-0015", "REQ-QUIC-RFC9000-S13P3-0016", "REQ-QUIC-RFC9000-S13P3-0017", "REQ-QUIC-RFC9000-S13P3-0018", "REQ-QUIC-RFC9000-S13P3-0019", "REQ-QUIC-RFC9000-S13P3-0020", "REQ-QUIC-RFC9000-S13P3-0021")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0016|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0017|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0018|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0019|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0020|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0021"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0016|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0017|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0018|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0019|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0020|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0021"'
            )
            success_gates = @(
                "MAX_* readvertisement behavior is runtime-backed and loss-aware",
                "the lane closes credit refresh reliability rather than only emitting frame payloads"
            )
            fail_gates = @(
                "frame serialization changes land without resend ownership",
                "loss-driven re-advertisement still lacks focused proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "blocked-signal-cadence"
            objective = "Close blocked-frame emission cadence and the rule that blocked signals do not force unrelated packets."
            priority = 12
            prerequisite_lane_ids = @("final-size-and-credit-accounting")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "src/Incursa.Quic/QuicDataBlockedFrame.cs",
                "src/Incursa.Quic/QuicStreamDataBlockedFrame.cs",
                "src/Incursa.Quic/QuicStreamsBlockedFrame.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S4P1-0015", "REQ-QUIC-RFC9000-S4P2-0002", "REQ-QUIC-RFC9000-S4P2-0003", "REQ-QUIC-RFC9000-S4P2-0004", "REQ-QUIC-RFC9000-S13P3-0022", "REQ-QUIC-RFC9000-S13P3-0023", "REQ-QUIC-RFC9000-S13P3-0024", "REQ-QUIC-RFC9000-S13P3-0025")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P1_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0022|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0023|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0024|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0025"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P1_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0022|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0023|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0024|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0025"'
            )
            success_gates = @(
                "blocked-frame cadence and no-forced-packet behavior are proven narrowly",
                "the lane closes a real flow-control runtime seam rather than only adding trace metadata"
            )
            fail_gates = @(
                "no negative proof lands for the no-extra-packet rule",
                "the same blocked-frame cadence blocker remains after the lane finishes"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "flow-control-receiver-contract"
            objective = "Close the remaining receiver-side flow-control contract for MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS receipts without reopening the sender-side blocked-feedback lanes."
            priority = 13
            prerequisite_lane_ids = @("final-size-and-credit-accounting")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicStream.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S4P1", "REQ-QUIC-RFC9000-S4P2")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P1_|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P1_|FullyQualifiedName~REQ_QUIC_RFC9000_S4P2_"'
            )
            success_gates = @(
                "receiver-side limit advertisement and duplicate-limit suppression remain runtime-backed and narrowly proven",
                "the lane closes the remaining S4P1 and S4P2 receiver obligations without touching resend scheduling"
            )
            fail_gates = @(
                "the lane turns into trace-only xref cleanup",
                "blocked-signal or resend-scheduler changes spill into the same commit"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "flow-control-loss-repair"
            objective = "Repair the remaining flow-control loss and retry path for MAX_DATA, MAX_STREAM_DATA, and blocked signals so the latest published credit is re-issued while still relevant."
            priority = 14
            prerequisite_lane_ids = @("flow-control-receiver-contract")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "src/Incursa.Quic/QuicStream.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S4P1-0015", "REQ-QUIC-RFC9000-S13P3-0018", "REQ-QUIC-RFC9000-S13P3-0019", "REQ-QUIC-RFC9000-S13P3-0024")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P1_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0018|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0019|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0024"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P1_0015|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0018|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0019|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0024"'
            )
            success_gates = @(
                "loss of the most recent credit or blocked frame produces a replacement only while the endpoint is still blocked",
                "the lane closes the residual flow-control retry proof without widening the scheduler"
            )
            fail_gates = @(
                "it turns into codec-only tests",
                "it requires new sender/recovery abstractions just to prove the residual cases"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "retransmission-send-scheduler"
            objective = "Close the remaining packet and frame resend scheduler for lost STREAM and CRYPTO material, connection-close suppression, path-challenge retry, and HANDSHAKE_DONE retransmission."
            priority = 15
            prerequisite_lane_ids = @("flow-control-loss-repair")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicHandshakeDoneFrame.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S13P3-0001", "REQ-QUIC-RFC9000-S13P3-0002", "REQ-QUIC-RFC9000-S13P3-0003", "REQ-QUIC-RFC9000-S13P3-0004", "REQ-QUIC-RFC9000-S13P3-0005", "REQ-QUIC-RFC9000-S13P3-0006", "REQ-QUIC-RFC9000-S13P3-0007", "REQ-QUIC-RFC9000-S13P3-0008", "REQ-QUIC-RFC9000-S13P3-0009", "REQ-QUIC-RFC9000-S13P3-0010", "REQ-QUIC-RFC9000-S13P3-0014", "REQ-QUIC-RFC9000-S13P3-0026", "REQ-QUIC-RFC9000-S13P3-0033")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0005|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0006|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0007|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0009|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0014|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0026|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0033"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0005|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0006|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0007|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0009|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0014|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0026|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0033"'
            )
            success_gates = @(
                "lost STREAM and CRYPTO material is re-sent through the runtime scheduler instead of being retried only in helpers",
                "HANDSHAKE_DONE and PATH_CHALLENGE remain in the reliability slice instead of the handshake umbrella"
            )
            fail_gates = @(
                "the lane broadens into migration or interop work",
                "resend policy is still only expressed through tests without scheduler ownership"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "retransmission-scheduler-tail"
            objective = "Finish the residual resend-scheduler proof tail that still leaves a handful of RFC 9000 S13P3 retransmission rules partially covered."
            priority = 16
            prerequisite_lane_ids = @("retransmission-send-scheduler")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicHandshakeDoneFrame.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S13P3-0010", "REQ-QUIC-RFC9000-S13P3-0011", "REQ-QUIC-RFC9000-S13P3-0013", "REQ-QUIC-RFC9000-S13P3-0026", "REQ-QUIC-RFC9000-S13P3-0033")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0011|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0013|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0026|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0033"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0011|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0013|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0026|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0033"'
            )
            success_gates = @(
                "the remaining retransmission tail becomes proof-backed without widening into migration or interop harness work",
                "the lane keeps the resend scheduler as the owner of the residual proof, not trace cleanup"
            )
            fail_gates = @(
                "the lane broadens into unrelated migration or TLS message-processing work",
                "the result is only trace reshaping with no runtime proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "flow-control-loss-repair-proof-topoff"
            objective = "Finish the residual flow-control loss-repair proof for MAX_STREAM_DATA and blocked-signal retry cases that still sit behind the completed flow-control lanes."
            priority = 17
            prerequisite_lane_ids = @("flow-control-loss-repair")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionStreamState.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionSendRuntime.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S13P3-0018", "REQ-QUIC-RFC9000-S13P3-0019", "REQ-QUIC-RFC9000-S13P3-0024")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0018|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0019|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0024"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0018|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0019|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0024"'
            )
            success_gates = @(
                "the remaining MAX_STREAM_DATA and blocked-frame loss repair is proven with the existing runtime seam",
                "the lane does not re-open resend-scheduler or migration scope"
            )
            fail_gates = @(
                "the lane turns into trace-only xref cleanup",
                "it requires a new scheduler surface just to prove the residual flow-control cases"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "path-migration-recovery-reset"
            objective = "Close the post-switch recovery reset rules that keep old-path traffic from poisoning the new path's congestion and RTT state."
            priority = 16
            prerequisite_lane_ids = @("path-migration-cid-runtime")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicCongestionControlState.cs",
                "src/Incursa.Quic/QuicAddressValidation.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P4-0001", "REQ-QUIC-RFC9000-S9P4-0002", "REQ-QUIC-RFC9000-S9P4-0003", "REQ-QUIC-RFC9000-S9P4-0005")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0005"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0005"'
            )
            success_gates = @(
                "old-path packets stop influencing the new path's congestion and RTT state",
                "peer address confirmation keeps or resets migration state exactly as the requirement family allows"
            )
            fail_gates = @(
                "the lane widens into sender or ECN work that belongs elsewhere",
                "the result is only trace reshaping with no runtime proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "cross-path-ack-coverage"
            objective = "Close the cross-path ACK coverage rules that remain after path migration."
            priority = 17
            prerequisite_lane_ids = @("path-migration-recovery-reset")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P4-0004", "REQ-QUIC-RFC9000-S9P4-0006")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0006"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0006"'
            )
            success_gates = @(
                "ACK frames continue to cover packets received on multiple paths",
                "path migration does not split ACK ownership by path"
            )
            fail_gates = @(
                "the lane turns into a generic migration cleanup sweep",
                "the result is only trace reshaping with no runtime proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "path-validation-timer-discipline"
            objective = "Close the PATH_CHALLENGE timer discipline rules that keep validation conservative across retries."
            priority = 18
            prerequisite_lane_ids = @("cross-path-ack-coverage")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicRecoveryTiming.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P4-0008", "REQ-QUIC-RFC9000-S9P4-0009", "REQ-QUIC-RFC9000-S9P4-0010", "REQ-QUIC-RFC9000-S9P4-0011")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0009|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0011"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0009|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0011"'
            )
            success_gates = @(
                "PATH_CHALLENGE timers remain conservative and retry cleanly when PATH_RESPONSE is missing",
                "path validation stays bounded by the existing recovery timing surface"
            )
            fail_gates = @(
                "timer behavior is changed without path-ack proof",
                "the lane broadens into sender scheduler work"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "path-validation-probe-loss-exception"
            objective = "Close the probe-packet loss exception rule at the recovery boundary."
            priority = 19
            prerequisite_lane_ids = @("retransmission-send-scheduler")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicCongestionControlState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P4-0007")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0007"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P4_0007"'
            )
            success_gates = @(
                "probe packets stay exempt from normal loss-induced congestion reduction only where the requirement allows",
                "the recovery/congestion boundary stays narrowly proven"
            )
            fail_gates = @(
                "the lane becomes a second resend-scheduler implementation",
                "the proof broadens into unrelated migration work"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "recovery-timer-granularity-floor"
            objective = "Close the RFC 9002 recovery timing floor and conflicting-timer proof around the shared helper surface."
            priority = 20
            prerequisite_lane_ids = @("retransmission-send-scheduler")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicRecoveryTiming.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9002",
                "specs/requirements/quic/SPEC-QUIC-RFC9002",
                "specs/architecture/quic/ARC-QUIC-RFC9002",
                "specs/work-items/quic/WI-QUIC-RFC9002",
                "specs/verification/quic/VER-QUIC-RFC9002",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9002-S6P1P2-0006", "REQ-QUIC-RFC9002-S6P2P1-0010")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9002_S6P1P2_0006|FullyQualifiedName~REQ_QUIC_RFC9002_S6P2P1_0010"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9002_S6P1P2_0006|FullyQualifiedName~REQ_QUIC_RFC9002_S6P2P1_0010"'
            )
            success_gates = @(
                "the recovery timing helper still honors the one-millisecond floor",
                "the PTO and loss-detection timer selection proof stays narrow and test-backed"
            )
            fail_gates = @(
                "the lane becomes trace-only xref cleanup",
                "it drifts into sender or migration behavior outside the timing helper"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "rfc9001-key-phase-toggle-detection-floor"
            objective = "Close the managed RFC 9001 client/runtime key-phase toggle and detection floor on the existing bridge seam."
            priority = 21
            prerequisite_lane_ids = @()
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicHandshakeFlowCoordinator.cs",
                "src/Incursa.Quic/QuicTlsTransportBridgeDriver.cs",
                "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9001",
                "specs/requirements/quic/SPEC-QUIC-RFC9001",
                "specs/architecture/quic/ARC-QUIC-RFC9001",
                "specs/work-items/quic/WI-QUIC-RFC9001",
                "specs/verification/quic/VER-QUIC-RFC9001",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9001-S6-0004", "REQ-QUIC-RFC9001-S6-0005")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9001_S6_0004|FullyQualifiedName~REQ_QUIC_RFC9001_S6_0005"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9001_S6_0004|FullyQualifiedName~REQ_QUIC_RFC9001_S6_0005"'
            )
            success_gates = @(
                "the managed client/runtime can signal a key-phase change and a recipient can observe the change through the existing packet parser",
                "the empty 0004/0005 requirement homes become runtime-backed without widening into TLS KeyUpdate prohibition or error handling"
            )
            fail_gates = @(
                "the lane broadens into the deferred TLS KeyUpdate prohibition/error path",
                "the result is trace-only churn without requirement-home proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "rfc9001-key-phase-detection-edge-coverage"
            objective = "Finish the edge coverage around managed RFC 9001 key-phase detection without waiting on the deferred TLS message-processing surface."
            priority = 22
            prerequisite_lane_ids = @("rfc9001-key-phase-toggle-detection-floor")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicHandshakeFlowCoordinator.cs",
                "src/Incursa.Quic/QuicTlsTransportBridgeDriver.cs",
                "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9001",
                "specs/requirements/quic/SPEC-QUIC-RFC9001",
                "specs/architecture/quic/ARC-QUIC-RFC9001",
                "specs/work-items/quic/WI-QUIC-RFC9001",
                "specs/verification/quic/VER-QUIC-RFC9001",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9001-S6-0005")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9001_S6_0005"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9001_S6_0005"'
            )
            success_gates = @(
                "the recipient-detection edge cases for the key-phase floor are fully proven",
                "the lane stays on the bridge/runtime seam instead of expanding into TLS KeyUpdate processing"
            )
            fail_gates = @(
                "the lane broadens into the deferred TLS KeyUpdate prohibition/error path",
                "the result is only proof reshaping with no runtime-backed edge coverage"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "path-migration-routing-proof"
            objective = "Prove the existing runtime migration routing floor: subsequent packets follow the migrated address, path validation starts, and the highest-numbered non-probing packet gate stays honest."
            priority = 23
            prerequisite_lane_ids = @("path-migration-cid-runtime")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeStateModels.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicPathMigrationRecoveryTestSupport.cs",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @(
                "REQ-QUIC-RFC9000-S9P3-0001",
                "REQ-QUIC-RFC9000-S9P3-0006",
                "REQ-QUIC-RFC9000-S9P3-0007",
                "REQ-QUIC-RFC9000-S9P3-0008"
            )
            verification_commands = @(
                "dotnet test Incursa.Quic.slnx --filter ""FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0006|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0007|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0008"""
            )
            merge_check_commands = @(
                "dotnet test Incursa.Quic.slnx --filter ""FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0006|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0007|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0008"""
            )
            success_gates = @(
                "migration routing and path validation initiation become requirement-home proven on the existing runtime seam",
                "the lane does not widen into address-validation token emission or other migration families"
            )
            fail_gates = @(
                "the lane becomes a trace-only reshuffle",
                "the lane drifts into the deferred 0005/0011 token-emission work"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "path-migration-address-safety-proof"
            objective = "Prove the remaining migration address-safety guards: unvalidated peer-address traffic, recent-address reuse, spoofing protection, and abandonment of stale validation paths."
            priority = 24
            prerequisite_lane_ids = @("path-migration-routing-proof")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeStateModels.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicPathMigrationRecoveryTestSupport.cs",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @(
                "REQ-QUIC-RFC9000-S9P3-0002",
                "REQ-QUIC-RFC9000-S9P3-0003",
                "REQ-QUIC-RFC9000-S9P3-0004",
                "REQ-QUIC-RFC9000-S9P3-0009",
                "REQ-QUIC-RFC9000-S9P3-0010"
            )
            verification_commands = @(
                "dotnet test Incursa.Quic.slnx --filter ""FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0009|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0010"""
            )
            merge_check_commands = @(
                "dotnet test Incursa.Quic.slnx --filter ""FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0002|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0004|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0009|FullyQualifiedName~REQ_QUIC_RFC9000_S9P3_0010"""
            )
            success_gates = @(
                "unvalidated-address safety and stale-path abandonment become requirement-home proven on the existing runtime seam",
                "the lane does not widen into the deferred 0005/0011 token-emission work"
            )
            fail_gates = @(
                "the lane becomes a trace-only reshuffle",
                "the lane drifts into address-validation token emission instead of the safety floor"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "trace-metadata-reconciliation"
            objective = "Reconcile xrefs, generated summaries, and proof metadata only after a semantic merge has landed."
            priority = 22
            prerequisite_lane_ids = @()
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "specs/generated/quic",
                "specs/requirements/quic",
                "specs/architecture/quic",
                "specs/work-items/quic",
                "specs/verification/quic",
                "tests/Incursa.Quic.Tests/RequirementHomes"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic",
                "src/Incursa.Quic.InteropHarness"
            )
            requirement_families = @("REQ-QUIC")
            verification_commands = @(
                'pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/spec-trace/Generate-QuicRequirementCoverageTriage.ps1'
            )
            merge_check_commands = @(
                'pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/spec-trace/Generate-QuicRequirementCoverageTriage.ps1'
            )
            success_gates = @(
                "generated and canonical trace surfaces align after a semantic merge"
            )
            fail_gates = @(
                "used as a primary overnight lane",
                "run while the same section is still changing semantically"
            )
            repeatable = $true
        }
        [pscustomobject]@{
            lane_id = "migration-connection-id-discipline"
            objective = "Close the RFC 9000 section 9 connection-ID migration discipline tail: CID reuse guards, zero-length CID restrictions, and migration prerequisites on the existing runtime and endpoint surfaces."
            priority = 25
            prerequisite_lane_ids = @("path-migration-address-safety-proof")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicClientConnectionHost.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeStateModels.cs",
                "src/Incursa.Quic/QuicTransportParametersCodec.cs",
                "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicPathMigrationRecoveryTestSupport.cs",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P5-")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P5_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P5_"'
            )
            success_gates = @(
                "connection-id reuse, zero-length CID restrictions, and migration prerequisites become requirement-home proven on the existing runtime and endpoint seams",
                "the lane stays on CID and routing discipline instead of widening into broader preferred-address choreography"
            )
            fail_gates = @(
                "the lane becomes a broad migration umbrella instead of a CID-discipline slice",
                "the result is trace-only churn without focused section 9 proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "preferred-address-client-transition"
            objective = "Close the client-side unexpected-server-address and preferred-address transition floor on the existing transport-parameter and path-validation seams."
            priority = 26
            prerequisite_lane_ids = @("migration-connection-id-discipline")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicClientConnectionHost.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeStateModels.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicPreferredAddress.cs",
                "src/Incursa.Quic/QuicTransportParametersCodec.cs",
                "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicPathMigrationRecoveryTestSupport.cs",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P6-", "REQ-QUIC-RFC9000-S9P6P1-")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6_|FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P1_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6_|FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P1_"'
            )
            success_gates = @(
                "the client-side preferred-address branch becomes requirement-home proven without broadening into server-side path ownership",
                "unexpected server-address traffic and preferred-address selection stay honest on the existing transport-parameter seam"
            )
            fail_gates = @(
                "the lane widens into generic migration cleanup or interop work",
                "preferred-address behavior is claimed without focused client-side proof"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "preferred-address-server-transition"
            objective = "Close the server-side preferred-address migration contract: validation, non-probing gating, and old-address handling on the existing runtime seam."
            priority = 27
            prerequisite_lane_ids = @("preferred-address-client-transition")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeStateModels.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicPreferredAddress.cs",
                "src/Incursa.Quic/QuicTransportParametersCodec.cs",
                "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicPathMigrationRecoveryTestSupport.cs",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P6P2-")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P2_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P2_"'
            )
            success_gates = @(
                "server-side preferred-address validation and old-address handling become requirement-home proven on the existing runtime seam",
                "the lane stays on the server transition contract instead of reopening generic CID issuance or TLS transport-parameter work"
            )
            fail_gates = @(
                "the lane broadens into a mixed client/server migration sweep",
                "proof is added without runtime-backed preferred-address transition behavior"
            )
            repeatable = $false
        }
        [pscustomobject]@{
            lane_id = "preferred-address-dual-validation-safety"
            objective = "Finish the concurrent-validation and preferred-address safety tail after the basic client and server transition floors are in place."
            priority = 28
            prerequisite_lane_ids = @("preferred-address-server-transition")
            blocking_gap_ids = @()
            allowed_path_prefixes = @(
                "src/Incursa.Quic/QuicClientConnectionHost.cs",
                "src/Incursa.Quic/QuicConnectionRuntime.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs",
                "src/Incursa.Quic/QuicConnectionRuntimeStateModels.cs",
                "src/Incursa.Quic/QuicPathValidation.cs",
                "src/Incursa.Quic/QuicPreferredAddress.cs",
                "src/Incursa.Quic/QuicTransportParametersCodec.cs",
                "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000",
                "tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicPathMigrationRecoveryTestSupport.cs",
                "specs/requirements/quic/SPEC-QUIC-RFC9000",
                "specs/architecture/quic/ARC-QUIC-RFC9000",
                "specs/work-items/quic/WI-QUIC-RFC9000",
                "specs/verification/quic/VER-QUIC-RFC9000",
                "specs/requirements/quic/REQUIREMENT-GAPS.md"
            )
            forbidden_path_prefixes = @(
                "src/Incursa.Quic.InteropHarness",
                "src/Incursa.Quic/QuicTls",
                "specs/generated"
            )
            requirement_families = @("REQ-QUIC-RFC9000-S9P6P3-")
            verification_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P3_"'
            )
            merge_check_commands = @(
                'dotnet test Incursa.Quic.slnx --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P3_"'
            )
            success_gates = @(
                "concurrent validation, preferred-address attack protection, and address-family safety become requirement-home proven without broadening beyond the preferred-address tail",
                "the lane keeps the remaining S9P6P3 work isolated from unrelated migration, interop, or TLS expansion"
            )
            fail_gates = @(
                "the lane becomes a catch-all migration umbrella",
                "clean S9P6P3 transport-parameter parsing proofs are relitigated instead of closing the remaining runtime tail"
            )
            repeatable = $false
        }
    )
}

function New-LaneCatalog {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$TargetBranch,
        [Parameter(Mandatory = $true)]$TriageJson,
        [Parameter(Mandatory = $true)][string[]]$OpenGapIds,
        [Parameter(Mandatory = $true)]$StateObject,
        [Parameter(Mandatory = $true)][string]$PlannerModel,
        [Parameter(Mandatory = $true)][string]$PlannerReasoningEffort,
        [Parameter(Mandatory = $true)][string]$WorkerModel,
        [Parameter(Mandatory = $true)][string]$WorkerReasoningEffort
    )

    $completedLaneIds = @(Get-NormalizedStringList -Items $StateObject.completed_lane_ids)
    $pendingReconciliationLaneIds = @(Get-NormalizedStringList -Items $StateObject.pending_reconciliation_lane_ids)
    $activeLaneId = if ($null -ne $StateObject.active_lane -and $StateObject.active_lane.PSObject.Properties.Name -contains "lane_id") { [string]$StateObject.active_lane.lane_id } else { "" }
    $recommendedLaneId = ""

    $lanes = New-Object System.Collections.Generic.List[object]
    foreach ($template in Get-LaneTemplateDefinitions) {
        $status = "eligible"
        $statusReason = "ready"
        $prerequisiteIds = @(Get-NormalizedStringList -Items $template.prerequisite_lane_ids)
        $blockingGapIds = @(Get-NormalizedStringList -Items $template.blocking_gap_ids)
        $openBlockingGaps = @($blockingGapIds | Where-Object { $OpenGapIds -contains $_ })

        if ($template.lane_id -eq "trace-metadata-reconciliation" -and $pendingReconciliationLaneIds.Count -eq 0) {
            $status = "deferred"
            $statusReason = "no semantic merge is waiting for reconciliation"
        }
        elseif ($completedLaneIds -contains $template.lane_id -and -not [bool]$template.repeatable) {
            $status = "completed"
            $statusReason = "recorded as completed in orchestration state"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($activeLaneId) -and $activeLaneId -eq $template.lane_id) {
            $status = "active"
            $statusReason = "currently assigned to the worker worktree"
        }
        else {
            $missingPrerequisites = @($prerequisiteIds | Where-Object { $completedLaneIds -notcontains $_ })
            if ($missingPrerequisites.Count -gt 0) {
                $status = "blocked_prerequisite"
                $statusReason = "waiting for prerequisite lanes: " + ($missingPrerequisites -join ", ")
            }
            elseif ($openBlockingGaps.Count -gt 0) {
                $status = "blocked_gap"
                $statusReason = "blocked by open gaps: " + ($openBlockingGaps -join ", ")
            }
        }

        $requirementSummary = Get-LaneRequirementSummary -TriageJson $TriageJson -RequirementFamilies $template.requirement_families
        $lane = [pscustomobject]@{
            lane_id = $template.lane_id
            objective = $template.objective
            priority = $template.priority
            prerequisite_lane_ids = @($prerequisiteIds)
            blocking_gap_ids = @($blockingGapIds)
            allowed_path_prefixes = @(Get-NormalizedPathPrefixList -Items $template.allowed_path_prefixes)
            forbidden_path_prefixes = @(Get-NormalizedPathPrefixList -Items $template.forbidden_path_prefixes)
            requirement_families = @(Get-NormalizedStringList -Items $template.requirement_families)
            verification_commands = @(Get-NormalizedStringList -Items $template.verification_commands)
            merge_check_commands = @(Get-NormalizedStringList -Items $template.merge_check_commands)
            success_gates = @(Get-NormalizedStringList -Items $template.success_gates)
            fail_gates = @(Get-NormalizedStringList -Items $template.fail_gates)
            repeatable = [bool]$template.repeatable
            status = $status
            status_reason = $statusReason
            matching_requirements = $requirementSummary
        }

        if ([string]::IsNullOrWhiteSpace($recommendedLaneId) -and $status -eq "eligible") {
            $recommendedLaneId = $template.lane_id
        }

        [void]$lanes.Add($lane)
    }

    return [pscustomobject]@{
        generated_at = (Get-Date).ToString("o")
        repo_root = $RepoRoot
        target_branch = $TargetBranch
        sources = [pscustomobject]@{
            triage = "specs/generated/quic/quic-requirement-coverage-triage.json"
            requirement_gaps = "specs/requirements/quic/REQUIREMENT-GAPS.md"
            state_file = ".artifacts/interop-autopilot/orchestration-state.json"
        }
        operating_model = [pscustomobject]@{
            default_parallel_lanes = 2
            planner = [pscustomobject]@{
                model = $PlannerModel
                reasoning_effort = $PlannerReasoningEffort
            }
            worker = [pscustomobject]@{
                model = $WorkerModel
                reasoning_effort = $WorkerReasoningEffort
            }
        }
        open_gap_ids = @($OpenGapIds)
        completed_lane_ids = @($completedLaneIds)
        pending_reconciliation_lane_ids = @($pendingReconciliationLaneIds)
        active_lane_id = $activeLaneId
        recommended_lane_id = $recommendedLaneId
        lanes = $lanes.ToArray()
    }
}

function Get-CatalogLane {
    param(
        [Parameter(Mandatory = $true)]$Catalog,
        [Parameter(Mandatory = $true)][string]$LaneId
    )

    $lane = @($Catalog.lanes | Where-Object { $_.lane_id -eq $LaneId } | Select-Object -First 1)
    if ($lane.Count -eq 0) {
        throw "Unknown lane id: $LaneId"
    }

    return $lane[0]
}

function New-WorkerContract {
    param(
        [Parameter(Mandatory = $true)]$Lane,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [Parameter(Mandatory = $true)][string]$BranchName,
        [Parameter(Mandatory = $true)][string]$BaseRef,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$TargetBranch,
        [Parameter(Mandatory = $true)][string]$PlannerModel,
        [Parameter(Mandatory = $true)][string]$PlannerReasoningEffort,
        [Parameter(Mandatory = $true)][string]$WorkerModel,
        [Parameter(Mandatory = $true)][string]$WorkerReasoningEffort
    )

    return [pscustomobject]@{
        schema_version = 1
        created_at = (Get-Date).ToString("o")
        lane_id = $Lane.lane_id
        objective = $Lane.objective
        priority = $Lane.priority
        target_branch = $TargetBranch
        prerequisite_lane_ids = @($Lane.prerequisite_lane_ids)
        blocking_gap_ids = @($Lane.blocking_gap_ids)
        allowed_path_prefixes = @($Lane.allowed_path_prefixes)
        forbidden_path_prefixes = @($Lane.forbidden_path_prefixes)
        requirement_families = @($Lane.requirement_families)
        verification_commands = @($Lane.verification_commands)
        merge_check_commands = @($Lane.merge_check_commands)
        success_gates = @($Lane.success_gates)
        fail_gates = @($Lane.fail_gates)
        planner = [pscustomobject]@{
            model = $PlannerModel
            reasoning_effort = $PlannerReasoningEffort
        }
        worker = [pscustomobject]@{
            model = $WorkerModel
            reasoning_effort = $WorkerReasoningEffort
        }
        repo_root = $RepoRoot
        worktree_path = $WorktreePath
        branch_name = $BranchName
        base_ref = $BaseRef
        output_directory = $OutputDirectory
    }
}

function Start-WorkerRun {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$RunnerScriptPath,
        [Parameter(Mandatory = $true)][string]$MissionPromptFile,
        [Parameter(Mandatory = $true)]$WorkerContract,
        [Parameter(Mandatory = $true)][string]$CodexCommand,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$WorkerModel,
        [Parameter(Mandatory = $true)][string]$WorkerReasoningEffort,
        [Parameter(Mandatory = $true)][int]$WorkerMaxIterations,
        [Parameter(Mandatory = $true)][int]$WorkerMaxRescueAttemptsPerTurn
    )

    $runnerParameters = [ordered]@{
        WorkingDirectory             = $WorkerContract.worktree_path
        InitialPromptFile            = $MissionPromptFile
        OutputDirectory              = $WorkerContract.output_directory
        CodexCommand                 = $CodexCommand
        Sandbox                      = $Sandbox
        Model                        = $WorkerModel
        ReasoningEffort              = $WorkerReasoningEffort
        MissionPromptStyle           = "always_digest"
        MaxIterations                = $WorkerMaxIterations
        MaxRescueAttemptsPerTurn     = $WorkerMaxRescueAttemptsPerTurn
        TargetLaneId                 = $WorkerContract.lane_id
        TargetScope                  = $WorkerContract.objective
        AllowedPathPrefixes          = @($WorkerContract.allowed_path_prefixes)
        ForbiddenPathPrefixes        = @($WorkerContract.forbidden_path_prefixes)
        RequirementFamilies          = @($WorkerContract.requirement_families)
        BlockingGapIds               = @($WorkerContract.blocking_gap_ids)
        VerificationCommands         = @($WorkerContract.verification_commands)
        MergeCheckCommands           = @($WorkerContract.merge_check_commands)
        RequirementGapsPath          = (Join-Path $WorkerContract.worktree_path "specs/requirements/quic/REQUIREMENT-GAPS.md")
        StopOnPathViolation          = $true
        StopOnBlockedGap             = $true
    }

    $bootstrapParametersPath = Join-Path $WorkerContract.output_directory "worker-runner.parameters.json"
    $bootstrapScriptPath = Join-Path $WorkerContract.output_directory "worker-runner.bootstrap.ps1"
    ($runnerParameters | ConvertTo-Json -Depth 100) | Set-Content -LiteralPath $bootstrapParametersPath -Encoding utf8

    $escapedParametersPath = $bootstrapParametersPath.Replace("'", "''")
    $escapedRunnerScriptPath = $RunnerScriptPath.Replace("'", "''")
    $bootstrapScript = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

`$runnerParameters = Get-Content -LiteralPath '$escapedParametersPath' -Raw | ConvertFrom-Json -AsHashtable
foreach (`$arrayKey in @('AllowedPathPrefixes', 'ForbiddenPathPrefixes', 'RequirementFamilies', 'BlockingGapIds', 'VerificationCommands', 'MergeCheckCommands')) {
    if (`$runnerParameters.ContainsKey(`$arrayKey)) {
        `$runnerParameters[`$arrayKey] = @(`$runnerParameters[`$arrayKey])
    }
}

foreach (`$switchKey in @('StopOnPathViolation', 'StopOnBlockedGap')) {
    if (`$runnerParameters.ContainsKey(`$switchKey)) {
        `$runnerParameters[`$switchKey] = [bool]`$runnerParameters[`$switchKey]
    }
}

& '$escapedRunnerScriptPath' @runnerParameters
if (Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue) {
    exit `$global:LASTEXITCODE
}

if (`$?) {
    exit 0
}

exit 1
"@
    Set-Content -LiteralPath $bootstrapScriptPath -Value $bootstrapScript -Encoding utf8

    & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $bootstrapScriptPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Worker lane runner failed with exit code $LASTEXITCODE."
    }
}

function Get-WorkerFinalDecision {
    param([Parameter(Mandatory = $true)][string]$OutputDirectory)

    $summaryPath = Join-Path $OutputDirectory "autopilot-summary.csv"
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        return $null
    }

    $rows = Import-Csv -LiteralPath $summaryPath
    if ($null -eq $rows -or @($rows).Count -eq 0) {
        return $null
    }

    return @($rows)[-1]
}

function Get-ActiveLaneDisposition {
    param(
        [Parameter(Mandatory = $true)]$StateObject,
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    if ($null -eq $StateObject.active_lane) {
        return [pscustomobject]@{
            Action        = "none"
            Reason        = "No active worker lane is recorded."
            DecisionState = ""
            CommitCount   = 0
        }
    }

    if ($StateObject.active_lane.PSObject.Properties.Name -contains "merged" -and [bool]$StateObject.active_lane.merged) {
        return [pscustomobject]@{
            Action        = "cleanup"
            Reason        = "The active lane has already been merged and only cleanup remains."
            DecisionState = "merged"
            CommitCount   = 0
        }
    }

    $contractPath = [string]$StateObject.active_lane.contract_path
    if ([string]::IsNullOrWhiteSpace($contractPath) -or -not (Test-Path -LiteralPath $contractPath)) {
        return [pscustomobject]@{
            Action        = "cleanup"
            Reason        = "The active lane contract is missing; cleanup is the only safe recovery."
            DecisionState = ""
            CommitCount   = 0
        }
    }

    $workerContract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]::IsNullOrWhiteSpace($workerContract.worktree_path) -or -not (Test-Path -LiteralPath $workerContract.worktree_path)) {
        return [pscustomobject]@{
            Action        = "cleanup"
            Reason        = "The active lane worktree is missing; cleanup is the only safe recovery."
            DecisionState = ""
            CommitCount   = 0
            WorkerContract = $workerContract
        }
    }

    $workerDecision = Get-WorkerFinalDecision -OutputDirectory $workerContract.output_directory
    $workerHead = Get-GitHead -GitExecutable $GitExecutable -RepositoryRoot $workerContract.worktree_path -Ref "HEAD"
    $commitShas = @(Get-CommitRange -GitExecutable $GitExecutable -RepositoryRoot $workerContract.worktree_path -FromRef $workerContract.base_ref -ToRef $workerHead)
    $commitCount = $commitShas.Count
    $decisionState = ""

    if ($null -ne $workerDecision) {
        if ($workerDecision.PSObject.Properties.Name -contains "State") {
            $decisionState = [string]$workerDecision.State
        }
        elseif ($workerDecision.PSObject.Properties.Name -contains "state") {
            $decisionState = [string]$workerDecision.state
        }
    }

    $action = "resume"
    $reason = "The active lane has not reached a terminal decision yet."

    switch ($decisionState) {
        "continue" {
            if ($commitCount -gt 0) {
                $action = "merge"
                $reason = "The active lane produced commits and requested another autonomous turn."
            }
            else {
                $action = "resume"
                $reason = "The active lane requested another autonomous turn and has not produced commits yet."
            }
        }
        "complete" {
            if ($commitCount -gt 0) {
                $action = "merge"
                $reason = "The active lane completed and has commits ready to merge."
            }
            else {
                $action = "cleanup"
                $reason = "The active lane completed without commits; cleanup only."
            }
        }
        "pause_manual" {
            if ($commitCount -gt 0) {
                $action = "merge"
                $reason = "The active lane requested manual review, but it produced commits and will be merged under supervisor mode."
            }
            else {
                $action = "cleanup"
                $reason = "The active lane requested manual review without commits; cleanup only."
            }
        }
        "stuck" {
            if ($commitCount -gt 0) {
                $action = "stop"
                $reason = "The active lane is stuck and has commits present."
            }
            else {
                $action = "cleanup"
                $reason = "The active lane is stuck without commits; cleanup only."
            }
        }
        default {
            if ($commitCount -gt 0) {
                $action = "merge"
                $reason = "The active lane has commits and no terminal worker decision summary."
            }
            else {
                $action = "resume"
                $reason = "The active lane has no terminal summary and no commits yet."
            }
        }
    }

    return [pscustomobject]@{
        Action        = $action
        Reason        = $reason
        DecisionState = $decisionState
        CommitCount   = $commitCount
        WorkerDecision = $workerDecision
        WorkerContract = $workerContract
    }
}

function Invoke-WorkerLaneExecution {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$RunnerScriptPath,
        [Parameter(Mandatory = $true)][string]$MissionPromptFile,
        [Parameter(Mandatory = $true)]$WorkerContract,
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$CodexCommand,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$WorkerModel,
        [Parameter(Mandatory = $true)][string]$WorkerReasoningEffort,
        [Parameter(Mandatory = $true)][int]$WorkerMaxIterations,
        [Parameter(Mandatory = $true)][int]$WorkerMaxRescueAttemptsPerTurn
    )

    Start-WorkerRun `
        -PowerShellExecutable $PowerShellExecutable `
        -RunnerScriptPath $RunnerScriptPath `
        -MissionPromptFile $MissionPromptFile `
        -WorkerContract $WorkerContract `
        -CodexCommand $CodexCommand `
        -Sandbox $Sandbox `
        -WorkerModel $WorkerModel `
        -WorkerReasoningEffort $WorkerReasoningEffort `
        -WorkerMaxIterations $WorkerMaxIterations `
        -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn

    $workerDecision = Get-WorkerFinalDecision -OutputDirectory $WorkerContract.output_directory
    $workerHead = Get-GitHead -GitExecutable $GitExecutable -RepositoryRoot $WorkerContract.worktree_path -Ref "HEAD"
    $commitShas = @(Get-CommitRange -GitExecutable $GitExecutable -RepositoryRoot $WorkerContract.worktree_path -FromRef $WorkerContract.base_ref -ToRef $workerHead)

    Write-Host "Worker lane finished: $($WorkerContract.lane_id)" -ForegroundColor Green
    if ($null -ne $workerDecision) {
        Write-Host "  Final state: $($workerDecision.State)"
    }
    Write-Host "  Commits: $($commitShas.Count)"

    $shouldMerge = $false
    if ($commitShas.Count -gt 0) {
        if ($null -eq $workerDecision -or ($workerDecision.State -notin @("pause_manual", "stuck"))) {
            $shouldMerge = $true
        }
    }

    return [pscustomobject]@{
        Decision    = $workerDecision
        CommitShas  = $commitShas
    }
}

function Resolve-WorkerExecutionResult {
    param([Parameter(Mandatory = $true)][AllowNull()]$Execution)

    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Execution)) {
        if ($null -eq $item) {
            continue
        }

        $propertyNames = @($item.PSObject.Properties.Name)
        if ($propertyNames -contains "CommitShas" -or $propertyNames -contains "commit_shas" -or $propertyNames -contains "Decision" -or $propertyNames -contains "decision") {
            [void]$candidates.Add($item)
        }
    }

    if ($candidates.Count -eq 0) {
        throw "Worker execution did not return a structured summary result."
    }

    $result = $candidates[$candidates.Count - 1]
    $propertyNames = @($result.PSObject.Properties.Name)
    $commitShas = if ($propertyNames -contains "CommitShas") {
        @($result.CommitShas)
    }
    elseif ($propertyNames -contains "commit_shas") {
        @($result.commit_shas)
    }
    else {
        @()
    }

    $decision = if ($propertyNames -contains "Decision") {
        $result.Decision
    }
    elseif ($propertyNames -contains "decision") {
        $result.decision
    }
    else {
        $null
    }

    return [pscustomobject]@{
        Decision   = $decision
        CommitShas = $commitShas
    }
}

function Test-LanePreflightMerge {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)]$WorkerContract,
        [Parameter(Mandatory = $true)][string[]]$CommitShas,
        [Parameter(Mandatory = $true)][string]$StateDirectory
    )

    if ($CommitShas.Count -eq 0) {
        return
    }

    $integrationRoot = Ensure-Directory -Path (Join-Path $StateDirectory "integration")
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $branchName = "codex/integration-$($WorkerContract.lane_id)-$timestamp"
    $worktreePath = Join-Path $integrationRoot "$($WorkerContract.lane_id)-$timestamp"
    $targetHead = Get-GitHead -GitExecutable $GitExecutable -RepositoryRoot $RepoRoot -Ref $WorkerContract.target_branch
    $worktreeInfo = Ensure-GitWorktree -GitExecutable $GitExecutable -RepoRoot $RepoRoot -WorktreePath $worktreePath -BranchName $branchName -BaseRef $targetHead

    try {
        foreach ($commitSha in $CommitShas) {
            $result = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $worktreeInfo.WorktreePath, "cherry-pick", $commitSha)
            if ($result.ExitCode -ne 0) {
                throw "Preflight cherry-pick failed for ${commitSha}: $($result.StdErr.Trim())"
            }
        }

        $mergeCheckResults = Invoke-CommandBatch -WorkingDirectory $worktreeInfo.WorktreePath -Commands $WorkerContract.merge_check_commands -Label "preflight-merge"
        if (@($mergeCheckResults | Where-Object { $_.ExitCode -ne 0 }).Count -gt 0) {
            $failed = @($mergeCheckResults | Where-Object { $_.ExitCode -ne 0 } | Select-Object -First 1)[0]
            throw "Preflight merge checks failed: $($failed.CommandText)"
        }
    }
    finally {
        Remove-GitWorktreeAndBranch -GitExecutable $GitExecutable -RepoRoot $RepoRoot -WorktreePath $worktreeInfo.WorktreePath -BranchName $worktreeInfo.BranchName
    }
}

function Complete-WorkerLaneMerge {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)]$WorkerContract,
        [Parameter(Mandatory = $true)][string[]]$CommitShas
    )

    foreach ($commitSha in $CommitShas) {
        $result = Invoke-NativeCapture -FilePath $GitExecutable -ArgumentList @("-C", $RepoRoot, "cherry-pick", $commitSha)
        if ($result.ExitCode -ne 0) {
            throw "Cherry-pick to $($WorkerContract.target_branch) failed for ${commitSha}: $($result.StdErr.Trim())"
        }
    }

    $mergeCheckResults = Invoke-CommandBatch -WorkingDirectory $RepoRoot -Commands $WorkerContract.merge_check_commands -Label "merge"
    $failed = @($mergeCheckResults | Where-Object { $_.ExitCode -ne 0 } | Select-Object -First 1)
    if ($failed.Count -gt 0) {
        throw "Merge checks failed on $($WorkerContract.target_branch): $($failed[0].CommandText)"
    }
}

try {
    $resolvedRepoRoot = Resolve-ExistingPath -Path $RepoRoot
    $modesNeedingWorkerLaunchInputs = @("prepare", "run", "resume", "supervise")
    $resolvedRunnerScriptPath = if ($modesNeedingWorkerLaunchInputs -contains $Mode) {
        Resolve-ExistingPath -Path $RunnerScriptPath
    }
    else {
        $RunnerScriptPath
    }

    $resolvedMissionPromptFile = if ($modesNeedingWorkerLaunchInputs -contains $Mode) {
        Resolve-ExistingPath -Path $MissionPromptFile
    }
    else {
        $MissionPromptFile
    }
    $resolvedWorktreeRoot = Ensure-Directory -Path $WorktreeRoot
    $resolvedStateDirectory = Ensure-Directory -Path $StateDirectory
    $catalogPath = Join-Path $resolvedStateDirectory "lane-catalog.json"
    $statePath = Join-Path $resolvedStateDirectory "orchestration-state.json"
    $contractsDirectory = Ensure-Directory -Path (Join-Path $resolvedStateDirectory "contracts")
    $gitExecutable = Resolve-CommandPath -Command "git" -Candidates @("git.exe", "git")
    $powerShellExecutable = Resolve-CommandPath -Command (Get-CurrentPowerShellExecutable) -Candidates @("pwsh.exe", "pwsh", "powershell.exe")

    $resolvedTriagePath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "specs/generated/quic/quic-requirement-coverage-triage.json")
    $resolvedRequirementGapsPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "specs/requirements/quic/REQUIREMENT-GAPS.md")
    $triageJson = Get-Content -LiteralPath $resolvedTriagePath -Raw | ConvertFrom-Json -Depth 100
    $openGapIds = Get-OpenGapIds -Path $resolvedRequirementGapsPath
    $state = Get-OrchestrationState -StatePath $statePath

    $catalog = New-LaneCatalog `
        -RepoRoot $resolvedRepoRoot `
        -TargetBranch $TargetBranch `
        -TriageJson $triageJson `
        -OpenGapIds $openGapIds `
        -StateObject $state `
        -PlannerModel $PlannerModel `
        -PlannerReasoningEffort $PlannerReasoningEffort `
        -WorkerModel $WorkerModel `
        -WorkerReasoningEffort $WorkerReasoningEffort

    ($catalog | ConvertTo-Json -Depth 100) | Set-Content -LiteralPath $catalogPath -Encoding utf8

    switch ($Mode) {
        "smoke" {
            $supervisorSettings = Resolve-SupervisorSettings `
                -BoundParameters $PSBoundParameters `
                -PollIntervalSeconds $SupervisorPollIntervalSeconds `
                -MaxIdleCycles $SupervisorMaxIdleCycles `
                -MaxIdleMinutes $SupervisorMaxIdleMinutes `
                -MaxCycles $SupervisorMaxCycles `
                -UseOvernightPreset ([bool]$Overnight)

            Invoke-SupervisorSmokeValidation -DefaultSettings $supervisorSettings
            break
        }

        "plan" {
            Write-Host "Lane catalog: $catalogPath" -ForegroundColor Green
            Write-Host "Recommended lane: $($catalog.recommended_lane_id)" -ForegroundColor Green
            foreach ($lane in $catalog.lanes) {
                Write-Host "  $($lane.lane_id) [$($lane.status)] - $($lane.status_reason)"
            }
            break
        }

        "prepare" {
            if ($null -ne $state.active_lane -and -not $Force) {
                throw "An active worker lane is already recorded. Use -Force to override or run cleanup/merge first."
            }

            $selectedLaneId = if ([string]::IsNullOrWhiteSpace($LaneId)) { [string]$catalog.recommended_lane_id } else { $LaneId }
            if ([string]::IsNullOrWhiteSpace($selectedLaneId)) {
                throw "No eligible lane is available."
            }

            $lane = Get-CatalogLane -Catalog $catalog -LaneId $selectedLaneId
            if ($lane.status -ne "eligible" -and -not $Force) {
                throw "Lane '$selectedLaneId' is not eligible: $($lane.status_reason)"
            }

            $currentBranch = Get-GitCurrentBranch -GitExecutable $gitExecutable -RepositoryRoot $resolvedRepoRoot
            if ($currentBranch -ne $TargetBranch -and -not $Force) {
                throw "Repository must be on '$TargetBranch' before preparing a worker lane. Current branch: $currentBranch"
            }

            if (-not (Test-GitClean -GitExecutable $gitExecutable -RepositoryRoot $resolvedRepoRoot) -and -not $Force) {
                throw "Repository must be clean before preparing a worker lane."
            }

            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $branchName = "codex/$($lane.lane_id)-$timestamp"
            $worktreePath = Join-Path $resolvedWorktreeRoot "$($lane.lane_id)-$timestamp"
            $outputDirectory = Join-Path $resolvedStateDirectory ("runs\" + $lane.lane_id + "-" + $timestamp)
            Ensure-Directory -Path $outputDirectory | Out-Null
            $baseRef = Get-GitHead -GitExecutable $gitExecutable -RepositoryRoot $resolvedRepoRoot -Ref $TargetBranch
            $worktreeInfo = Ensure-GitWorktree -GitExecutable $gitExecutable -RepoRoot $resolvedRepoRoot -WorktreePath $worktreePath -BranchName $branchName -BaseRef $baseRef
            $workerContract = New-WorkerContract `
                -Lane $lane `
                -RepoRoot $resolvedRepoRoot `
                -WorktreePath $worktreeInfo.WorktreePath `
                -BranchName $worktreeInfo.BranchName `
                -BaseRef $worktreeInfo.BaseRef `
                -OutputDirectory $outputDirectory `
                -TargetBranch $TargetBranch `
                -PlannerModel $PlannerModel `
                -PlannerReasoningEffort $PlannerReasoningEffort `
                -WorkerModel $WorkerModel `
                -WorkerReasoningEffort $WorkerReasoningEffort
            $contractPath = Join-Path $contractsDirectory ("worker-contract-" + $lane.lane_id + "-" + $timestamp + ".json")
            ($workerContract | ConvertTo-Json -Depth 100) | Set-Content -LiteralPath $contractPath -Encoding utf8

            $state.active_lane = [pscustomobject]@{
                lane_id = $workerContract.lane_id
                branch_name = $workerContract.branch_name
                worktree_path = $workerContract.worktree_path
                contract_path = $contractPath
                output_directory = $workerContract.output_directory
                base_ref = $workerContract.base_ref
                target_branch = $TargetBranch
                started_at = (Get-Date).ToString("o")
            }
            Save-OrchestrationState -StatePath $statePath -StateObject $state

            Write-Host "Prepared lane: $($workerContract.lane_id)" -ForegroundColor Green
            Write-Host "  Contract: $contractPath"
            Write-Host "  Branch:   $($workerContract.branch_name)"
            Write-Host "  Worktree: $($workerContract.worktree_path)"
            Write-Host "  Output:   $($workerContract.output_directory)"
            break
        }

        "run" {
            if ($null -ne $state.active_lane) {
                throw "An active worker lane already exists. Use merge/cleanup first."
            }

            & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode prepare -RepoRoot $resolvedRepoRoot -RunnerScriptPath $resolvedRunnerScriptPath -MissionPromptFile $resolvedMissionPromptFile -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -LaneId $LaneId -TargetBranch $TargetBranch -PlannerModel $PlannerModel -PlannerReasoningEffort $PlannerReasoningEffort -WorkerModel $WorkerModel -WorkerReasoningEffort $WorkerReasoningEffort -Force:$Force
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to prepare worker lane."
            }

            $state = Get-OrchestrationState -StatePath $statePath
            if ($null -eq $state.active_lane) {
                throw "Prepare step did not record an active lane."
            }

            & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode resume -RepoRoot $resolvedRepoRoot -RunnerScriptPath $resolvedRunnerScriptPath -MissionPromptFile $resolvedMissionPromptFile -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -TargetBranch $TargetBranch -CodexCommand $CodexCommand -Sandbox $Sandbox -PlannerModel $PlannerModel -PlannerReasoningEffort $PlannerReasoningEffort -WorkerModel $WorkerModel -WorkerReasoningEffort $WorkerReasoningEffort -WorkerMaxIterations $WorkerMaxIterations -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn -AutoMerge:$AutoMerge -CleanupAfterMerge:$CleanupAfterMerge -Force:$Force
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to resume worker lane."
            }

            break
        }

        "resume" {
            if ($null -eq $state.active_lane) {
                throw "No active worker lane is recorded."
            }

            $disposition = Get-ActiveLaneDisposition -StateObject $state -GitExecutable $gitExecutable -RepoRoot $resolvedRepoRoot
            Write-Host "Active lane disposition: $($disposition.Action)" -ForegroundColor Green
            Write-Host "  Reason: $($disposition.Reason)" -ForegroundColor Gray

            switch ($disposition.Action) {
                "merge" {
                    & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode merge -RepoRoot $resolvedRepoRoot -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -TargetBranch $TargetBranch -Force:$Force
                    if ($LASTEXITCODE -ne 0) {
                        throw "Merge step failed."
                    }

                    $shouldCleanup = if ($PSBoundParameters.ContainsKey("CleanupAfterMerge")) { [bool]$CleanupAfterMerge } else { $true }
                    if ($shouldCleanup) {
                        & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode cleanup -RepoRoot $resolvedRepoRoot -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -Force:$Force
                        if ($LASTEXITCODE -ne 0) {
                            throw "Cleanup step failed."
                        }
                    }
                }
                "cleanup" {
                    & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode cleanup -RepoRoot $resolvedRepoRoot -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -Force:$Force
                    if ($LASTEXITCODE -ne 0) {
                        throw "Cleanup step failed."
                    }
                }
                "stop" {
                    throw $disposition.Reason
                }
                default {
                    $contractPath = Resolve-ExistingPath -Path $state.active_lane.contract_path
                    $workerContract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json -Depth 100
                    $execution = Resolve-WorkerExecutionResult -Execution (Invoke-WorkerLaneExecution `
                        -PowerShellExecutable $powerShellExecutable `
                        -RunnerScriptPath $resolvedRunnerScriptPath `
                        -MissionPromptFile $resolvedMissionPromptFile `
                        -WorkerContract $workerContract `
                        -GitExecutable $gitExecutable `
                        -CodexCommand $CodexCommand `
                        -Sandbox $Sandbox `
                        -WorkerModel $WorkerModel `
                        -WorkerReasoningEffort $WorkerReasoningEffort `
                        -WorkerMaxIterations $WorkerMaxIterations `
                        -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn)

                    $shouldMerge = if ($PSBoundParameters.ContainsKey("AutoMerge")) { [bool]$AutoMerge } else { $true }
                    $hasCommits = @($execution.CommitShas).Count -gt 0
                    $workerState = if ($null -ne $execution.Decision -and $execution.Decision.PSObject.Properties.Name -contains "State") { [string]$execution.Decision.State } else { "" }
                    $executionShouldMerge = $hasCommits -and ($workerState -notin @("pause_manual", "stuck"))

                    if ($executionShouldMerge -and $shouldMerge) {
                        & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode merge -RepoRoot $resolvedRepoRoot -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -TargetBranch $TargetBranch -Force:$Force
                        if ($LASTEXITCODE -ne 0) {
                            throw "Merge step failed."
                        }

                        $shouldCleanup = if ($PSBoundParameters.ContainsKey("CleanupAfterMerge")) { [bool]$CleanupAfterMerge } else { $true }
                        if ($shouldCleanup) {
                            & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode cleanup -RepoRoot $resolvedRepoRoot -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -Force:$Force
                            if ($LASTEXITCODE -ne 0) {
                                throw "Cleanup step failed."
                            }
                        }
                    }
                    elseif ($executionShouldMerge -and -not $shouldMerge) {
                        Write-Warning "Worker lane produced commits, but auto-merge is disabled."
                    }
                    elseif (-not $executionShouldMerge) {
                        Write-Warning "Worker lane was not auto-merged. Inspect the worktree and run merge or cleanup manually."
                    }
                }
            }

            break
        }

        "merge" {
            $state = Get-OrchestrationState -StatePath $statePath
            if ($null -eq $state.active_lane) {
                throw "No active worker lane is recorded."
            }

            $contractPath = Resolve-ExistingPath -Path $state.active_lane.contract_path
            $workerContract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json -Depth 100
            $currentBranch = Get-GitCurrentBranch -GitExecutable $gitExecutable -RepositoryRoot $resolvedRepoRoot

            if (-not (Test-GitClean -GitExecutable $gitExecutable -RepositoryRoot $resolvedRepoRoot) -and -not $Force) {
                throw "Repository must be clean before merging."
            }

            $workerHead = Get-GitHead -GitExecutable $gitExecutable -RepositoryRoot $workerContract.worktree_path -Ref "HEAD"
            $commitShas = @(Get-CommitRange -GitExecutable $gitExecutable -RepositoryRoot $workerContract.worktree_path -FromRef $workerContract.base_ref -ToRef $workerHead)
            if ($commitShas.Count -eq 0) {
                throw "No commits are available to cherry-pick for lane '$($workerContract.lane_id)'."
            }

            $mergeRepoRoot = $resolvedRepoRoot
            $temporaryMergeWorktreePath = ""
            try {
                if ($currentBranch -ne $workerContract.target_branch) {
                    $mergeTargetsRoot = Ensure-Directory -Path (Join-Path $resolvedStateDirectory "merge-targets")
                    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                    $temporaryMergeWorktreePath = Join-Path $mergeTargetsRoot "$($workerContract.lane_id)-target-$timestamp"
                    $mergeRepoRoot = Add-ExistingBranchWorktree -GitExecutable $gitExecutable -RepoRoot $resolvedRepoRoot -WorktreePath $temporaryMergeWorktreePath -BranchName $workerContract.target_branch
                }

                Test-LanePreflightMerge -GitExecutable $gitExecutable -RepoRoot $mergeRepoRoot -WorkerContract $workerContract -CommitShas $commitShas -StateDirectory $resolvedStateDirectory
                Complete-WorkerLaneMerge -GitExecutable $gitExecutable -RepoRoot $mergeRepoRoot -WorkerContract $workerContract -CommitShas $commitShas
            }
            finally {
                if (-not [string]::IsNullOrWhiteSpace($temporaryMergeWorktreePath)) {
                    Remove-GitWorktreeOnly -GitExecutable $gitExecutable -RepoRoot $resolvedRepoRoot -WorktreePath $temporaryMergeWorktreePath
                }
            }

            if ($workerContract.lane_id -eq "trace-metadata-reconciliation") {
                $state.pending_reconciliation_lane_ids = @()
            }
            else {
                $state.completed_lane_ids = @($state.completed_lane_ids + @($workerContract.lane_id))
                $state.pending_reconciliation_lane_ids = @($state.pending_reconciliation_lane_ids + @($workerContract.lane_id))
            }

            if ($null -eq $state.active_lane) {
                $state.active_lane = [pscustomobject]@{}
            }
            $state.active_lane | Add-Member -NotePropertyName merged -NotePropertyValue $true -Force
            $state.active_lane | Add-Member -NotePropertyName merged_at -NotePropertyValue (Get-Date).ToString("o") -Force
            Save-OrchestrationState -StatePath $statePath -StateObject $state

            Write-Host "Merged lane '$($workerContract.lane_id)' to $($workerContract.target_branch). Cleanup is still required to remove the active worktree." -ForegroundColor Green
            break
        }

        "supervise" {
            $supervisorSettings = Resolve-SupervisorSettings `
                -BoundParameters $PSBoundParameters `
                -PollIntervalSeconds $SupervisorPollIntervalSeconds `
                -MaxIdleCycles $SupervisorMaxIdleCycles `
                -MaxIdleMinutes $SupervisorMaxIdleMinutes `
                -MaxCycles $SupervisorMaxCycles `
                -UseOvernightPreset ([bool]$Overnight)

            $supervisorCycles = 0
            $idleCycles = 0
            $idleStartedAt = $null

            Write-Host "Supervisor settings:" -ForegroundColor Green
            Write-Host "  Poll interval:        $($supervisorSettings.PollIntervalSeconds)s"
            Write-Host "  Max idle cycles:      $($supervisorSettings.MaxIdleCycles)"
            Write-Host "  Max idle wall-clock:  $($supervisorSettings.MaxIdleMinutes) minutes"
            Write-Host "  Max overall cycles:   $($supervisorSettings.MaxCycles)"
            if ($supervisorSettings.UsesOvernightPreset) {
                Write-Host "  Preset:               overnight"
            }

            while ($true) {
                if ($supervisorSettings.MaxCycles -gt 0 -and $supervisorCycles -ge $supervisorSettings.MaxCycles) {
                    Write-Host "Supervisor reached the configured cycle limit of $($supervisorSettings.MaxCycles)." -ForegroundColor Yellow
                    break
                }

                $shouldStopSupervisor = $false

                $state = Get-OrchestrationState -StatePath $statePath
                if ($null -ne $state.active_lane) {
                    $pollAction = Get-SupervisorPollAction `
                        -HasActiveLane:$true `
                        -RecommendedLaneId "" `
                        -IdleCycles $idleCycles `
                        -IdleStartedAt $idleStartedAt `
                        -Now (Get-Date) `
                        -Settings $supervisorSettings

                    Write-Host $pollAction.Reason -ForegroundColor Gray
                    & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode resume -RepoRoot $resolvedRepoRoot -RunnerScriptPath $resolvedRunnerScriptPath -MissionPromptFile $resolvedMissionPromptFile -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -TargetBranch $TargetBranch -CodexCommand $CodexCommand -Sandbox $Sandbox -PlannerModel $PlannerModel -PlannerReasoningEffort $PlannerReasoningEffort -WorkerModel $WorkerModel -WorkerReasoningEffort $WorkerReasoningEffort -WorkerMaxIterations $WorkerMaxIterations -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn -AutoMerge:$AutoMerge -CleanupAfterMerge:$CleanupAfterMerge -Force:$Force
                    if ($LASTEXITCODE -ne 0) {
                        throw "Supervisor resume step failed."
                    }

                    $idleCycles = 0
                    $idleStartedAt = $null
                }
                else {
                    $catalog = Invoke-SupervisorCatalogRefresh `
                        -PowerShellExecutable $powerShellExecutable `
                        -ScriptPath $PSCommandPath `
                        -RepoRoot $resolvedRepoRoot `
                        -StateDirectory $resolvedStateDirectory `
                        -TargetBranch $TargetBranch `
                        -PlannerModel $PlannerModel `
                        -PlannerReasoningEffort $PlannerReasoningEffort `
                        -WorkerModel $WorkerModel `
                        -WorkerReasoningEffort $WorkerReasoningEffort `
                        -CatalogPath $catalogPath

                    $pollAction = Get-SupervisorPollAction `
                        -HasActiveLane:$false `
                        -RecommendedLaneId ([string]$catalog.recommended_lane_id) `
                        -IdleCycles $idleCycles `
                        -IdleStartedAt $idleStartedAt `
                        -Now (Get-Date) `
                        -Settings $supervisorSettings

                    switch ($pollAction.Action) {
                        "run" {
                            Write-Host "Supervisor starting eligible lane '$($pollAction.LaneId)'." -ForegroundColor Green
                            & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode run -RepoRoot $resolvedRepoRoot -RunnerScriptPath $resolvedRunnerScriptPath -MissionPromptFile $resolvedMissionPromptFile -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -LaneId $pollAction.LaneId -TargetBranch $TargetBranch -CodexCommand $CodexCommand -Sandbox $Sandbox -PlannerModel $PlannerModel -PlannerReasoningEffort $PlannerReasoningEffort -WorkerModel $WorkerModel -WorkerReasoningEffort $WorkerReasoningEffort -WorkerMaxIterations $WorkerMaxIterations -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn -AutoMerge:$AutoMerge -CleanupAfterMerge:$CleanupAfterMerge -Force:$Force
                            if ($LASTEXITCODE -ne 0) {
                                throw "Supervisor run step failed."
                            }

                            $idleCycles = 0
                            $idleStartedAt = $null
                        }
                        "sleep" {
                            $idleCycles = $pollAction.IdleCycles
                            $idleStartedAt = $pollAction.IdleStartedAt
                            Write-Host $pollAction.Reason -ForegroundColor Yellow
                            Start-Sleep -Seconds $supervisorSettings.PollIntervalSeconds
                        }
                        "stop_idle" {
                            Write-Host $pollAction.Reason -ForegroundColor Yellow
                            $shouldStopSupervisor = $true
                        }
                        default {
                            throw "Unexpected supervisor poll action '$($pollAction.Action)'."
                        }
                    }
                }

                if ($shouldStopSupervisor) {
                    break
                }

                $supervisorCycles++
            }

            break
        }

        "cleanup" {
            $state = Get-OrchestrationState -StatePath $statePath
            if ($null -eq $state.active_lane) {
                Write-Host "No active lane to clean up." -ForegroundColor Yellow
                break
            }

            Remove-GitWorktreeAndBranch -GitExecutable $gitExecutable -RepoRoot $resolvedRepoRoot -WorktreePath $state.active_lane.worktree_path -BranchName $state.active_lane.branch_name
            $state.active_lane = $null
            Save-OrchestrationState -StatePath $statePath -StateObject $state
            Write-Host "Removed active worker worktree and cleared orchestration state." -ForegroundColor Green
            break
        }
    }
}
catch {
    Write-Error (Get-ExceptionDetail -Exception $_.Exception)
    exit 1
}
