param(
    [ValidateSet("plan", "prepare", "run", "resume", "merge", "cleanup", "supervise")]
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
            lane_id = "trace-metadata-reconciliation"
            objective = "Reconcile xrefs, generated summaries, and proof metadata only after a semantic merge has landed."
            priority = 13
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

    & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $bootstrapScriptPath
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
                    $execution = Invoke-WorkerLaneExecution `
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
                        -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn

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
            $supervisorCycles = 0

            while ($true) {
                if ($SupervisorMaxCycles -gt 0 -and $supervisorCycles -ge $SupervisorMaxCycles) {
                    Write-Host "Supervisor reached the configured cycle limit of $SupervisorMaxCycles." -ForegroundColor Yellow
                    break
                }

                $state = Get-OrchestrationState -StatePath $statePath
                if ($null -ne $state.active_lane) {
                    & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode resume -RepoRoot $resolvedRepoRoot -RunnerScriptPath $resolvedRunnerScriptPath -MissionPromptFile $resolvedMissionPromptFile -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -TargetBranch $TargetBranch -CodexCommand $CodexCommand -Sandbox $Sandbox -PlannerModel $PlannerModel -PlannerReasoningEffort $PlannerReasoningEffort -WorkerModel $WorkerModel -WorkerReasoningEffort $WorkerReasoningEffort -WorkerMaxIterations $WorkerMaxIterations -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn -AutoMerge:$AutoMerge -CleanupAfterMerge:$CleanupAfterMerge -Force:$Force
                    if ($LASTEXITCODE -ne 0) {
                        throw "Supervisor resume step failed."
                    }
                }
                else {
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
                    if ([string]::IsNullOrWhiteSpace($catalog.recommended_lane_id)) {
                        Write-Host "Supervisor found no eligible lane remaining." -ForegroundColor Green
                        break
                    }

                    & $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Mode run -RepoRoot $resolvedRepoRoot -RunnerScriptPath $resolvedRunnerScriptPath -MissionPromptFile $resolvedMissionPromptFile -WorktreeRoot $resolvedWorktreeRoot -StateDirectory $resolvedStateDirectory -LaneId $catalog.recommended_lane_id -TargetBranch $TargetBranch -CodexCommand $CodexCommand -Sandbox $Sandbox -PlannerModel $PlannerModel -PlannerReasoningEffort $PlannerReasoningEffort -WorkerModel $WorkerModel -WorkerReasoningEffort $WorkerReasoningEffort -WorkerMaxIterations $WorkerMaxIterations -WorkerMaxRescueAttemptsPerTurn $WorkerMaxRescueAttemptsPerTurn -AutoMerge:$AutoMerge -CleanupAfterMerge:$CleanupAfterMerge -Force:$Force
                    if ($LASTEXITCODE -ne 0) {
                        throw "Supervisor run step failed."
                    }
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
