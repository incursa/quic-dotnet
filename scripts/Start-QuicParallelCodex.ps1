param(
    [string]$RepoRoot = "",

    [string]$LaneManifestPath = "",

    [string]$WorktreeRoot = "",

    [string]$LaunchOutputRoot = "",

    [string]$WorkerScriptPath = "",

    [string]$BaseRef = "",

    [string]$GitCommand = "git",

    [string]$PowerShellExecutable = "pwsh",

    [string]$CodexCommand = "codex",

    [string]$Sandbox = "danger-full-access",

    [string]$Model = "gpt-5.4-mini",

    [string]$ReasoningEffort = "xhigh",

    [int]$MaxIterations = 8,

    [string[]]$LaneIds = @(),

    [switch]$AllowDirtyMain,

    [switch]$AllowDirtyWorktrees,

    [switch]$AllowMultipleRuntimeLanes,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsWindows {
    return $env:OS -eq "Windows_NT"
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-ExistingPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path $BasePath -ChildPath $Path))
}

function Get-PropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $Object) {
        return $Default
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return $property.Value
}

function Get-StringArray {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return @()
        }

        return @($Value)
    }

    return @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = & $GitCommand -C $WorkingDirectory @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $text = ($output | Out-String).Trim()
        throw "git $($Arguments -join ' ') failed in $WorkingDirectory with exit code $exitCode. $text"
    }

    return @($output)
}

function Test-GitRefExists {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RefName
    )

    & $GitCommand -C $RepoRoot show-ref --verify --quiet "refs/heads/$RefName"
    return $LASTEXITCODE -eq 0
}

function Test-GitWorktreeExists {
    param([Parameter(Mandatory = $true)][string]$WorktreePath)

    if (-not (Test-Path -LiteralPath $WorktreePath)) {
        return $false
    }

    return Test-Path -LiteralPath (Join-Path -Path $WorktreePath -ChildPath ".git")
}

function Convert-ToQuotedCommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )

    function Quote-Value {
        param([AllowEmptyString()][string]$Value)

        if ([string]::IsNullOrWhiteSpace($Value)) {
            return "''"
        }

        if ($Value -notmatch '[\s"''`]') {
            return $Value
        }

        return "'" + ($Value -replace "'", "''") + "'"
    }

    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add((Quote-Value -Value $FilePath))
    foreach ($argument in $ArgumentList) {
        [void]$parts.Add((Quote-Value -Value $argument))
    }

    return ($parts -join ' ')
}

function Ensure-GitWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [Parameter(Mandatory = $true)][string]$BranchName,
        [Parameter(Mandatory = $true)][string]$BaseRef
    )

    if (Test-GitWorktreeExists -WorktreePath $WorktreePath) {
        $currentBranch = ((Invoke-Git -WorkingDirectory $WorktreePath -Arguments @("branch", "--show-current")) -join "").Trim()
        if ($currentBranch -ne $BranchName) {
            throw "Existing worktree $WorktreePath is on branch '$currentBranch', expected '$BranchName'."
        }

        return [pscustomobject]@{
            Created  = $false
            Worktree = $WorktreePath
            Branch   = $BranchName
            BaseRef  = $BaseRef
        }
    }

    if (Test-Path -LiteralPath $WorktreePath) {
        throw "Path exists but is not a git worktree: $WorktreePath"
    }

    $parent = Split-Path -Path $WorktreePath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Ensure-Directory -Path $parent | Out-Null
    }

    if (Test-GitRefExists -RepoRoot $RepoRoot -RefName $BranchName) {
        Invoke-Git -WorkingDirectory $RepoRoot -Arguments @("worktree", "add", $WorktreePath, $BranchName) | Out-Null
    }
    else {
        Invoke-Git -WorkingDirectory $RepoRoot -Arguments @("worktree", "add", "-b", $BranchName, $WorktreePath, $BaseRef) | Out-Null
    }

    return [pscustomobject]@{
        Created  = $true
        Worktree = $WorktreePath
        Branch   = $BranchName
        BaseRef  = $BaseRef
    }
}

function Add-Argument {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$List,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowEmptyString()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }

    [void]$List.Add($Name)
    [void]$List.Add($Value)
}

function Add-ArrayArgument {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$List,
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$Values
    )

    $items = @(Get-StringArray -Value $Values)
    if ($items.Count -eq 0) {
        return
    }

    [void]$List.Add($Name)
    foreach ($item in $items) {
        [void]$List.Add($item)
    }
}

function Convert-LanePrompt {
    param(
        [Parameter(Mandatory = $true)][object]$Lane,
        [Parameter(Mandatory = $true)][string]$PromptPath,
        [Parameter(Mandatory = $true)][string]$EffectivePromptPath,
        [Parameter(Mandatory = $true)][string]$BranchName,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [Parameter(Mandatory = $true)][string]$BaseRef
    )

    $basePrompt = Get-Content -LiteralPath $PromptPath -Raw
    $allowed = @(Get-StringArray -Value (Get-PropertyValue -Object $Lane -Name "allowedPathPrefixes" -Default @()))
    $forbidden = @(Get-StringArray -Value (Get-PropertyValue -Object $Lane -Name "forbiddenPathPrefixes" -Default @()))
    $verification = @(Get-StringArray -Value (Get-PropertyValue -Object $Lane -Name "verificationCommands" -Default @()))
    $mergeChecks = @(Get-StringArray -Value (Get-PropertyValue -Object $Lane -Name "mergeCheckCommands" -Default @()))
    $targetScope = [string](Get-PropertyValue -Object $Lane -Name "targetScope" -Default "")

    function Format-List {
        param([string[]]$Items)

        if ($Items.Count -eq 0) {
            return "- (none)"
        }

        return (($Items | ForEach-Object { "- $_" }) -join [Environment]::NewLine)
    }

    $contract = @"

## Generated Parallel Lane Contract

Lane id: $($Lane.id)
Branch: $BranchName
Worktree: $WorktreePath
Base ref: $BaseRef
Target scope: $targetScope

Allowed path prefixes:
$(Format-List -Items $allowed)

Forbidden path prefixes:
$(Format-List -Items $forbidden)

Verification commands:
$(Format-List -Items $verification)

Merge check commands:
$(Format-List -Items $mergeChecks)

Parallel coordination rules:
- You are not alone in this repository. Other Codex workers may be editing other worktrees and branches.
- Stay inside the allowed path prefixes. If a requirement forces a change outside the lane, stop and report the exact blocked requirement and file path.
- Do not revert or rewrite unrelated work.
- Keep the slice reviewable and independently mergeable.
- Run the lane verification commands before finishing when practical.
- Leave a local commit for useful completed or partial work.
"@

    $parent = Split-Path -Path $EffectivePromptPath -Parent
    Ensure-Directory -Path $parent | Out-Null
    [System.IO.File]::WriteAllText($EffectivePromptPath, ($basePrompt.TrimEnd() + $contract), [System.Text.UTF8Encoding]::new($false))
}

function Convert-ToPowerShellSingleQuotedString {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) {
        $Value = ""
    }

    return "'" + ($Value -replace "'", "''") + "'"
}

function Convert-ToPowerShellArrayLiteral {
    param([AllowNull()][object]$Value)

    $items = @(Get-StringArray -Value $Value)
    if ($items.Count -eq 0) {
        return "@()"
    }

    return "@(" + (($items | ForEach-Object { Convert-ToPowerShellSingleQuotedString -Value $_ }) -join ", ") + ")"
}

function Write-LaneRunnerScript {
    param(
        [Parameter(Mandatory = $true)][object]$Lane,
        [Parameter(Mandatory = $true)][string]$RunnerScriptPath,
        [Parameter(Mandatory = $true)][string]$WorkerScriptPath,
        [Parameter(Mandatory = $true)][string]$WorktreePath,
        [Parameter(Mandatory = $true)][string]$EffectivePromptPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$CodexCommand,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Model,
        [Parameter(Mandatory = $true)][string]$ReasoningEffort,
        [Parameter(Mandatory = $true)][int]$MaxIterations
    )

    $laneId = [string]$Lane.id
    $targetScope = [string](Get-PropertyValue -Object $Lane -Name "targetScope" -Default "")
    $allowed = Convert-ToPowerShellArrayLiteral -Value (Get-PropertyValue -Object $Lane -Name "allowedPathPrefixes" -Default @())
    $forbidden = Convert-ToPowerShellArrayLiteral -Value (Get-PropertyValue -Object $Lane -Name "forbiddenPathPrefixes" -Default @())
    $requirementFamilies = Convert-ToPowerShellArrayLiteral -Value (Get-PropertyValue -Object $Lane -Name "requirementFamilies" -Default @())
    $blockingGaps = Convert-ToPowerShellArrayLiteral -Value (Get-PropertyValue -Object $Lane -Name "blockingGapIds" -Default @())
    $verification = Convert-ToPowerShellArrayLiteral -Value (Get-PropertyValue -Object $Lane -Name "verificationCommands" -Default @())
    $mergeChecks = Convert-ToPowerShellArrayLiteral -Value (Get-PropertyValue -Object $Lane -Name "mergeCheckCommands" -Default @())

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add("Set-StrictMode -Version Latest")
    [void]$lines.Add('$ErrorActionPreference = "Stop"')
    [void]$lines.Add("")
    [void]$lines.Add('$parameters = @{')
    [void]$lines.Add("    WorkingDirectory = $(Convert-ToPowerShellSingleQuotedString -Value $WorktreePath)")
    [void]$lines.Add("    InitialPromptFile = $(Convert-ToPowerShellSingleQuotedString -Value $EffectivePromptPath)")
    [void]$lines.Add("    OutputDirectory = $(Convert-ToPowerShellSingleQuotedString -Value $OutputDirectory)")
    [void]$lines.Add("    CodexCommand = $(Convert-ToPowerShellSingleQuotedString -Value $CodexCommand)")
    [void]$lines.Add("    Sandbox = $(Convert-ToPowerShellSingleQuotedString -Value $Sandbox)")
    [void]$lines.Add("    Model = $(Convert-ToPowerShellSingleQuotedString -Value $Model)")
    [void]$lines.Add("    ReasoningEffort = $(Convert-ToPowerShellSingleQuotedString -Value $ReasoningEffort)")
    [void]$lines.Add("    MaxIterations = $MaxIterations")
    [void]$lines.Add("    TargetLaneId = $(Convert-ToPowerShellSingleQuotedString -Value $laneId)")
    [void]$lines.Add("    TargetScope = $(Convert-ToPowerShellSingleQuotedString -Value $targetScope)")
    [void]$lines.Add("    AllowedPathPrefixes = $allowed")
    [void]$lines.Add("    ForbiddenPathPrefixes = $forbidden")
    [void]$lines.Add("    RequirementFamilies = $requirementFamilies")
    [void]$lines.Add("    BlockingGapIds = $blockingGaps")
    [void]$lines.Add("    VerificationCommands = $verification")
    [void]$lines.Add("    MergeCheckCommands = $mergeChecks")
    [void]$lines.Add("}")
    [void]$lines.Add("")
    [void]$lines.Add("& $(Convert-ToPowerShellSingleQuotedString -Value $WorkerScriptPath) @parameters -AutoCommitIfDirty -StopOnPathViolation")
    [void]$lines.Add("if (-not `$?) { exit 1 }")

    [System.IO.File]::WriteAllText($RunnerScriptPath, ($lines -join [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
}

try {
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = Join-Path -Path $PSScriptRoot -ChildPath ".."
    }

    if ([string]::IsNullOrWhiteSpace($LaneManifestPath)) {
        $LaneManifestPath = Join-Path -Path $PSScriptRoot -ChildPath "parallel-codex/quic-parallel-lanes.json"
    }

    $repoRootPath = Resolve-ExistingPath -Path $RepoRoot
    $manifestPath = Resolve-ExistingPath -Path $LaneManifestPath
    $manifestRoot = Split-Path -Path $manifestPath -Parent
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    if ([string]::IsNullOrWhiteSpace($BaseRef)) {
        $BaseRef = [string](Get-PropertyValue -Object $manifest -Name "baseRef" -Default "origin/main")
    }

    if ([string]::IsNullOrWhiteSpace($WorktreeRoot)) {
        $WorktreeRoot = [string](Get-PropertyValue -Object $manifest -Name "worktreeRoot" -Default "C:/src/incursa/quic-dotnet.worktrees")
    }

    if ([string]::IsNullOrWhiteSpace($LaunchOutputRoot)) {
        $LaunchOutputRoot = [string](Get-PropertyValue -Object $manifest -Name "launchOutputRoot" -Default ".artifacts/codex-parallel-launches")
    }

    if ([string]::IsNullOrWhiteSpace($WorkerScriptPath)) {
        $WorkerScriptPath = [string](Get-PropertyValue -Object $manifest -Name "workerScript" -Default "scripts/Run-CodexAutopilot.ps1")
    }

    $worktreeRootPath = Resolve-ConfiguredPath -Path $WorktreeRoot -BasePath $repoRootPath
    $launchOutputBasePath = Resolve-ConfiguredPath -Path $LaunchOutputRoot -BasePath $repoRootPath
    $workerScriptFullPath = Resolve-ExistingPath -Path (Resolve-ConfiguredPath -Path $WorkerScriptPath -BasePath $repoRootPath)
    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $launchRoot = Ensure-Directory -Path (Join-Path -Path $launchOutputBasePath -ChildPath $timestamp)

    Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("rev-parse", "--verify", "$BaseRef^{commit}") | Out-Null

    $mainStatus = @(Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("status", "--porcelain"))
    if ($mainStatus.Count -gt 0 -and -not $AllowDirtyMain) {
        throw "Repo root has uncommitted changes. Commit/stash them or rerun with -AllowDirtyMain."
    }

    $lanes = @($manifest.lanes)
    if ($lanes.Count -eq 0) {
        throw "Manifest has no lanes: $manifestPath"
    }

    if ($LaneIds.Count -gt 0) {
        $wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($laneId in $LaneIds) {
            [void]$wanted.Add($laneId)
        }

        $lanes = @($lanes | Where-Object { $wanted.Contains([string]$_.id) })
        if ($lanes.Count -ne $wanted.Count) {
            $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($lane in $lanes) {
                [void]$found.Add([string]$lane.id)
            }

            $missing = @($wanted | Where-Object { -not $found.Contains($_) })
            throw "Unknown lane id(s): $($missing -join ', ')"
        }
    }
    else {
        $lanes = @($lanes | Where-Object {
            [bool](Get-PropertyValue -Object $_ -Name "enabled" -Default $true) -and
            [bool](Get-PropertyValue -Object $_ -Name "launchByDefault" -Default $false)
        })
    }

    $disabled = @($lanes | Where-Object { -not [bool](Get-PropertyValue -Object $_ -Name "enabled" -Default $true) })
    if ($disabled.Count -gt 0) {
        throw "Selected disabled lane(s): $((@($disabled | ForEach-Object { $_.id })) -join ', ')"
    }

    $runtimeLanes = @($lanes | Where-Object { [bool](Get-PropertyValue -Object $_ -Name "runtimeExclusive" -Default $false) })
    if ($runtimeLanes.Count -gt 1 -and -not $AllowMultipleRuntimeLanes) {
        throw "Selected more than one runtime-exclusive lane: $((@($runtimeLanes | ForEach-Object { $_.id })) -join ', '). Rerun with -AllowMultipleRuntimeLanes only if you accept merge conflict risk."
    }

    if ($lanes.Count -eq 0) {
        throw "No lanes selected."
    }

    $records = New-Object System.Collections.Generic.List[object]

    foreach ($lane in $lanes) {
        $laneId = [string]$lane.id
        $branchName = [string](Get-PropertyValue -Object $lane -Name "branch" -Default "codex/quic-$laneId")
        $worktreeName = [string](Get-PropertyValue -Object $lane -Name "worktree" -Default $laneId)
        $worktreePath = Resolve-ConfiguredPath -Path $worktreeName -BasePath $worktreeRootPath
        $promptRelativePath = [string](Get-PropertyValue -Object $lane -Name "prompt" -Default "")
        if ([string]::IsNullOrWhiteSpace($promptRelativePath)) {
            throw "Lane '$laneId' does not define a prompt path."
        }

        $promptPath = Resolve-ExistingPath -Path (Resolve-ConfiguredPath -Path $promptRelativePath -BasePath $manifestRoot)
        $laneLaunchRoot = Ensure-Directory -Path (Join-Path -Path $launchRoot -ChildPath ("lanes/" + $laneId))
        $effectivePromptPath = Join-Path -Path $laneLaunchRoot -ChildPath "prompt.md"
        $runnerScriptPath = Join-Path -Path $laneLaunchRoot -ChildPath "run-lane.ps1"
        $launcherStdout = Join-Path -Path $laneLaunchRoot -ChildPath "launcher.stdout.log"
        $launcherStderr = Join-Path -Path $laneLaunchRoot -ChildPath "launcher.stderr.log"

        if (-not $DryRun) {
            Ensure-GitWorktree -RepoRoot $repoRootPath -WorktreePath $worktreePath -BranchName $branchName -BaseRef $BaseRef | Out-Null
            $worktreeStatus = @(Invoke-Git -WorkingDirectory $worktreePath -Arguments @("status", "--porcelain"))
            if ($worktreeStatus.Count -gt 0 -and -not $AllowDirtyWorktrees) {
                throw "Lane '$laneId' worktree has uncommitted changes: $worktreePath"
            }

            Convert-LanePrompt -Lane $lane -PromptPath $promptPath -EffectivePromptPath $effectivePromptPath -BranchName $branchName -WorktreePath $worktreePath -BaseRef $BaseRef
            Write-LaneRunnerScript -Lane $lane -RunnerScriptPath $runnerScriptPath -WorkerScriptPath $workerScriptFullPath -WorktreePath $worktreePath -EffectivePromptPath $effectivePromptPath -OutputDirectory $laneLaunchRoot -CodexCommand $CodexCommand -Sandbox $Sandbox -Model $Model -ReasoningEffort $ReasoningEffort -MaxIterations $MaxIterations
        }

        $arguments = New-Object System.Collections.Generic.List[string]
        foreach ($arg in @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $runnerScriptPath)) {
            [void]$arguments.Add($arg)
        }

        $commandLine = Convert-ToQuotedCommandLine -FilePath $PowerShellExecutable -ArgumentList $arguments.ToArray()
        $processId = $null
        $status = "DryRun"

        if (-not $DryRun) {
            $startParameters = @{
                FilePath = $PowerShellExecutable
                ArgumentList = $arguments.ToArray()
                WorkingDirectory = $worktreePath
                RedirectStandardOutput = $launcherStdout
                RedirectStandardError = $launcherStderr
                PassThru = $true
            }

            if (Test-IsWindows) {
                $startParameters["WindowStyle"] = "Hidden"
            }

            $process = Start-Process @startParameters
            $processId = $process.Id
            $status = "Launched"
        }

        $records.Add([pscustomobject]@{
            LaneId = $laneId
            BranchName = $branchName
            WorktreePath = $worktreePath
            RuntimeExclusive = [bool](Get-PropertyValue -Object $lane -Name "runtimeExclusive" -Default $false)
            BaseRef = $BaseRef
            PromptPath = $promptPath
            EffectivePromptPath = $effectivePromptPath
            RunnerScriptPath = $runnerScriptPath
            OutputDirectory = $laneLaunchRoot
            LauncherStdout = $launcherStdout
            LauncherStderr = $launcherStderr
            CommandLine = $commandLine
            ProcessId = $processId
            Status = $status
            StartedAt = if ($DryRun) { "" } else { (Get-Date).ToString("o") }
        })

        Write-Host "$status lane '$laneId' on branch '$branchName'"
        Write-Host "  Worktree: $worktreePath"
        Write-Host "  Output:   $laneLaunchRoot"
        if ($null -ne $processId) {
            Write-Host "  PID:      $processId"
        }
    }

    $summary = [pscustomobject]@{
        generatedAt = (Get-Date).ToString("o")
        repoRoot = $repoRootPath
        manifestPath = $manifestPath
        launchRoot = $launchRoot
        baseRef = $BaseRef
        workerScript = $workerScriptFullPath
        model = $Model
        reasoningEffort = $ReasoningEffort
        sandbox = $Sandbox
        maxIterations = $MaxIterations
        dryRun = [bool]$DryRun
        lanes = $records.ToArray()
    }

    $jsonPath = Join-Path -Path $launchRoot -ChildPath "launch-summary.json"
    $csvPath = Join-Path -Path $launchRoot -ChildPath "launch-summary.csv"
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding utf8
    $records | Export-Csv -LiteralPath $csvPath -NoTypeInformation

    Write-Host ""
    Write-Host "Launch summary: $jsonPath"
    Write-Host "Status command: pwsh -NoProfile -File scripts/Show-QuicParallelCodexStatus.ps1 -LaunchSummaryPath '$jsonPath'"
    Write-Host "Merge command:  pwsh -NoProfile -File scripts/Merge-QuicParallelCodex.ps1 -LaunchSummaryPath '$jsonPath'"
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
