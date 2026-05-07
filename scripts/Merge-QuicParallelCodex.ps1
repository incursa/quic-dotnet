param(
    [string]$RepoRoot = "",

    [string]$LaneManifestPath = "",

    [string]$LaunchSummaryPath = "",

    [string]$LaunchOutputRoot = "",

    [string]$TargetBranch = "main",

    [string]$GitCommand = "git",

    [string[]]$LaneIds = @(),

    [switch]$AllowDirtyMain,

    [switch]$AllowRunningLanes,

    [switch]$SkipAutopilotMergeReadyCheck,

    [switch]$SkipMergeChecks,

    [switch]$Push,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path -Path $PSScriptRoot -ChildPath "AutopilotOrchestration.Common.ps1")

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

function Find-LatestLaunchSummary {
    param([Parameter(Mandatory = $true)][string]$LaunchOutputRoot)

    $candidates = @(
        Get-ChildItem -LiteralPath $LaunchOutputRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending
    )

    foreach ($candidate in $candidates) {
        $summary = Join-Path -Path $candidate.FullName -ChildPath "launch-summary.json"
        if (Test-Path -LiteralPath $summary) {
            return (Resolve-Path -LiteralPath $summary).Path
        }
    }

    throw "No launch-summary.json found under $LaunchOutputRoot"
}

function Get-LatestAutopilotRow {
    param([Parameter(Mandatory = $true)][string]$OutputDirectory)

    $summaryPath = Join-Path -Path $OutputDirectory -ChildPath "autopilot-summary.csv"
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        return $null
    }

    $rows = @(Import-Csv -LiteralPath $summaryPath)
    if ($rows.Count -eq 0) {
        return $null
    }

    return ($rows | Sort-Object { [int]$_.Turn } | Select-Object -Last 1)
}

function Invoke-CommandString {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$CommandText
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        Write-Host "  > $CommandText"
        $global:LASTEXITCODE = 0
        Invoke-Expression $CommandText
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: $CommandText"
        }
    }
    finally {
        Pop-Location
    }
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

    if ([string]::IsNullOrWhiteSpace($LaunchSummaryPath)) {
        if ([string]::IsNullOrWhiteSpace($LaunchOutputRoot)) {
            $LaunchOutputRoot = [string](Get-PropertyValue -Object $manifest -Name "launchOutputRoot" -Default ".artifacts/codex-parallel-launches")
        }

        $LaunchSummaryPath = Find-LatestLaunchSummary -LaunchOutputRoot (Resolve-ConfiguredPath -Path $LaunchOutputRoot -BasePath $repoRootPath)
    }

    $launchSummaryPathFull = Resolve-ExistingPath -Path $LaunchSummaryPath
    $launchSummary = Get-Content -LiteralPath $launchSummaryPathFull -Raw | ConvertFrom-Json
    $baseRef = [string](Get-PropertyValue -Object $launchSummary -Name "baseRef" -Default ([string](Get-PropertyValue -Object $manifest -Name "baseRef" -Default "origin/main")))
    $lanes = @($launchSummary.lanes)

    if ($LaneIds.Count -gt 0) {
        $wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($laneId in $LaneIds) {
            [void]$wanted.Add($laneId)
        }

        $lanes = @($lanes | Where-Object { $wanted.Contains([string]$_.LaneId) })
        if ($lanes.Count -ne $wanted.Count) {
            $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($lane in $lanes) {
                [void]$found.Add([string]$lane.LaneId)
            }

            $missing = @($wanted | Where-Object { -not $found.Contains($_) })
            throw "Unknown launched lane id(s): $($missing -join ', ')"
        }
    }

    if ($lanes.Count -eq 0) {
        throw "No lanes selected for merge."
    }

    $currentBranch = ((Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("branch", "--show-current")) -join "").Trim()
    if (-not [string]::IsNullOrWhiteSpace($TargetBranch) -and $currentBranch -ne $TargetBranch) {
        throw "Repo root is on '$currentBranch', not target branch '$TargetBranch'. Checkout the target branch first or pass -TargetBranch '$currentBranch'."
    }

    $mainStatus = @(Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("status", "--porcelain"))
    if ($mainStatus.Count -gt 0 -and -not $AllowDirtyMain) {
        throw "Repo root has uncommitted changes. Commit/stash them or rerun with -AllowDirtyMain."
    }

    $mergeRoot = Ensure-Directory -Path (Join-Path -Path $repoRootPath -ChildPath (".artifacts/codex-parallel-merges/" + (Get-Date).ToString("yyyyMMdd-HHmmss")))
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($lane in $lanes) {
        $laneId = [string]$lane.LaneId
        $branchName = [string]$lane.BranchName
        $worktreePath = [string]$lane.WorktreePath
        $outputDirectory = [string]$lane.OutputDirectory

        Write-Host ""
        Write-Host "Lane: $laneId"

        $worktreeExists = (Test-Path -LiteralPath $worktreePath) -and (Test-Path -LiteralPath (Join-Path -Path $worktreePath -ChildPath ".git"))
        if (-not $worktreeExists) {
            $results.Add([pscustomobject]@{
                LaneId = $laneId
                BranchName = $branchName
                Status = "SkippedMissingWorktree"
                Reason = "Lane worktree does not exist."
            })
            Write-Warning "  Skipped because the lane worktree does not exist: $worktreePath"
            continue
        }

        $processRunning = $false
        if ($null -ne $lane.ProcessId -and -not [string]::IsNullOrWhiteSpace([string]$lane.ProcessId)) {
            $processRunning = $null -ne (Get-Process -Id ([int]$lane.ProcessId) -ErrorAction SilentlyContinue)
        }

        if ($processRunning -and -not $AllowRunningLanes) {
            $results.Add([pscustomobject]@{
                LaneId = $laneId
                BranchName = $branchName
                Status = "SkippedRunning"
                Reason = "Lane process is still running."
            })
            Write-Warning "  Skipped because the lane process is still running."
            continue
        }

        $worktreeStatus = @(Invoke-Git -WorkingDirectory $worktreePath -Arguments @("status", "--porcelain"))
        $worktreeClean = $worktreeStatus.Count -eq 0
        if (-not $worktreeClean) {
            $results.Add([pscustomobject]@{
                LaneId = $laneId
                BranchName = $branchName
                Status = "SkippedDirtyWorktree"
                Reason = "Lane worktree has uncommitted changes."
            })
            Write-Warning "  Skipped because the lane worktree is dirty: $worktreePath"
            continue
        }

        $aheadText = ((Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("rev-list", "--count", "$baseRef..$branchName")) -join "").Trim()
        $ahead = [int]$aheadText
        if ($ahead -eq 0) {
            $results.Add([pscustomobject]@{
                LaneId = $laneId
                BranchName = $branchName
                Status = "SkippedNoCommits"
                Reason = "Lane branch has no commits beyond $baseRef."
            })
            Write-Host "  Skipped: no commits beyond $baseRef."
            continue
        }

        $latest = Get-LatestAutopilotRow -OutputDirectory $outputDirectory
        $mergeReady = $true
        $state = ""
        $commitSha = ""
        $tests = ""
        if ($null -ne $latest) {
            $state = [string]$latest.State
            $commitSha = [string]$latest.CommitSha
            $tests = [string]$latest.Tests
        }

        if (-not $SkipAutopilotMergeReadyCheck) {
            if ($null -eq $latest) {
                $mergeReady = $false
            }
            else {
                $disposition = Get-AutopilotReconciliationDisposition -State $state -CommitSha $commitSha -TestsSummary $tests -WorktreeClean $worktreeClean
                $mergeReady = [bool]$disposition.MergeReady
            }
        }

        if (-not $mergeReady) {
            $results.Add([pscustomobject]@{
                LaneId = $laneId
                BranchName = $branchName
                Status = "SkippedNotMergeReady"
                Reason = "Autopilot summary is not merge-ready. Use -SkipAutopilotMergeReadyCheck to override."
                State = $state
                CommitSha = $commitSha
                Tests = $tests
            })
            Write-Warning "  Skipped: autopilot summary is not merge-ready."
            continue
        }

        if ($DryRun) {
            $results.Add([pscustomobject]@{
                LaneId = $laneId
                BranchName = $branchName
                Status = "DryRunMergeReady"
                Reason = "Would run: git merge --no-ff $branchName"
                State = $state
                CommitSha = $commitSha
                Tests = $tests
            })
            Write-Host "  Dry run: would merge $branchName."
            continue
        }

        Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("merge", "--no-ff", $branchName, "-m", "Merge $laneId Codex lane") | Out-Null
        Write-Host "  Merged $branchName."

        $mergeCheckStatus = "Skipped"
        if (-not $SkipMergeChecks) {
            $manifestLane = @($manifest.lanes | Where-Object { [string]$_.id -eq $laneId } | Select-Object -First 1)
            $mergeChecks = @(Get-StringArray -Value (Get-PropertyValue -Object $manifestLane -Name "mergeCheckCommands" -Default @()))
            foreach ($command in $mergeChecks) {
                Invoke-CommandString -WorkingDirectory $repoRootPath -CommandText $command
            }

            $mergeCheckStatus = "Passed"
        }

        $results.Add([pscustomobject]@{
            LaneId = $laneId
            BranchName = $branchName
            Status = "Merged"
            Reason = ""
            State = $state
            CommitSha = $commitSha
            Tests = $tests
            MergeCheckStatus = $mergeCheckStatus
        })

        if ($Push) {
            Invoke-Git -WorkingDirectory $repoRootPath -Arguments @("push", "origin", $currentBranch) | Out-Null
            Write-Host "  Pushed $currentBranch."
        }
    }

    $summaryObject = [pscustomobject]@{
        generatedAt = (Get-Date).ToString("o")
        repoRoot = $repoRootPath
        targetBranch = $currentBranch
        launchSummaryPath = $launchSummaryPathFull
        dryRun = [bool]$DryRun
        results = $results.ToArray()
    }

    $jsonPath = Join-Path -Path $mergeRoot -ChildPath "merge-summary.json"
    $csvPath = Join-Path -Path $mergeRoot -ChildPath "merge-summary.csv"
    $summaryObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding utf8
    $results | Export-Csv -LiteralPath $csvPath -NoTypeInformation

    Write-Host ""
    Write-Host "Merge summary: $jsonPath"
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
