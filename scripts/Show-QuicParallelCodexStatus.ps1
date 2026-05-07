[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$RepoRoot = "",

    [string]$LaunchSummaryPath = "",

    [string]$LaunchOutputRoot = "",

    [string]$GitCommand = "git",

    [string[]]$LaneIds = @(),

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingLaneIds = @()
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

function Invoke-GitOrEmpty {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    try {
        $output = & $GitCommand -C $WorkingDirectory @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            return @()
        }

        return @($output)
    }
    catch {
        return @()
    }
}

function Get-NormalizedLaneIds {
    param([AllowNull()][string[]]$Items = @())

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Items)) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            continue
        }

        foreach ($part in ([string]$item -split ",")) {
            $trimmed = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                [void]$result.Add($trimmed)
            }
        }
    }

    return $result.ToArray()
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

function Get-StartupErrorSummary {
    param([Parameter(Mandatory = $true)][string]$LauncherStderr)

    if ([string]::IsNullOrWhiteSpace($LauncherStderr) -or -not (Test-Path -LiteralPath $LauncherStderr)) {
        return ""
    }

    $content = Get-Content -LiteralPath $LauncherStderr -Raw
    if ([string]::IsNullOrWhiteSpace($content)) {
        return ""
    }

    $summary = ($content -replace '\s+', ' ').Trim()
    if ($summary.Length -gt 180) {
        return $summary.Substring(0, 177) + "..."
    }

    return $summary
}

try {
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = Join-Path -Path $PSScriptRoot -ChildPath ".."
    }

    $repoRootPath = Resolve-ExistingPath -Path $RepoRoot

    if ([string]::IsNullOrWhiteSpace($LaunchSummaryPath)) {
        if ([string]::IsNullOrWhiteSpace($LaunchOutputRoot)) {
            $LaunchOutputRoot = Join-Path -Path $repoRootPath -ChildPath ".artifacts/codex-parallel-launches"
        }

        $LaunchSummaryPath = Find-LatestLaunchSummary -LaunchOutputRoot (Resolve-ConfiguredPath -Path $LaunchOutputRoot -BasePath $repoRootPath)
    }

    $summaryPath = Resolve-ExistingPath -Path $LaunchSummaryPath
    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $lanes = @($summary.lanes)

    $selectedLaneIds = @(Get-NormalizedLaneIds -Items (@($LaneIds) + @($RemainingLaneIds)))
    if ($selectedLaneIds.Count -gt 0) {
        $wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($laneId in $selectedLaneIds) {
            [void]$wanted.Add($laneId)
        }

        $lanes = @($lanes | Where-Object { $wanted.Contains([string]$_.LaneId) })
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($lane in $lanes) {
        $pidText = ""
        $processState = "NotStarted"
        if ($null -ne $lane.ProcessId -and -not [string]::IsNullOrWhiteSpace([string]$lane.ProcessId)) {
            $pidText = [string]$lane.ProcessId
            $process = Get-Process -Id ([int]$lane.ProcessId) -ErrorAction SilentlyContinue
            $processState = if ($null -eq $process) { "Exited" } else { "Running" }
        }

        $worktreePath = [string]$lane.WorktreePath
        $worktreeExists = (Test-Path -LiteralPath $worktreePath) -and (Test-Path -LiteralPath (Join-Path -Path $worktreePath -ChildPath ".git"))
        $worktreeClean = "missing"
        $ahead = "?"
        if ($worktreeExists) {
            $gitStatus = @(Invoke-GitOrEmpty -WorkingDirectory $worktreePath -Arguments @("status", "--porcelain"))
            $worktreeClean = if ($gitStatus.Count -eq 0) { "clean" } else { "dirty" }
            $ahead = ((Invoke-GitOrEmpty -WorkingDirectory $worktreePath -Arguments @("rev-list", "--count", "$($lane.BaseRef)..HEAD")) -join "").Trim()
            if ([string]::IsNullOrWhiteSpace($ahead)) {
                $ahead = "?"
            }
        }

        $latest = Get-LatestAutopilotRow -OutputDirectory ([string]$lane.OutputDirectory)
        $state = ""
        $reconcile = ""
        $commit = ""
        $tests = ""
        $details = ""
        if ($null -ne $latest) {
            $state = [string]$latest.State
            $reconcile = [string]$latest.ReconcileAction
            $commit = [string]$latest.CommitSha
            $tests = [string]$latest.Tests
        }
        elseif ($processState -eq "Exited") {
            $details = Get-StartupErrorSummary -LauncherStderr ([string]$lane.LauncherStderr)
            if (-not [string]::IsNullOrWhiteSpace($details)) {
                $state = "startup_error"
            }
        }

        $rows.Add([pscustomobject]@{
            Lane = [string]$lane.LaneId
            Process = $processState
            Pid = $pidText
            Branch = [string]$lane.BranchName
            Ahead = $ahead
            Worktree = $worktreeClean
            State = $state
            Reconcile = $reconcile
            Commit = $commit
            Details = $details
            Tests = $tests
            OutputDirectory = [string]$lane.OutputDirectory
        })
    }

    Write-Host "Launch summary: $summaryPath"
    Write-Host ""
    $rows | Format-Table -AutoSize

    $startupErrors = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Details) })
    if ($startupErrors.Count -gt 0) {
        Write-Host ""
        Write-Host "Startup errors:"
        foreach ($row in $startupErrors) {
            Write-Host "  $($row.Lane): $($row.Details)"
        }
    }
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
