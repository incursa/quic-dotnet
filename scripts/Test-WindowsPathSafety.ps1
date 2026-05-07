<#
Checks that tracked repository paths stay friendly to normal Windows clones.

The default projected root mirrors the long Codex worktree names used by
parallel local agents and stays below the Win32 MAX_PATH checkout boundary
without requiring Git's long-path setting.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),

    [int]$MaxRelativePathLength = 125,

    [int]$MaxProjectedFullPathLength = 240,

    [string]$ProjectedCloneRoot = "C:\src\incursa\.codex-worktrees\quic-dotnet\you-are-one-of-several-parallel-codex-workers-in-00000000-000000-00000000",

    [string]$Treeish,

    [switch]$VerifyWorktree
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedRepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$WorkingDirectory = $resolvedRepoRoot
    )

    $output = & git -C $WorkingDirectory @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }

    return @($output)
}

if ([string]::IsNullOrWhiteSpace($Treeish)) {
    $trackedPaths = Invoke-Git -Arguments @("ls-files")
}
else {
    $trackedPaths = Invoke-Git -Arguments @("ls-tree", "-r", "--name-only", $Treeish)
}

if ($trackedPaths.Count -eq 0) {
    throw "No tracked paths were found under '$resolvedRepoRoot'."
}

$pathBudget = foreach ($path in $trackedPaths) {
    $projectedPath = Join-Path $ProjectedCloneRoot ($path -replace '/', '\')
    [pscustomobject]@{
        RelativeLength = $path.Length
        ProjectedFullLength = $projectedPath.Length
        Path = $path
    }
}

$relativeOffenders = @($pathBudget | Where-Object { $_.RelativeLength -gt $MaxRelativePathLength } | Sort-Object RelativeLength -Descending)
$projectedOffenders = @($pathBudget | Where-Object { $_.ProjectedFullLength -gt $MaxProjectedFullPathLength } | Sort-Object ProjectedFullLength -Descending)
$legacyBenchmarkRoots = @(
    $trackedPaths | Where-Object {
        $_ -like "artifacts/benchmark-baseline/*" -or
        $_ -match "/BenchmarkDotNet\.Artifacts(/|$)"
    }
)

if ($relativeOffenders.Count -gt 0) {
    $relativeOffenders | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    throw "Tracked relative paths exceed $MaxRelativePathLength characters."
}

if ($projectedOffenders.Count -gt 0) {
    $projectedOffenders | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    throw "Projected Windows paths exceed $MaxProjectedFullPathLength characters for '$ProjectedCloneRoot'."
}

if ($legacyBenchmarkRoots.Count -gt 0) {
    $legacyBenchmarkRoots | Sort-Object | Select-Object -First 20 | Out-String -Width 4096 | Write-Host
    throw "Tracked benchmark evidence must use artifacts/bb and bdn instead of long legacy roots."
}

$maxRelativePath = ($pathBudget | Sort-Object RelativeLength -Descending | Select-Object -First 1).RelativeLength
$maxProjectedPath = ($pathBudget | Sort-Object ProjectedFullLength -Descending | Select-Object -First 1).ProjectedFullLength
Write-Host "Tracked path check passed: $($trackedPaths.Count) paths; max relative length $maxRelativePath; max projected full length $maxProjectedPath."

if ($VerifyWorktree) {
    $checkoutTarget = if ([string]::IsNullOrWhiteSpace($Treeish)) { "HEAD" } else { $Treeish }
    $worktreeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("qpc-" + [guid]::NewGuid().ToString("N").Substring(0, 8))

    try {
        Invoke-Git -Arguments @("worktree", "add", "--detach", $worktreeRoot, $checkoutTarget) | Out-Null
        Invoke-Git -WorkingDirectory $worktreeRoot -Arguments @("status", "--short") | Out-Null
        Write-Host "Worktree checkout passed: $worktreeRoot"
    }
    finally {
        if (Test-Path -LiteralPath $worktreeRoot) {
            Invoke-Git -Arguments @("worktree", "remove", "--force", $worktreeRoot) | Out-Null
        }
    }
}
