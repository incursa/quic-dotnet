param(
    [string]$RepoRoot = "C:\src\incursa\quic-dotnet",
    [string]$ManifestPath = "C:\src\incursa\quic-dotnet\specs\generated\quic\implementation-chunk-manifest.json",
    [string]$WorkerScriptPath = "C:\src\incursa\quic-dotnet\scripts\Run-QuicCoverageCodex.ps1",
    [string]$WorktreeRoot = "C:\src\incursa\quic-dotnet.worktrees",
    [string]$LauncherOutputRoot = "C:\src\incursa\quic-dotnet\.artifacts\codex-launches",
    [string]$GitCommand = "git",
    [string]$PowerShellCommand = "pwsh",
    [string]$CodexCommand = "codex",
    [string]$Sandbox = "workspace-write",
    [string]$Model = "gpt-5.4-mini",
    [string]$ReasoningEffort = "high",
    [string[]]$TrackIds = @(),
    [switch]$IncludeTransportCore,
    [int]$BatchTargetCount = 6,
    [int]$BatchMaxCount = 12,
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

function Resolve-CommandPath {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Candidates = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($Command)) {
        $resolved = Get-Command -Name $Command -ErrorAction SilentlyContinue
        if ($resolved -and $resolved.CommandType -eq "Application" -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    foreach ($candidate in $Candidates) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved -and $resolved.CommandType -eq "Application" -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    throw "Unable to resolve a runnable command for '$Command'."
}

function Join-PathParts {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Parts
    )

    $path = $Root
    foreach ($part in $Parts) {
        if ([string]::IsNullOrWhiteSpace($part)) {
            continue
        }

        $path = Join-Path -Path $path -ChildPath $part
    }

    return $path
}

function Get-UniqueOrderedList {
    param([Parameter(Mandatory = $true)][object[]]$Items)

    $seen = New-Object System.Collections.Generic.HashSet[string]
    $values = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Items) {
        if ($null -eq $item) {
            continue
        }

        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }

        $normalized = $text.Trim()
        if ($seen.Add($normalized)) {
            [void]$values.Add($normalized)
        }
    }

    return $values.ToArray()
}

function Convert-RfcNameToFocus {
    param([Parameter(Mandatory = $true)][string]$RfcName)

    switch -Regex ($RfcName) {
        'RFC\s*8999' { return 'RFC8999' }
        'RFC\s*9000' { return 'RFC9000 bounded clusters' }
        'RFC\s*9001' { return 'RFC9001' }
        'RFC\s*9002' { return 'RFC9002' }
        default      { return '' }
    }
}

function Get-LaneDefinitions {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$ResolvedRepoRoot,
        [Parameter(Mandatory = $true)][string]$ResolvedWorktreeRoot
    )

    $chunkById = @{}
    foreach ($chunk in @($Manifest.chunks)) {
        if ($null -eq $chunk -or [string]::IsNullOrWhiteSpace([string]$chunk.chunk_id)) {
            continue
        }

        $chunkById[[string]$chunk.chunk_id] = $chunk
    }

    $lanes = New-Object System.Collections.Generic.List[object]
    foreach ($track in @($Manifest.parallelization_plan)) {
        if ($null -eq $track -or [string]::IsNullOrWhiteSpace([string]$track.track_id)) {
            continue
        }

        $chunkIds = @($track.chunk_ids)
        if ($chunkIds.Count -eq 0) {
            continue
        }

        $chunks = New-Object System.Collections.Generic.List[object]
        foreach ($chunkId in $chunkIds) {
            if ($chunkById.ContainsKey([string]$chunkId)) {
                [void]$chunks.Add($chunkById[[string]$chunkId])
            }
        }

        if ($chunks.Count -eq 0) {
            continue
        }

        $rfcs = Get-UniqueOrderedList -Items @($chunks | ForEach-Object { $_.rfc })
        $rfcOrder = New-Object System.Collections.Generic.List[string]
        foreach ($rfc in $rfcs) {
            $focus = Convert-RfcNameToFocus -RfcName $rfc
            if (-not [string]::IsNullOrWhiteSpace($focus)) {
                [void]$rfcOrder.Add($focus)
            }
        }

        $prefixItems = New-Object System.Collections.Generic.List[string]
        foreach ($chunk in $chunks) {
            foreach ($prefix in @($chunk.requirement_id_prefixes)) {
                if ([string]::IsNullOrWhiteSpace([string]$prefix)) {
                    continue
                }

                [void]$prefixItems.Add([string]$prefix)
            }
        }

        $sectionPrefixes = Get-UniqueOrderedList -Items $prefixItems.ToArray()

        $canRunInParallel = @($chunks | Where-Object { $_.can_run_in_parallel -ne 'yes' }).Count -eq 0
        $worktreePath = Join-PathParts -Root $ResolvedWorktreeRoot -Parts ($track.worktree -split '/')
        $branchName = 'codex/' + ($track.worktree -replace '\s+', '-')

        [void]$lanes.Add([pscustomobject]@{
            TrackId               = [string]$track.track_id
            WorktreeRelativePath  = [string]$track.worktree
            WorktreePath          = $worktreePath
            BranchName            = $branchName
            ChunkIds              = @($chunkIds)
            ChunkCount            = $chunks.Count
            RfcOrder              = @($rfcOrder)
            SectionPrefixAllowList = @($sectionPrefixes)
            CanRunInParallel      = $canRunInParallel
            Rationale             = if ($track.PSObject.Properties.Name -contains 'rationale') { [string]$track.rationale } else { '' }
            RepoRoot              = $ResolvedRepoRoot
        })
    }

    return $lanes.ToArray()
}

function Select-LaneDefinitions {
    param(
        [Parameter(Mandatory = $true)][object[]]$Lanes,
        [string[]]$TrackIds = @(),
        [switch]$IncludeTransportCore
    )

    if ($null -ne $TrackIds -and $TrackIds.Count -gt 0) {
        $selected = foreach ($trackId in $TrackIds) {
            $lane = $Lanes | Where-Object { $_.TrackId -eq $trackId } | Select-Object -First 1
            if ($null -eq $lane) {
                throw "Unknown track id: $trackId"
            }

            $lane
        }

        return @($selected)
    }

    $selected = @($Lanes | Where-Object { $_.CanRunInParallel })
    if ($IncludeTransportCore) {
        $transportLane = $Lanes | Where-Object { $_.TrackId -eq 'track-transport-core' } | Select-Object -First 1
        if ($null -ne $transportLane -and -not ($selected.TrackId -contains $transportLane.TrackId)) {
            $selected += $transportLane
        }
    }

    return @($selected)
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
            Created   = $false
            Worktree  = $WorktreePath
            Branch    = $BranchName
            BaseRef   = $BaseRef
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
        & $GitExecutable -C $RepoRoot worktree add $WorktreePath $BranchName
    }
    else {
        & $GitExecutable -C $RepoRoot worktree add -b $BranchName $WorktreePath $BaseRef
    }

    if ($LASTEXITCODE -ne 0) {
        throw "git worktree add failed for $WorktreePath ($BranchName)."
    }

    return [pscustomobject]@{
        Created   = $true
        Worktree  = $WorktreePath
        Branch    = $BranchName
        BaseRef   = $BaseRef
    }
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

        if ($Value -notmatch '[\s"''`]' ) {
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

function Start-LaneProcess {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$WorkerScriptPath,
        [Parameter(Mandatory = $true)][object]$Lane,
        [Parameter(Mandatory = $true)][string]$CodexCommand,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Model,
        [Parameter(Mandatory = $true)][string]$ReasoningEffort,
        [Parameter(Mandatory = $true)][int]$BatchTargetCount,
        [Parameter(Mandatory = $true)][int]$BatchMaxCount,
        [Parameter(Mandatory = $true)][int]$MaxIterations,
        [Parameter(Mandatory = $true)][int]$NoProgressLimit,
        [Parameter(Mandatory = $true)][int]$CooldownSeconds
    )

    $laneRequirementsRoot = Join-Path -Path $Lane.WorktreePath -ChildPath "specs/requirements/quic"
    $laneTriagePath = Join-Path -Path $Lane.WorktreePath -ChildPath "specs/generated/quic/quic-requirement-coverage-triage.json"
    $laneTriageScriptPath = Join-Path -Path $Lane.WorktreePath -ChildPath "scripts/spec-trace/Generate-QuicRequirementCoverageTriage.ps1"
    $laneOutputDirectory = Join-Path -Path $Lane.WorktreePath -ChildPath "specs/codex_work/loop"

    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        $WorkerScriptPath
        '-RepoRoot'
        $Lane.WorktreePath
        '-RequirementsRoot'
        $laneRequirementsRoot
        '-TriagePath'
        $laneTriagePath
        '-TriageScriptPath'
        $laneTriageScriptPath
        '-OutputDirectory'
        $laneOutputDirectory
        '-CodexCommand'
        $CodexCommand
        '-Sandbox'
        $Sandbox
        '-Model'
        $Model
        '-ReasoningEffort'
        $ReasoningEffort
        '-RfcOrder'
    ) + @($Lane.RfcOrder) + @(
        '-SectionPrefixAllowList'
    ) + @($Lane.SectionPrefixAllowList) + @(
        '-BatchTargetCount'
        $BatchTargetCount.ToString()
        '-BatchMaxCount'
        $BatchMaxCount.ToString()
        '-MaxIterations'
        $MaxIterations.ToString()
        '-NoProgressLimit'
        $NoProgressLimit.ToString()
        '-CooldownSeconds'
        $CooldownSeconds.ToString()
    )

    $commandLine = Convert-ToQuotedCommandLine -FilePath $PowerShellExecutable -ArgumentList $argumentList
    $process = Start-Process -FilePath $PowerShellExecutable -ArgumentList $argumentList -WorkingDirectory $Lane.WorktreePath -PassThru

    return [pscustomobject]@{
        TrackId               = $Lane.TrackId
        BranchName            = $Lane.BranchName
        WorktreePath          = $Lane.WorktreePath
        OutputDirectory       = $laneOutputDirectory
        RequirementsRoot      = $laneRequirementsRoot
        TriagePath            = $laneTriagePath
        TriageScriptPath      = $laneTriageScriptPath
        CommandLine           = $commandLine
        ProcessId             = $process.Id
        StartedAt             = Get-Date
        Status                = 'Launched'
        RfcOrder              = ($Lane.RfcOrder -join ', ')
        SectionPrefixAllowList = ($Lane.SectionPrefixAllowList -join ', ')
        ChunkIds              = ($Lane.ChunkIds -join ', ')
        ChunkCount            = $Lane.ChunkCount
        Rationale             = $Lane.Rationale
    }
}

try {
    $repoRoot = Resolve-ExistingPath -Path $RepoRoot
    $manifestPath = Resolve-ExistingPath -Path $ManifestPath
    $workerScriptPath = Resolve-ExistingPath -Path $WorkerScriptPath
    $worktreeRoot = Ensure-Directory -Path $WorktreeRoot
    $launcherOutputRoot = Ensure-Directory -Path $LauncherOutputRoot
    $gitExecutable = Resolve-CommandPath -Command $GitCommand -Candidates @('git.exe', 'git')
    $pwshExecutable = Resolve-CommandPath -Command $PowerShellCommand -Candidates @('pwsh.exe', 'pwsh', 'powershell.exe')

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 100
    $allLanes = Get-LaneDefinitions -Manifest $manifest -ResolvedRepoRoot $repoRoot -ResolvedWorktreeRoot $worktreeRoot
    $selectedLanes = Select-LaneDefinitions -Lanes $allLanes -TrackIds $TrackIds -IncludeTransportCore:$IncludeTransportCore

    if ($selectedLanes.Count -eq 0) {
        throw "No lanes were selected."
    }

    $launchId = Get-Date -Format 'yyyyMMdd-HHmmss'
    $launchRoot = Ensure-Directory -Path (Join-Path -Path $launcherOutputRoot -ChildPath $launchId)
    $summaryPath = Join-Path -Path $launchRoot -ChildPath 'summary.csv'
    $jsonPath = Join-Path -Path $launchRoot -ChildPath 'summary.json'

    $baseRef = (& $gitExecutable -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($baseRef)) {
        throw "Unable to resolve base Git commit for $repoRoot."
    }

    $dirtyStatus = & $gitExecutable -C $repoRoot status --porcelain
    if (-not [string]::IsNullOrWhiteSpace($dirtyStatus)) {
        Write-Warning "Repository has uncommitted changes. The new worktrees will be created from $baseRef, not the uncommitted main-worktree state."
    }

    Write-Host "Launching QUIC coverage lanes..." -ForegroundColor Cyan
    Write-Host "Repo root: $repoRoot" -ForegroundColor Yellow
    Write-Host "Manifest:  $manifestPath" -ForegroundColor Yellow
    Write-Host "Worktrees: $worktreeRoot" -ForegroundColor Yellow
    Write-Host "Launch:    $launchRoot" -ForegroundColor Yellow

    $launchRows = New-Object System.Collections.Generic.List[object]

    foreach ($lane in $selectedLanes) {
        $laneWorktree = Ensure-GitWorktree -GitExecutable $gitExecutable -RepoRoot $repoRoot -WorktreePath $lane.WorktreePath -BranchName $lane.BranchName -BaseRef $baseRef
        $launchRecord = Start-LaneProcess `
            -PowerShellExecutable $pwshExecutable `
            -WorkerScriptPath $workerScriptPath `
            -Lane $lane `
            -CodexCommand $CodexCommand `
            -Sandbox $Sandbox `
            -Model $Model `
            -ReasoningEffort $ReasoningEffort `
            -BatchTargetCount $BatchTargetCount `
            -BatchMaxCount $BatchMaxCount `
            -MaxIterations $MaxIterations `
            -NoProgressLimit $NoProgressLimit `
            -CooldownSeconds $CooldownSeconds

        [void]$launchRows.Add([pscustomobject]@{
            TrackId               = $launchRecord.TrackId
            BranchName            = $launchRecord.BranchName
            WorktreePath          = $launchRecord.WorktreePath
            OutputDirectory       = $launchRecord.OutputDirectory
            RequirementsRoot      = $launchRecord.RequirementsRoot
            TriagePath            = $launchRecord.TriagePath
            TriageScriptPath      = $launchRecord.TriageScriptPath
            CommandLine           = $launchRecord.CommandLine
            ProcessId             = $launchRecord.ProcessId
            LaunchStatus          = $launchRecord.Status
            LaneCreated           = $laneWorktree.Created
            StartedAt             = $launchRecord.StartedAt.ToString('o')
            RfcOrder              = $launchRecord.RfcOrder
            SectionPrefixAllowList = $launchRecord.SectionPrefixAllowList
            ChunkIds              = $launchRecord.ChunkIds
            ChunkCount            = $launchRecord.ChunkCount
            Rationale             = $launchRecord.Rationale
        })

        Write-Host "Launched $($lane.TrackId) -> PID $($launchRecord.ProcessId)" -ForegroundColor Green
        Write-Host "  Branch:   $($launchRecord.BranchName)" -ForegroundColor DarkGray
        Write-Host "  Worktree: $($launchRecord.WorktreePath)" -ForegroundColor DarkGray
    }

    $launchRows | Export-Csv -LiteralPath $summaryPath -NoTypeInformation
    $launchRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding utf8

    Write-Host ""
    Write-Host "Launcher summary written to:" -ForegroundColor Green
    Write-Host "  $summaryPath"
    Write-Host "  $jsonPath"
    Write-Host ""
    Write-Host "Launch breakdown:" -ForegroundColor Green
    foreach ($row in $launchRows) {
        Write-Host "  $($row.TrackId): PID $($row.ProcessId) Branch $($row.BranchName)"
    }
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
