[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int] $ProcessId,
    [int] $DurationSeconds = 15,
    [ValidateSet("cpu", "gc-allocation", "exception")]
    [string] $Mode = "cpu",
    [string] $ArtifactRoot,
    [string] $TraceTool = "dotnet-trace",
    [int] $TopN = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-DefaultArtifactRoot {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    Join-Path $repoRoot ".artifacts/perf/incursa-h3-p2/$stamp"
}

function Format-CommandLine([string] $FileName, [string[]] $Arguments) {
    $escaped = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argument
        }
    }

    "$FileName $($escaped -join ' ')"
}

function Invoke-ToolCapture([string] $FileName, [string[]] $Arguments, [string] $WorkingDirectory) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new($FileName)
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process) {
        throw "Failed to start $FileName."
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdoutTask.GetAwaiter().GetResult()
        Stderr = $stderrTask.GetAwaiter().GetResult()
    }
}

function Resolve-TraceCommand([string] $Tool, [string] $WorkingDirectory) {
    if (([IO.Path]::IsPathFullyQualified($Tool) -or $Tool.Contains([IO.Path]::DirectorySeparatorChar) -or $Tool.Contains([IO.Path]::AltDirectorySeparatorChar)) -and
        (Test-Path -LiteralPath $Tool)) {
        $version = Invoke-ToolCapture $Tool @("--version") $WorkingDirectory
        if ($version.ExitCode -eq 0) {
            return [pscustomobject]@{
                FileName = (Resolve-Path -LiteralPath $Tool).Path
                PrefixArguments = @()
                Source = "explicit"
                Version = ($version.Stdout + $version.Stderr).Trim()
            }
        }
    }

    $localVersion = Invoke-ToolCapture "dotnet" @("tool", "run", $Tool, "--", "--version") $WorkingDirectory
    if ($localVersion.ExitCode -eq 0) {
        return [pscustomobject]@{
            FileName = "dotnet"
            PrefixArguments = @("tool", "run", $Tool, "--")
            Source = "local-tool-manifest"
            Version = ($localVersion.Stdout + $localVersion.Stderr).Trim()
        }
    }

    $command = Get-Command $Tool -ErrorAction SilentlyContinue
    if ($command) {
        $pathVersion = Invoke-ToolCapture $command.Source @("--version") $WorkingDirectory
        if ($pathVersion.ExitCode -eq 0) {
            return [pscustomobject]@{
                FileName = $command.Source
                PrefixArguments = @()
                Source = "PATH"
                Version = ($pathVersion.Stdout + $pathVersion.Stderr).Trim()
            }
        }
    }

    return $null
}

function Get-TraceProfiles($TraceCommand, [string] $WorkingDirectory) {
    $result = Invoke-ToolCapture $TraceCommand.FileName (@($TraceCommand.PrefixArguments) + @("list-profiles")) $WorkingDirectory
    if ($result.ExitCode -ne 0) {
        return [pscustomobject]@{
            Profiles = @()
            Stdout = $result.Stdout
            Stderr = $result.Stderr
            Error = "dotnet-trace list-profiles exited with code $($result.ExitCode)."
        }
    }

    $profiles = @()
    foreach ($line in ($result.Stdout -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z0-9_.-]+)\s') {
            $profiles += $matches[1]
        }
    }

    [pscustomobject]@{
        Profiles = $profiles
        Stdout = $result.Stdout
        Stderr = $result.Stderr
        Error = $null
    }
}

function Select-TraceProfile([string] $Mode, [string[]] $Profiles) {
    if ($Mode -eq "cpu") {
        foreach ($candidate in @("dotnet-sampled-thread-time", "thread-time", "cpu-sampling")) {
            if ($Profiles -contains $candidate) {
                return $candidate
            }
        }

        return $null
    }

    foreach ($candidate in @("gc-verbose", "dotnet-common", "gc-collect")) {
        if ($Profiles -contains $candidate) {
            return $candidate
        }
    }

    return $null
}

if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    $ArtifactRoot = New-DefaultArtifactRoot
}

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null

$target = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
if (-not $target) {
    throw "Process $ProcessId was not found."
}

$workingDirectory = (Resolve-Path ".").Path
$command = Resolve-TraceCommand $TraceTool $workingDirectory
if (-not $command) {
    $message = @(
        "$TraceTool was not found as an explicit path, local dotnet tool, or PATH command.",
        "Provision locally from the repo root with:",
        "  dotnet tool install dotnet-trace --local",
        "Restore later with:",
        "  dotnet tool restore",
        "Then rerun this script against the Incursa server process id."
    )
    Set-Content -Path (Join-Path $ArtifactRoot "dotnet-trace.stderr.txt") -Value $message
    [ordered]@{
        status = "tool-unavailable"
        processId = $ProcessId
        tool = $TraceTool
        mode = $Mode
        artifactRoot = (Resolve-Path -LiteralPath $ArtifactRoot).Path
        instructions = $message
    } | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $ArtifactRoot "trace-summary.json")
    Get-Content -Path (Join-Path $ArtifactRoot "dotnet-trace.stderr.txt")
    exit 2
}

$profileInfo = Get-TraceProfiles $command $workingDirectory
Set-Content -Path (Join-Path $ArtifactRoot "dotnet-trace-list-profiles.stdout.txt") -Value $profileInfo.Stdout
Set-Content -Path (Join-Path $ArtifactRoot "dotnet-trace-list-profiles.stderr.txt") -Value $profileInfo.Stderr
$profile = if ($Mode -eq "exception") {
    "Exception+Stack"
}
else {
    Select-TraceProfile $Mode $profileInfo.Profiles
}

if ([string]::IsNullOrWhiteSpace($profile)) {
    $message = @(
        "No dotnet-trace profile suitable for mode '$Mode' was found.",
        "Available profiles:",
        ($profileInfo.Profiles -join ", ")
    )
    if ($profileInfo.Error) {
        $message += $profileInfo.Error
    }

    Set-Content -Path (Join-Path $ArtifactRoot "dotnet-trace.stderr.txt") -Value $message
    [ordered]@{
        status = "profile-unavailable"
        processId = $ProcessId
        tool = $TraceTool
        toolSource = $command.Source
        toolVersion = $command.Version
        mode = $Mode
        availableProfiles = $profileInfo.Profiles
        artifactRoot = (Resolve-Path -LiteralPath $ArtifactRoot).Path
        instructions = $message
    } | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactRoot "trace-summary.json")
    Get-Content -Path (Join-Path $ArtifactRoot "dotnet-trace.stderr.txt")
    exit 2
}

$tracePath = Join-Path $ArtifactRoot "trace.nettrace"
$stdoutPath = Join-Path $ArtifactRoot "dotnet-trace.stdout.txt"
$stderrPath = Join-Path $ArtifactRoot "dotnet-trace.stderr.txt"
$duration = [TimeSpan]::FromSeconds([Math]::Max(1, $DurationSeconds)).ToString("hh\:mm\:ss", [Globalization.CultureInfo]::InvariantCulture)
$args = @($command.PrefixArguments) + @(
    "collect",
    "--process-id", $ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--duration", $duration,
    "--output", $tracePath
)

if ($Mode -eq "exception") {
    $args += @(
        "--clrevents", "Exception+Stack",
        "--clreventlevel", "4"
    )
}
else {
    $args += @("--profile", $profile)
}
Set-Content -Path (Join-Path $ArtifactRoot "dotnet-trace-command.txt") -Value (Format-CommandLine $command.FileName $args)

$process = Start-Process `
    -FilePath $command.FileName `
    -ArgumentList $args `
    -WorkingDirectory $workingDirectory `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -WindowStyle Hidden `
    -PassThru
$process.WaitForExit()

$status = if ($process.ExitCode -eq 0 -and (Test-Path -LiteralPath $tracePath) -and (Get-Item -LiteralPath $tracePath).Length -gt 0) {
    "succeeded"
}
else {
    "failed"
}

[ordered]@{
    status = $status
    exitCode = $process.ExitCode
    processId = $ProcessId
    mode = $Mode
    profile = $profile
    toolSource = $command.Source
    toolVersion = $command.Version
    trace = $tracePath
    stdout = $stdoutPath
    stderr = $stderrPath
    command = Get-Content -Path (Join-Path $ArtifactRoot "dotnet-trace-command.txt") -Raw
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $ArtifactRoot "trace-summary.json")

if ($status -ne "succeeded") {
    Get-Content -Path $stderrPath -ErrorAction SilentlyContinue
    exit 1
}

$exclusivePath = Join-Path $ArtifactRoot "topN-exclusive.txt"
$inclusivePath = Join-Path $ArtifactRoot "topN-inclusive.txt"
$reportExclusive = Invoke-ToolCapture $command.FileName (@($command.PrefixArguments) + @("report", $tracePath, "topN", "--number", $TopN.ToString([Globalization.CultureInfo]::InvariantCulture), "--verbose")) $workingDirectory
Set-Content -Path $exclusivePath -Value ($reportExclusive.Stdout + $reportExclusive.Stderr)
$reportInclusive = Invoke-ToolCapture $command.FileName (@($command.PrefixArguments) + @("report", $tracePath, "topN", "--inclusive", "--number", $TopN.ToString([Globalization.CultureInfo]::InvariantCulture), "--verbose")) $workingDirectory
Set-Content -Path $inclusivePath -Value ($reportInclusive.Stdout + $reportInclusive.Stderr)

@(
    "# Incursa H3 P2 Trace Notes",
    "",
    "Mode: ``$Mode``",
    "Profile: ``$profile``",
    "Process ID: ``$ProcessId``",
    "Trace: ``$tracePath``",
    "Tool source: ``$($command.Source)``",
    "",
    "TopN reports are generated from ``dotnet-trace report topN``. CPU traces are sampled thread-time evidence. GC/allocation traces may still need PerfView or Visual Studio for object allocation-stack analysis."
) | Set-Content -Path (Join-Path $ArtifactRoot "notes.md")

Get-Content -Path (Join-Path $ArtifactRoot "trace-summary.json")
