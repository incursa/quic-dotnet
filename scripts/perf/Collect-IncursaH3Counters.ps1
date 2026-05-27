[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int] $ProcessId,
    [int] $DurationSeconds = 15,
    [int] $RefreshIntervalSeconds = 1,
    [ValidateSet("json", "csv")]
    [string] $Format = "json",
    [string] $ArtifactRoot,
    [string] $ProtocolLabRoot = "C:\src\incursa\protocol-lab",
    [string] $CounterTool = "dotnet-counters"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-DefaultArtifactRoot {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    Join-Path $repoRoot ".artifacts/perf/incursa-h3-p1/$stamp"
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

function Resolve-CounterCommand([string] $Tool, [string] $LabRoot) {
    $command = Get-Command $Tool -ErrorAction SilentlyContinue
    if ($command) {
        return [pscustomobject]@{
            FileName = $command.Source
            PrefixArguments = @()
            Source = "PATH"
        }
    }

    if ((Test-Path -LiteralPath $LabRoot) -and (Test-Path -LiteralPath (Join-Path $LabRoot "dotnet-tools.json"))) {
        $localArgs = @("tool", "run", $Tool, "--")
        $versionProcess = Start-Process `
            -FilePath "dotnet" `
            -ArgumentList ($localArgs + @("--version")) `
            -WorkingDirectory $LabRoot `
            -RedirectStandardOutput (Join-Path $ArtifactRoot "dotnet-counters-version.stdout.txt") `
            -RedirectStandardError (Join-Path $ArtifactRoot "dotnet-counters-version.stderr.txt") `
            -WindowStyle Hidden `
            -PassThru
        $versionProcess.WaitForExit()
        if ($versionProcess.ExitCode -eq 0) {
            return [pscustomobject]@{
                FileName = "dotnet"
                PrefixArguments = $localArgs
                Source = "ProtocolLab local tool manifest"
            }
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

$rawPath = Join-Path $ArtifactRoot ("counters.raw.$Format")
$stdoutPath = Join-Path $ArtifactRoot "counters.stdout.txt"
$stderrPath = Join-Path $ArtifactRoot "counters.stderr.txt"
$summaryPath = Join-Path $ArtifactRoot "counters-summary.json"

$command = Resolve-CounterCommand $CounterTool $ProtocolLabRoot
if (-not $command) {
    $message = @(
        "$CounterTool was not found on PATH or through the ProtocolLab local tool manifest.",
        "Provision with:",
        "  dotnet tool install --global dotnet-counters",
        "or from ProtocolLab:",
        "  cd $ProtocolLabRoot",
        "  dotnet tool restore"
    )
    Set-Content -Path $stderrPath -Value $message
    [ordered]@{
        status = "tool-unavailable"
        processId = $ProcessId
        tool = $CounterTool
        artifactRoot = (Resolve-Path -LiteralPath $ArtifactRoot).Path
        instructions = $message
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryPath
    Get-Content -Path $stderrPath
    exit 2
}

$duration = [TimeSpan]::FromSeconds([Math]::Max(1, $DurationSeconds)).ToString("hh\:mm\:ss", [Globalization.CultureInfo]::InvariantCulture)
$collectArgs = @(
    "collect",
    "--process-id", $ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture),
    "--refresh-interval", ([Math]::Max(1, $RefreshIntervalSeconds)).ToString([Globalization.CultureInfo]::InvariantCulture),
    "--counters", "System.Runtime",
    "--format", $Format,
    "--output", $rawPath,
    "--duration", $duration
)
$allArgs = @($command.PrefixArguments) + $collectArgs
Set-Content -Path (Join-Path $ArtifactRoot "counters-command.txt") -Value (Format-CommandLine $command.FileName $allArgs)

$process = Start-Process `
    -FilePath $command.FileName `
    -ArgumentList $allArgs `
    -WorkingDirectory ($(if (Test-Path -LiteralPath $ProtocolLabRoot) { $ProtocolLabRoot } else { (Resolve-Path ".").Path })) `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -WindowStyle Hidden `
    -PassThru
$process.WaitForExit()

$status = if ($process.ExitCode -eq 0 -and (Test-Path -LiteralPath $rawPath) -and (Get-Item -LiteralPath $rawPath).Length -gt 0) {
    "succeeded"
}
else {
    "failed"
}

[ordered]@{
    status = $status
    exitCode = $process.ExitCode
    processId = $ProcessId
    tool = $CounterTool
    toolSource = $command.Source
    raw = $rawPath
    stdout = $stdoutPath
    stderr = $stderrPath
    command = Get-Content -Path (Join-Path $ArtifactRoot "counters-command.txt") -Raw
} | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryPath

if ($status -ne "succeeded") {
    Get-Content -Path $stderrPath -ErrorAction SilentlyContinue
    exit 1
}

Get-Content -Path $summaryPath
