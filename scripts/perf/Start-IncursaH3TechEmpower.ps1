[CmdletBinding()]
param(
    [int] $Port = 5444,
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Debug",
    [string] $ArtifactRoot,
    [switch] $NoBuild,
    [int] $ReadyTimeoutSeconds = 30
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

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    $ArtifactRoot = New-DefaultArtifactRoot
}

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null

$projectPath = Join-Path $repoRoot "samples/Incursa.Http3.Samples.TechEmpower/Incursa.Http3.Samples.TechEmpower.csproj"
if (-not $NoBuild) {
    $buildArgs = @("build", $projectPath, "-c", $Configuration, "--nologo", "--verbosity", "minimal")
    Set-Content -Path (Join-Path $ArtifactRoot "build-command.txt") -Value (Format-CommandLine "dotnet" $buildArgs)
    & dotnet @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build failed with exit code $LASTEXITCODE."
    }
}

$targetPath = (& dotnet msbuild $projectPath "-getProperty:TargetPath" "-p:Configuration=$Configuration" "-nologo" |
    Where-Object { $_ -match '\.dll$' } |
    Select-Object -Last 1)
if ([string]::IsNullOrWhiteSpace($targetPath) -or -not (Test-Path -LiteralPath $targetPath)) {
    throw "Could not resolve the TechEmpower sample target DLL. Build the project first or omit -NoBuild."
}

$stdoutPath = Join-Path $ArtifactRoot "server.stdout.txt"
$stderrPath = Join-Path $ArtifactRoot "server.stderr.txt"
$commandArgs = @("exec", $targetPath, "--port", $Port.ToString([Globalization.CultureInfo]::InvariantCulture))
$commandLine = Format-CommandLine "dotnet" $commandArgs
Set-Content -Path (Join-Path $ArtifactRoot "server-command.txt") -Value $commandLine

$process = Start-Process `
    -FilePath "dotnet" `
    -ArgumentList $commandArgs `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -WindowStyle Hidden `
    -PassThru

$deadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
while ([DateTimeOffset]::UtcNow -lt $deadline) {
    if ($process.HasExited) {
        throw "Server process exited before readiness. See $stdoutPath and $stderrPath."
    }

    if ((Test-Path -LiteralPath $stdoutPath) -and
        ((Get-Content -Path $stdoutPath -Raw -ErrorAction SilentlyContinue) -match "Serving Incursa HTTP/3 TechEmpower-shaped sample")) {
        break
    }

    Start-Sleep -Milliseconds 250
}

$metadata = [ordered]@{
    processId = $process.Id
    port = $Port
    configuration = $Configuration
    targetPath = $targetPath
    artifactRoot = (Resolve-Path -LiteralPath $ArtifactRoot).Path
    commandLine = $commandLine
    stdout = $stdoutPath
    stderr = $stderrPath
    readySignalObserved = (Test-Path -LiteralPath $stdoutPath) -and
        ((Get-Content -Path $stdoutPath -Raw -ErrorAction SilentlyContinue) -match "Serving Incursa HTTP/3 TechEmpower-shaped sample")
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $ArtifactRoot "server-process.json")
$metadata
