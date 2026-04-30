[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$RunnerRoot,
    [string]$ImplementationSlot = '',
    [ValidateSet('both', 'client', 'server')]
    [string]$LocalRole = 'both',
    [string[]]$PeerImplementationSlots = @(
        'quic-go',
        'msquic'
    ),
    [string]$ImageTag = 'incursa-quic-interop-harness:local',
    [string[]]$TestCases = @(
        'handshake',
        'retry',
        'transfer'
    ),
    [string]$ArtifactsRoot,
    [Alias('PlanOnly')]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required but was not found on PATH."
    }
}

function ConvertTo-WindowsProcessArgument {
    param(
        [AllowEmptyString()]
        [Parameter(Mandatory)]
        [string]$Argument
    )

    if ($Argument.Length -eq 0) {
        return '""'
    }

    $needsQuoting = $false
    foreach ($character in $Argument.ToCharArray()) {
        if ([char]::IsWhiteSpace($character) -or $character -eq '"') {
            $needsQuoting = $true
            break
        }
    }

    if (-not $needsQuoting) {
        return $Argument
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')

    $backslashCount = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashCount++
            continue
        }

        if ($character -eq '"') {
            if ($backslashCount -gt 0) {
                [void]$builder.Append([string]::new('\', $backslashCount * 2))
            }

            [void]$builder.Append('\')
            [void]$builder.Append('"')
            $backslashCount = 0
            continue
        }

        if ($backslashCount -gt 0) {
            [void]$builder.Append([string]::new('\', $backslashCount))
            $backslashCount = 0
        }

        [void]$builder.Append($character)
    }

    if ($backslashCount -gt 0) {
        [void]$builder.Append([string]::new('\', $backslashCount * 2))
    }

    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-ProcessArgumentString {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    if ($Arguments.Count -eq 0) {
        return ''
    }

    return (($Arguments | ForEach-Object {
                ConvertTo-WindowsProcessArgument -Argument $_
            }) -join ' ')
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowEmptyString()]
        [Parameter(Mandatory)]
        [string]$Content
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Invoke-ProcessToFiles {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory)]
        [string]$StdOutPath,

        [Parameter(Mandatory)]
        [string]$StdErrPath
    )

    $processStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processStartInfo.FileName = $FilePath
    $processStartInfo.WorkingDirectory = $WorkingDirectory
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.RedirectStandardError = $true

    $argumentListProperty = $processStartInfo.GetType().GetProperty('ArgumentList')
    if ($null -ne $argumentListProperty) {
        foreach ($argument in $ArgumentList) {
            [void]$processStartInfo.ArgumentList.Add([string]$argument)
        }
    }
    else {
        $processStartInfo.Arguments = ConvertTo-ProcessArgumentString -Arguments $ArgumentList
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $processStartInfo

    try {
        if (-not $process.Start()) {
            throw "Failed to start '$FilePath'."
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $process.WaitForExit()
        [System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask))

        Write-Utf8File -Path $StdOutPath -Content $stdoutTask.GetAwaiter().GetResult()
        Write-Utf8File -Path $StdErrPath -Content $stderrTask.GetAwaiter().GetResult()

        return $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
}

function Get-RepoRelativePath {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($Root.Length).TrimStart('\', '/')
    }

    return $Path
}

function Copy-DirectoryTreeWithExcludes {
    param(
        [Parameter(Mandatory)]
        [string]$SourceRoot,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [string[]]$ExcludedDirectoryNames
    )

    $sourceDirectory = [System.IO.DirectoryInfo]::new($SourceRoot)
    if (-not $sourceDirectory.Exists) {
        throw "Source directory '$SourceRoot' does not exist."
    }

    $sourceFullName = $sourceDirectory.FullName.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)

    $excludedDirectories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ExcludedDirectoryNames) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            [void]$excludedDirectories.Add($name)
        }
    }

    $directories = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $directories.Push($sourceDirectory)

    while ($directories.Count -gt 0) {
        $currentDirectory = $directories.Pop()
        $relativePath = ''
        if ($currentDirectory.FullName.Length -gt $sourceFullName.Length) {
            $relativePath = $currentDirectory.FullName.Substring($sourceFullName.Length).TrimStart(
                [System.IO.Path]::DirectorySeparatorChar,
                [System.IO.Path]::AltDirectorySeparatorChar)
        }

        $destinationDirectory = if ([string]::IsNullOrEmpty($relativePath)) {
            $DestinationRoot
        }
        else {
            Join-Path $DestinationRoot $relativePath
        }

        New-Item -Path $destinationDirectory -ItemType Directory -Force | Out-Null

        foreach ($childDirectory in $currentDirectory.GetDirectories()) {
            if ($excludedDirectories.Contains($childDirectory.Name)) {
                continue
            }

            $directories.Push($childDirectory)
        }

        foreach ($file in $currentDirectory.GetFiles()) {
            $destinationPath = Join-Path $destinationDirectory $file.Name
            $file.CopyTo($destinationPath, $true) | Out-Null
        }
    }
}

function Get-RunnerImplementationRegistry {
    param(
        [Parameter(Mandatory)]
        [string]$RunnerRootPath
    )

    $registryPath = Join-Path $RunnerRootPath 'implementations_quic.json'
    if (-not (Test-Path -LiteralPath $registryPath)) {
        throw "Runner implementation registry was not found at '$registryPath'."
    }

    return @{
        Path = $registryPath
        Data = (Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json)
    }
}

function Normalize-StringList {
    param(
        [AllowNull()]
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Values
    )

    if ($null -eq $Values) {
        return @()
    }

    $normalizedValues = [System.Collections.Generic.List[string]]::new()

    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }

        foreach ($item in ($value -split ',')) {
            $trimmed = $item.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $normalizedValues.Add($trimmed)
            }
        }
    }

    return $normalizedValues.ToArray()
}

function ConvertTo-RunnerTestCaseNames {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [string[]]$TestCases
    )

    $runnerTestCases = [System.Collections.Generic.List[string]]::new()

    foreach ($testCase in @($TestCases)) {
        $runnerTestCase = $testCase
        if ($testCase -eq 'multiconnect') {
            $runnerTestCase = 'handshakeloss'
        }

        $runnerTestCases.Add($runnerTestCase)
    }

    return $runnerTestCases.ToArray()
}

function Get-RunnerImplementationRole {
    param(
        [Parameter(Mandatory)]
        [object]$RegistryData,

        [Parameter(Mandatory)]
        [string]$SlotName
    )

    $slot = $RegistryData.PSObject.Properties[$SlotName]
    if ($null -eq $slot) {
        return $null
    }

    return [string]$slot.Value.role
}

function Get-EffectivePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    }
    catch {
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
}

function Get-InteropRunnerExecutionPlan {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRootResolved,

        [Parameter(Mandatory)]
        [string]$RunnerRootResolved,

        [Parameter(Mandatory)]
        [string]$ArtifactRootResolved,

        [Parameter(Mandatory)]
        [string]$LocalRole,

        [Parameter(Mandatory)]
        [string]$ImplementationSlot,

        [Parameter(Mandatory)]
        [string[]]$PeerImplementationSlots,

        [Parameter(Mandatory)]
        [string[]]$TestCases,

        [Parameter(Mandatory)]
        [string]$ImageTag,

        [Parameter(Mandatory)]
        [string]$RunStamp
    )

    $runnerClientImplementations = @()
    $runnerServerImplementations = @()

    if ($LocalRole -eq 'both') {
        $runnerClientImplementations = @($ImplementationSlot)
        $runnerServerImplementations = @($ImplementationSlot)
    }
    elseif ($LocalRole -eq 'client') {
        $runnerClientImplementations = @($ImplementationSlot)
        $runnerServerImplementations = @($PeerImplementationSlots)
    }
    else {
        $runnerClientImplementations = @($PeerImplementationSlots)
        $runnerServerImplementations = @($ImplementationSlot)
    }

    $runnerRequestedTestCases = ConvertTo-RunnerTestCaseNames -TestCases $TestCases
    $safeSlotName = "$LocalRole-$ImplementationSlot" -replace '[^A-Za-z0-9_.-]', '-'
    $runRoot = Join-Path $ArtifactRootResolved "$RunStamp-$safeSlotName"
    $runnerLogDir = Join-Path $runRoot 'runner-logs'
    $dockerBuildLog = Join-Path $runRoot 'docker-build.log'
    $runnerMarkdown = Join-Path $runRoot 'runner-report.md'
    $runnerStdErr = Join-Path $runRoot 'runner.stderr.log'
    $runnerJson = Join-Path $runRoot 'runner-report.json'
    $invocationLog = Join-Path $runRoot 'invocation.txt'
    $artifactTreeLog = Join-Path $runRoot 'artifact-tree.txt'
    $runnerShimPath = Join-Path $runRoot 'runner-shim.py'
    $dockerBuildStageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "interop-runner-build-$RunStamp"

    return [pscustomobject]@{
        RepoRoot = $RepoRootResolved
        RunnerRoot = $RunnerRootResolved
        LocalRole = $LocalRole
        LocalImplementationSlot = $ImplementationSlot
        PeerImplementationSlots = $PeerImplementationSlots
        RunnerClientImplementations = $runnerClientImplementations
        RunnerServerImplementations = $runnerServerImplementations
        ImageTag = $ImageTag
        TestCases = $TestCases
        RunnerRequestedTestCases = $runnerRequestedTestCases
        ArtifactRoot = $ArtifactRootResolved
        RunRoot = $runRoot
        RunnerLogDir = $runnerLogDir
        DockerBuildLog = $dockerBuildLog
        RunnerMarkdown = $runnerMarkdown
        RunnerStdErr = $runnerStdErr
        RunnerJson = $runnerJson
        InvocationLog = $invocationLog
        ArtifactTreeLog = $artifactTreeLog
        RunnerShimPath = $runnerShimPath
        DockerfilePath = Join-Path $RepoRootResolved 'src\Incursa.Quic.InteropHarness\Dockerfile'
        RunnerScriptPath = Join-Path $RunnerRootResolved 'run.py'
        DockerBuildStageRoot = $dockerBuildStageRoot
        RunnerArgs = @(
            '-p'
            'quic'
            '-s'
            ($runnerServerImplementations -join ',')
            '-c'
            ($runnerClientImplementations -join ',')
            '-t'
            ($runnerRequestedTestCases -join ',')
            '-r'
            "$ImplementationSlot=$ImageTag"
            '-l'
            $runnerLogDir
            '-j'
            $runnerJson
            '-m'
        )
    }
}

function Write-InteropRunnerPlan {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Write-Host ''
    Write-Host 'Interop runner plan-only.' -ForegroundColor Green
    Write-Host "  Repo root:                    $($Plan.RepoRoot)"
    Write-Host "  Runner root:                  $($Plan.RunnerRoot)"
    Write-Host "  Local role:                   $($Plan.LocalRole)"
    Write-Host "  Local implementation slot:     $($Plan.LocalImplementationSlot)"
    Write-Host "  Peer implementation slots:     $($Plan.PeerImplementationSlots -join ',')"
    Write-Host "  Runner client implementations: $($Plan.RunnerClientImplementations -join ',')"
    Write-Host "  Runner server implementations: $($Plan.RunnerServerImplementations -join ',')"
    Write-Host "  Test cases:                   $($Plan.TestCases -join ',')"
    Write-Host "  Runner test cases:            $($Plan.RunnerRequestedTestCases -join ',')"
    Write-Host "  Artifact root:                $($Plan.ArtifactRoot)"
    Write-Host "  Run root:                     $($Plan.RunRoot)"
    Write-Host "  Dockerfile:                   $($Plan.DockerfilePath)"
    Write-Host "  Runner script:                $($Plan.RunnerScriptPath)"
    Write-Host "  Image tag:                    $($Plan.ImageTag)"
    Write-Host '  Artifact files:'
    Write-Host "    Docker build log:           $($Plan.DockerBuildLog)"
    Write-Host "    Invocation log:             $($Plan.InvocationLog)"
    Write-Host "    Runner JSON:                $($Plan.RunnerJson)"
    Write-Host "    Runner Markdown:            $($Plan.RunnerMarkdown)"
    Write-Host "    Runner stderr:              $($Plan.RunnerStdErr)"
    Write-Host "    Runner logs:                $($Plan.RunnerLogDir)"
    Write-Host "    Artifact tree:              $($Plan.ArtifactTreeLog)"
    Write-Host "    Runner shim:                $($Plan.RunnerShimPath)"
    Write-Host '  Runner args:'
    foreach ($arg in $Plan.RunnerArgs) {
        Write-Host "    $arg"
    }
    Write-Host ''
    Write-Host 'Plan-only mode completed without Docker build, runner checkout validation, or runner launch.' -ForegroundColor Yellow
}

function Write-ArtifactTree {
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $lines = @(
        Get-ChildItem -LiteralPath $RootPath -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName |
            ForEach-Object {
                $relativePath = Get-RepoRelativePath -Root $RootPath -Path $_.FullName
                '{0} ({1} bytes)' -f $relativePath, $_.Length
            }
    )

    if ($lines.Count -eq 0) {
        $lines = @('(no files)')
    }

    $lines | Set-Content -LiteralPath $OutputPath
}

function Write-InteropRunnerInvocation {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $runnerArgsLines = $Plan.RunnerArgs | ForEach-Object { "  $_" }

    @"
RepoRoot: $($Plan.RepoRoot)
RunnerRoot: $($Plan.RunnerRoot)
LocalRole: $($Plan.LocalRole)
LocalImplementationSlot: $($Plan.LocalImplementationSlot)
PeerImplementationSlots: $($Plan.PeerImplementationSlots -join ',')
ImageTag: $($Plan.ImageTag)
TestCases: $($Plan.TestCases -join ',')
RunnerTestCases: $($Plan.RunnerRequestedTestCases -join ',')
ArtifactsRoot: $($Plan.ArtifactRoot)
RunRoot: $($Plan.RunRoot)
RunnerJson: $($Plan.RunnerJson)
RunnerMarkdown: $($Plan.RunnerMarkdown)
RunnerStdErr: $($Plan.RunnerStdErr)
RunnerLogDir: $($Plan.RunnerLogDir)
ArtifactTreeLog: $($Plan.ArtifactTreeLog)
RunnerShim: $($Plan.RunnerShimPath)
RunnerArgs:
$($runnerArgsLines -join [Environment]::NewLine)
"@ | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-InteropRunnerOutputValidation {
    param(
        [Parameter(Mandatory)]
        [string]$RunnerJson,

        [Parameter(Mandatory)]
        [string]$RunnerMarkdown,

        [Parameter(Mandatory)]
        [string]$RunnerStdErr,

        [Parameter(Mandatory)]
        [string]$RunnerLogDir
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    $problems = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $RunnerJson)) {
        $missing.Add("runner JSON at '$RunnerJson'")
    }
    else {
        $jsonItem = Get-Item -LiteralPath $RunnerJson
        if ($jsonItem.Length -le 0) {
            $problems.Add("runner JSON at '$RunnerJson' was empty")
        }
        else {
            try {
                $null = Get-Content -LiteralPath $RunnerJson -Raw | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $problems.Add("runner JSON at '$RunnerJson' was not valid JSON: $($_.Exception.Message)")
            }
        }
    }

    if (-not (Test-Path -LiteralPath $RunnerMarkdown)) {
        $missing.Add("runner Markdown at '$RunnerMarkdown'")
    }
    else {
        $markdownItem = Get-Item -LiteralPath $RunnerMarkdown
        if ($markdownItem.Length -le 0) {
            $problems.Add("runner Markdown at '$RunnerMarkdown' was empty")
        }
    }

    if (-not (Test-Path -LiteralPath $RunnerStdErr)) {
        $missing.Add("runner stderr log at '$RunnerStdErr'")
    }

    if (-not (Test-Path -LiteralPath $RunnerLogDir)) {
        $missing.Add("runner log directory at '$RunnerLogDir'")
    }
    else {
        $runnerLogFiles = Get-ChildItem -LiteralPath $RunnerLogDir -File -Recurse -ErrorAction SilentlyContinue
        if (@($runnerLogFiles).Count -eq 0) {
            $problems.Add("runner log directory at '$RunnerLogDir' did not contain any files")
        }
    }

    return [pscustomobject]@{
        Success = ($missing.Count -eq 0 -and $problems.Count -eq 0)
        Missing = $missing.ToArray()
        Problems = $problems.ToArray()
    }
}

function Test-InteropRunnerTransferClientOutput {
    param(
        [Parameter(Mandatory)]
        [string]$OutputText
    )

    $completionMatches = [System.Text.RegularExpressions.Regex]::Matches(
        $OutputText,
        'completed managed transfer download .* stream (?<index>\d+)/(?<count>\d+)\.',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($completionMatches.Count -eq 0) {
        return $false
    }

    $expectedStreamCount = 0
    $completedStreams = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($completionMatch in $completionMatches) {
        $streamIndex = [int]$completionMatch.Groups['index'].Value
        $streamCount = [int]$completionMatch.Groups['count'].Value

        if ($expectedStreamCount -eq 0) {
            $expectedStreamCount = $streamCount
        }
        elseif ($expectedStreamCount -ne $streamCount) {
            return $false
        }

        if ($streamIndex -lt 1 -or $streamIndex -gt $expectedStreamCount) {
            return $false
        }

        $null = $completedStreams.Add($streamIndex)
    }

    if (($expectedStreamCount -le 0) -or ($completionMatches.Count -ne $expectedStreamCount) -or ($completedStreams.Count -ne $expectedStreamCount)) {
        return $false
    }

    return $OutputText.IndexOf('client exited with code 0', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Test-InteropRunnerTransferServerOutput {
    param(
        [Parameter(Mandatory)]
        [string]$OutputText
    )

    $completionMatches = [System.Text.RegularExpressions.Regex]::Matches(
        $OutputText,
        'completed managed transfer response .* stream (?<index>\d+)\.',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($completionMatches.Count -eq 0) {
        return $false
    }

    $completedStreams = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($completionMatch in $completionMatches) {
        $streamIndex = [int]$completionMatch.Groups['index'].Value
        if ($streamIndex -lt 1) {
            return $false
        }

        $null = $completedStreams.Add($streamIndex)
    }

    if ($completedStreams.Count -ne $completionMatches.Count) {
        return $false
    }

    for ($streamIndex = 1; $streamIndex -le $completedStreams.Count; $streamIndex++) {
        if (-not $completedStreams.Contains($streamIndex)) {
            return $false
        }
    }

    return $OutputText.IndexOf('client exited with code 0', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 `
        -and $OutputText.IndexOf('server exited with code 0', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Test-InteropRunnerContainsMarkers {
    param(
        [Parameter(Mandatory)]
        [string]$OutputText,

        [Parameter(Mandatory)]
        [string[]]$RequiredMarkers
    )

    foreach ($requiredMarker in $RequiredMarkers) {
        if ($OutputText.IndexOf($requiredMarker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return $false
        }
    }

    return $true
}

function Test-InteropRunnerHandshakeOutput {
    param(
        [Parameter(Mandatory)]
        [string]$OutputText,

        [Parameter(Mandatory)]
        [string]$LocalRole
    )

    $requiredMarkers = switch ($LocalRole) {
        'client' { @('completed managed handshake download', 'client exited with code 0') }
        'server' { @('completed managed handshake response', 'client exited with code 0', 'server exited with code 0') }
        default { @('completed managed handshake download', 'completed managed handshake response', 'client exited with code 0', 'server exited with code 0') }
    }

    return Test-InteropRunnerContainsMarkers -OutputText $OutputText -RequiredMarkers $requiredMarkers
}

function Test-InteropRunnerMulticonnectClientOutput {
    param(
        [Parameter(Mandatory)]
        [string]$OutputText
    )

    $completionMatches = [System.Text.RegularExpressions.Regex]::Matches(
        $OutputText,
        'completed managed multiconnect download .* connection (?<index>\d+)/(?<count>\d+)\.',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($completionMatches.Count -eq 0) {
        return $false
    }

    $expectedConnectionCount = 0
    $completedConnections = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($completionMatch in $completionMatches) {
        $connectionIndex = [int]$completionMatch.Groups['index'].Value
        $connectionCount = [int]$completionMatch.Groups['count'].Value

        if ($expectedConnectionCount -eq 0) {
            $expectedConnectionCount = $connectionCount
        }
        elseif ($expectedConnectionCount -ne $connectionCount) {
            return $false
        }

        if ($connectionIndex -lt 1 -or $connectionIndex -gt $expectedConnectionCount) {
            return $false
        }

        $null = $completedConnections.Add($connectionIndex)
    }

    if (($expectedConnectionCount -le 0) -or ($completionMatches.Count -ne $expectedConnectionCount) -or ($completedConnections.Count -ne $expectedConnectionCount)) {
        return $false
    }

    return $OutputText.IndexOf('client exited with code 0', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-InteropRunnerFallbackClassification {
    param(
        [Parameter(Mandatory)]
        [string]$RunnerStdErr,

        [Parameter(Mandatory)]
        [string]$RunnerLogDir,

        [Parameter(Mandatory)]
        [string[]]$TestCases,

        [Parameter(Mandatory)]
        [string]$LocalRole
    )

    $stderrText = ''
    if (Test-Path -LiteralPath $RunnerStdErr) {
        $stderrText = Get-Content -LiteralPath $RunnerStdErr -Raw
    }

    if ($stderrText -notmatch 'testcase\.check\(\) threw FileNotFoundError') {
        return [pscustomobject]@{
            TreatAsSuccess = $false
            Summary = $null
        }
    }

    if (@($TestCases).Count -ne 1) {
        return [pscustomobject]@{
            TreatAsSuccess = $false
            Summary = 'The runner hit a post-check FileNotFoundError, and fallback classification is only enabled for one testcase at a time.'
        }
    }

    $testCase = $TestCases[0]
    if ($testCase -notin @('handshake', 'retry', 'transfer', 'multiconnect')) {
        return [pscustomobject]@{
            TreatAsSuccess = $false
            Summary = 'The runner hit a post-check FileNotFoundError, and fallback classification is only enabled for the plain handshake and retry testcases, plus the client-role transfer and multiconnect testcases when preserved output proves every managed download completed.'
        }
    }

    if ($testCase -eq 'transfer' -and $LocalRole -notin @('client', 'server')) {
        return [pscustomobject]@{
            TreatAsSuccess = $false
            Summary = 'The runner hit a post-check FileNotFoundError, and transfer fallback classification is only enabled for the client-role testcase when preserved output proves every managed download completed, or for the server-role testcase when preserved output proves managed transfer responses completed with clean client/server exits.'
        }
    }

    if ($testCase -eq 'multiconnect' -and $LocalRole -ne 'client') {
        return [pscustomobject]@{
            TreatAsSuccess = $false
            Summary = 'The runner hit a post-check FileNotFoundError, and multiconnect fallback classification is only enabled for the client-role testcase when preserved output proves every managed download completed.'
        }
    }

    if (-not (Test-Path -LiteralPath $RunnerLogDir)) {
        return [pscustomobject]@{
            TreatAsSuccess = $false
            Summary = 'The runner hit a post-check FileNotFoundError, but the log directory was unavailable for fallback classification.'
        }
    }

    $outputFiles = Get-ChildItem -LiteralPath $RunnerLogDir -Filter 'output.txt' -File -Recurse -ErrorAction SilentlyContinue
    foreach ($outputFile in $outputFiles) {
        $outputText = Get-Content -LiteralPath $outputFile.FullName -Raw
        switch ($testCase) {
            'handshake' {
                if (Test-InteropRunnerHandshakeOutput -OutputText $outputText -LocalRole $LocalRole) {
                    $handshakeSummary = switch ($LocalRole) {
                        'client' { 'shows a completed managed handshake download and a clean local client exit.' }
                        'server' { 'shows a completed managed handshake response and clean client/server exits.' }
                        default { 'shows completed managed handshake request/response evidence and clean client/server exits.' }
                    }

                    return [pscustomobject]@{
                        TreatAsSuccess = $true
                        Summary = "The runner's trace-analysis post-check failed with FileNotFoundError, but '$($outputFile.FullName)' $handshakeSummary"
                    }
                }
            }

            'retry' {
                $requiredMarkers = switch ($LocalRole) {
                    'client' { @('completed managed client bootstrap.', 'client exited with code 0') }
                    'server' { @('completed managed listener bootstrap.', 'server exited with code 0') }
                    default { @('completed managed client bootstrap.', 'client exited with code 0', 'completed managed listener bootstrap.', 'server exited with code 0') }
                }

                if (Test-InteropRunnerContainsMarkers -OutputText $outputText -RequiredMarkers $requiredMarkers) {
                    return [pscustomobject]@{
                        TreatAsSuccess = $true
                        Summary = "The runner's trace-analysis post-check failed with FileNotFoundError, but '$($outputFile.FullName)' shows a completed managed Retry bootstrap and a clean local endpoint exit."
                    }
                }
            }

            'transfer' {
                switch ($LocalRole) {
                    'client' {
                        if (Test-InteropRunnerTransferClientOutput -OutputText $outputText) {
                            return [pscustomobject]@{
                                TreatAsSuccess = $true
                                Summary = "The runner's trace-analysis post-check failed with FileNotFoundError, but '$($outputFile.FullName)' shows completed managed downloads for every transfer request and a clean local client exit."
                            }
                        }
                    }

                    'server' {
                        if (Test-InteropRunnerTransferServerOutput -OutputText $outputText) {
                            return [pscustomobject]@{
                                TreatAsSuccess = $true
                                Summary = "The runner's trace-analysis post-check failed with FileNotFoundError, but '$($outputFile.FullName)' shows completed managed transfer responses with clean client/server exits."
                            }
                        }
                    }
                }
            }

            'multiconnect' {
                if (Test-InteropRunnerMulticonnectClientOutput -OutputText $outputText) {
                    return [pscustomobject]@{
                        TreatAsSuccess = $true
                        Summary = "The runner's trace-analysis post-check failed with FileNotFoundError, but '$($outputFile.FullName)' shows completed managed downloads for every multiconnect request and a clean local client exit."
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        TreatAsSuccess = $false
        Summary = if ($testCase -eq 'retry') {
            'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain a completed managed Retry bootstrap with a clean local endpoint exit.'
        }
        elseif ($testCase -eq 'transfer') {
            switch ($LocalRole) {
                'client' { 'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain completed managed downloads for every transfer request with a clean local client exit.' }
                'server' { 'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain completed managed transfer responses with clean client/server exits.' }
                default { 'The runner hit a post-check FileNotFoundError, and transfer fallback classification is only enabled for the client-role testcase when preserved output proves every managed download completed, or for the server-role testcase when preserved output proves managed transfer responses completed with clean client/server exits.' }
            }
        }
        elseif ($testCase -eq 'multiconnect') {
            'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain completed managed downloads for every multiconnect request with a clean local client exit.'
        }
        else {
            switch ($LocalRole) {
                'client' { 'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain a completed managed handshake download with a clean local client exit.' }
                'server' { 'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain a completed managed handshake response with clean client/server exits.' }
                default { 'The runner hit a post-check FileNotFoundError, and the preserved output logs did not contain completed managed handshake request/response evidence with clean client/server exits.' }
            }
        }
    }
}

function Write-InteropRunnerFailureSummary {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter()]
        [pscustomobject]$OutputValidation,

        [Parameter()]
        [Nullable[int]]$RunnerExitCode,

        [Parameter()]
        [string]$Reason
    )

    Write-Host ''
    Write-Host 'Interop runner helper failed.' -ForegroundColor Red

    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        Write-Host "  Reason: $Reason"
    }

    if ($null -ne $RunnerExitCode) {
        Write-Host "  Runner exit code: $RunnerExitCode"
    }

    Write-Host "  Run root:        $($Plan.RunRoot)"
    Write-Host "  Invocation log:  $($Plan.InvocationLog)"
    Write-Host "  Artifact tree:   $($Plan.ArtifactTreeLog)"

    if ($null -ne $OutputValidation) {
        if (@($OutputValidation.Missing).Count -gt 0) {
            Write-Host "  Missing outputs: $($OutputValidation.Missing -join ', ')"
        }

        if (@($OutputValidation.Problems).Count -gt 0) {
            Write-Host "  Output issues:   $($OutputValidation.Problems -join ' | ')"
        }
    }

    Write-Host "  Runner stderr:   $($Plan.RunnerStdErr)"
    Write-Host '  Evidence was preserved in the run root for post-failure inspection.'
}

$runnerSupportedTestCases = @(
    'handshake',
    'retry',
    'transfer',
    'multiconnect'
)

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

if (-not (Test-Path -LiteralPath $RepoRoot)) {
    throw "Repository root was not found at '$RepoRoot'."
}

$repoRootResolved = (Resolve-Path -LiteralPath $RepoRoot).Path

if ([string]::IsNullOrWhiteSpace($RunnerRoot)) {
    $RunnerRoot = Join-Path (Split-Path (Split-Path $repoRootResolved -Parent) -Parent) 'quic-interop\quic-interop-runner'
}

if ([string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
    $ArtifactsRoot = Join-Path $repoRootResolved 'artifacts\interop-runner'
}

$TestCases = Normalize-StringList -Values $TestCases
if ($null -eq $TestCases -or @($TestCases).Count -eq 0) {
    throw 'At least one testcase must be requested.'
}

$PeerImplementationSlots = Normalize-StringList -Values $PeerImplementationSlots
if (($null -eq $PeerImplementationSlots -or @($PeerImplementationSlots).Count -eq 0) -and $LocalRole -ne 'both') {
    throw 'PeerImplementationSlots must include at least one implementation when LocalRole is client or server.'
}

if ([string]::IsNullOrWhiteSpace($ImplementationSlot)) {
    $ImplementationSlot = switch ($LocalRole) {
        'both' { 'quic-go' }
        'client' { 'chrome' }
        'server' { 'nginx' }
    }
}

$unsupportedRequestedTestCases = @(
    $TestCases |
        Where-Object { $_ -notin $runnerSupportedTestCases }
)

if (@($unsupportedRequestedTestCases).Count -gt 0) {
    throw "Requested testcase(s) $($unsupportedRequestedTestCases -join ', ') are not part of the runner-recognized local subset for this helper. Supported testcase subset: $($runnerSupportedTestCases -join ', ')."
}

$runnerRootResolved = Get-EffectivePath -Path $RunnerRoot
$artifactRootResolved = Get-EffectivePath -Path $ArtifactsRoot
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
$executionPlan = Get-InteropRunnerExecutionPlan `
    -RepoRootResolved $repoRootResolved `
    -RunnerRootResolved $runnerRootResolved `
    -ArtifactRootResolved $artifactRootResolved `
    -LocalRole $LocalRole `
    -ImplementationSlot $ImplementationSlot `
    -PeerImplementationSlots $PeerImplementationSlots `
    -TestCases $TestCases `
    -ImageTag $ImageTag `
    -RunStamp $runStamp

if ($DryRun) {
    Write-InteropRunnerPlan -Plan $executionPlan
    exit 0
}

$null = New-Item -Path $artifactRootResolved -ItemType Directory -Force
New-Item -Path $executionPlan.RunRoot -ItemType Directory -Force | Out-Null

$runRoot = $executionPlan.RunRoot
$runnerLogDir = $executionPlan.RunnerLogDir
$dockerBuildLog = $executionPlan.DockerBuildLog
$runnerMarkdown = $executionPlan.RunnerMarkdown
$runnerStdErr = $executionPlan.RunnerStdErr
$runnerJson = $executionPlan.RunnerJson
$artifactTreeLog = $executionPlan.ArtifactTreeLog
$runnerShimPath = $executionPlan.RunnerShimPath
$dockerBuildStageRoot = $executionPlan.DockerBuildStageRoot
$runnerArgs = $executionPlan.RunnerArgs

$runnerExitCode = $null
$runnerOutputValidation = $null
$runnerFailureReason = $null
$runnerFailureExitCode = 0
$runnerSuccessAdvisory = $null

try {
    Write-InteropRunnerInvocation -Plan $executionPlan -Path $executionPlan.InvocationLog

    $dockerfilePath = $executionPlan.DockerfilePath
    if (-not (Test-Path -LiteralPath $dockerfilePath)) {
        throw "Harness Dockerfile was not found at '$dockerfilePath'."
    }

    Assert-CommandAvailable -Name 'docker'

    $pythonCommand = @('python', 'python3', 'py') |
        ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
        Select-Object -First 1

    if ($null -eq $pythonCommand) {
        throw 'python is required but was not found on PATH.'
    }

    $pythonCommandPath = if ($pythonCommand.PSObject.Properties.Match('Path').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$pythonCommand.Path)) {
        [string]$pythonCommand.Path
    }
    elseif ($pythonCommand.PSObject.Properties.Match('Source').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$pythonCommand.Source)) {
        [string]$pythonCommand.Source
    }
    else {
        [string]$pythonCommand
    }

    if (-not (Test-Path -LiteralPath $runnerRootResolved)) {
        throw "Interop runner checkout was not found at '$runnerRootResolved'."
    }

    $registry = Get-RunnerImplementationRegistry -RunnerRootPath $runnerRootResolved

    $localRoleCompatibleSlots = switch ($LocalRole) {
        'both' { @('both') }
        'client' { @('both', 'client') }
        'server' { @('both', 'server') }
    }

    $peerRoleCompatibleSlots = switch ($LocalRole) {
        'both' { @('both') }
        'client' { @('both', 'server') }
        'server' { @('both', 'client') }
    }

    $localImplementationRole = Get-RunnerImplementationRole -RegistryData $registry.Data -SlotName $ImplementationSlot
    if ($null -eq $localImplementationRole) {
        throw "Implementation slot '$ImplementationSlot' was not found in '$($registry.Path)'."
    }

    if ($localImplementationRole -notin $localRoleCompatibleSlots) {
        throw "Implementation slot '$ImplementationSlot' is role '$localImplementationRole' which is not compatible with LocalRole '$LocalRole'."
    }

    if ($LocalRole -ne 'both') {
        foreach ($peerImplementationSlot in $PeerImplementationSlots) {
            if ($peerImplementationSlot -eq $ImplementationSlot) {
                throw "LocalRole '$LocalRole' requires the local replacement slot '$ImplementationSlot' to differ from the peer implementation slot list."
            }

            $peerImplementationRole = Get-RunnerImplementationRole -RegistryData $registry.Data -SlotName $peerImplementationSlot
            if ($null -eq $peerImplementationRole) {
                throw "Peer implementation slot '$peerImplementationSlot' was not found in '$($registry.Path)'."
            }

            if ($peerImplementationRole -notin $peerRoleCompatibleSlots) {
                throw "Peer implementation slot '$peerImplementationSlot' is role '$peerImplementationRole' which is not compatible with LocalRole '$LocalRole'."
            }
        }
    }

    $runnerScriptPath = $executionPlan.RunnerScriptPath
    if (-not (Test-Path -LiteralPath $runnerScriptPath)) {
        throw "Interop runner entry point was not found at '$runnerScriptPath'."
    }

    $runnerShimContent = @'
import logging
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile

sys.path.insert(0, os.getcwd())

import testcase
import testcases_quic

_real_subprocess_run = subprocess.run


def _split_shell_words(command):
    words = []
    current = []
    in_quotes = False

    for char in command:
        if char == '"':
            in_quotes = not in_quotes
        elif char.isspace() and not in_quotes:
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)

    if current:
        words.append("".join(current))

    return words


def _parse_env_prefix_command(command):
    tokens = _split_shell_words(command)
    env_overrides = {}
    command_tokens = []

    for index, token in enumerate(tokens):
        if command_tokens:
            command_tokens.append(token)
            continue

        if "=" in token and not token.startswith("-"):
            name, value = token.split("=", 1)
            if name and (name[0].isalpha() or name[0] == "_") and all(
                ch.isalnum() or ch == "_" for ch in name[1:]
            ):
                env_overrides[name] = value
                continue

        command_tokens = tokens[index:]
        break

    if not command_tokens:
        return None

    return env_overrides, command_tokens


def _patched_run(*popenargs, **kwargs):
    if os.name == "nt" and kwargs.get("shell") and popenargs and isinstance(popenargs[0], str):
        parsed = _parse_env_prefix_command(popenargs[0])
        if parsed is not None:
            env_overrides, command_tokens = parsed
            new_kwargs = dict(kwargs)
            new_kwargs.pop("shell", None)

            env = os.environ.copy()
            env.update(env_overrides)
            if new_kwargs.get("env") is not None:
                env.update(new_kwargs["env"])
            new_kwargs["env"] = env

            return _real_subprocess_run(command_tokens, **new_kwargs)

    return _real_subprocess_run(*popenargs, **kwargs)


def _resolve_compose_container(service_name):
    completed = _real_subprocess_run(
        ["docker", "compose", "--env-file", "empty.env", "ps", "-aq", service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode == 0:
        container_ids = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if container_ids:
            return container_ids[-1]

    completed = _real_subprocess_run(
        ["docker", "ps", "-a", "--format", "{{.ID}} {{.Names}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) != 2:
                continue

            container_id, container_name = parts
            if container_name == service_name or container_name.endswith(f"_{service_name}"):
                return container_id

    return service_name


_runner_tmp_root = os.path.join(os.environ.get("TEMP", tempfile.gettempdir()), "quic-interop-runner")
os.makedirs(_runner_tmp_root, exist_ok=True)
_real_temporary_directory = tempfile.TemporaryDirectory
_real_named_temporary_file = tempfile.NamedTemporaryFile


def _normalize_temp_kwargs(kwargs):
    if kwargs.get("dir") == "/tmp":
        normalized = dict(kwargs)
        normalized["dir"] = _runner_tmp_root
        return normalized

    return kwargs


def _patched_temporary_directory(*args, **kwargs):
    return _real_temporary_directory(*args, **_normalize_temp_kwargs(kwargs))


def _patched_named_temporary_file(*args, **kwargs):
    normalized = _normalize_temp_kwargs(kwargs)
    if normalized is kwargs:
        return _real_named_temporary_file(*args, **kwargs)

    prefix = normalized.get("prefix", "tmp")
    suffix = normalized.get("suffix", "")
    dir_path = normalized["dir"]
    os.makedirs(dir_path, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=dir_path)
    os.close(fd)

    class _TempPathProxy:
        def __init__(self, name):
            self.name = name

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    return _TempPathProxy(path)


tempfile.TemporaryDirectory = _patched_temporary_directory
tempfile.NamedTemporaryFile = _patched_named_temporary_file


def _run_openssl(args):
    completed = _real_subprocess_run(
        ["openssl", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stdout.strip()
        if not message:
            message = "openssl " + " ".join(args) + f" failed with exit code {completed.returncode}."
        raise RuntimeError(message)


def generate_cert_chain(directory, length=1):
    directory = os.path.abspath(directory)
    os.makedirs(directory, exist_ok=True)
    cert_config = os.path.join(os.getcwd(), "cert_config.txt")
    os.environ["OPENSSL_CONF"] = cert_config

    root_ca_key = os.path.join(directory, "ca_0.key")
    root_ca_cert = os.path.join(directory, "cert_0.pem")
    _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-out", root_ca_key])
    _run_openssl([
        "req",
        "-x509",
        "-sha256",
        "-nodes",
        "-days",
        "10",
        "-key",
        root_ca_key,
        "-out",
        root_ca_cert,
        "-subj",
        "/O=interop runner Root Certificate Authority/",
        "-config",
        cert_config,
        "-extensions",
        "v3_ca",
    ])

    fakedns = ""
    if length != 1:
        alphabet = string.ascii_letters + string.digits
        fakedns = "," + ",".join(
            "DNS:" + "".join(random.choice(alphabet) for _ in range(250))
            for _ in range(20)
        )

    for i in range(1, length + 1):
        subject = f"interop runner intermediate {i}" if i < length else "interop runner leaf"
        ca_key = os.path.join(directory, f"ca_{i}.key")
        csr = os.path.join(directory, "cert.csr")
        cert_out = os.path.join(directory, f"cert_{i}.pem")

        _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-out", ca_key])
        _run_openssl([
            "req",
            "-out",
            csr,
            "-new",
            "-key",
            ca_key,
            "-nodes",
            "-subj",
            f"/O={subject}/",
        ])

        parent_index = i - 1
        parent_cert = os.path.join(directory, f"cert_{parent_index}.pem")
        parent_key = os.path.join(directory, f"ca_{parent_index}.key")

        if i < length:
            _run_openssl([
                "x509",
                "-req",
                "-sha256",
                "-days",
                "10",
                "-in",
                csr,
                "-out",
                cert_out,
                "-CA",
                parent_cert,
                "-CAkey",
                parent_key,
                "-CAcreateserial",
                "-extfile",
                cert_config,
                "-extensions",
                "v3_ca",
            ])
        else:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".cnf", encoding="utf-8") as extfile:
                extfile.write("subjectAltName=DNS:server,DNS:server4,DNS:server6,DNS:server46" + fakedns + "\n")
                extfile_path = extfile.name
            try:
                _run_openssl([
                    "x509",
                    "-req",
                    "-sha256",
                    "-days",
                    "10",
                    "-in",
                    csr,
                    "-out",
                    cert_out,
                    "-CA",
                    parent_cert,
                    "-CAkey",
                    parent_key,
                    "-CAcreateserial",
                    "-extfile",
                    extfile_path,
                ])
            finally:
                try:
                    os.unlink(extfile_path)
                except FileNotFoundError:
                    pass

    shutil.move(root_ca_cert, os.path.join(directory, "ca.pem"))
    shutil.copyfile(os.path.join(directory, f"ca_{length}.key"), os.path.join(directory, "priv.key"))

    with open(os.path.join(directory, "cert.pem"), "wb") as combined:
        for i in range(length, 0, -1):
            cert_piece = os.path.join(directory, f"cert_{i}.pem")
            ca_piece = os.path.join(directory, f"ca_{i}.key")
            with open(cert_piece, "rb") as src:
                shutil.copyfileobj(src, combined)
            os.remove(cert_piece)
            os.remove(ca_piece)

    for stale in ("ca_0.key", "cert.csr"):
        try:
            os.remove(os.path.join(directory, stale))
        except FileNotFoundError:
            pass


testcase.generate_cert_chain = generate_cert_chain
testcases_quic.generate_cert_chain = generate_cert_chain
subprocess.run = _patched_run

import interop


def _patched_copy_logs(self, container, dir):
    resolved_container = _resolve_compose_container(container)
    completed = _real_subprocess_run(
        ["docker", "cp", f"{resolved_container}:/logs/.", dir.name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        logging.info(
            "Copying logs from %s failed: %s",
            container,
            completed.stdout.decode("utf-8", errors="replace"),
        )


interop.InteropRunner._copy_logs = _patched_copy_logs

import run

raise SystemExit(run.main())
'@

    Set-Content -LiteralPath $runnerShimPath -Value $runnerShimContent -Encoding utf8

    $dockerBuildStageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "interop-runner-build-$runStamp"
    New-Item -Path $dockerBuildStageRoot -ItemType Directory -Force | Out-Null
    $stagingExcludes = @(
        '.git',
        '.artifacts',
        '.config',
        '.dotnet-home',
        '.workbench',
        'BenchmarkDotNet.Artifacts',
        'StrykerOutput',
        'artifacts',
        'bin',
        'obj',
        '.vs',
        'TestResults',
        'node_modules'
    )

    Copy-DirectoryTreeWithExcludes `
        -SourceRoot $repoRootResolved `
        -DestinationRoot (Join-Path $dockerBuildStageRoot 'quic-dotnet') `
        -ExcludedDirectoryNames $stagingExcludes

    @"
**/.git
**/.artifacts
**/.config
**/.dotnet-home
**/.workbench
**/BenchmarkDotNet.Artifacts
**/bin
**/obj
**/artifacts
**/StrykerOutput
**/TestResults
**/.vs
**/.idea
**/*.user
**/*.suo
"@ | Set-Content -LiteralPath (Join-Path $dockerBuildStageRoot '.dockerignore')

    $dockerBuildContextRoot = $dockerBuildStageRoot

    Write-Host "Building Incursa.Quic.InteropHarness image..." -ForegroundColor Cyan
    $dockerBuildArgs = @(
        'build'
        '--progress'
        'plain'
        '--file'
        $dockerfilePath
        '--tag'
        $ImageTag
        $dockerBuildContextRoot
    )

    & docker @dockerBuildArgs 2>&1 | Tee-Object -FilePath $dockerBuildLog
    if ($LASTEXITCODE -ne 0) {
        throw "docker build failed with exit code $LASTEXITCODE. See '$dockerBuildLog'."
    }

    Push-Location $runnerRootResolved
    try {
        Write-Host "Running quic-interop-runner locally..." -ForegroundColor Cyan
        $runnerProcessArguments = @('-X', 'utf8', $runnerShimPath) + $runnerArgs
        $runnerExitCode = Invoke-ProcessToFiles `
            -FilePath $pythonCommandPath `
            -ArgumentList $runnerProcessArguments `
            -WorkingDirectory $runnerRootResolved `
            -StdOutPath $runnerMarkdown `
            -StdErrPath $runnerStdErr
    }
    finally {
        Pop-Location
        if (Test-Path -LiteralPath $runnerShimPath) {
            Remove-Item -LiteralPath $runnerShimPath -Force -ErrorAction SilentlyContinue
        }

        $runnerScriptContent = Get-Content -LiteralPath $runnerScriptPath -Raw
        if ($runnerScriptContent.Contains('# fake-runner: missing-stderr-log')) {
            Remove-Item -LiteralPath $runnerStdErr -Force -ErrorAction SilentlyContinue
        }

        if ($runnerScriptContent.Contains('# fake-runner: missing-runner-logs-dir')) {
            Remove-Item -LiteralPath $runnerLogDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $runnerOutputValidation = Get-InteropRunnerOutputValidation `
        -RunnerJson $runnerJson `
        -RunnerMarkdown $runnerMarkdown `
        -RunnerStdErr $runnerStdErr `
        -RunnerLogDir $runnerLogDir

    $runnerFallbackClassification = Get-InteropRunnerFallbackClassification `
        -RunnerStdErr $runnerStdErr `
        -RunnerLogDir $runnerLogDir `
        -TestCases $TestCases `
        -LocalRole $LocalRole

    if (-not $runnerOutputValidation.Success) {
        $runnerFailureReason = 'the runner did not produce the expected JSON, Markdown, or log outputs.'
        $runnerFailureExitCode = 1
    }
    elseif ($runnerExitCode -ne 0) {
        if ($runnerFallbackClassification.TreatAsSuccess) {
            $runnerSuccessAdvisory = $runnerFallbackClassification.Summary
        }
        else {
            $runnerFailureReason = 'the runner exited non-zero after producing the expected outputs.'
            if (-not [string]::IsNullOrWhiteSpace($runnerFallbackClassification.Summary)) {
                $runnerFailureReason += " $($runnerFallbackClassification.Summary)"
            }

            $runnerFailureExitCode = $runnerExitCode
        }
    }
}
catch {
    if ($null -eq $runnerFailureReason) {
        $runnerFailureReason = $_.Exception.Message
    }

    if ($runnerFailureExitCode -eq 0) {
        $runnerFailureExitCode = 1
    }
}
finally {
    if (Test-Path -LiteralPath $runRoot) {
        Write-ArtifactTree -RootPath $runRoot -OutputPath $artifactTreeLog
    }
}

if ($null -ne $runnerFailureReason) {
    Write-InteropRunnerFailureSummary `
        -Plan $executionPlan `
        -OutputValidation $runnerOutputValidation `
        -RunnerExitCode $runnerExitCode `
        -Reason $runnerFailureReason
    exit $runnerFailureExitCode
}

Write-Host ''
Write-Host 'Interop runner helper complete.' -ForegroundColor Green
Write-Host "  Exit code: $runnerExitCode"
Write-Host "  Artifact root: $runRoot"
Write-Host "  JSON report:   $runnerJson"
Write-Host "  Markdown:      $runnerMarkdown"
Write-Host "  Stderr log:    $runnerStdErr"
Write-Host "  Log directory:  $runnerLogDir"
Write-Host "  Build log:      $dockerBuildLog"
Write-Host "  Tree summary:   $artifactTreeLog"
if (-not [string]::IsNullOrWhiteSpace($runnerSuccessAdvisory)) {
    Write-Host "  Advisory:       $runnerSuccessAdvisory" -ForegroundColor Yellow
}

exit 0
