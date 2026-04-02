param(
    [Parameter(Mandatory = $true)]
    [string]$PromptDirectory,

    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory,

    [string]$OutputDirectory = "",

    [string]$CodexCommand = "codex",

    [string]$Sandbox = "workspace-write"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-ExceptionDetail {
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

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

function Test-IsWindows {
    return $env:OS -eq "Windows_NT"
}

function Resolve-CodexCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    if (-not (Test-IsWindows) -or $Command -ne "codex") {
        return $Command
    }

    foreach ($candidate in @("codex.cmd", "codex.exe")) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved -and $resolved.CommandType -eq "Application" -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    throw "Unable to resolve a runnable Codex executable. Looked for codex.cmd and codex.exe on PATH."
}

function Write-CodexStreamLine {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("stdout", "stderr", "heartbeat")]
        [string]$StreamName,

        [AllowEmptyString()]
        [Parameter(Mandatory = $true)]
        [string]$Line,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        return
    }

    [System.IO.File]::AppendAllText($LogPath, "[$StreamName] $Line$([Environment]::NewLine)")

    $summary = $Line
    $color = if ($StreamName -eq "stdout") { "Cyan" } else { "DarkYellow" }

    if ($StreamName -eq "stdout" -and $Line.StartsWith("{")) {
        try {
            $event = $Line | ConvertFrom-Json -ErrorAction Stop

            switch ($event.type) {
                "thread.started" {
                    if ($event.PSObject.Properties.Name -contains "thread_id" -and -not [string]::IsNullOrWhiteSpace([string]$event.thread_id)) {
                        $summary = "Codex thread started ($($event.thread_id))"
                    }
                    else {
                        $summary = "Codex thread started"
                    }
                }
                "turn.started" {
                    $summary = "Codex turn started"
                }
                "item.completed" {
                    if ($null -ne $event.item -and $event.item.PSObject.Properties.Name -contains "type") {
                        if ($event.item.type -eq "agent_message" -and $event.item.PSObject.Properties.Name -contains "text") {
                            $messageText = [string]$event.item.text
                            $messageText = ($messageText -replace '\s+', ' ').Trim()
                            if ($messageText.Length -gt 160) {
                                $messageText = $messageText.Substring(0, 157) + "..."
                            }

                            $summary = "Codex message: $messageText"
                        }
                        else {
                            $summary = "Codex item completed ($($event.item.type))"
                        }
                    }
                    else {
                        $summary = "Codex item completed"
                    }
                }
                "turn.completed" {
                    if ($null -ne $event.usage) {
                        $inputTokens = if ($event.usage.PSObject.Properties.Name -contains "input_tokens") { $event.usage.input_tokens } else { $null }
                        $outputTokens = if ($event.usage.PSObject.Properties.Name -contains "output_tokens") { $event.usage.output_tokens } else { $null }

                        if ($null -ne $inputTokens -or $null -ne $outputTokens) {
                            $summary = "Codex turn completed (input=$inputTokens, output=$outputTokens)"
                        }
                        else {
                            $summary = "Codex turn completed"
                        }
                    }
                    else {
                        $summary = "Codex turn completed"
                    }
                }
                default {
                    $summary = "Codex event: $($event.type)"
                }
            }
        }
        catch {
            $summary = $Line
        }
    }
    elseif ($StreamName -eq "stderr") {
        $summary = "Codex stderr: $summary"
    }

    $summary = ($summary -replace '\s+', ' ').Trim()
    if ($summary.Length -gt 220) {
        $summary = $summary.Substring(0, 217) + "..."
    }

    Write-Host "  $summary" -ForegroundColor $color
}

try {
    $promptRoot = Resolve-ExistingPath -Path $PromptDirectory
    $workRoot   = Resolve-ExistingPath -Path $WorkingDirectory
    $codexExecutable = Resolve-CodexCommand -Command $CodexCommand

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $outputRoot = Join-Path $promptRoot "_codex-output"
    }
    else {
        $outputRoot = Ensure-Directory -Path $OutputDirectory
    }

    $outputRoot = Ensure-Directory -Path $outputRoot

    $stdoutRoot = Ensure-Directory -Path (Join-Path $outputRoot "results")
    $stderrRoot = Ensure-Directory -Path (Join-Path $outputRoot "logs")

    $promptFiles = @(
        Get-ChildItem -LiteralPath $promptRoot -File -Filter *.md |
            Sort-Object Name
    )

    if (-not $promptFiles -or $promptFiles.Count -eq 0) {
        Write-Host "No markdown files found in: $promptRoot"
        exit 0
    }

    $appendText = @"

Before you finish:
- If you made any changes, create a local git commit for the work completed.
- If commit signing blocks the commit, retry with --no-gpg-sign.
- Do not leave changes uncommitted if the task was completed or partially completed with useful work.
- Do not delete/revert logs files, result files, or the working directory, as they may be needed for later analysis.
- If no files changed, say so explicitly in your final response.
"@

    $summary = New-Object System.Collections.Generic.List[object]

    foreach ($file in $promptFiles) {
        $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $resultPath = Join-Path $stdoutRoot ($baseName + ".output.md")
        $logPath    = Join-Path $stderrRoot ($baseName + ".log.txt")

        Write-Host ""
        Write-Host "Processing: $($file.Name)"

        $originalPrompt = Get-Content -LiteralPath $file.FullName -Raw
        $finalPrompt = $originalPrompt.TrimEnd() + [Environment]::NewLine + [Environment]::NewLine + $appendText.Trim()

        $startTime = Get-Date
        $exitCode = $null
        $process = $null
        $stdoutDone = $false
        $stderrDone = $false
        $stdoutTask = $null
        $stderrTask = $null
        $nextHeartbeatAt = $startTime.AddMinutes(5)

        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $codexExecutable
            $psi.WorkingDirectory = $workRoot
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            [void]$psi.ArgumentList.Add("exec")
            [void]$psi.ArgumentList.Add("--json")
            [void]$psi.ArgumentList.Add("--output-last-message")
            [void]$psi.ArgumentList.Add($resultPath)
            [void]$psi.ArgumentList.Add("--sandbox")
            [void]$psi.ArgumentList.Add($Sandbox)
            [void]$psi.ArgumentList.Add("--model")
            [void]$psi.ArgumentList.Add("gpt-5.4-mini")
            [void]$psi.ArgumentList.Add("--config")
            [void]$psi.ArgumentList.Add('model_reasoning_effort="high"')

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi

            [void]$process.Start()

            $process.StandardInput.Write($finalPrompt)
            $process.StandardInput.Close()

            $stdoutTask = $process.StandardOutput.ReadLineAsync()
            $stderrTask = $process.StandardError.ReadLineAsync()

            while ($true) {
                $delayTask = [System.Threading.Tasks.Task]::Delay(250)
                $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]

                if (-not $stdoutDone) {
                    [void]$tasks.Add([System.Threading.Tasks.Task]$stdoutTask)
                }

                if (-not $stderrDone) {
                    [void]$tasks.Add([System.Threading.Tasks.Task]$stderrTask)
                }

                [void]$tasks.Add($delayTask)

                $completed = [System.Threading.Tasks.Task]::WhenAny($tasks.ToArray()).GetAwaiter().GetResult()

                if ($completed -eq $delayTask) {
                    $now = Get-Date

                    if ($now -ge $nextHeartbeatAt) {
                        $elapsed = $now - $startTime
                        $elapsedText = $elapsed.ToString("hh\:mm\:ss")
                        Write-CodexStreamLine -StreamName "heartbeat" -Line "Codex still running after $elapsedText on $($file.Name)" -LogPath $logPath
                        $nextHeartbeatAt = $now.AddMinutes(5)
                    }

                    if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                        break
                    }

                    continue
                }

                if (-not $stdoutDone -and $completed -eq $stdoutTask) {
                    $line = $stdoutTask.GetAwaiter().GetResult()

                    if ($null -eq $line) {
                        $stdoutDone = $true
                    }
                    else {
                        Write-CodexStreamLine -StreamName "stdout" -Line $line -LogPath $logPath
                        $nextHeartbeatAt = (Get-Date).AddMinutes(5)
                    }

                    if (-not $stdoutDone) {
                        $stdoutTask = $process.StandardOutput.ReadLineAsync()
                    }
                }
                elseif (-not $stderrDone -and $completed -eq $stderrTask) {
                    $line = $stderrTask.GetAwaiter().GetResult()

                    if ($null -eq $line) {
                        $stderrDone = $true
                    }
                    else {
                        Write-CodexStreamLine -StreamName "stderr" -Line $line -LogPath $logPath
                        $nextHeartbeatAt = (Get-Date).AddMinutes(5)
                    }

                    if (-not $stderrDone) {
                        $stderrTask = $process.StandardError.ReadLineAsync()
                    }
                }

                if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                    break
                }
            }

            $process.WaitForExit()
            $exitCode = $process.ExitCode

            $endTime = Get-Date
            $duration = $endTime - $startTime

            $status = if ($exitCode -eq 0) { "Success" } else { "Failed" }

            $summary.Add([pscustomobject]@{
                File             = $file.Name
                Status           = $status
                ExitCode         = $exitCode
                PromptDirectory  = $promptRoot
                WorkingDirectory = $workRoot
                ResultFile       = $resultPath
                LogFile          = $logPath
                Seconds          = [math]::Round($duration.TotalSeconds, 2)
            })

            if ($exitCode -eq 0) {
                Write-Host "  Success"
            }
            else {
                Write-Warning "  Failed with exit code $exitCode"
            }
        }
        catch {
            $endTime = Get-Date
            $duration = $endTime - $startTime

            $errorDetail = Get-ExceptionDetail -Exception $_.Exception
            $errorText = $_ | Out-String
            [System.IO.File]::AppendAllText($logPath, "[exception] $errorText$([Environment]::NewLine)")

            $summary.Add([pscustomobject]@{
                File             = $file.Name
                Status           = "Exception"
                ExitCode         = -1
                PromptDirectory  = $promptRoot
                WorkingDirectory = $workRoot
                ResultFile       = $resultPath
                LogFile          = $logPath
                Seconds          = [math]::Round($duration.TotalSeconds, 2)
            })

            Write-Warning "  Exception while processing $($file.Name): $errorDetail"
        }
        finally {
            if ($null -ne $process) {
                try {
                    $process.Dispose()
                }
                catch {
                }
            }
        }
    }

    $summaryPath = Join-Path $outputRoot "summary.csv"
    $summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation

    Write-Host ""
    Write-Host "Done."
    Write-Host "Prompt directory:  $promptRoot"
    Write-Host "Working directory: $workRoot"
    Write-Host "Results:           $stdoutRoot"
    Write-Host "Logs:              $stderrRoot"
    Write-Host "Summary:           $summaryPath"
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
