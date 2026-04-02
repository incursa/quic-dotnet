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

try {
    $promptRoot = Resolve-ExistingPath -Path $PromptDirectory
    $workRoot   = Resolve-ExistingPath -Path $WorkingDirectory

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $outputRoot = Join-Path $promptRoot "_codex-output"
    }
    else {
        $outputRoot = Ensure-Directory -Path $OutputDirectory
    }

    $outputRoot = Ensure-Directory -Path $outputRoot

    $stdoutRoot = Ensure-Directory -Path (Join-Path $outputRoot "results")
    $stderrRoot = Ensure-Directory -Path (Join-Path $outputRoot "logs")

    $promptFiles = Get-ChildItem -LiteralPath $promptRoot -File -Filter *.md |
        Sort-Object Name

    if (-not $promptFiles -or $promptFiles.Count -eq 0) {
        Write-Host "No markdown files found in: $promptRoot"
        exit 0
    }

    $appendText = @"

Before you finish:
- If you made any changes, create a local git commit for the work completed.
- If commit signing blocks the commit, retry with --no-gpg-sign.
- Do not leave changes uncommitted if the task was completed or partially completed with useful work.
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

        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $CodexCommand
            $psi.WorkingDirectory = $workRoot
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            [void]$psi.ArgumentList.Add("exec")
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

            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()

            $process.WaitForExit()
            $exitCode = $process.ExitCode

            [System.IO.File]::WriteAllText($resultPath, $stdout)
            [System.IO.File]::WriteAllText($logPath, $stderr)

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

            $errorText = $_ | Out-String
            [System.IO.File]::WriteAllText($logPath, $errorText)

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

            Write-Warning "  Exception while processing $($file.Name)"
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
