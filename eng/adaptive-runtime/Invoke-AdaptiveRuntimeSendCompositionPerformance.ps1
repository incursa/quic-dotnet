# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [ValidateSet('Pilot', 'Train', 'Holdout', 'All')]
    [string] $Phase = 'Pilot',
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $OutputRoot = (Join-Path 'C:\shared\temp' (
        'quic-send-composition-performance-{0}' -f
        (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string] $PilotEvidenceRoot,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $NoBuild,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-CampaignCondition([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Invoke-CapturedProcess(
    [string] $FileName,
    [string[]] $Arguments,
    [string] $StdOutPath,
    [string] $StdErrPath,
    [TimeSpan] $Timeout
) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.WorkingDirectory = $RepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $startedUtc = [DateTimeOffset]::UtcNow
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit([int]$Timeout.TotalMilliseconds)) {
        $process.Kill($true)
        $process.WaitForExit()
        $timedOut = $true
    }
    else {
        $timedOut = $false
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText($StdOutPath, $stdout)
    [IO.File]::WriteAllText($StdErrPath, $stderr)
    [pscustomobject][ordered]@{
        started_utc = $startedUtc.ToString('O')
        ended_utc = [DateTimeOffset]::UtcNow.ToString('O')
        exit_code = if ($timedOut) { -1 } else { $process.ExitCode }
        timed_out = $timedOut
        command = "$FileName $($Arguments -join ' ')"
        stdout_path = $StdOutPath
        stderr_path = $StdErrPath
    }
}

$resolvedOutputRoot = [IO.Path]::GetFullPath($OutputRoot)
Assert-CampaignCondition (-not (Test-Path -LiteralPath $resolvedOutputRoot)) `
    'performance_output_root_already_exists'

& (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1') `
    -CampaignPath $CampaignPath `
    -RepositoryRoot $RepositoryRoot | Out-Null

$sourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
Assert-CampaignCondition ($LASTEXITCODE -eq 0) `
    'performance_source_commit_unresolved'
$status = @(& git -C $RepositoryRoot status --porcelain=v2)
Assert-CampaignCondition ($LASTEXITCODE -eq 0 -and $status.Count -eq 0) `
    'performance_source_tree_not_clean'

$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
if ($Phase -ne 'Pilot') {
    Assert-CampaignCondition (
        -not [string]::IsNullOrWhiteSpace($PilotEvidenceRoot)
    ) 'performance_pilot_evidence_required'
    $pilotValidationPath = Join-Path $PilotEvidenceRoot `
        'validation\pilot-validation.json'
    Assert-CampaignCondition (Test-Path -LiteralPath $pilotValidationPath) `
        'performance_pilot_validation_missing'
    $pilotValidation = Get-Content $pilotValidationPath -Raw |
        ConvertFrom-Json
    Assert-CampaignCondition ($pilotValidation.passed -eq $true) `
        'performance_pilot_gate_failed'
}
$batchProof = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\batch-single-eligible.review.json')
$bufferProof = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\reviewed-proofs\buffer-memory-conservative.review.json')

New-Item -ItemType Directory -Force `
    $resolvedOutputRoot,
    (Join-Path $resolvedOutputRoot 'raw'),
    (Join-Path $resolvedOutputRoot 'logs'),
    (Join-Path $resolvedOutputRoot 'validation') | Out-Null

$buildLog = Join-Path $resolvedOutputRoot 'logs\build'
if (-not $NoBuild) {
    $build = Invoke-CapturedProcess 'dotnet' @(
        'build',
        (Join-Path $RepositoryRoot `
            'benchmarks\Incursa.Quic.Benchmarks.csproj'),
        '-c', 'Release', '--nologo'
    ) "$buildLog.stdout.log" "$buildLog.stderr.log" (
        [TimeSpan]::FromMinutes(15))
    $build | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath "$buildLog.command.json"
    Assert-CampaignCondition (
        -not $build.timed_out -and $build.exit_code -eq 0
    ) 'performance_focused_build_failed'
}

$runnerPath = Join-Path $RepositoryRoot `
    'benchmarks\bin\Release\net10.0\Incursa.Quic.Benchmarks.dll'
Assert-CampaignCondition (Test-Path -LiteralPath $runnerPath) `
    'performance_runner_missing'
$binaryHash = (Get-FileHash $runnerPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
$operatingSystem =
    [Runtime.InteropServices.RuntimeInformation]::OSDescription
$architecture =
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.
        ToString().ToLowerInvariant()
$processorCount = [Environment]::ProcessorCount
$machineInput = '{0}|{1}|{2}|{3}' -f
    [Environment]::MachineName,
    $processorCount,
    $operatingSystem,
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
$machineFingerprint = Get-AdaptiveRuntimeSha256 $machineInput
$machineNameHash = Get-AdaptiveRuntimeSha256 ([Environment]::MachineName)
$dotnetVersion = (& dotnet --version).Trim()

$manifest = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-composition-performance-manifest-v1'
    document_id = "manifest.send_composition.performance.$($sourceCommit.Substring(0,12))"
    document_version = 1
    content_sha256 = '0' * 64
    campaign_ref = [pscustomobject][ordered]@{
        document_id = [string]$campaign.document_id
        schema_version = [string]$campaign.schema_version
        document_version = [long]$campaign.document_version
        content_sha256 = [string]$campaign.content_sha256
    }
    source_commit = $sourceCommit
    source_tree_clean = $true
    binary_path = $runnerPath
    binary_sha256 = $binaryHash
    runner_version = 'send_composition_performance_runner.v1'
    runner_sha256 = $binaryHash
    host = [pscustomobject][ordered]@{
        fingerprint_sha256 = $machineFingerprint
        machine_name_sha256 = $machineNameHash
        operating_system = $operatingSystem
        architecture = $architecture
        processor_count = $processorCount
        dotnet_version = $dotnetVersion
    }
    cells = @($campaign.cells | ForEach-Object {
        [pscustomobject][ordered]@{
            cell_id = [string]$_.cell_id
            batch_value = [string]$_.batch_value
            buffer_value = [string]$_.buffer_value
            expected_effective_signature =
                [string]$_.expected_effective_signature
            performance_comparable = [bool]$_.performance_comparable
        }
    })
    orders = @($campaign.design.orders)
    measurement_authorization = $true
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    production_activation_authorization = $false
    trace_references = $campaign.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $manifest)
$manifestPath = Join-Path $resolvedOutputRoot 'compiled-manifest.json'
Write-AdaptiveRuntimeCanonicalDocument $manifest $manifestPath
& (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1') `
    -CampaignPath $CampaignPath `
    -ManifestPath $manifestPath `
    -RepositoryRoot $RepositoryRoot | Out-Null

$selectedSplits = switch ($Phase) {
    'Pilot' { @('pilot') }
    'Train' { @('train') }
    'Holdout' { @('holdout') }
    'All' { @('pilot', 'train', 'holdout') }
}
$workloads = @($campaign.workloads |
    Where-Object { [string]$_.split -in $selectedSplits } |
    Sort-Object split, workload_id)
$records = [Collections.Generic.List[object]]::new()
$rawPaths = [Collections.Generic.List[string]]::new()

foreach ($workload in $workloads) {
    $repetitions = if ([string]$workload.split -ceq 'pilot') {
        [int]$campaign.design.pilot_repetitions
    }
    else {
        [int]$campaign.design.full_repetitions
    }
    for ($block = 0; $block -lt $repetitions; $block++) {
        $order = @($campaign.design.orders[
            $block % @($campaign.design.orders).Count])
        for ($position = 0; $position -lt $order.Count; $position++) {
            $cellId = [string]$order[$position]
            $baseName = '{0}-{1}-b{2:D2}-o{3:D2}-{4}' -f
                $workload.split,
                $workload.workload_id,
                $block,
                $position,
                $cellId
            $rawPath = Join-Path $resolvedOutputRoot "raw\$baseName.json"
            $stdoutPath =
                Join-Path $resolvedOutputRoot "logs\$baseName.stdout.log"
            $stderrPath =
                Join-Path $resolvedOutputRoot "logs\$baseName.stderr.log"
            $arguments = @(
                $runnerPath,
                '--send-composition-performance',
                '--campaign-id', [string]$campaign.document_id,
                '--manifest-sha256', [string]$manifest.content_sha256,
                '--batch-proof-sha256', [string]$batchProof.content_sha256,
                '--buffer-proof-sha256', [string]$bufferProof.content_sha256,
                '--source-commit', $sourceCommit,
                '--binary-sha256', $binaryHash,
                '--cell', $cellId,
                '--workload-id', [string]$workload.workload_id,
                '--split', [string]$workload.split,
                '--block', [string]$block,
                '--order', [string]$position,
                '--scenario', [string]$workload.scenario,
                '--payload-bytes', [string]$workload.payload_bytes,
                '--response-payload-bytes',
                    [string]$workload.response_payload_bytes,
                '--concurrency', [string]$workload.concurrency,
                '--receive-window-bytes',
                    [string]$workload.receive_window_bytes,
                '--warmup-seconds', [string]$campaign.design.warmup_seconds,
                '--duration-seconds', [string]$campaign.design.duration_seconds,
                '--json', $rawPath
            )
            $record = Invoke-CapturedProcess 'dotnet' $arguments `
                $stdoutPath $stderrPath ([TimeSpan]::FromMinutes(5))
            $record | Add-Member -NotePropertyName workload_id `
                -NotePropertyValue ([string]$workload.workload_id)
            $record | Add-Member -NotePropertyName split `
                -NotePropertyValue ([string]$workload.split)
            $record | Add-Member -NotePropertyName cell_id `
                -NotePropertyValue $cellId
            $record | Add-Member -NotePropertyName block `
                -NotePropertyValue $block
            $record | Add-Member -NotePropertyName order `
                -NotePropertyValue $position
            [void]$records.Add($record)
            $records | ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath (
                    Join-Path $resolvedOutputRoot 'execution-records.json')
            if (Test-Path -LiteralPath $rawPath) {
                [void]$rawPaths.Add($rawPath)
            }
            Assert-CampaignCondition (
                -not $record.timed_out -and $record.exit_code -eq 0
            ) 'performance_run_correctness_failed'
            if ([int]$campaign.design.cooldown_seconds -gt 0) {
                Start-Sleep -Seconds ([int]$campaign.design.cooldown_seconds)
            }
        }
    }
}

$validation = & (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1') `
    -CampaignPath $CampaignPath `
    -ManifestPath $manifestPath `
    -RawEvidencePath @($rawPaths) `
    -RepositoryRoot $RepositoryRoot `
    -PassThru
$validation | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath (
        Join-Path $resolvedOutputRoot 'validation\raw-validation.json')

$checksums = @(Get-ChildItem $resolvedOutputRoot -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        [pscustomobject][ordered]@{
            path = [IO.Path]::GetRelativePath(
                $resolvedOutputRoot,
                $_.FullName).Replace('\', '/')
            bytes = $_.Length
            sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).
                Hash.ToLowerInvariant()
        }
    })
$checksums | Export-Csv -NoTypeInformation -LiteralPath (
    Join-Path $resolvedOutputRoot 'artifact-checksums.csv')

$result = [pscustomobject][ordered]@{
    output_root = $resolvedOutputRoot
    phase = $Phase
    source_commit = $sourceCommit
    campaign_sha256 = [string]$campaign.content_sha256
    manifest_path = $manifestPath
    manifest_sha256 = [string]$manifest.content_sha256
    binary_path = $runnerPath
    binary_sha256 = $binaryHash
    host_fingerprint_sha256 = $machineFingerprint
    command_count = @($records).Count
    raw_evidence_count = @($rawPaths).Count
    failed_command_count = @($records |
        Where-Object { $_.exit_code -ne 0 -or $_.timed_out }).Count
    validation = $validation
}
if ($PassThru) {
    $result
}
else {
    $result | ConvertTo-Json -Depth 12
}
