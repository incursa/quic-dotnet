# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\queued-send-performance-runner-tests'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$assertionCount = 0
function Assert-Test([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
    $script:assertionCount++
}

$runnerPath = Join-Path $PSScriptRoot `
    'Invoke-AdaptiveRuntimeQueuedSendPerformanceCampaign.ps1'
$runnerText = Get-Content -LiteralPath $runnerPath -Raw
Assert-Test ($runnerText.Contains('[switch] $Resume') -and
    $runnerText.Contains('[int] $StopAfterCompletedRunCount = 16') -and
    $runnerText.Contains('ReplayEvidenceJobId') -and
    $runnerText.Contains('queued_q1_activation_predicate_not_observed') -and
    $runnerText.Contains('QueuedSendBurstLegalBudgetGreaterThanOneCount') -and
    $runnerText.Contains('accepted_timed_row = $false') -and
    $runnerText.Contains('failed_evidence_validation') -and
    $runnerText.Contains('Write-CampaignState') -and
    $runnerText.Contains('Assert-CampaignPackageIdentities') -and
    $runnerText.Contains('package_resume_hash_mismatch') -and
    $runnerText.Contains('package_resume_attestation_mismatch') -and
    $runnerText.Contains('$priorPreflightAttempts = @()') -and
    $runnerText.Contains('c1-s1-r1/result\.json$') -and
    -not $runnerText.Contains('c1-s100-r1') -and
    $runnerText.Contains('plab-worker-x64-02') -and
    $runnerText.Contains('plab-worker-x64-03') -and
    $runnerText.Contains('AdaptiveRuntimeQueuedSendPerformanceManifestContentSha256') -and
    -not $runnerText.Contains('CaptureTrace = $true') -and
    -not $runnerText.Contains('CaptureCounters = $true')) `
    'queued_runner_safety_controls_missing'
Assert-Test ($runnerText.Contains(
    "'cell.queued_send_burst_budget.performance.q0'") -and
    $runnerText.Contains(
        "'cell.queued_send_burst_budget.performance.q1'") -and
    $runnerText.Contains("'quic.transport.stream-download.1mb'") -and
    -not $runnerText.Contains("ScenarioId='quic.transport.stream-throughput.1mb'") -and
    $runnerText.Contains('$boundedEpochsThroughBenchmark') -and
    $runnerText.Contains('$nonMonotonicEpochs') -and
    $runnerText.Contains('QUIC_ADAPTIVE_RUNTIME_BOUNDED_AGGREGATE_INTERVAL_SECONDS=5')) `
    'queued_runner_exact_scope_missing'

$planRoot = Join-Path $TemporaryRoot 'plan-only'
$plan = & $runnerPath -RepositoryRoot $RepositoryRoot `
    -OutputRoot $planRoot | ConvertFrom-Json
Assert-Test ([string]$plan.mode -ceq 'plan_only' -and
    [string]$plan.compiled_manifest_sha256 -ceq
        '2ad809ecdb882f000c38d00c97f69604cbb3e004186535fd2348800e7c8a27ab' -and
    [int]$plan.planned_run_count -eq 16 -and
    [int]$plan.activation_preflight_run_count -eq 0 -and
    [int]$plan.actual_measurements_run -eq 0) `
    'queued_runner_plan_only_invalid'

# Dot-source the plan-only entry point so its resume-identity validator can be
# exercised without submitting a controller job.
. $runnerPath -RepositoryRoot $RepositoryRoot `
    -OutputRoot (Join-Path $TemporaryRoot 'resume-helper-load') `
    -PassThru | Out-Null
$control = Get-Content -LiteralPath (Join-Path $RepositoryRoot `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-queued-send-performance-campaign-v1.json') `
    -Raw | ConvertFrom-Json -Depth 100
$sourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
$versionPrefix = 'adaptive-runtime-queued-send-{0}-{1}' -f
    ([string]$control.content_sha256).Substring(0,8),$sourceCommit.Substring(0,8)
$identityRoot = Join-Path $TemporaryRoot 'resume-identities'
[void](New-Item -ItemType Directory -Force -Path $identityRoot)
$packageIdentities = @()
foreach ($binding in @($control.cell_bindings)) {
    $cellId = [string]$binding.cell_id
    $packagePath = Join-Path $identityRoot "$($cellId.Split('.')[-1]).plabpkg"
    "synthetic package bytes for $cellId" |
        Set-Content -LiteralPath $packagePath -Encoding utf8
    $sha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).
        Hash.ToLowerInvariant()
    $packageVersion = "$versionPrefix-$cellId"
    $attestationPath = "$packagePath.build-attestation.json"
    [pscustomobject][ordered]@{
        schemaVersion = 'protocol-lab.package-build-attestation.v1'
        parityEligible = $true
        source = [pscustomobject][ordered]@{
            workingTreeClean = $true
            commitSha = $sourceCommit
        }
        package = [pscustomobject][ordered]@{
            packageId = 'quic-dotnet-raw-dev'
            packageVersion = $packageVersion
            sha256 = $sha256
            queuedSendPerformancePackagePathSelected = $true
            queuedSendPerformanceCampaignId =
                'campaign.queued_send_burst_budget.performance.v1'
            queuedSendPerformanceManifestContentSha256 =
                '2ad809ecdb882f000c38d00c97f69604cbb3e004186535fd2348800e7c8a27ab'
            queuedSendPerformanceCellId = $cellId
            queuedSendPerformanceCellContentSha256 =
                [string]$binding.content_sha256
            adaptiveRuntimeQueuedSendBurstPolicy =
                [string]$binding.queued_send_burst_budget
        }
    } | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $attestationPath -Encoding utf8
    $packageIdentities += [pscustomobject][ordered]@{
        cell_id = $cellId
        package_ref = [pscustomobject][ordered]@{
            packageId = 'quic-dotnet-raw-dev'
            packageVersion = $packageVersion
            sha256 = $sha256
        }
        package_path = $packagePath
        package_attestation_path = $attestationPath
    }
}
Assert-CampaignPackageIdentities -PackageIdentities $packageIdentities `
    -CellBindings @($control.cell_bindings) `
    -ExpectedVersionPrefix $versionPrefix -SourceCommit $sourceCommit `
    -ManifestContentSha256 ([string]$plan.compiled_manifest_sha256)
Assert-Test $true 'queued_runner_resume_identity_positive_invalid'

$packageIdentities[0].package_ref.sha256 =
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
$resumeFailure = $null
try {
    Assert-CampaignPackageIdentities -PackageIdentities $packageIdentities `
        -CellBindings @($control.cell_bindings) `
        -ExpectedVersionPrefix $versionPrefix -SourceCommit $sourceCommit `
        -ManifestContentSha256 ([string]$plan.compiled_manifest_sha256)
}
catch {
    $resumeFailure = $_.Exception.Message
}
Assert-Test ([string]$resumeFailure -ceq
    'package_resume_hash_mismatch:cell.queued_send_burst_budget.performance.q0') `
    'queued_runner_resume_identity_negative_invalid'

[pscustomobject][ordered]@{
    assertion_count=$assertionCount
    manifest_sha256=[string]$plan.compiled_manifest_sha256
    planned_run_count=[int]$plan.planned_run_count
    activation_preflight_run_count=[int]$plan.activation_preflight_run_count
    actual_measurements_run=[int]$plan.actual_measurements_run
} | ConvertTo-Json -Depth 6
