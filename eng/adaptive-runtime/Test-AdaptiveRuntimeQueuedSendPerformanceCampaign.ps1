# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Test([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Test-BytesEqual([string] $LeftPath, [string] $RightPath) {
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($LeftPath)) -ceq
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($RightPath))
}

$compiler = Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeQueuedSendPerformanceCampaign.ps1'
$controlPath = Join-Path $PSScriptRoot `
    'experiment-control\adaptive-runtime-queued-send-performance-campaign-v1.json'
$checkedManifestPath = Join-Path $PSScriptRoot `
    'experiment-control\adaptive-runtime-queued-send-performance-manifest-v1.json'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('queued-send-performance-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $testRoot)
try {
    $first = Join-Path $testRoot 'first.json'
    $second = Join-Path $testRoot 'second.json'
    & $compiler -ControlPath $controlPath -OutputPath $first `
        -RepositoryRoot $RepositoryRoot | Out-Null
    & $compiler -ControlPath $controlPath -OutputPath $second `
        -RepositoryRoot $RepositoryRoot | Out-Null
    Assert-Test (Test-BytesEqual $first $second) `
        'queued manifest compilation was not byte deterministic'
    Assert-Test (Test-BytesEqual $first $checkedManifestPath) `
        'queued checked-in manifest did not replay byte-identically'

    $manifest = Read-AdaptiveRuntimeJsonDocument $first
    Assert-Test (Test-AdaptiveRuntimeDocumentHash $manifest) `
        'queued manifest hash did not verify'
    Assert-Test (@($manifest.planned_runs).Count -eq 16) `
        'queued manifest did not contain 16 jobs'
    foreach ($cellId in @($manifest.selected_cells)) {
        $runs = @($manifest.planned_runs | Where-Object cell_id -CEQ $cellId)
        Assert-Test ($runs.Count -eq 8) `
            "queued manifest did not contain 8 runs for $cellId"
        foreach ($position in 1..2) {
            Assert-Test (
                @($runs | Where-Object position_index -EQ $position).Count -eq 4
            ) "queued manifest position balance failed for $cellId/$position"
        }
    }

    $negativeCases = @(
        @{ Name = 'covering-array'; Mutate = {
            param($value)
            $value.covering_array_required = $true
        } },
        @{ Name = 'adjacent-axis'; Mutate = {
            param($value)
            $value.cell_bindings[1].adjacent_axes.application_send_batch_formation =
                'single_eligible'
        } },
        @{ Name = 'workload'; Mutate = {
            param($value)
            $value.package_selection.scenario_id = 'wrong.scenario'
        } },
        @{ Name = 'activation'; Mutate = {
            param($value)
            $value.active_behavior_authorization = $true
        } }
    )
    foreach ($case in $negativeCases) {
        $mutated = Read-AdaptiveRuntimeJsonDocument $controlPath
        & $case.Mutate $mutated
        foreach ($binding in @($mutated.cell_bindings)) {
            [void](Set-AdaptiveRuntimeDocumentHash $binding)
        }
        [void](Set-AdaptiveRuntimeDocumentHash $mutated)
        $mutatedPath = Join-Path $testRoot ($case.Name + '.json')
        Write-AdaptiveRuntimeCanonicalDocument $mutated $mutatedPath
        $failedClosed = $false
        try {
            & $compiler -ControlPath $mutatedPath `
                -OutputPath (Join-Path $testRoot ($case.Name + '-manifest.json')) `
                -RepositoryRoot $RepositoryRoot | Out-Null
        }
        catch {
            $failedClosed = $true
        }
        Assert-Test $failedClosed `
            "queued compiler accepted negative case $($case.Name)"
    }
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

[pscustomobject][ordered]@{
    status = 'passed'
    control_sha256 =
        (Read-AdaptiveRuntimeJsonDocument $controlPath).content_sha256
    manifest_sha256 =
        (Read-AdaptiveRuntimeJsonDocument $checkedManifestPath).content_sha256
    job_count = 16
    repetitions_per_cell = 8
    negative_case_count = 4
}
