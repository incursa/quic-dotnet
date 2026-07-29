# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\admission-performance-pilot-tests'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$assertionCount = 0
function Assert-Ready([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
    $script:assertionCount++
}

function Read-Repo([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function Copy-Document([object] $Document) {
    $Document | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json -Depth 100
}

function Join-Values([object[]] $Values) {
    [string]::Join('|', @($Values | ForEach-Object { [string]$_ }))
}

function Assert-CompileRejects(
    [object] $Pilot,
    [string] $Name,
    [string] $ExpectedCode
) {
    [void](Set-AdaptiveRuntimeDocumentHash $Pilot)
    $pilotPath = Join-Path $TemporaryRoot "$Name.pilot.json"
    $manifestPath = Join-Path $TemporaryRoot "$Name.manifest.json"
    Write-AdaptiveRuntimeCanonicalDocument $Pilot $pilotPath
    try {
        & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeAdmissionPerformancePilot.ps1') `
            -RepositoryRoot $RepositoryRoot `
            -PilotPath $pilotPath `
            -OutputPath $manifestPath | Out-Null
        throw "expected_rejection_missing:$Name"
    }
    catch {
        Assert-Ready ($_.Exception.Message -like "*$ExpectedCode*") `
            "unexpected_rejection:${Name}:$($_.Exception.Message)"
    }
}

[void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)

$pilotPath = 'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json'
$campaignPath = 'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-campaign-v1.json'
$pilotSchema = 'schemas\adaptive-runtime-send-admission-performance-pilot-v1.schema.json'
$manifestSchema = 'schemas\adaptive-runtime-send-admission-performance-pilot-manifest-v1.schema.json'

$pilot = Read-Repo $pilotPath
$campaign = Read-Repo $campaignPath
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $pilot) 'pilot_hash_invalid'
Assert-Ready (Test-AdaptiveRuntimeJsonSchema $pilot (Join-Path $RepositoryRoot $pilotSchema)) `
    'pilot_schema_invalid'
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $campaign) 'campaign_hash_invalid'

$manifestOnePath = Join-Path $TemporaryRoot 'manifest-one.json'
$manifestTwoPath = Join-Path $TemporaryRoot 'manifest-two.json'
& (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeAdmissionPerformancePilot.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
    -OutputPath $manifestOnePath | Out-Null
& (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeAdmissionPerformancePilot.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
    -OutputPath $manifestTwoPath | Out-Null

$manifestOne = Read-AdaptiveRuntimeJsonDocument $manifestOnePath
$manifestTwo = Read-AdaptiveRuntimeJsonDocument $manifestTwoPath
Assert-Ready (Test-AdaptiveRuntimeDocumentHash $manifestOne) 'manifest_hash_invalid'
Assert-Ready (Test-AdaptiveRuntimeJsonSchema $manifestOne (Join-Path $RepositoryRoot $manifestSchema)) `
    'manifest_schema_invalid'
Assert-Ready (
    [string]$manifestOne.content_sha256 -ceq [string]$manifestTwo.content_sha256
) 'manifest_replay_hash_mismatch'
Assert-Ready (
    [string]$manifestOne.controller_uri -ceq 'http://10.10.99.176:5088' -and
    [string]$manifestOne.host_selection.placement_policy -ceq 'isolated-pair' -and
    [string]$manifestOne.host_selection.worker_selection_owner -ceq 'controller-owned' -and
    [string]$manifestOne.package_selection.package_target -ceq 'RawQuic' -and
    [string]$manifestOne.package_selection.implementation_id -ceq 'quic-dotnet-raw-dev' -and
    [string]$manifestOne.package_selection.suite_id -ceq 'quic-transport-v1-comparison' -and
    [string]$manifestOne.package_selection.scenario_id -ceq 'quic.transport.multiplex.100x64kb' -and
    [string]$manifestOne.package_selection.protocol -ceq 'quic' -and
    [string]$manifestOne.package_selection.test_executor_id -ceq 'quic-go-raw-load' -and
    [string]$manifestOne.package_selection.load_profile_id -ceq 'raw-quic-peer-confidence' -and
    [int]$manifestOne.package_selection.repetitions_per_cell -eq 2 -and
    $manifestOne.package_selection.package_backed_execution -eq $true -and
    $manifestOne.no_measurements -eq $true -and
    $manifestOne.timing_execution_authorized -eq $true
) 'manifest_controls_invalid'
Assert-Ready (
    (@($manifestOne.package_selection.component_package_references |
        ForEach-Object {
            "{0}|{1}|{2}" -f
                [string]$_.package_id,
                [string]$_.package_version,
                [string]$_.sha256
        }) -join ';') -ceq
    'org.protocol-lab.components.executor.quic-go-raw-load|0.1.17|e5a8c03cebd67a9722d47d080728fbb2c52d4dcdd34474880e179972d0df5167;org.protocol-lab.components.scenario.raw-quic-transport|0.1.20|b9ab49d83404b7dd4d377fb6ed04dd0594869f69c01c05082a28bbb5cb4a3bd2'
) 'manifest_component_package_references_invalid'
Assert-Ready (
    @($manifestOne.planned_runs).Count -eq 4 -and
    @($manifestOne.selected_cells).Count -eq 4 -and
    (Join-Values @($manifestOne.execution_sequence)) -ceq
        (Join-Values @('a0','a4','a3','a7'))
) 'manifest_run_shape_invalid'

$selectedPilot = Copy-Document $pilot
$selectedPilot.selected_cells = @('a0','a3','a4')
Assert-CompileRejects $selectedPilot 'missing-cell' 'selected_cells'

$orderPilot = Copy-Document $pilot
$orderPilot.execution_sequence = @('a0','a3','a4','a7')
Assert-CompileRejects $orderPilot 'wrong-order' 'execution_sequence'

$timingPilot = Copy-Document $pilot
$timingPilot.timing_execution_authorized = $false
Assert-CompileRejects $timingPilot 'timing-disabled' 'timing_execution_authorized'

$placementPilot = Copy-Document $pilot
$placementPilot.host_selection.placement_policy = 'single-node'
Assert-CompileRejects $placementPilot 'wrong-placement' 'host_selection/placement_policy'

$boundedPilot = Copy-Document $pilot
$boundedPilot.excluded_values.oversized_write_admission_quantum = @()
Assert-CompileRejects $boundedPilot 'missing-bounded-exclusion' 'excluded_values'

$cellPilot = Copy-Document $pilot
$cellPilot.cell_bindings[3].oversized_write_admission_quantum = 'bounded_multi_fragment'
Assert-CompileRejects $cellPilot 'bounded-cell' 'cell_bindings'

$componentPackagePilot = Copy-Document $pilot
$componentPackagePilot.package_selection.component_package_references[1].sha256 =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
Assert-CompileRejects $componentPackagePilot 'wrong-component-package' `
    'component_package_references'

$driverPath = Join-Path $PSScriptRoot 'Invoke-AdaptiveRuntimeAdmissionPerformancePilot.ps1'
$driverText = Get-Content -LiteralPath $driverPath -Raw
Assert-Ready (
    $driverText.Contains('$runJson.job.result.runId') -and
    $driverText.Contains('pilot_cell_job_failed') -and
    $driverText.Contains('Write-PilotState')
) 'driver_terminal_failure_retention_missing'
Assert-Ready (
    $driverText.Contains('independent_physical_hosts') -and
    $driverText.Contains('pilot_cell_topology_not_credible') -and
    $driverText.Contains('$Job.crossWorkerRun.target.nodeId') -and
    $driverText.Contains('$Job.crossWorkerRun.load.nodeId')
) 'driver_credible_topology_gate_missing'
Assert-Ready (
    $driverText.Contains('$sourceCommit.Substring(0, 8)')
) 'driver_source_commit_package_version_missing'
Assert-Ready (
    $driverText.Contains('$nodeResponse = Invoke-ControllerJson') -and
    $driverText.Contains('$nodes = @(foreach ($node in $nodeResponse)')
) 'driver_controller_node_response_flattening_missing'
Assert-Ready (
    $driverText.Contains(
        "'evidenceTier=offline-ml-two-host-vm'")
) 'driver_x64_worker_pair_capability_missing'
$packageBuilderText = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot '..\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1') -Raw
Assert-Ready (
    $packageBuilderText.Contains(
        'PROTOCOL_LAB_INCURSA_RAW_QUIC_EVIDENCE_MODE: bounded_aggregate')
) 'driver_bounded_aggregate_evidence_missing'
$runHelperText = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot '..\protocol-lab\Invoke-QuicDotNetProtocolLabRun.ps1') -Raw
Assert-Ready (
    $runHelperText.Contains('function ConvertTo-RequiredCapability') -and
    $runHelperText.Contains('$trimmed.IndexOf(''='')') -and
    $runHelperText.Contains('$_.IndexOf(''='') -lt 0') -and
    $runHelperText.Contains('ConvertTo-RequiredCapability -Capability $_')
) 'run_helper_valued_capability_missing'
$driverRoot = Join-Path $TemporaryRoot 'driver'
$planOnly = & $driverPath `
    -RepositoryRoot $RepositoryRoot `
    -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
    -OutputRoot $driverRoot
$planOnly = $planOnly | ConvertFrom-Json
Assert-Ready (
    [string]$planOnly.mode -ceq 'plan_only' -and
    [int]$planOnly.planned_run_count -eq 4 -and
    [int]$planOnly.submitted_job_count -eq 0
) 'driver_plan_only_invalid'

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    manifest_sha256 = [string]$manifestOne.content_sha256
    selected_cell_count = @($manifestOne.selected_cells).Count
    planned_run_count = @($manifestOne.planned_runs).Count
    actual_measurements_run = 0
} | ConvertTo-Json -Depth 8
