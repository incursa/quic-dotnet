# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $TemporaryRoot =
        'C:\shared\temp\quic-dotnet\admission-performance-pairwise-request-tests'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$assertionCount = 0
function Assert-Test([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
    $script:assertionCount++
}

function Read-Repo([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function Join-Values([object[]] $Values) {
    [string]::Join('|', @($Values | ForEach-Object { [string]$_ }))
}

function New-HashLiteral([int] $Nibble) {
    return ([string]('{0:x1}' -f $Nibble)) * 64
}

function Write-JsonFile([string] $Path, [object] $Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 100),
        [System.Text.UTF8Encoding]::new($false))
}

[void](New-Item -ItemType Directory -Force -Path $TemporaryRoot)

$pilotPath = 'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json'
$pilot = Read-Repo $pilotPath
Assert-Test (Test-AdaptiveRuntimeDocumentHash $pilot) 'pairwise_request_test_pilot_hash_invalid'

$packageManifestPath = Join-Path $TemporaryRoot 'existing-packages.json'
$packageManifest = [pscustomobject][ordered]@{
    schemaVersion = 'adaptive-runtime-admission-performance-pairwise-package-manifest-v1'
    controllerUri = [string]$pilot.controller_uri
    experimentId = 'adaptive-runtime-send-admission-performance-pairwise'
    experimentVersion = '2026.08.03-test'
    sourceCommit = ('a' * 40)
    packageVersionPrefix = 'adaptive-runtime-admission-stage-e1-test'
    implementation_packages = @(
        foreach ($cellId in @('a0','a1','a2','a3','a4','a5','a6','a7')) {
            $ordinal = [int]$cellId.Substring(1)
            [pscustomobject][ordered]@{
                cell_id = $cellId
                package_ref = [pscustomobject][ordered]@{
                    packageId = 'quic-dotnet-raw-dev'
                    packageVersion = "adaptive-runtime-admission-stage-e1-test-$cellId"
                    sha256 = New-HashLiteral ($ordinal + 1)
                }
            }
        }
    )
}
Write-JsonFile -Path $packageManifestPath -Value $packageManifest

$outputRoot = Join-Path $TemporaryRoot 'output'
$driverPath = Join-Path $PSScriptRoot 'New-AdaptiveRuntimeAdmissionPerformancePairwiseRequest.ps1'
$result = & $driverPath `
    -RepositoryRoot $RepositoryRoot `
    -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
    -ControllerUri 'http://127.0.0.1:5088/' `
    -ExistingPackageManifestPath $packageManifestPath `
    -OutputRoot $outputRoot `
    -PassThru

Assert-Test (
    [string]$result.controller_uri -ceq 'http://127.0.0.1:5088' -and
    [string]$result.experiment_id -ceq 'adaptive-runtime-send-admission-performance-pairwise' -and
    [int]$result.candidate_arm_count -eq 4
) 'pairwise_request_driver_summary_invalid'
Assert-Test (
    (Join-Values @($result.pinned_arm_ids)) -ceq
        (Join-Values @('a0','a4','a3','a7'))
) 'pairwise_request_driver_pinned_ids_invalid'
Assert-Test (
    (Join-Values @($result.execution_sequence_arm_ids)) -ceq
        (Join-Values @('a0','a4','a3','a7'))
) 'pairwise_request_driver_execution_sequence_invalid'

$request = Get-Content -LiteralPath $result.request_path -Raw |
    ConvertFrom-Json -Depth 100 -DateKind String
Assert-Test (
    [string]$request.schemaVersion -ceq
        'protocol-lab-internal-experiment-pairwise-generation-request-v1' -and
    [string]$request.strategyId -ceq 'pairwise-greedy-v1' -and
    [string]$request.displayName -ceq
        'Adaptive runtime send admission performance pilot'
) 'pairwise_request_header_invalid'
Assert-Test (
    @($request.candidateArms).Count -eq 4 -and
    (Join-Values @($request.pinnedArmIds)) -ceq
        (Join-Values @('a0','a4','a3','a7')) -and
    (Join-Values @($request.executionSequenceArmIds)) -ceq
        (Join-Values @('a0','a4','a3','a7')) -and
    @($request.coverage.excludedPairs).Count -eq 0
) 'pairwise_request_candidate_pool_invalid'
Assert-Test (
    (Join-Values @($request.coverage.factors.factorId)) -ceq
        (Join-Values @(
            'oversized_write_admission_quantum',
            'send_composition_profile'
        ))
) 'pairwise_request_coverage_factors_invalid'

$candidateById = @{}
foreach ($candidate in @($request.candidateArms)) {
    $candidateById[[string]$candidate.armId] = $candidate
}

Assert-Test (
    [string]$candidateById['a0'].role -ceq 'baseline' -and
    [string]$candidateById['a3'].role -ceq 'candidate' -and
    [string]$candidateById['a7'].factorValues.send_composition_profile -ceq
        'single_eligible_memory_conservative' -and
    [string]$candidateById['a4'].factorValues.oversized_write_admission_quantum -ceq
        'single_fragment'
) 'pairwise_request_candidate_controls_invalid'
Assert-Test (
    @($candidateById['a0'].machineRoles).Count -eq 2 -and
    [string]$candidateById['a0'].placementPolicy -ceq 'isolated-pair' -and
    (Join-Values @($candidateById['a0'].machineRoles.roleId)) -ceq
        (Join-Values @('sut','load')) -and
    [string]$candidateById['a0'].machineRoles[0].resourceRequirements.capabilities[0].name -ceq 'role' -and
    [string]$candidateById['a0'].machineRoles[1].resourceRequirements.capabilities[1].value -ceq
        'offline-ml-two-host-vm'
) 'pairwise_request_machine_roles_invalid'

$runPlan = $candidateById['a7'].runPlan
Assert-Test (
    [string]$runPlan.schemaVersion -ceq 'protocol-lab-run-plan-v1' -and
    [string]$runPlan.targetMode -ceq 'implementation-resolved' -and
    [string]$runPlan.targetNetworkMode -ceq 'published-endpoint' -and
    [string]$runPlan.publicationIntent -ceq 'local-only' -and
    [int]$runPlan.repetitions -eq 2 -and
    [string]$runPlan.requiredCapabilities[0].name -ceq 'evidenceTier' -and
    [string]$runPlan.requiredCapabilities[0].value -ceq 'offline-ml-two-host-vm'
) 'pairwise_request_run_plan_controls_invalid'
Assert-Test (
    (Join-Values @($request.executionSequenceArmIds)) -ceq
        (Join-Values @('a0', 'a4', 'a3', 'a7'))
) 'pairwise_request_execution_sequence_bridge_invalid'
Assert-Test (
    @($runPlan.packages).Count -eq 3 -and
    [string]$runPlan.packages[0].packageId -ceq 'quic-dotnet-raw-dev' -and
    [string]$runPlan.packages[0].packageVersion -ceq
        'adaptive-runtime-admission-stage-e1-test-a7'
) 'pairwise_request_run_plan_packages_invalid'
Assert-Test (
    @($runPlan.traceReferences).Count -eq 9 -and
    [string]$runPlan.traceReferences[0] -like 'architecture:*' -and
    [string]$runPlan.traceReferences[-1] -like 'work-item:*'
) 'pairwise_request_trace_references_invalid'

$packageManifestOutput = Get-Content -LiteralPath $result.package_manifest_path -Raw |
    ConvertFrom-Json -Depth 100 -DateKind String
Assert-Test (
    @($packageManifestOutput.implementation_packages).Count -eq 4 -and
    [string]$packageManifestOutput.implementation_packages[3].cell_id -ceq 'a7'
) 'pairwise_request_package_manifest_invalid'

$guardStartPath = Join-Path $TemporaryRoot 'guard-start'
try {
    & $driverPath `
        -RepositoryRoot $RepositoryRoot `
        -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
        -ControllerUri 'http://127.0.0.1:5088/' `
        -ExistingPackageManifestPath $packageManifestPath `
        -OutputRoot $guardStartPath `
        -Start | Out-Null
    throw 'expected_start_guard_missing'
}
catch {
    Assert-Test (
        $_.Exception.Message -like '*pairwise_request_start_requires_import*'
    ) 'pairwise_request_start_requires_import_guard_invalid'
}

$guardConflictPath = Join-Path $TemporaryRoot 'guard-conflict'
try {
    & $driverPath `
        -RepositoryRoot $RepositoryRoot `
        -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
        -ControllerUri 'http://127.0.0.1:5088/' `
        -ExistingPackageManifestPath $packageManifestPath `
        -OutputRoot $guardConflictPath `
        -Import `
        -Start `
        -PublishPackages | Out-Null
    throw 'expected_start_publish_conflict_missing'
}
catch {
    Assert-Test (
        $_.Exception.Message -like '*pairwise_request_start_conflicts_publish_packages*'
    ) 'pairwise_request_start_publish_packages_guard_invalid'
}

$global:pairwiseRequestControllerCalls = [System.Collections.Generic.List[object]]::new()
function Invoke-RestMethod {
    param(
        [string] $Uri,
        [string] $Method,
        [string] $ContentType,
        [object] $Body,
        [object] $Form,
        [int] $TimeoutSec,
        [System.Management.Automation.ActionPreference] $ErrorAction
    )

    $parsedBody = $null
    if ($null -ne $Body) {
        $parsedBody = $Body | ConvertFrom-Json -Depth 100 -DateKind String
    }

    [void]$global:pairwiseRequestControllerCalls.Add([pscustomobject][ordered]@{
        uri = $Uri
        method = $Method
        contentType = $ContentType
        body = $parsedBody
        form = $Form
    })

    if ($Uri -like '*package-matrix/jobs*') {
        throw "unexpected_manual_job_endpoint:$Uri"
    }

    if ($Uri -like '*/api/lab/packages/upload') {
        throw "unexpected_package_upload:$Uri"
    }

    switch -Wildcard ($Uri) {
        '*pairwise-generation/preview' {
            return [pscustomobject][ordered]@{
                status = 'ready'
                canImport = $true
                requestContentHash = 'reviewed-request-hash'
                generatedManifestContentHash = 'reviewed-manifest-hash'
                preview = [pscustomobject][ordered]@{
                    compilationContentHash = 'reviewed-compilation-hash'
                }
                selectedArmIds = @('a0', 'a3', 'a4', 'a7')
            }
        }
        '*pairwise-generation/import' {
            return [pscustomobject][ordered]@{
                status = 'imported'
                manifestContentHash = 'reviewed-manifest-hash'
                compilationContentHash = 'reviewed-compilation-hash'
            }
        }
        '*/executions' {
            return [pscustomobject][ordered]@{
                executionId = 'experiment-execution-start-1'
                experimentId = 'adaptive-runtime-send-admission-performance-pairwise'
                experimentVersion = '2026.08.03-test'
                manifestContentHash = 'reviewed-manifest-hash'
                compilationContentHash = 'reviewed-compilation-hash'
                status = 'submitted'
                createdAt = '2026-08-04T21:00:00Z'
                updatedAt = '2026-08-04T21:00:01Z'
            }
        }
        default {
            throw "unexpected_controller_call:$Uri"
        }
    }
}

$startRoot = Join-Path $TemporaryRoot 'start'
$startResult = & $driverPath `
    -RepositoryRoot $RepositoryRoot `
    -PilotPath (Join-Path $RepositoryRoot $pilotPath) `
    -ControllerUri 'http://127.0.0.1:5088/' `
    -ExistingPackageManifestPath $packageManifestPath `
    -OutputRoot $startRoot `
    -Import `
    -Start `
    -PassThru

Remove-Item function:Invoke-RestMethod -ErrorAction SilentlyContinue

Assert-Test (
    @($global:pairwiseRequestControllerCalls).Count -eq 3 -and
    [string]$global:pairwiseRequestControllerCalls[0].uri -ceq 'http://127.0.0.1:5088/api/lab/experiments/pairwise-generation/preview' -and
    [string]$global:pairwiseRequestControllerCalls[1].uri -ceq 'http://127.0.0.1:5088/api/lab/experiments/pairwise-generation/import' -and
    [string]$global:pairwiseRequestControllerCalls[2].uri -ceq
        ("http://127.0.0.1:5088/api/lab/experiments/adaptive-runtime-send-admission-performance-pairwise/versions/{0}/executions" -f [string]$startResult.experiment_version)
) 'pairwise_request_start_endpoint_sequence_invalid'
Assert-Test (
    $null -eq $global:pairwiseRequestControllerCalls[2].body.executionId -and
    [string]$global:pairwiseRequestControllerCalls[2].body.expectedManifestContentHash -ceq 'reviewed-manifest-hash' -and
    [string]$global:pairwiseRequestControllerCalls[2].body.expectedCompilationContentHash -ceq 'reviewed-compilation-hash'
) 'pairwise_request_start_body_invalid'
Assert-Test (
    [bool]$startResult.start_completed -eq $true -and
    [string]$startResult.start_execution_id -ceq 'experiment-execution-start-1' -and
    [string]$startResult.start_status -ceq 'submitted'
) 'pairwise_request_start_result_summary_invalid'

$startRequest = Get-Content -LiteralPath $startResult.start_request_path -Raw |
    ConvertFrom-Json -Depth 100 -DateKind String
$startResponse = Get-Content -LiteralPath $startResult.start_response_path -Raw |
    ConvertFrom-Json -Depth 100 -DateKind String
Assert-Test (
    [string]$startRequest.schemaVersion -ceq 'admission-performance-pairwise-start-request-v1' -and
    $null -eq $startRequest.executionId -and
    [string]$startRequest.expectedManifestContentHash -ceq 'reviewed-manifest-hash' -and
    [string]$startRequest.expectedCompilationContentHash -ceq 'reviewed-compilation-hash'
) 'pairwise_request_start_request_artifact_invalid'
Assert-Test (
    [string]$startResponse.schemaVersion -ceq 'admission-performance-pairwise-start-response-v1' -and
    [string]$startResponse.execution_id -ceq 'experiment-execution-start-1' -and
    [string]$startResponse.status -ceq 'submitted'
) 'pairwise_request_start_response_artifact_invalid'

$driverText = Get-Content -LiteralPath $driverPath -Raw
Assert-Test (
    $driverText.Contains('/api/lab/experiments/pairwise-generation/preview') -and
    $driverText.Contains('/api/lab/experiments/pairwise-generation/import') -and
    $driverText.Contains('pairwise_request_start_requires_import') -and
    $driverText.Contains('pairwise_request_start_conflicts_publish_packages') -and
    $driverText.Contains('pairwise_request_start_sequence_mismatch') -and
    -not $driverText.Contains('/api/lab/package-matrix/jobs')
) 'pairwise_request_live_preview_import_start_path_missing'

[pscustomobject][ordered]@{
    assertion_count = $assertionCount
    candidate_arm_count = @($request.candidateArms).Count
    pinned_arm_count = @($request.pinnedArmIds).Count
    package_count = @($packageManifestOutput.implementation_packages).Count
    experiment_id = [string]$request.experimentId
    output_root = [string]$result.output_root
} | ConvertTo-Json -Depth 8
