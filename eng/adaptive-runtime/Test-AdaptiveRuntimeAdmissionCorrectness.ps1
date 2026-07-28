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
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Assert-Condition([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}

function Copy-Document([object] $Value) {
    $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100 -DateKind String
}

$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-send-admission-correctness'
$capturePath = Join-Path $fixtureRoot 'runtime-capture.json'
$planPath = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-correctness-plan-v1.json'
$validationPath = Join-Path $fixtureRoot 'control\plan-validation.json'
$manifestPath = Join-Path $fixtureRoot 'control\compiled-manifest.json'
$authorizationPath = Join-Path $fixtureRoot `
    'control\correctness-authorization.json'
$generator = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeAdmissionCorrectnessEvidence.ps1'
$catalog = Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v3.json')
$compatibilityCatalog = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $RepositoryRoot `
        'eng\adaptive-runtime\experiment-control\adaptive-runtime-classification-compatibility-catalog-v1.json')
$capture = Read-AdaptiveRuntimeJsonDocument $capturePath

$positiveAssertions = 0
$cellRoots = @(Get-ChildItem -LiteralPath (Join-Path $fixtureRoot 'cells') `
    -Directory | Sort-Object Name)
Assert-Condition ($cellRoots.Count -eq 8) 'admission_fixture_cell_count'
$positiveAssertions++
$allOperationKeys = @()
foreach ($cellRoot in $cellRoots) {
    $files = @(Get-ChildItem -LiteralPath $cellRoot.FullName -File -Recurse)
    Assert-Condition ($files.Count -eq 18) `
        "admission_fixture_chain_count:$($cellRoot.Name)"
    $positiveAssertions++
    foreach ($file in $files) {
        $document = Read-AdaptiveRuntimeJsonDocument $file.FullName
        Assert-Condition (Test-AdaptiveRuntimeDocumentHash $document) `
            "admission_fixture_hash_invalid:$($file.FullName)"
        $positiveAssertions++
    }
    $inputRoot = Join-Path $cellRoot.FullName 'inputs'
    $evidence = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputRoot 'operation_evidence.json')
    $behavior = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputRoot 'behavior_materialization.json')
    $outcome = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputRoot 'outcome_materialization.json')
    $classifications = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $inputRoot 'classifications.json')
    $projection = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $cellRoot.FullName 'expected\analytical_projection.json')
    $cellResult = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $cellRoot.FullName 'expected\cell_correctness_result.json')
    $recomputedBehavior = New-AdaptiveRuntimeBehaviorMaterializationV3 `
        $evidence $catalog
    $recomputedOutcome = New-AdaptiveRuntimeOutcomeMaterializationV2 `
        $evidence $catalog $classifications
    Assert-Condition (
        (ConvertTo-AdaptiveRuntimeCanonicalJson $behavior) -ceq
        (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedBehavior)
    ) "admission_behavior_not_recomputable:$($cellRoot.Name)"
    $positiveAssertions++
    Assert-Condition (
        (ConvertTo-AdaptiveRuntimeCanonicalJson $outcome) -ceq
        (ConvertTo-AdaptiveRuntimeCanonicalJson $recomputedOutcome)
    ) "admission_outcome_not_recomputable:$($cellRoot.Name)"
    $positiveAssertions++
    Assert-Condition (
        [string]$projection.behavior_materialization_sha256 -ceq
            [string]$behavior.content_sha256 -and
        [string]$projection.outcome_materialization_sha256 -ceq
            [string]$outcome.content_sha256 -and
        [int]$projection.performance_metric_count -eq 0
    ) "admission_projection_binding_invalid:$($cellRoot.Name)"
    $positiveAssertions++
    Assert-Condition (
        [string]$cellResult.result -ceq 'correctness_passed' -and
        @($cellResult.failed_assertions).Count -eq 0 -and
        $cellResult.active_behavior_authorization -eq $false -and
        $cellResult.performance_acceptance_authorization -eq $false
    ) "admission_cell_result_not_passed:$($cellRoot.Name)"
    $positiveAssertions++
    foreach ($property in $cellResult.axis_values.psobject.Properties) {
        if ([string]$property.Value -cne 'legacy_current') {
            Assert-Condition (
                [long]$cellResult.behavior_distinct_actuations.
                    $($property.Name) -eq 1
            ) "admission_nonlegacy_not_actuated:$(
                $cellRoot.Name):$($property.Name)"
            $positiveAssertions++
        }
    }
    $allOperationKeys += @($evidence.operations | ForEach-Object {
        (New-AdaptiveRuntimeOperationIdentity $_).operation_key
    })
}
Assert-Condition (
    $allOperationKeys.Count -eq 24 -and
    @($allOperationKeys | Sort-Object -Unique).Count -eq 24
) 'admission_cross_cell_composite_identity_leakage'
$positiveAssertions++

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "quic-admission-correctness-$([Guid]::NewGuid().ToString('N'))")
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$negativeCaseCount = 0
try {
    $replayRoot = Join-Path $tempRoot 'replay'
    $replayCapturePath = Join-Path $tempRoot 'replay-capture.json'
    Copy-Item -LiteralPath $capturePath -Destination $replayCapturePath
    $replay = & $generator `
        -CapturePath $replayCapturePath `
        -PlanPath $planPath `
        -ValidationPath $validationPath `
        -ManifestPath $manifestPath `
        -AuthorizationPath $authorizationPath `
        -OutputRoot $replayRoot `
        -RepositoryRoot $RepositoryRoot `
        -PassThru
    Assert-Condition (
        $replay.correctness_passed_count -eq 8 -and
        $replay.activation_incomplete_count -eq 0 -and
        $replay.correctness_failed_count -eq 0 -and
        $replay.execution_blocked_count -eq 0
    ) 'admission_replay_result_mismatch'
    $positiveAssertions++
    $fixtureFiles = @(Get-ChildItem -LiteralPath (
        Join-Path $fixtureRoot 'cells') -File -Recurse)
    foreach ($fixtureFile in $fixtureFiles) {
        $relative = [IO.Path]::GetRelativePath(
            (Join-Path $fixtureRoot 'cells'), $fixtureFile.FullName)
        $replayFile = Join-Path $replayRoot $relative
        Assert-Condition (
            (Test-Path -LiteralPath $replayFile -PathType Leaf) -and
            (Get-Content -LiteralPath $fixtureFile.FullName -Raw) -ceq
            (Get-Content -LiteralPath $replayFile -Raw)
        ) "admission_replay_not_deterministic:$relative"
        $positiveAssertions++
    }

    $negativeCases = @(
        [pscustomobject]@{
            id = 'active_authorization'
            mutate = { param($d) $d.active_behavior_authorization = $true }
        },
        [pscustomobject]@{
            id = 'performance_authorization'
            mutate = {
                param($d)
                $d.performance_acceptance_authorization = $true
            }
        },
        [pscustomobject]@{
            id = 'fourth_axis'
            mutate = {
                param($d)
                $d.cells[0].configured_values.queued_send_burst_budget =
                    'single_datagram'
            }
        },
        [pscustomobject]@{
            id = 'missing_cell'
            mutate = { param($d) $d.cells = @($d.cells | Select-Object -Skip 1) }
        },
        [pscustomobject]@{
            id = 'duplicate_run'
            mutate = { param($d) $d.cells[1].run_id = $d.cells[0].run_id }
        },
        [pscustomobject]@{
            id = 'duplicate_operation_identity'
            mutate = {
                param($d)
                $d.cells[1].operations[0].operation_identity =
                    $d.cells[0].operations[0].operation_identity
            }
        },
        [pscustomobject]@{
            id = 'mismatched_applied_value'
            mutate = {
                param($d)
                $target = @($d.cells | Where-Object {
                    [string]$_.cell_id -ceq
                        'cell.send_admission_composition.correctness.a7'
                })[0]
                $operation = @($target.operations | Where-Object {
                    [string]$_.axis_id -ceq
                        'application_send_batch_formation'
                })[0]
                $operation.evidence.applied_value = 'legacy_current'
            }
        },
        [pscustomobject]@{
            id = 'unknown_mechanism'
            mutate = {
                param($d)
                $target = @($d.cells | Where-Object {
                    [string]$_.cell_id -ceq
                        'cell.send_admission_composition.correctness.a7'
                })[0]
                $operation = @($target.operations | Where-Object {
                    [string]$_.axis_id -ceq
                        'oversized_write_admission_quantum'
                })[0]
                $operation.evidence.mechanism_event = 'UnknownAdmission'
            }
        },
        [pscustomobject]@{
            id = 'missing_operation'
            mutate = {
                param($d)
                $d.cells[0].operations =
                    @($d.cells[0].operations | Select-Object -Skip 1)
            }
        },
        [pscustomobject]@{
            id = 'stale_binary'
            mutate = { param($d) $d.binary_sha256 = 'f' * 64 }
        }
    )
    foreach ($case in $negativeCases) {
        $mutated = Copy-Document $capture
        & $case.mutate $mutated
        $mutated.content_sha256 = '0' * 64
        $casePath = Join-Path $tempRoot "$($case.id).json"
        $caseOutput = Join-Path $tempRoot "$($case.id)-output"
        $mutated | ConvertTo-Json -Depth 100 |
            Set-Content -LiteralPath $casePath -Encoding utf8
        $rejected = $false
        try {
            $null = & $generator `
                -CapturePath $casePath `
                -PlanPath $planPath `
                -ValidationPath $validationPath `
                -ManifestPath $manifestPath `
                -AuthorizationPath $authorizationPath `
                -OutputRoot $caseOutput `
                -RepositoryRoot $RepositoryRoot `
                -PassThru
        } catch {
            $rejected = $true
        }
        Assert-Condition $rejected `
            "admission_negative_not_rejected:$($case.id)"
        $negativeCaseCount++
    }
} finally {
    $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
    $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedTemp.StartsWith(
        $systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedTemp) -like
            'quic-admission-correctness-*') {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}

[pscustomobject][ordered]@{
    fixture_cell_count = 8
    immutable_document_count = 144
    operation_identity_count = 24
    positive_assertion_count = $positiveAssertions
    negative_case_count = $negativeCaseCount
    correctness_passed_count = 8
    activation_incomplete_count = 0
    correctness_failed_count = 0
    execution_blocked_count = 0
    performance_acceptance_authorization = $false
    active_behavior_authorization = $false
} | ConvertTo-Json -Depth 10
