# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $BinaryPath = $PSCommandPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Condition([bool] $Condition, [string] $Code) {
    if (-not $Condition) { throw $Code }
}
function Copy-Document([object] $Value) {
    $Value | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100 -DateKind String
}

$planPath = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-send-admission-correctness-plan-v1.json'
$compiler = Join-Path $PSScriptRoot `
    'Compile-AdaptiveRuntimeAdmissionCorrectnessPlan.ps1'
$planGenerator = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeAdmissionCorrectnessPlan.ps1'
$plan = Read-AdaptiveRuntimeJsonDocument $planPath
$sourceCommit = 'a' * 40
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "quic-admission-authorization-$([Guid]::NewGuid().ToString('N'))")
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $regeneratedPlanPath = Join-Path $tempRoot 'regenerated-plan.json'
    $regeneratedPlan = & $planGenerator `
        -OutputPath $regeneratedPlanPath `
        -RepositoryRoot $RepositoryRoot `
        -PassThru
    Assert-Condition (
        (Get-Content -LiteralPath $regeneratedPlanPath -Raw) -ceq
        (Get-Content -LiteralPath $planPath -Raw)
    ) 'admission_plan_not_deterministic'

    $positiveRoot = Join-Path $tempRoot 'positive'
    $positive = & $compiler `
        -PlanPath $planPath `
        -SourceCommit $sourceCommit `
        -BinaryPath $BinaryPath `
        -OutputRoot $positiveRoot `
        -RepositoryRoot $RepositoryRoot `
        -PassThru
    Assert-Condition (
        [string]$positive.validation.validation_classification -ceq
            'valid_exact_eight_cell_correctness' -and
        @($positive.manifest.compiled_cell_refs).Count -eq 8 -and
        @($positive.authorization.authorized_cell_refs).Count -eq 8 -and
        [string]$positive.authorization.authorization_id -ceq
            'send_admission_composition_correctness_v1' -and
        $positive.authorization.active_behavior_authorization -eq $false -and
        $positive.authorization.performance_acceptance_authorization -eq
            $false
    ) 'admission_positive_authorization_invalid'

    $repeatRoot = Join-Path $tempRoot 'repeat'
    $null = & $compiler `
        -PlanPath $planPath `
        -SourceCommit $sourceCommit `
        -BinaryPath $BinaryPath `
        -OutputRoot $repeatRoot `
        -RepositoryRoot $RepositoryRoot
    foreach ($name in @(
        'plan-validation.json',
        'compiled-manifest.json',
        'correctness-authorization.json'
    )) {
        Assert-Condition (
            (Get-Content -LiteralPath (
                Join-Path $positiveRoot $name) -Raw) -ceq
            (Get-Content -LiteralPath (
                Join-Path $repeatRoot $name) -Raw)
        ) "admission_compilation_not_deterministic:$name"
    }

    $negativeCases = @(
        [pscustomobject]@{
            Name = 'bounded_multi_fragment'
            Mutate = {
                param($value)
                $value.planned_cells[4].
                    oversized_write_admission_quantum =
                        'bounded_multi_fragment'
            }
        },
        [pscustomobject]@{
            Name = 'queued_nonlegacy'
            Mutate = {
                param($value)
                $value.fixed_axis_values[1].configured_value =
                    'single_datagram'
            }
        },
        [pscustomobject]@{
            Name = 'fourth_behavior_distinct_axis'
            Mutate = {
                param($value)
                $value.allowed_axis_levels += [pscustomobject]@{
                    axis_id = 'queued_send_burst_budget'
                    levels = @('legacy_current','single_datagram')
                }
            }
        },
        [pscustomobject]@{
            Name = 'unreviewed_value'
            Mutate = {
                param($value)
                $value.planned_cells[2].
                    application_send_batch_formation = 'conservative'
            }
        },
        [pscustomobject]@{
            Name = 'stale_proof_hash'
            Mutate = {
                param($value)
                $value.source_document_refs[-1].content_sha256 = 'f' * 64
            }
        },
        [pscustomobject]@{
            Name = 'stale_family_catalog'
            Mutate = {
                param($value)
                @($value.source_document_refs | Where-Object {
                    $_.document_id -ceq
                        'adaptive_runtime_experiment_family_catalog_v5'
                })[0].content_sha256 = 'f' * 64
            }
        },
        [pscustomobject]@{
            Name = 'stale_constraint_catalog'
            Mutate = {
                param($value)
                @($value.source_document_refs | Where-Object {
                    $_.document_id -ceq
                        'adaptive_runtime_combination_constraint_catalog_v2'
                })[0].content_sha256 = 'f' * 64
            }
        },
        [pscustomobject]@{
            Name = 'ninth_cell'
            Mutate = {
                param($value)
                $value.planned_cells +=
                    Copy-Document $value.planned_cells[0]
            }
        },
        [pscustomobject]@{
            Name = 'active_authorization'
            Mutate = {
                param($value)
                $value.active_behavior_authorization = $true
            }
        },
        [pscustomobject]@{
            Name = 'performance_authorization'
            Mutate = {
                param($value)
                $value.performance_acceptance_authorization = $true
            }
        },
        [pscustomobject]@{
            Name = 'wildcard_family'
            Mutate = {
                param($value)
                $value.family_id = '*'
            }
        },
        [pscustomobject]@{
            Name = 'cell_hash_mismatch'
            Mutate = {
                param($value)
                $value.planned_cells[0].content_sha256 = 'f' * 64
            }
        }
    )
    $rejected = [Collections.Generic.List[string]]::new()
    foreach ($case in $negativeCases) {
        $mutated = Copy-Document $plan
        & $case.Mutate $mutated
        [void](Set-AdaptiveRuntimeDocumentHash $mutated)
        $mutatedPath = Join-Path $tempRoot "$($case.Name).json"
        Write-AdaptiveRuntimeCanonicalDocument $mutated $mutatedPath
        try {
            $null = & $compiler `
                -PlanPath $mutatedPath `
                -SourceCommit $sourceCommit `
                -BinaryPath $BinaryPath `
                -OutputRoot (Join-Path $tempRoot $case.Name) `
                -RepositoryRoot $RepositoryRoot
        }
        catch {
            $rejected.Add($case.Name)
        }
    }
    Assert-Condition (
        $rejected.Count -eq $negativeCases.Count
    ) 'admission_negative_case_not_rejected'

    [pscustomobject][ordered]@{
        result = 'passed'
        authorization_id =
            [string]$positive.authorization.authorization_id
        planned_cell_count = @($plan.planned_cells).Count
        compiled_cell_count =
            @($positive.manifest.compiled_cell_refs).Count
        deterministic_output_count = 3
        negative_case_count = $rejected.Count
        negative_case_ids = @($rejected)
        active_behavior_authorized = $false
        performance_measurement_ran = $false
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
