# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentEvidence.Common.psm1') -Force

function Read-ControlDocument([string] $RelativePath) {
    $document = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $RepositoryRoot $RelativePath)
    if (-not (Test-AdaptiveRuntimeDocumentHash $document)) {
        throw "admission_plan_source_hash_invalid:$RelativePath"
    }
    $document
}
function New-Trace {
    [pscustomobject][ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0241',
            'REQ-QUIC-CRT-0242',
            'REQ-QUIC-CRT-0243',
            'REQ-QUIC-CRT-0244',
            'REQ-QUIC-CRT-0245',
            'REQ-QUIC-CRT-0246'
        )
        architecture_ids = @('ARC-QUIC-CRT-0116')
        work_item_ids = @('WI-QUIC-CRT-0117')
        verification_ids = @('VER-QUIC-CRT-0118')
    }
}
function New-Cell(
    [string] $Id,
    [string] $Oversized,
    [string] $Batch,
    [string] $Buffer
) {
    $cell = [pscustomobject][ordered]@{
        cell_id = "cell.send_admission_composition.correctness.$Id"
        content_sha256 = '0' * 64
        oversized_write_admission_quantum = $Oversized
        application_send_batch_formation = $Batch
        buffer_copy_coalescing = $Buffer
    }
    [void](Set-AdaptiveRuntimeDocumentHash $cell)
    $cell
}

$axisCatalog = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-policy-axis-contracts-v2.json'
$behaviorCatalog = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-effective-behavior-catalog-v3.json'
$relationshipCatalog = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-policy-relationship-graph-v3.json'
$constraintCatalog = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-combination-constraint-catalog-v2.json'
$familyCatalog = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\adaptive-runtime-experiment-family-catalog-v5.json'
$batchReview = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\batch-single-eligible.review.json'
$bufferReview = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\buffer-memory-conservative.review.json'
$oversizedReview = Read-ControlDocument `
    'eng\adaptive-runtime\experiment-control\reviewed-proofs\oversized-single-fragment.review.json'

$plan = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-admission-correctness-plan-v1'
    document_id =
        'adaptive_runtime_send_admission_correctness_plan_v1'
    document_version = 1
    content_sha256 = '0' * 64
    authorization_id = 'send_admission_composition_correctness_v1'
    family_id = 'send_admission_composition'
    execution_purpose = 'correctness_only'
    allowed_axis_levels = @(
        [pscustomobject][ordered]@{
            axis_id = 'oversized_write_admission_quantum'
            levels = @('legacy_current','single_fragment')
        },
        [pscustomobject][ordered]@{
            axis_id = 'application_send_batch_formation'
            levels = @('legacy_current','single_eligible')
        },
        [pscustomobject][ordered]@{
            axis_id = 'buffer_copy_coalescing'
            levels = @('legacy_current','memory_conservative')
        }
    )
    fixed_axis_values = @(
        [pscustomobject][ordered]@{
            axis_id = 'application_send_turn_planning'
            configured_value = 'legacy_current'
        },
        [pscustomobject][ordered]@{
            axis_id = 'queued_send_burst_budget'
            configured_value = 'legacy_current'
        }
    )
    planned_cells = @(
        New-Cell 'a0' 'legacy_current' 'legacy_current' 'legacy_current'
        New-Cell 'a1' 'legacy_current' 'legacy_current' 'memory_conservative'
        New-Cell 'a2' 'legacy_current' 'single_eligible' 'legacy_current'
        New-Cell 'a3' 'legacy_current' 'single_eligible' 'memory_conservative'
        New-Cell 'a4' 'single_fragment' 'legacy_current' 'legacy_current'
        New-Cell 'a5' 'single_fragment' 'legacy_current' 'memory_conservative'
        New-Cell 'a6' 'single_fragment' 'single_eligible' 'legacy_current'
        New-Cell 'a7' 'single_fragment' 'single_eligible' 'memory_conservative'
    )
    source_document_refs = @(
        $axisCatalog,
        $behaviorCatalog,
        $relationshipCatalog,
        $constraintCatalog,
        $familyCatalog,
        $batchReview,
        $bufferReview,
        $oversizedReview
    ) | ForEach-Object { New-AdaptiveRuntimeDocumentRef $_ }
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = New-Trace
}
[void](Set-AdaptiveRuntimeDocumentHash $plan)
$schemaPath = Join-Path $RepositoryRoot `
    'schemas\adaptive-runtime-send-admission-correctness-plan-v1.schema.json'
if (-not (Test-AdaptiveRuntimeJsonSchema $plan $schemaPath)) {
    throw 'admission_correctness_plan_schema_invalid'
}
Write-AdaptiveRuntimeCanonicalDocument $plan $OutputPath
if ($PassThru) { $plan }
