# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $ValidationPath,
    [Parameter(Mandatory = $true)][string] $ManifestPath,
    [string] $RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
}
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$plan = Read-AdaptiveRuntimeJsonDocument -Path $PlanPath
$validation = Read-AdaptiveRuntimeJsonDocument -Path $ValidationPath
$manifest = Read-AdaptiveRuntimeJsonDocument -Path $ManifestPath
$codes = [System.Collections.Generic.List[string]]::new()

function Add-Code([string] $Code) {
    if (-not $codes.Contains($Code)) { $codes.Add($Code) }
}

$knownManifestFields = @(
    'schema_version','document_id','document_version','content_sha256','trace_references',
    'active_behavior_authorization','performance_acceptance_authorization',
    'compiled_execution_manifest_id','source_plan_ref','source_validation_ref','source_commit',
    'binary_provenance','runner_identity','host_fingerprint','host_capabilities','execution_order',
    'execution_order_policy','randomization_seed','executable_cells','capability_ineligible_cells',
    'excluded_cells','output_roots','retention_rules','expected_result_schemas','post_build_refs',
    'build_status','notes'
)
foreach ($property in $manifest.PSObject.Properties.Name) {
    if ($knownManifestFields -notcontains $property) { Add-Code 'unknown_field' }
}

try {
    $schemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-compiled-execution-manifest-v1.schema.json'
    if (-not (Test-AdaptiveRuntimeJsonSchema -Document $manifest -SchemaPath $schemaPath) -and
        -not $codes.Contains('unknown_field')) {
        Add-Code 'schema_validation_failed'
    }
}
catch {
    if (-not $codes.Contains('unknown_field')) { Add-Code 'schema_validation_failed' }
}

if (-not (Test-AdaptiveRuntimeDocumentHash -Document $manifest) -or
    -not (Test-AdaptiveRuntimeDocumentHash -Document $validation) -or
    -not (Test-AdaptiveRuntimeDocumentHash -Document $plan)) {
    Add-Code 'hash_mismatch'
}
if ($manifest.source_plan_ref.schema_version -ne $plan.schema_version -or
    [int]$manifest.source_plan_ref.document_version -ne [int]$plan.document_version -or
    $manifest.source_plan_ref.content_sha256 -ne $plan.content_sha256) {
    Add-Code 'stale_contract_reference'
}
if ($manifest.source_validation_ref.schema_version -ne $validation.schema_version -or
    [int]$manifest.source_validation_ref.document_version -ne [int]$validation.document_version -or
    $manifest.source_validation_ref.content_sha256 -ne $validation.content_sha256) {
    Add-Code 'stale_contract_reference'
}
if ($validation.validated_plan_ref.content_sha256 -ne $plan.content_sha256) {
    Add-Code 'stale_contract_reference'
}
if ($manifest.active_behavior_authorization -ne $false) {
    Add-Code 'active_behavior_unauthorized'
}
if ($manifest.performance_acceptance_authorization -ne $false) {
    Add-Code 'performance_acceptance_unauthorized'
}

[pscustomobject][ordered]@{
    valid = $codes.Count -eq 0
    error_codes = @($codes | Sort-Object)
    plan_hash = [string]$plan.content_sha256
    validation_hash = [string]$validation.content_sha256
    manifest_hash = [string]$manifest.content_sha256
}
