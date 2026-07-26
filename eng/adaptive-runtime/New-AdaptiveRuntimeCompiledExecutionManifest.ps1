# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [Parameter(Mandatory = $true)][string] $ValidationPath,
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [Parameter(Mandatory = $true)][string] $RunnerPath,
    [Parameter(Mandatory = $true)][string] $RunnerVersion,
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [string[]] $ResolvedCapability = @(),
    [string[]] $OutputRoot = @('artifacts/adaptive-runtime/dry-run'),
    [string[]] $RetentionRule = @('retain_plan_validation_manifest_and_failures'),
    [string[]] $ExpectedResultSchema = @(
        'adaptive-runtime-policy-local-result-v1',
        'adaptive-runtime-unified-epoch-raw-v13'
    ),
    [string] $BinaryRole = 'test_binary',
    [string] $RepositoryRoot,
    [switch] $AllowDirtySource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
}
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$plan = Read-AdaptiveRuntimeJsonDocument -Path $PlanPath
$validation = Read-AdaptiveRuntimeJsonDocument -Path $ValidationPath
if (-not (Test-AdaptiveRuntimeDocumentHash -Document $plan)) {
    throw 'The source-plan hash is invalid.'
}
if (-not (Test-AdaptiveRuntimeDocumentHash -Document $validation)) {
    throw 'The plan-validation hash is invalid.'
}
if ($validation.validated_plan_ref.content_sha256 -ne $plan.content_sha256 -or
    $validation.validated_plan_ref.schema_version -ne $plan.schema_version) {
    throw 'The validation result does not identify the exact source plan.'
}
if ($validation.validation_classification -in @('invalid','blocked')) {
    throw "A '$($validation.validation_classification)' validation result cannot produce a compiled manifest."
}
if ($plan.active_behavior_authorization -ne $false -or $validation.active_behavior_authorization -ne $false) {
    throw 'Active behavior authorization must remain false.'
}
if ($plan.performance_acceptance_authorization -ne $false -or
    $validation.performance_acceptance_authorization -ne $false) {
    throw 'Performance acceptance authorization must remain false.'
}

$sourceCommit = (& git -C $RepositoryRoot rev-parse --verify HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'The exact committed source identity could not be resolved.'
}
$dirtyEntries = @(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
    throw 'The source worktree state could not be resolved.'
}
if ($dirtyEntries.Count -gt 0 -and -not $AllowDirtySource) {
    throw 'The compiled manifest requires a clean committed source worktree.'
}

$resolvedBinaryPath = (Resolve-Path -LiteralPath $BinaryPath).Path
$resolvedRunnerPath = (Resolve-Path -LiteralPath $RunnerPath).Path
$binaryHash = (Get-FileHash -LiteralPath $resolvedBinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
$runnerHash = (Get-FileHash -LiteralPath $resolvedRunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()

$capabilityById = [ordered]@{}
foreach ($capability in $ResolvedCapability) {
    $parts = $capability -split '=', 2
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$' -or
        $parts[1] -notin @('available','unavailable','unknown')) {
        throw "Resolved capability '$capability' must use capability_id=available|unavailable|unknown."
    }
    $capabilityById[$parts[0]] = $parts[1]
}
foreach ($expected in @($plan.expected_capabilities)) {
    if (-not $capabilityById.Contains([string]$expected.capability_id)) {
        $capabilityById[[string]$expected.capability_id] = 'unknown'
    }
}
$resolvedCapabilities = @($capabilityById.Keys | Sort-Object | ForEach-Object {
    [pscustomobject][ordered]@{
        capability_id = $_
        state = $capabilityById[$_]
    }
})

$machineName = [Environment]::MachineName
$os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription.Trim()
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$processorCount = [Environment]::ProcessorCount
$physicalHostId = $null
$vmId = $null
if ($IsWindows) {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        if ($computerSystem.HypervisorPresent) {
            $vmId = [string]$product.UUID
            $physicalHostId = 'unavailable_from_guest'
        }
        else {
            $physicalHostId = [string]$product.UUID
        }
    }
    catch {
        $physicalHostId = 'unresolved'
    }
}
$fingerprintSource = @(
    $machineName,
    $os,
    $architecture,
    $processorCount,
    $physicalHostId,
    $vmId
) -join '|'
$fingerprintId = "host.$((Get-AdaptiveRuntimeSha256 -Text $fingerprintSource).Substring(0,24))"

function Convert-ManifestCell {
    param([object] $Cell, [string] $ExecutionState)
    return [pscustomobject][ordered]@{
        cell_id = [string]$Cell.cell_id
        cell_order = [int]$Cell.cell_order
        axis_ids = @($Cell.axis_ids)
        treatment_ids = @($Cell.treatment_ids)
        execution_state = $ExecutionState
        notes = @("Derived from validation state '$($Cell.execution_state)'.")
    }
}

$executableCells = @($validation.expanded_planned_cells |
    Where-Object execution_state -in @('executable','retained_for_verification') |
    Sort-Object cell_order, cell_id |
    ForEach-Object {
        $state = if ($_.execution_state -eq 'retained_for_verification') {
            'retained_for_verification'
        } else { 'executable' }
        Convert-ManifestCell -Cell $_ -ExecutionState $state
    })
$capabilityIneligibleCells = @($validation.expanded_planned_cells |
    Where-Object execution_state -eq 'capability_pending' |
    Sort-Object cell_order, cell_id |
    ForEach-Object { Convert-ManifestCell -Cell $_ -ExecutionState 'capability_ineligible' })
$excludedCells = @($validation.expanded_planned_cells |
    Where-Object execution_state -notin @('executable','retained_for_verification','capability_pending') |
    Sort-Object cell_order, cell_id |
    ForEach-Object { Convert-ManifestCell -Cell $_ -ExecutionState 'excluded' })

$orderPolicy = [string](Get-AdaptiveRuntimeJsonProperty $plan 'execution_order_policy')
if ([string]::IsNullOrWhiteSpace($orderPolicy)) { $orderPolicy = 'deterministic' }
$executionOrder = @($executableCells.cell_id)
$randomizationSeed = Get-AdaptiveRuntimeJsonProperty $plan 'randomization_seed'
if ($orderPolicy -eq 'randomized') {
    if ($null -eq $randomizationSeed) {
        throw 'Randomized execution order requires a source-plan randomization_seed.'
    }
    $random = [System.Random]::new([int]$randomizationSeed)
    for ($i = $executionOrder.Count - 1; $i -gt 0; $i--) {
        $j = $random.Next($i + 1)
        $temporary = $executionOrder[$i]
        $executionOrder[$i] = $executionOrder[$j]
        $executionOrder[$j] = $temporary
    }
}

$hostFlags = [System.Collections.Generic.List[string]]::new()
$hostFlags.Add('source_plan_valid')
$hostFlags.Add('post_build_refs_present')
if ($executableCells.Count -gt 0) { $hostFlags.Add('single_axis_executable') }
if ($capabilityIneligibleCells.Count -gt 0) {
    $hostFlags.Add('current_combination_blocked')
    $hostFlags.Add('multi_axis_blocked')
}

$manifest = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-compiled-execution-manifest-v1'
    document_id = "manifest.$($plan.experiment_plan_id).$($sourceCommit.Substring(0,12))"
    document_version = 1
    content_sha256 = ('0' * 64)
    trace_references = New-AdaptiveRuntimeTraceReferences
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    compiled_execution_manifest_id = "manifest.$($plan.experiment_plan_id).$($sourceCommit.Substring(0,12)).v1"
    source_plan_ref = [ordered]@{
        document_id = [string]$plan.document_id
        schema_version = [string]$plan.schema_version
        document_version = [int]$plan.document_version
        content_sha256 = [string]$plan.content_sha256
    }
    source_validation_ref = [ordered]@{
        document_id = [string]$validation.document_id
        schema_version = [string]$validation.schema_version
        document_version = [int]$validation.document_version
        content_sha256 = [string]$validation.content_sha256
    }
    source_commit = $sourceCommit
    binary_provenance = @([pscustomobject][ordered]@{
        role = $BinaryRole
        path = $resolvedBinaryPath
        content_sha256 = $binaryHash
    })
    runner_identity = [ordered]@{
        runner_id = 'adaptive_runtime_experiment_plan_compiler'
        version = $RunnerVersion
        path = $resolvedRunnerPath
        content_sha256 = $runnerHash
    }
    host_fingerprint = [ordered]@{
        fingerprint_id = $fingerprintId
        machine_name = $machineName
        os = $os
        architecture = $architecture
        processor_count = $processorCount
    }
    host_capabilities = [ordered]@{
        host_id = $fingerprintId
        os = $os
        architecture = $architecture
        processor_count = $processorCount
        capability_flags = @($hostFlags | Sort-Object -Unique)
        resolved_capabilities = $resolvedCapabilities
    }
    execution_order = $executionOrder
    execution_order_policy = $orderPolicy
    executable_cells = $executableCells
    capability_ineligible_cells = $capabilityIneligibleCells
    excluded_cells = $excludedCells
    output_roots = @($OutputRoot)
    retention_rules = @($RetentionRule)
    expected_result_schemas = @($ExpectedResultSchema)
    post_build_refs = @(
        [pscustomobject][ordered]@{
            document_id = [string]$plan.document_id
            schema_version = [string]$plan.schema_version
            document_version = [int]$plan.document_version
            content_sha256 = [string]$plan.content_sha256
        },
        [pscustomobject][ordered]@{
            document_id = [string]$validation.document_id
            schema_version = [string]$validation.schema_version
            document_version = [int]$validation.document_version
            content_sha256 = [string]$validation.content_sha256
        }
    )
    build_status = if ($executableCells.Count -gt 0) { 'compiled' }
        elseif ($capabilityIneligibleCells.Count -gt 0) { 'blocked_by_capability' }
        else { 'deferred' }
    notes = @(
        'Dry-run manifest only; it does not authorize or launch execution.',
        'Performance measurement and active behavior remain unauthorized.'
    )
}
$reviewedProofValue = Get-AdaptiveRuntimeJsonProperty $plan `
    'reviewed_actuation_proof_refs'
$reviewedProofRefs = if ($null -eq $reviewedProofValue) {
    @()
}
else {
    @($reviewedProofValue)
}
if ($plan.experiment_type -eq 'interaction_screen' -and
    (Get-AdaptiveRuntimeJsonProperty $plan 'execution_purpose') -eq
        'correctness_only' -and
    $executableCells.Count -eq 1 -and
    $reviewedProofRefs.Count -eq 2) {
    $manifest | Add-Member -NotePropertyName `
        correctness_interaction_authorization -NotePropertyValue (
        [pscustomobject][ordered]@{
            execution_purpose = 'correctness_only'
            family_id = [string]$plan.family_id
            cell_id = [string]$executableCells[0].cell_id
            axis_values = @($plan.treatments | Where-Object {
                $null -ne (Get-AdaptiveRuntimeJsonProperty $_ 'forced_value')
            } | Sort-Object axis_id | ForEach-Object {
                [pscustomobject][ordered]@{
                    axis_id = [string]$_.axis_id
                    policy_value = [string]$_.forced_value
                }
            })
            reviewed_proof_refs = @($reviewedProofRefs)
            relationship_graph_version = 2
            constraint_catalog_version = 1
            maximum_behavior_distinct_axes = 2
            active_behavior_authorization = $false
            performance_acceptance_authorization = $false
        })
}
if (-not [string]::IsNullOrWhiteSpace($physicalHostId)) {
    $manifest.host_fingerprint.physical_host_id = $physicalHostId
}
if (-not [string]::IsNullOrWhiteSpace($vmId)) {
    $manifest.host_fingerprint.vm_id = $vmId
}
if ($orderPolicy -eq 'randomized') {
    $manifest | Add-Member -NotePropertyName randomization_seed -NotePropertyValue ([int]$randomizationSeed)
}

[void](Set-AdaptiveRuntimeDocumentHash -Document $manifest)
$manifestSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-compiled-execution-manifest-v1.schema.json'
if (-not (Test-AdaptiveRuntimeJsonSchema -Document $manifest -SchemaPath $manifestSchemaPath)) {
    throw 'Compiler defect: generated manifest failed adaptive-runtime-compiled-execution-manifest-v1.'
}
Write-AdaptiveRuntimeCanonicalDocument -Document $manifest -Path $OutputPath
$manifest
