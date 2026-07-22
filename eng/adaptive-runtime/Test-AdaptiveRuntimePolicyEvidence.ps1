# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $LocalResultPath,

    [Parameter(Mandatory = $true)]
    [string[]] $EpochDatasetPath,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$localResultSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-local-result-v1.schema.json'
$epochDatasetSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-policy-epoch-dataset-v1.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$validatedLocalResults = [System.Collections.Generic.List[object]]::new()
$validatedEpochRows = [System.Collections.Generic.List[object]]::new()

function Test-SchemaDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Destination
    )

    try {
        $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
        $json = Get-Content -LiteralPath $resolvedPath -Raw
        if (-not ($json | Test-Json -SchemaFile $SchemaPath -ErrorAction Stop)) {
            $failures.Add("Schema validation failed: $resolvedPath")
            return
        }

        $document = $json | ConvertFrom-Json -Depth 100
        $Destination.Add([pscustomobject]@{
            Path = $resolvedPath
            Document = $document
        })
    }
    catch {
        $failures.Add("$Path`: $($_.Exception.Message)")
    }
}

foreach ($path in $LocalResultPath) {
    Test-SchemaDocument -Path $path -SchemaPath $localResultSchemaPath -Destination $validatedLocalResults
}

foreach ($path in $EpochDatasetPath) {
    Test-SchemaDocument -Path $path -SchemaPath $epochDatasetSchemaPath -Destination $validatedEpochRows
}

$localResultsByRunId = @{}
foreach ($item in $validatedLocalResults) {
    $document = $item.Document
    if ($localResultsByRunId.ContainsKey($document.runId)) {
        $failures.Add("Duplicate local-result runId '$($document.runId)'.")
        continue
    }

    $localResultsByRunId[$document.runId] = $document
}

foreach ($item in $validatedEpochRows) {
    $row = $item.Document
    if (-not $row.workloadAnalysisOnly.excludedFromProductionFeatures) {
        $failures.Add("Epoch row '$($row.rowId)' does not exclude workload identity from production features.")
    }

    if ($row.currentPolicyState.ruleVersion -ne $row.provenance.ruleVersion) {
        $failures.Add("Epoch row '$($row.rowId)' has inconsistent rule versions.")
    }

    if ($row.currentPolicyState.observationContractVersion -ne $row.provenance.observationContractVersion) {
        $failures.Add("Epoch row '$($row.rowId)' has inconsistent observation contract versions.")
    }

    if (-not $localResultsByRunId.ContainsKey($row.runId)) {
        $failures.Add("Epoch row '$($row.rowId)' cannot be joined to local-result runId '$($row.runId)'.")
        continue
    }

    $result = $localResultsByRunId[$row.runId]
    if ($row.campaignId -ne $result.campaignId -or $row.cellId -ne $result.cellId) {
        $failures.Add("Epoch row '$($row.rowId)' does not match its local-result campaign/cell identity.")
    }

    if ($row.provenance.resultSchemaVersion -ne $result.schemaVersion) {
        $failures.Add("Epoch row '$($row.rowId)' does not name its source result schema version.")
    }

    if ($row.provenance.ruleVersion -ne $result.policyConfiguration.ruleVersion -or
        $row.provenance.observationContractVersion -ne $result.policyConfiguration.observationContractVersion) {
        $failures.Add("Epoch row '$($row.rowId)' does not match its local-result policy contract versions.")
    }

    if ($row.currentPolicyState.appliedPolicy -ne $row.candidatePolicySelection.selectedPolicy) {
        $failures.Add("Epoch row '$($row.rowId)' does not keep the selected policy aligned with the applied policy snapshot.")
    }

    if ($result.mode -eq 'forced') {
        if ($row.candidatePolicySelection.selectionSource -ne 'forced') {
            $failures.Add("Epoch row '$($row.rowId)' from a forced result did not record selectionSource='forced'.")
        }

        if ($result.policyConfiguration.forcedPolicy -ne $null -and
            $row.currentPolicyState.appliedPolicy -ne $result.policyConfiguration.forcedPolicy) {
            $failures.Add("Epoch row '$($row.rowId)' does not match the forced policy recorded on the local result.")
        }

        $sourceSample = @($result.samples | Where-Object { $_.sampleId -eq $row.sampleId }) |
            Select-Object -First 1
        if ($null -eq $sourceSample) {
            $failures.Add("Epoch row '$($row.rowId)' does not resolve to source sample '$($row.sampleId)'.")
        }
        else {
            $treatmentProperty = $result.treatments.PSObject.Properties[[string] $sourceSample.treatment]
            if ($null -eq $treatmentProperty) {
                $failures.Add("Epoch row '$($row.rowId)' source sample names unknown treatment '$($sourceSample.treatment)'.")
            }
            elseif ($row.currentPolicyState.appliedPolicy -ne $treatmentProperty.Value.policy) {
                $failures.Add("Epoch row '$($row.rowId)' applied policy does not match source sample treatment '$($sourceSample.treatment)'.")
            }
        }
    }
    elseif ($result.mode -eq 'shadow' -and $row.candidatePolicySelection.selectionSource -ne 'shadow_rule') {
        $failures.Add("Epoch row '$($row.rowId)' from a shadow result did not record selectionSource='shadow_rule'.")
    }
}

$summary = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-evidence-validation-v1'
    valid = $failures.Count -eq 0
    localResultCount = $validatedLocalResults.Count
    epochRowCount = $validatedEpochRows.Count
    failures = @($failures)
}

$summary | ConvertTo-Json -Depth 10
if ($failures.Count -ne 0) {
    exit 1
}
