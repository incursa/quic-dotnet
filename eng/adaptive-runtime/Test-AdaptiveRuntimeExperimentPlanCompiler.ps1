# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param([string] $RepositoryRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
}
Import-Module (Join-Path $PSScriptRoot 'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$fixtureRoot = Join-Path $RepositoryRoot 'tests\fixtures\adaptive-runtime-experiment-plan-compiler'
$catalogRoot = Join-Path $RepositoryRoot 'eng\adaptive-runtime\experiment-control'
$expectations = Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $fixtureRoot 'expectations.json')
$invalidExpectations = Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $fixtureRoot 'invalid\expectations.json')
$manifestExpectations = Read-AdaptiveRuntimeJsonDocument -Path (Join-Path $fixtureRoot 'invalid\manifest-expectations.json')
$failures = [System.Collections.Generic.List[string]]::new()
$validCount = 0
$warningCount = 0
$invalidPlanCount = 0
$invalidManifestCount = 0
$warningProofCount = 0

function Add-Failure([string] $Message) { $failures.Add($Message) }
function Get-PropertyValue([object] $Object, [string] $Name) {
    return $Object.PSObject.Properties[$Name].Value
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "incursa-adaptive-runtime-compiler-$([guid]::NewGuid().ToString('N'))"
[void](New-Item -ItemType Directory -Path $temporaryRoot)
try {
    foreach ($property in $expectations.PSObject.Properties | Sort-Object Name) {
        $relativePath = $property.Name.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $planPath = Join-Path $fixtureRoot $relativePath
        $expected = $property.Value
        $first = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
            -PlanPath $planPath -CatalogRoot $catalogRoot -RepositoryRoot $RepositoryRoot -PassThru
        $second = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
            -PlanPath $planPath -CatalogRoot $catalogRoot -RepositoryRoot $RepositoryRoot -PassThru
        $firstBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            (ConvertTo-AdaptiveRuntimeCanonicalJson $first -IncludeRootContentSha256))
        $secondBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            (ConvertTo-AdaptiveRuntimeCanonicalJson $second -IncludeRootContentSha256))
        if (-not [System.Linq.Enumerable]::SequenceEqual[byte]($firstBytes, $secondBytes)) {
            Add-Failure "$relativePath did not produce byte-equivalent repeated validation output."
        }
        if ($first.content_sha256 -ne $second.content_sha256) {
            Add-Failure "$relativePath did not produce identical repeated validation hashes."
        }
        if ($first.validation_classification -ne $expected.classification) {
            Add-Failure "$relativePath expected '$($expected.classification)' but got '$($first.validation_classification)'."
        }
        if ([int]$first.cell_counts.configured -ne [int]$expected.configured -or
            [int]$first.cell_counts.expected_effective -ne [int]$expected.expected_effective) {
            Add-Failure "$relativePath produced unexpected configured/effective cell counts."
        }
        if ($relativePath.StartsWith('warning')) {
            $warningCount++
            $observedWarnings = @($first.validation_warnings.warning_code | Sort-Object -Unique)
            foreach ($warningCode in @($expected.warning_codes)) {
                if ($observedWarnings -notcontains $warningCode) {
                    Add-Failure "$relativePath did not emit warning '$warningCode'."
                }
                else { $warningProofCount++ }
            }
        }
        else { $validCount++ }
    }

    foreach ($property in $invalidExpectations.PSObject.Properties | Sort-Object Name) {
        $planPath = Join-Path (Join-Path $fixtureRoot 'invalid') $property.Name
        $expected = $property.Value
        $selectedCatalogRoot = if ($expected.catalog -eq 'stage5') {
            Join-Path $fixtureRoot 'catalogs-stage5'
        } else { $catalogRoot }
        $result = & (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') `
            -PlanPath $planPath -CatalogRoot $selectedCatalogRoot -RepositoryRoot $RepositoryRoot `
            -PassThru -AllowInvalid
        if ($result.validation_classification -ne 'invalid') {
            Add-Failure "$($property.Name) was expected to be invalid but classified '$($result.validation_classification)'."
        }
        $observedCodes = @($result.validation_errors.error_code | Sort-Object -Unique)
        foreach ($expectedCode in @($expected.error_codes)) {
            if ($observedCodes -notcontains $expectedCode) {
                Add-Failure "$($property.Name) did not emit expected error '$expectedCode'; observed '$($observedCodes -join ',')'."
            }
        }
        $invalidPlanCount++
    }

    $validPlanPath = Join-Path $fixtureRoot 'valid\batch-actuation.plan.json'
    $validValidationPath = Join-Path $fixtureRoot 'valid\batch-actuation.validation.json'
    $validManifestPath = Join-Path $fixtureRoot 'valid\compiled-manifest.fixture.json'
    $validManifestResult = & (Join-Path $PSScriptRoot 'Test-AdaptiveRuntimeCompiledExecutionManifest.ps1') `
        -PlanPath $validPlanPath -ValidationPath $validValidationPath `
        -ManifestPath $validManifestPath -RepositoryRoot $RepositoryRoot
    if (-not $validManifestResult.valid) {
        Add-Failure "The valid compiled-manifest shape failed: $($validManifestResult.error_codes -join ',')."
    }

    foreach ($property in $manifestExpectations.PSObject.Properties | Sort-Object Name) {
        $manifestPath = $validManifestPath
        $validationPath = $validValidationPath
        if ($property.Name.EndsWith('.manifest.json')) {
            $manifestPath = Join-Path (Join-Path $fixtureRoot 'invalid') $property.Name
        }
        else {
            $validationPath = Join-Path (Join-Path $fixtureRoot 'invalid') $property.Name
        }
        $result = & (Join-Path $PSScriptRoot 'Test-AdaptiveRuntimeCompiledExecutionManifest.ps1') `
            -PlanPath $validPlanPath -ValidationPath $validationPath `
            -ManifestPath $manifestPath -RepositoryRoot $RepositoryRoot
        foreach ($expectedCode in @($property.Value)) {
            if (@($result.error_codes) -notcontains $expectedCode) {
                Add-Failure "$($property.Name) did not emit manifest/link error '$expectedCode'."
            }
        }
        $invalidManifestCount++
    }

    $plan = Read-AdaptiveRuntimeJsonDocument $validPlanPath
    $validation = Read-AdaptiveRuntimeJsonDocument $validValidationPath
    $manifest = Read-AdaptiveRuntimeJsonDocument $validManifestPath
    if ($plan.content_sha256 -eq $validation.content_sha256 -or
        $plan.content_sha256 -eq $manifest.content_sha256 -or
        $validation.content_sha256 -eq $manifest.content_sha256) {
        Add-Failure 'Plan, validation, and manifest hashes were not distinct.'
    }

    $selfHashPlan = Read-AdaptiveRuntimeJsonDocument $validPlanPath
    $originalPlanHash = Get-AdaptiveRuntimeDocumentHash $selfHashPlan
    $selfHashPlan.content_sha256 = ('9' * 64)
    if ((Get-AdaptiveRuntimeDocumentHash $selfHashPlan) -ne $originalPlanHash) {
        Add-Failure 'The root self-hash field affected its own hash input.'
    }

    $unorderedPlan = Read-AdaptiveRuntimeJsonDocument $validPlanPath
    $unorderedPlan.fixed_axis_ids = @($unorderedPlan.fixed_axis_ids | Sort-Object -Descending)
    if ((Get-AdaptiveRuntimeDocumentHash $unorderedPlan) -ne $originalPlanHash) {
        Add-Failure 'A semantically unordered axis array changed the canonical plan hash.'
    }

    $orderedPlan = Read-AdaptiveRuntimeJsonDocument $validPlanPath
    $orderedPlan.treatment_order = @($orderedPlan.treatment_order | Sort-Object -Descending)
    if ((Get-AdaptiveRuntimeDocumentHash $orderedPlan) -eq $originalPlanHash) {
        Add-Failure 'A semantically meaningful treatment-order change did not alter the plan hash.'
    }

    $meaningfulPlan = Read-AdaptiveRuntimeJsonDocument $validPlanPath
    $meaningfulPlan.treatments[1].candidate_value = 'legacy_current'
    if ((Get-AdaptiveRuntimeDocumentHash $meaningfulPlan) -eq $originalPlanHash) {
        Add-Failure 'A meaningful candidate-value change did not alter the plan hash.'
    }

    $substitutedManifest = Read-AdaptiveRuntimeJsonDocument $validManifestPath
    $substitutedManifest.source_validation_ref.content_sha256 = $plan.content_sha256
    Write-AdaptiveRuntimeCanonicalDocument $substitutedManifest (Join-Path $temporaryRoot 'substituted-manifest.json')
    $substitutionResult = & (Join-Path $PSScriptRoot 'Test-AdaptiveRuntimeCompiledExecutionManifest.ps1') `
        -PlanPath $validPlanPath -ValidationPath $validValidationPath `
        -ManifestPath (Join-Path $temporaryRoot 'substituted-manifest.json') -RepositoryRoot $RepositoryRoot
    if (@($substitutionResult.error_codes) -notcontains 'stale_contract_reference') {
        Add-Failure 'A plan hash substituted for a validation hash was not rejected.'
    }
}
finally {
    $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
    $resolvedSystemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolvedTemporaryRoot.StartsWith($resolvedSystemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedTemporaryRoot).StartsWith('incursa-adaptive-runtime-compiler-')) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}

$summary = [pscustomobject][ordered]@{
    valid = $failures.Count -eq 0
    valid_plan_count = $validCount
    warning_plan_count = $warningCount
    warning_proof_count = $warningProofCount
    invalid_plan_count = $invalidPlanCount
    invalid_manifest_or_validation_count = $invalidManifestCount
    canonical_serialization_byte_equivalent = -not ($failures | Where-Object { $_ -like '*byte-equivalent*' })
    repeated_hashes_identical = -not ($failures | Where-Object { $_ -like '*identical repeated*' })
    self_hash_excluded = -not ($failures | Where-Object { $_ -like '*self-hash*' })
    unordered_arrays_normalized = -not ($failures | Where-Object { $_ -like '*unordered axis*' })
    significant_order_preserved = -not ($failures | Where-Object { $_ -like '*treatment-order*' })
    meaningful_changes_alter_hashes = -not ($failures | Where-Object { $_ -like '*candidate-value*' })
    hash_roles_not_interchangeable = -not ($failures | Where-Object { $_ -like '*substituted*' -or $_ -like '*not distinct*' })
    failures = @($failures)
}
$summary | ConvertTo-Json -Depth 20 -Compress
if (-not $summary.valid) { exit 1 }
