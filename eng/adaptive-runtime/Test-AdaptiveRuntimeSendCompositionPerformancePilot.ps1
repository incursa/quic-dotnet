# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceRoot,
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $OutputPath = (Join-Path $EvidenceRoot `
        'validation\pilot-validation.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Get-CoefficientOfVariation([double[]] $Values) {
    if ($Values.Count -lt 2) {
        return 0.0
    }
    $mean = ($Values | Measure-Object -Average).Average
    if ($mean -eq 0) {
        return 0.0
    }
    $sum = 0.0
    foreach ($value in $Values) {
        $sum += [Math]::Pow($value - $mean, 2)
    }
    $standardDeviation = [Math]::Sqrt($sum / ($Values.Count - 1))
    return 100.0 * $standardDeviation / $mean
}

$root = (Resolve-Path $EvidenceRoot).Path
$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
$manifestPath = Join-Path $root 'compiled-manifest.json'
$rawPaths = @(Get-ChildItem (Join-Path $root 'raw') -File `
    -Filter '*.json' | Sort-Object Name | ForEach-Object FullName)
$validation = & (Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1') `
    -CampaignPath $CampaignPath `
    -ManifestPath $manifestPath `
    -RawEvidencePath $rawPaths `
    -RepositoryRoot $RepositoryRoot `
    -PassThru

$rows = @($rawPaths | ForEach-Object {
    $raw = Read-AdaptiveRuntimeJsonDocument $_
    if ([string]$raw.split -ne 'pilot') {
        return
    }
    [pscustomobject]@{
        workload_id = [string]$raw.workloadId
        cell_id = [string]$raw.cellId
        useful_bytes_per_second = [double]$raw.sample.usefulBytesPerSecond
        batch_distinct = [long]$raw.sample.evidence.batchDistinctOperations
        buffer_distinct = [long]$raw.sample.evidence.bufferDistinctOperations
        correctness = [bool]$raw.correctnessPassed
    }
})
$groups = @($rows | Group-Object workload_id, cell_id |
    ForEach-Object {
        [pscustomobject][ordered]@{
            workload_id = [string]$_.Group[0].workload_id
            cell_id = [string]$_.Group[0].cell_id
            repetitions = $_.Count
            useful_goodput_cv_percent = Get-CoefficientOfVariation (
                [double[]]@($_.Group.useful_bytes_per_second))
            correctness_passed = @($_.Group |
                Where-Object correctness -EQ $false).Count -eq 0
            batch_activation_observed =
                [long](($_.Group.batch_distinct |
                    Measure-Object -Sum).Sum) -gt 0
            buffer_activation_observed =
                [long](($_.Group.buffer_distinct |
                    Measure-Object -Sum).Sum) -gt 0
        }
    } | Sort-Object workload_id, cell_id)
$maximumCv = if ($groups.Count -eq 0) {
    [double]::PositiveInfinity
}
else {
    [double](($groups.useful_goodput_cv_percent |
        Measure-Object -Maximum).Maximum)
}
$activeGroups = @($groups |
    Where-Object workload_id -EQ 'pilot_segment_rich')
$activationPassed =
    @($activeGroups | Where-Object {
        $_.cell_id -in @('B', 'D') -and
        -not $_.batch_activation_observed
    }).Count -eq 0 -and
    @($activeGroups | Where-Object {
        $_.cell_id -eq 'C' -and
        -not $_.buffer_activation_observed
    }).Count -eq 0
$passed = $validation.raw_evidence_count -eq $rows.Count -and
    @($groups | Where-Object correctness_passed -EQ $false).Count -eq 0 -and
    $activationPassed -and
    $maximumCv -le [double]$campaign.early_termination.
        pilot_maximum_cv_percent

$result = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-composition-performance-pilot-validation-v1'
    passed = $passed
    maximum_cv_percent = $maximumCv
    permitted_maximum_cv_percent =
        [double]$campaign.early_termination.pilot_maximum_cv_percent
    activation_passed = $activationPassed
    raw_evidence_count = $rows.Count
    groups = $groups
}
$directory = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
New-Item -ItemType Directory -Force $directory | Out-Null
$result | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $OutputPath
if ($PassThru) {
    $result
}
else {
    $result | ConvertTo-Json -Depth 8
}
if (-not $passed) {
    exit 1
}
