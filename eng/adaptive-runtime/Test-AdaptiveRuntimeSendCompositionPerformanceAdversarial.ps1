# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceRoot,
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$validatorPath = Join-Path $PSScriptRoot `
    'Test-AdaptiveRuntimeSendCompositionPerformance.ps1'
$projectionPath = Join-Path $PSScriptRoot `
    'New-AdaptiveRuntimeSendCompositionPerformanceProjection.ps1'
$manifestPath = Join-Path $EvidenceRoot 'compiled-manifest.json'
$rawPath = Get-ChildItem (Join-Path $EvidenceRoot 'raw') `
    -Filter '*.json' -File |
    Sort-Object Name |
    Select-Object -First 1 -ExpandProperty FullName
if ([string]::IsNullOrWhiteSpace($rawPath)) {
    throw 'performance_adversarial_raw_evidence_missing'
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'adaptive-runtime-performance-adversarial-{0}' -f
    [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temporaryRoot)
$results = [Collections.Generic.List[object]]::new()

function Add-Result([string] $CaseId, [string] $ExpectedCode, [string] $ActualCode) {
    [void]$results.Add([pscustomobject][ordered]@{
        case_id = $CaseId
        expected_code = $ExpectedCode
        actual_code = $ActualCode
        passed = $ActualCode.Contains(
            $ExpectedCode,
            [StringComparison]::Ordinal)
    })
}

function Invoke-ExpectedFailure(
    [string] $CaseId,
    [string] $ExpectedCode,
    [scriptblock] $Action
) {
    $actualCode = 'no_error'
    try {
        & $Action | Out-Null
    }
    catch {
        $actualCode = [string]$_.Exception.Message
    }
    Add-Result $CaseId $ExpectedCode $actualCode
}

function Write-MutatedDocument(
    [object] $Document,
    [string] $Name
) {
    $path = Join-Path $temporaryRoot $Name
    Write-AdaptiveRuntimeCanonicalDocument -Document $Document -Path $path
    return $path
}

try {
    $campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
    $manifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
    $raw = Read-AdaptiveRuntimeJsonDocument $rawPath

    $activeCampaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
    $activeCampaign.active_behavior_authorization = $true
    $activeCampaignPath = Write-MutatedDocument $activeCampaign 'campaign-active.json'
    Invoke-ExpectedFailure 'active_authorization' `
        'Expected "false"' {
        & $validatorPath -CampaignPath $activeCampaignPath `
            -RepositoryRoot $RepositoryRoot
    }

    $duplicateCellCampaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
    $duplicateCellCampaign.cells = @(
        $duplicateCellCampaign.cells
        $duplicateCellCampaign.cells[0]
    )
    $duplicateCellCampaignPath = Write-MutatedDocument `
        $duplicateCellCampaign 'campaign-duplicate-cell.json'
    Invoke-ExpectedFailure 'duplicate_cell' `
        'at most 4 items' {
        & $validatorPath -CampaignPath $duplicateCellCampaignPath `
            -RepositoryRoot $RepositoryRoot
    }

    $wrongProofCampaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
    $originalCampaignHash = [string]$wrongProofCampaign.content_sha256
    $originalProofHash =
        [string]$wrongProofCampaign.reviewed_proof_refs[0].content_sha256
    $wrongProofCampaign.reviewed_proof_refs[0].content_sha256 =
        ('0' * 64)
    $newCampaignHash = Get-AdaptiveRuntimeDocumentHash $wrongProofCampaign
    $wrongProofCampaignPath =
        Join-Path $temporaryRoot 'campaign-wrong-proof.json'
    $wrongProofCampaignText = [IO.File]::ReadAllText($CampaignPath).
        Replace($originalCampaignHash, $newCampaignHash).
        Replace($originalProofHash, ('0' * 64))
    [IO.File]::WriteAllText(
        $wrongProofCampaignPath,
        $wrongProofCampaignText,
        [Text.UTF8Encoding]::new($false))
    Invoke-ExpectedFailure 'wrong_proof_reference' `
        'performance_batch_proof_reference_mismatch' {
        & $validatorPath -CampaignPath $wrongProofCampaignPath `
            -RepositoryRoot $RepositoryRoot
    }

    $staleManifest = Read-AdaptiveRuntimeJsonDocument $manifestPath
    $staleManifest.binary_sha256 = ('1' * 64)
    $staleManifestPath = Write-MutatedDocument `
        $staleManifest 'manifest-stale-binary.json'
    Invoke-ExpectedFailure 'stale_binary_identity' `
        'performance_raw_manifest_identity_mismatch' {
        & $validatorPath -CampaignPath $CampaignPath `
            -ManifestPath $staleManifestPath `
            -RawEvidencePath $rawPath `
            -RepositoryRoot $RepositoryRoot
    }

    $wrongCellRaw = Read-AdaptiveRuntimeJsonDocument $rawPath
    $wrongCellRaw.batchValue = if ($wrongCellRaw.batchValue -ceq
        'legacy_current') { 'single_eligible' } else { 'legacy_current' }
    $wrongCellRawPath = Join-Path $temporaryRoot 'raw-wrong-cell.json'
    $wrongCellRaw | ConvertTo-Json -Depth 100 -Compress |
        Set-Content -LiteralPath $wrongCellRawPath -Encoding utf8NoBOM
    Invoke-ExpectedFailure 'wrong_runtime_cell' `
        'performance_raw_cell_value_mismatch' {
        & $validatorPath -CampaignPath $CampaignPath `
            -ManifestPath $manifestPath `
            -RawEvidencePath $wrongCellRawPath `
            -RepositoryRoot $RepositoryRoot
    }

    $wrongReleaseRaw = Read-AdaptiveRuntimeJsonDocument $rawPath
    $wrongReleaseRaw.sample.evidence.combinedOwnerReleases =
        [long]$wrongReleaseRaw.sample.evidence.combinedOwnerRents + 1
    $wrongReleaseRawPath = Join-Path $temporaryRoot 'raw-wrong-release.json'
    $wrongReleaseRaw | ConvertTo-Json -Depth 100 -Compress |
        Set-Content -LiteralPath $wrongReleaseRawPath -Encoding utf8NoBOM
    Invoke-ExpectedFailure 'duplicate_owner_release' `
        'performance_owner_release_invalid' {
        & $validatorPath -CampaignPath $CampaignPath `
            -ManifestPath $manifestPath `
            -RawEvidencePath $wrongReleaseRawPath `
            -RepositoryRoot $RepositoryRoot
    }

    $substitutionRoot = Join-Path $temporaryRoot 'substitution'
    [void](New-Item -ItemType Directory -Path (
        Join-Path $substitutionRoot 'raw'))
    Copy-Item -LiteralPath $manifestPath -Destination (
        Join-Path $substitutionRoot 'compiled-manifest.json')
    Copy-Item -LiteralPath $rawPath -Destination (
        Join-Path $substitutionRoot 'raw\observation.json')
    $substitutedRaw = Read-AdaptiveRuntimeJsonDocument (
        Join-Path $substitutionRoot 'raw\observation.json')
    $substitutedRaw.manifestSha256 = ('2' * 64)
    $substitutedRaw | ConvertTo-Json -Depth 100 -Compress |
        Set-Content -LiteralPath (
            Join-Path $substitutionRoot 'raw\observation.json') `
            -Encoding utf8NoBOM
    Invoke-ExpectedFailure 'projection_input_substitution' `
        'performance_raw_manifest_identity_mismatch' {
        & $projectionPath -EvidenceRoot $substitutionRoot `
            -CampaignPath $CampaignPath `
            -RepositoryRoot $RepositoryRoot
    }

    $failed = @($results | Where-Object passed -EQ $false)
    if ($failed.Count -ne 0) {
        throw ('performance_adversarial_case_failed:{0}' -f (
            @($failed | ForEach-Object {
                '{0}={1}' -f $_.case_id, $_.actual_code
            }) -join ','))
    }

    $result = [pscustomobject][ordered]@{
        case_count = $results.Count
        passed_count = @($results | Where-Object passed -EQ $true).Count
        failed_count = $failed.Count
        cases = @($results)
    }
    if ($PassThru) {
        return $result
    }
    $result | ConvertTo-Json -Depth 10
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
