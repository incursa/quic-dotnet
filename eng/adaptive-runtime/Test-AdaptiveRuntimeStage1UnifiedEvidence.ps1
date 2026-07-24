# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $UnifiedEpochPath,

    [Parameter(Mandatory = $true)]
    [string[]] $AxisDecisionPath,

    [string] $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

$unifiedEpochSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-unified-epoch-v1.schema.json'
$axisDecisionSchemaPath = Join-Path $RepositoryRoot 'schemas\adaptive-runtime-stage1-axis-decision-v1.schema.json'
$failures = [System.Collections.Generic.List[string]]::new()
$validatedEpochRows = [System.Collections.Generic.List[object]]::new()
$validatedAxisDecisions = [System.Collections.Generic.List[object]]::new()
$epochRowsById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$axisRecordsByJoinKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$axisDecisionsByJoinKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$variedAxisCounts = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)

$canonicalAxisOrder = @(
    'application_send_turn_planning',
    'application_send_batch_formation',
    'queued_send_burst_budget',
    'oversized_write_admission_quantum'
)

$allowedValuesByAxis = @{
    application_send_turn_planning = @('legacy_current', 'conservative')
    application_send_batch_formation = @('legacy_current', 'single_eligible')
    queued_send_burst_budget = @('legacy_current', 'single_datagram')
    oversized_write_admission_quantum = @('legacy_current', 'single_fragment', 'bounded_multi_fragment')
}

$expectedBoundaryByAxis = @{
    application_send_turn_planning = 'actor_turn'
    application_send_batch_formation = 'packet_plan'
    queued_send_burst_budget = 'actor_turn'
    oversized_write_admission_quantum = 'logical_write_admission'
}

$expectedLatchLifetimeByAxis = @{
    application_send_turn_planning = 'actor_turn'
    application_send_batch_formation = 'packet_plan'
    queued_send_burst_budget = 'actor_turn'
    oversized_write_admission_quantum = 'logical_write'
}

$expectedRecordKindByAxis = @{
    application_send_turn_planning = 'construction'
    application_send_batch_formation = 'packet_plan'
    queued_send_burst_budget = 'actor_turn'
    oversized_write_admission_quantum = 'logical_write'
}

function Test-AllowedPolicyValue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $AxisId,

        [AllowNull()][object] $Value
    )

    $normalizedValue = Get-NullableString -Value $Value
    if ($null -eq $normalizedValue) {
        return $true
    }

    return $allowedValuesByAxis[$AxisId] -contains $normalizedValue
}

function Get-JoinKey {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CampaignId,

        [Parameter(Mandatory = $true)]
        [string] $RunId,

        [Parameter(Mandatory = $true)]
        [string] $CellId,

        [Parameter(Mandatory = $true)]
        [string] $SampleId,

        [Parameter(Mandatory = $true)]
        [string] $ConnectionKey,

        [Parameter(Mandatory = $true)]
        [long] $EpochIndex,

        [Parameter(Mandatory = $true)]
        [string] $AxisId,

        [Parameter(Mandatory = $true)]
        [long] $DecisionSequence
    )

    return [string]::Join(
        '|',
        @(
            $CampaignId,
            $RunId,
            $CellId,
            $SampleId,
            $ConnectionKey,
            $EpochIndex,
            $AxisId,
            $DecisionSequence
        ))
}

function Get-NullableString {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text
}

function Read-ValidatedEvidenceRecords {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $resolvedSchemaPath = Resolve-AdaptiveRuntimePath -Path $SchemaPath
    $content = Get-Content -LiteralPath $resolvedPath -Raw
    $sourceSha256 = Get-FileSha256Hex -Path $resolvedPath

    try {
        $document = $content | ConvertFrom-Json -Depth 100
        $records = if ($document -is [Array]) {
            @($document)
        }
        else {
            @($document)
        }
    }
    catch {
        $records = [System.Collections.Generic.List[object]]::new()
        $lineNumber = 0
        foreach ($line in ($content -split '\r?\n')) {
            $lineNumber++
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            try {
                [void] $records.Add(($line | ConvertFrom-Json -Depth 100))
            }
            catch {
                throw "Line $lineNumber is not valid JSON: $($_.Exception.Message)"
            }
        }
    }

    $result = [System.Collections.Generic.List[object]]::new()
    $recordIndex = 0
    foreach ($record in $records) {
        $json = $record | ConvertTo-Json -Depth 100 -Compress
        if (-not ($json | Test-Json -SchemaFile $resolvedSchemaPath -ErrorAction Stop)) {
            throw "Record $recordIndex failed schema validation."
        }

        [void] $result.Add([pscustomobject]@{
            Path = $resolvedPath
            Sha256 = $sourceSha256
            RecordIndex = $recordIndex
            Document = $record
        })
        $recordIndex++
    }

    return $result
}

foreach ($path in $UnifiedEpochPath) {
    try {
        foreach ($document in (Read-ValidatedEvidenceRecords -Path $path -SchemaPath $unifiedEpochSchemaPath)) {
            [void] $validatedEpochRows.Add($document)
        }
    }
    catch {
        $failures.Add("Unified epoch '$path' failed schema validation: $($_.Exception.Message)")
    }
}

foreach ($path in $AxisDecisionPath) {
    try {
        foreach ($document in (Read-ValidatedEvidenceRecords -Path $path -SchemaPath $axisDecisionSchemaPath)) {
            [void] $validatedAxisDecisions.Add($document)
        }
    }
    catch {
        $failures.Add("Axis decision '$path' failed schema validation: $($_.Exception.Message)")
    }
}

if ($validatedEpochRows.Count -eq 0) {
    $failures.Add('At least one schema-valid Stage 1 unified epoch row is required.')
}

if ($validatedAxisDecisions.Count -eq 0) {
    $failures.Add('At least one schema-valid Stage 1 axis decision row is required.')
}

foreach ($item in $validatedEpochRows) {
    $row = $item.Document
    $rowId = [string] $row.rowId

    if ($epochRowsById.ContainsKey($rowId)) {
        $failures.Add("Unified epoch rowId '$rowId' is duplicated.")
        continue
    }

    $epochRowsById[$rowId] = $row

    $forcedCount = 0
    for ($index = 0; $index -lt $canonicalAxisOrder.Count; $index++) {
        $axisRecord = $row.axisRecords[$index]
        $axisId = [string] $axisRecord.axisId
        $expectedAxisId = $canonicalAxisOrder[$index]

        if ($axisId -ne $expectedAxisId) {
            $failures.Add("Unified epoch row '$rowId' expected axisRecords[$index]='$expectedAxisId' but found '$axisId'.")
            continue
        }

        if ($axisRecord.decisionBoundary -ne $expectedBoundaryByAxis[$axisId]) {
            $failures.Add("Unified epoch row '$rowId' axis '$axisId' recorded decisionBoundary '$($axisRecord.decisionBoundary)' instead of '$($expectedBoundaryByAxis[$axisId])'.")
        }

        if ($axisRecord.latch.lifetime -ne $expectedLatchLifetimeByAxis[$axisId]) {
            $failures.Add("Unified epoch row '$rowId' axis '$axisId' recorded latch lifetime '$($axisRecord.latch.lifetime)' instead of '$($expectedLatchLifetimeByAxis[$axisId])'.")
        }

        foreach ($propertyName in @('forcedValue', 'shadowRecommendation', 'selectedValue', 'appliedValue')) {
            $value = Get-NullableString -Value $axisRecord.$propertyName
            if (-not (Test-AllowedPolicyValue -AxisId $axisId -Value $value)) {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' recorded invalid $propertyName '$value'.")
            }
        }

        if ($null -ne (Get-NullableString -Value $axisRecord.forcedValue)) {
            $forcedCount++
            if (-not $variedAxisCounts.ContainsKey($axisId)) {
                $variedAxisCounts.Add($axisId, 0)
            }
            $variedAxisCounts[$axisId]++

            if (-not [bool] $axisRecord.safetyOverride.applied -and
                [string] $axisRecord.appliedValue -ne [string] $axisRecord.forcedValue) {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' forcedValue '$($axisRecord.forcedValue)' does not match appliedValue '$($axisRecord.appliedValue)'.")
            }

            if (-not [bool] $axisRecord.safetyOverride.applied -and
                [string] $axisRecord.selectedValue -ne [string] $axisRecord.forcedValue) {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' forcedValue '$($axisRecord.forcedValue)' does not match selectedValue '$($axisRecord.selectedValue)'.")
            }

            if ([string] $axisRecord.selectionSource -eq 'shadow_rule') {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' cannot use selectionSource='shadow_rule' while a forcedValue is present.")
            }

            if (-not [bool] $axisRecord.safetyOverride.applied -and
                [string] $axisRecord.selectionSource -ne 'forced') {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' has a forcedValue without selectionSource='forced'.")
            }
        }
        elseif ([string] $axisRecord.appliedValue -ne 'legacy_current') {
            $failures.Add("Unified epoch row '$rowId' unforced axis '$axisId' applied '$($axisRecord.appliedValue)' instead of 'legacy_current'.")
        }

        if ([string] $axisRecord.selectionSource -eq 'forced' -and
            $null -eq (Get-NullableString -Value $axisRecord.forcedValue)) {
            $failures.Add("Unified epoch row '$rowId' axis '$axisId' used selectionSource='forced' without forcedValue.")
        }

        $shadowRecommendation = Get-NullableString -Value $axisRecord.shadowRecommendation
        if ([string] $axisRecord.selectionSource -eq 'shadow_rule') {
            if ($null -eq $shadowRecommendation) {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' used selectionSource='shadow_rule' without shadowRecommendation.")
            }

            if ([string] $axisRecord.appliedValue -ne 'legacy_current') {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' allowed shadow selection to change appliedValue '$($axisRecord.appliedValue)'.")
            }
        }

        if ([bool] $axisRecord.safetyOverride.applied) {
            if ([string] $axisRecord.selectionSource -ne 'safety_override') {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' marked safetyOverride.applied=true without selectionSource='safety_override'.")
            }

            if ($null -eq (Get-NullableString -Value $axisRecord.safetyOverride.reasonCode)) {
                $failures.Add("Unified epoch row '$rowId' axis '$axisId' applied a safety override without reasonCode.")
            }
        }
        elseif ([string] $axisRecord.selectionSource -eq 'safety_override') {
            $failures.Add("Unified epoch row '$rowId' axis '$axisId' used selectionSource='safety_override' while safetyOverride.applied=false.")
        }
        elseif ($null -ne (Get-NullableString -Value $axisRecord.safetyOverride.reasonCode)) {
            $failures.Add("Unified epoch row '$rowId' axis '$axisId' recorded a safety-override reason while safetyOverride.applied=false.")
        }

        $joinKey = Get-JoinKey `
            -CampaignId ([string] $row.campaignId) `
            -RunId ([string] $row.runId) `
            -CellId ([string] $row.cellId) `
            -SampleId ([string] $row.sampleId) `
            -ConnectionKey ([string] $row.connectionKey) `
            -EpochIndex ([long] $row.epochIndex) `
            -AxisId $axisId `
            -DecisionSequence ([long] $axisRecord.decisionSequence)

        if ($axisRecordsByJoinKey.ContainsKey($joinKey)) {
            $failures.Add("Unified epoch join key '$joinKey' is duplicated across rows.")
            continue
        }

        $axisRecordsByJoinKey[$joinKey] = [pscustomobject]@{
            Row = $row
            RowId = $rowId
            AxisRecord = $axisRecord
        }
    }

    if ($forcedCount -gt 1) {
        $failures.Add("Unified epoch row '$rowId' forced $forcedCount Stage 1 axes; at most one is allowed.")
    }
}

foreach ($item in $validatedAxisDecisions) {
    $decision = $item.Document
    $joinKey = Get-JoinKey `
        -CampaignId ([string] $decision.campaignId) `
        -RunId ([string] $decision.runId) `
        -CellId ([string] $decision.cellId) `
        -SampleId ([string] $decision.sampleId) `
        -ConnectionKey ([string] $decision.connectionKey) `
        -EpochIndex ([long] $decision.epochIndex) `
        -AxisId ([string] $decision.axisId) `
        -DecisionSequence ([long] $decision.decisionSequence)

    if ($axisDecisionsByJoinKey.ContainsKey($joinKey)) {
        $failures.Add("Axis decision join key '$joinKey' is duplicated.")
        continue
    }

    $axisDecisionsByJoinKey[$joinKey] = $decision

    $axisId = [string] $decision.axisId
    foreach ($propertyName in @('forcedValue', 'selectedValue', 'appliedValue')) {
        $value = Get-NullableString -Value $decision.$propertyName
        if (-not (Test-AllowedPolicyValue -AxisId $axisId -Value $value)) {
            $failures.Add("Axis decision '$joinKey' recorded invalid $propertyName '$value'.")
        }
    }

    if ([string] $decision.recordKind -ne $expectedRecordKindByAxis[$axisId]) {
        $failures.Add("Axis decision '$joinKey' recorded recordKind '$($decision.recordKind)' instead of '$($expectedRecordKindByAxis[$axisId])'.")
    }

    switch ([string] $decision.recordKind) {
        'packet_plan' {
            if ($null -eq (Get-NullableString -Value $decision.planKey)) {
                $failures.Add("Axis decision '$joinKey' requires planKey for recordKind='packet_plan'.")
            }

            if ($null -ne (Get-NullableString -Value $decision.operationKey)) {
                $failures.Add("Axis decision '$joinKey' must not set operationKey for recordKind='packet_plan'.")
            }
        }
        'logical_write' {
            if ($null -eq (Get-NullableString -Value $decision.operationKey)) {
                $failures.Add("Axis decision '$joinKey' requires operationKey for recordKind='logical_write'.")
            }
        }
        'construction' {
            if ($null -ne (Get-NullableString -Value $decision.operationKey) -or
                $null -ne (Get-NullableString -Value $decision.planKey)) {
                $failures.Add("Axis decision '$joinKey' must not set operationKey or planKey for recordKind='construction'.")
            }
        }
        'actor_turn' {
            if ($null -ne (Get-NullableString -Value $decision.operationKey) -or
                $null -ne (Get-NullableString -Value $decision.planKey)) {
                $failures.Add("Axis decision '$joinKey' must not set operationKey or planKey for recordKind='actor_turn'.")
            }
        }
    }

    if (-not $axisRecordsByJoinKey.ContainsKey($joinKey)) {
        $failures.Add("Axis decision '$joinKey' does not resolve to a unified epoch axis record.")
        continue
    }

    $rowContext = $axisRecordsByJoinKey[$joinKey]
    $row = $rowContext.Row
    $axisRecord = $rowContext.AxisRecord

    if ([string] $decision.epochRowId -ne [string] $row.rowId) {
        $failures.Add("Axis decision '$joinKey' points to epochRowId '$($decision.epochRowId)' but unified row is '$($row.rowId)'.")
    }

    foreach ($propertyName in @('forcedValue', 'selectedValue', 'appliedValue')) {
        $decisionValue = Get-NullableString -Value $decision.$propertyName
        $rowValue = Get-NullableString -Value $axisRecord.$propertyName
        if ($decisionValue -ne $rowValue) {
            $failures.Add("Axis decision '$joinKey' $propertyName '$decisionValue' does not match unified row value '$rowValue'.")
        }
    }

    $rowPlanKey = Get-NullableString -Value $axisRecord.latch.planKey
    $rowOperationKey = Get-NullableString -Value $axisRecord.latch.operationKey
    if ((Get-NullableString -Value $decision.planKey) -ne $rowPlanKey) {
        $failures.Add("Axis decision '$joinKey' planKey '$($decision.planKey)' does not match unified row latch.planKey '$rowPlanKey'.")
    }

    if ((Get-NullableString -Value $decision.operationKey) -ne $rowOperationKey) {
        $failures.Add("Axis decision '$joinKey' operationKey '$($decision.operationKey)' does not match unified row latch.operationKey '$rowOperationKey'.")
    }

}

foreach ($joinKey in $axisRecordsByJoinKey.Keys) {
    if (-not $axisDecisionsByJoinKey.ContainsKey($joinKey)) {
        $failures.Add("Unified epoch axis record '$joinKey' has no matching axis decision record.")
    }
}

$summary = [ordered]@{
    schemaVersion = 'adaptive-runtime-stage1-unified-evidence-validation-v1'
    valid = $failures.Count -eq 0
    unifiedEpochRowCount = $validatedEpochRows.Count
    uniqueUnifiedEpochRowCount = $epochRowsById.Count
    axisRecordCount = $axisRecordsByJoinKey.Count
    axisDecisionRowCount = $validatedAxisDecisions.Count
    uniqueAxisDecisionCount = $axisDecisionsByJoinKey.Count
    variedAxisEpochCounts = [ordered]@{
        application_send_turn_planning = if ($variedAxisCounts.ContainsKey('application_send_turn_planning')) {
            $variedAxisCounts['application_send_turn_planning']
        } else { 0 }
        application_send_batch_formation = if ($variedAxisCounts.ContainsKey('application_send_batch_formation')) {
            $variedAxisCounts['application_send_batch_formation']
        } else { 0 }
        queued_send_burst_budget = if ($variedAxisCounts.ContainsKey('queued_send_burst_budget')) {
            $variedAxisCounts['queued_send_burst_budget']
        } else { 0 }
        oversized_write_admission_quantum = if ($variedAxisCounts.ContainsKey('oversized_write_admission_quantum')) {
            $variedAxisCounts['oversized_write_admission_quantum']
        } else { 0 }
    }
    failures = @($failures)
}

$summary | ConvertTo-Json -Depth 10
if ($failures.Count -ne 0) {
    exit 1
}
