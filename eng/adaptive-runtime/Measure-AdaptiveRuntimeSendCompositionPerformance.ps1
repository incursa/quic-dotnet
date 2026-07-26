# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceRoot,
    [string] $ProjectionPath = (Join-Path $EvidenceRoot `
        'performance-projection.json'),
    [string] $CampaignPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-composition-performance-campaign-v1.json'),
    [string] $OutputPath = (Join-Path $EvidenceRoot `
        'performance-analysis.json'),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-AnalysisCondition([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Get-Median([double[]] $Values) {
    if ($Values.Count -eq 0) {
        return 0.0
    }
    $ordered = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if ($ordered.Count % 2 -eq 1) {
        return [double]$ordered[$middle]
    }
    return ([double]$ordered[$middle - 1] +
        [double]$ordered[$middle]) / 2.0
}

function Get-PercentDifference([double] $Treatment, [double] $Baseline) {
    if ($Baseline -eq 0) {
        return 0.0
    }
    return 100.0 * ($Treatment - $Baseline) / $Baseline
}

function Get-BootstrapInterval(
    [double[]] $Values,
    [int] $Iterations,
    [int] $Seed
) {
    if ($Values.Count -eq 0) {
        return @(0.0, 0.0)
    }
    $random = [Random]::new($Seed)
    $samples = [double[]]::new($Iterations)
    for ($iteration = 0; $iteration -lt $Iterations; $iteration++) {
        $draw = [double[]]::new($Values.Count)
        for ($index = 0; $index -lt $Values.Count; $index++) {
            $draw[$index] = $Values[$random.Next($Values.Count)]
        }
        $samples[$iteration] = Get-Median $draw
    }
    [Array]::Sort($samples)
    $low = [int][Math]::Floor(0.025 * ($samples.Length - 1))
    $high = [int][Math]::Ceiling(0.975 * ($samples.Length - 1))
    return @($samples[$low], $samples[$high])
}

function Get-EffectClassification(
    [string] $EffectId,
    [double] $Median,
    [double] $Low,
    [double] $High,
    [double] $PracticalThreshold
) {
    if ($EffectId -ceq 'expected_equivalence_d_vs_b' -and
        [Math]::Abs($Median) -lt $PracticalThreshold) {
        return 'expected_equivalent'
    }
    if ($Low -le 0 -and $High -ge 0) {
        return 'uncertain'
    }
    if ([Math]::Abs($Median) -lt $PracticalThreshold) {
        return 'practically_trivial'
    }
    if ($Median -gt 0) {
        return 'material_positive'
    }
    return 'material_negative'
}

function New-DocumentReference([object] $Document) {
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [long]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

$resolvedRoot = (Resolve-Path $EvidenceRoot).Path
$campaign = Read-AdaptiveRuntimeJsonDocument $CampaignPath
$projection = Read-AdaptiveRuntimeJsonDocument $ProjectionPath
Assert-AnalysisCondition (Test-AdaptiveRuntimeDocumentHash $campaign) `
    'performance_analysis_campaign_hash_mismatch'
Assert-AnalysisCondition (Test-AdaptiveRuntimeDocumentHash $projection) `
    'performance_analysis_projection_hash_mismatch'
Assert-AnalysisCondition (
    Test-AdaptiveRuntimeJsonSchema $projection (
        Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-send-composition-performance-projection-v1.schema.json')
) 'performance_analysis_projection_schema_invalid'

$rows = [Collections.Generic.List[object]]::new()
foreach ($reference in @($projection.raw_evidence_refs)) {
    $path = Join-Path $resolvedRoot ([string]$reference.relative_path)
    Assert-AnalysisCondition (Test-Path -LiteralPath $path) `
        'performance_analysis_raw_missing'
    Assert-AnalysisCondition (
        (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            [string]$reference.content_sha256
    ) 'performance_analysis_raw_hash_mismatch'
    $raw = Read-AdaptiveRuntimeJsonDocument $path
    [void]$rows.Add([pscustomobject][ordered]@{
        workload_id = [string]$raw.workloadId
        split = [string]$raw.split
        cell_id = [string]$raw.cellId
        block = [long]$raw.block
        classification = [string]$reference.classification
        useful_bytes_per_second = [double]$raw.sample.usefulBytesPerSecond
        p95_milliseconds = [double]$raw.sample.latencyP95Milliseconds
        cpu_microseconds_per_operation =
            [double]$raw.sample.cpuMicrosecondsPerOperation
        allocated_bytes_per_operation =
            [double]$raw.sample.allocatedBytesPerOperation
        fairness = [double]$raw.sample.jainFairness
        batch_activation_rate = if (
            [long]$raw.sample.evidence.batchOperations -eq 0
        ) { 0.0 } else {
            [double]$raw.sample.evidence.batchDistinctOperations /
                [double]$raw.sample.evidence.batchOperations
        }
        buffer_activation_rate = if (
            [long]$raw.sample.evidence.bufferOperations -eq 0
        ) { 0.0 } else {
            [double]$raw.sample.evidence.bufferDistinctOperations /
                [double]$raw.sample.evidence.bufferOperations
        }
        legal_write_average = if (
            [long]$raw.sample.evidence.batchOperations -eq 0
        ) { 0.0 } else {
            [double]$raw.sample.evidence.batchLegalWrites /
                [double]$raw.sample.evidence.batchOperations
        }
        source_segment_average = if (
            [long]$raw.sample.evidence.bufferOperations -eq 0
        ) { 0.0 } else {
            [double]$raw.sample.evidence.bufferLegalSegments /
                [double]$raw.sample.evidence.bufferOperations
        }
    })
}

$workloadResults = @($rows |
    Group-Object workload_id, split, cell_id |
    ForEach-Object {
        $group = @($_.Group)
        [pscustomobject][ordered]@{
            workload_id = [string]$group[0].workload_id
            split = [string]$group[0].split
            cell_id = [string]$group[0].cell_id
            run_count = $group.Count
            median_useful_bytes_per_second = Get-Median (
                [double[]]@($group.useful_bytes_per_second))
            median_p95_milliseconds = Get-Median (
                [double[]]@($group.p95_milliseconds))
            median_cpu_microseconds_per_operation = Get-Median (
                [double[]]@($group.cpu_microseconds_per_operation))
            median_allocated_bytes_per_operation = Get-Median (
                [double[]]@($group.allocated_bytes_per_operation))
            median_fairness = Get-Median ([double[]]@($group.fairness))
            batch_activation_rate = Get-Median (
                [double[]]@($group.batch_activation_rate))
            buffer_activation_rate = Get-Median (
                [double[]]@($group.buffer_activation_rate))
        }
    } | Sort-Object split, workload_id, cell_id)

$effectRows = [Collections.Generic.List[object]]::new()
$eligibleGroups = @($rows |
    Where-Object {
        $_.classification -in @(
            'performance_eligible',
            'expected_equivalent')
    } |
    Group-Object split, workload_id, block)
foreach ($group in $eligibleGroups) {
    $cells = @{}
    foreach ($row in @($group.Group)) {
        $cells[[string]$row.cell_id] = $row
    }
    if ($cells.Count -ne 4) {
        continue
    }
    $a = [double]$cells.A.useful_bytes_per_second
    $b = [double]$cells.B.useful_bytes_per_second
    $c = [double]$cells.C.useful_bytes_per_second
    $d = [double]$cells.D.useful_bytes_per_second
    $values = [ordered]@{
        batch_main_b_vs_a = Get-PercentDifference $b $a
        buffer_main_c_vs_a = Get-PercentDifference $c $a
        configured_interaction =
            if ($a -eq 0) { 0.0 } else {
                100.0 * (($d - $b) - ($c - $a)) / $a
            }
        expected_equivalence_d_vs_b = Get-PercentDifference $d $b
    }
    foreach ($entry in $values.GetEnumerator()) {
        [void]$effectRows.Add([pscustomobject][ordered]@{
            split = [string]$group.Group[0].split
            workload_id = [string]$group.Group[0].workload_id
            block = [long]$group.Group[0].block
            effect_id = [string]$entry.Key
            percent = [double]$entry.Value
        })
    }
}

$effectEstimates = @($effectRows |
    Group-Object split, effect_id |
    ForEach-Object {
        $values = [double[]]@($_.Group.percent)
        $median = Get-Median $values
        $effectSeed = [Convert]::ToInt32(
            (Get-AdaptiveRuntimeSha256 ([string]$_.Name)).Substring(0, 7),
            16)
        $interval = Get-BootstrapInterval $values `
            ([int]$campaign.analysis.bootstrap_iterations) `
            ([int]$campaign.design.seed + $effectSeed)
        [pscustomobject][ordered]@{
            split = [string]$_.Group[0].split
            effect_id = [string]$_.Group[0].effect_id
            observation_count = $values.Count
            median_percent = $median
            confidence_low_percent = [double]$interval[0]
            confidence_high_percent = [double]$interval[1]
            classification = Get-EffectClassification `
                ([string]$_.Group[0].effect_id) `
                $median `
                ([double]$interval[0]) `
                ([double]$interval[1]) `
                ([double]$campaign.analysis.practical_goodput_percent)
        }
    } | Sort-Object split, effect_id)

function Get-ContextLabels([string] $Split) {
    $labels = [Collections.Generic.List[object]]::new()
    $contexts = @($workloadResults |
        Where-Object { $_.split -ceq $Split } |
        Group-Object workload_id)
    foreach ($context in $contexts) {
        $byCell = @{}
        foreach ($result in @($context.Group |
            Where-Object { $_.cell_id -in @('A', 'B', 'C') })) {
            $byCell[[string]$result.cell_id] = $result
        }
        if ($byCell.Count -ne 3) {
            continue
        }
        $baseline = $byCell.A
        $acceptable = @($byCell.Values |
            Where-Object {
                [double]$_.median_p95_milliseconds -le
                    [double]$baseline.median_p95_milliseconds *
                        (1.0 + [double]$campaign.analysis.
                            maximum_p95_regression_percent / 100.0) -and
                [double]$_.median_fairness -ge
                    [double]$campaign.analysis.minimum_fairness
            } |
            Sort-Object median_useful_bytes_per_second -Descending)
        $winner = if ($acceptable.Count -eq 0) {
            $baseline
        }
        else {
            $acceptable[0]
        }
        if ((Get-PercentDifference `
            ([double]$winner.median_useful_bytes_per_second) `
            ([double]$baseline.median_useful_bytes_per_second)) -lt
            [double]$campaign.analysis.practical_goodput_percent) {
            $winner = $baseline
        }
        $baselineRows = @($rows |
            Where-Object {
                $_.split -ceq $Split -and
                $_.workload_id -ceq [string]$context.Name -and
                $_.cell_id -ceq 'A'
            })
        [void]$labels.Add([pscustomobject][ordered]@{
            workload_id = [string]$context.Name
            winner = [string]$winner.cell_id
            legal_write_average = Get-Median (
                [double[]]@($baselineRows.legal_write_average))
            source_segment_average = Get-Median (
                [double[]]@($baselineRows.source_segment_average))
            cell_results = $byCell
        })
    }
    return @($labels)
}

function Measure-Rule([object] $Rule, [object[]] $Labels) {
    if ($Labels.Count -eq 0) {
        return [pscustomobject]@{ accuracy = 0.0; regret = 0.0 }
    }
    $correct = 0
    $regrets = [Collections.Generic.List[double]]::new()
    foreach ($label in $Labels) {
        $feature = [double]$label.($Rule.feature)
        $prediction = if ($feature -ge [double]$Rule.threshold) {
            [string]$Rule.high_cell
        }
        else {
            [string]$Rule.low_cell
        }
        if ($prediction -ceq [string]$label.winner) {
            $correct++
        }
        $winnerValue = [double]$label.cell_results[
            [string]$label.winner].median_useful_bytes_per_second
        $predictedValue = [double]$label.cell_results[
            $prediction].median_useful_bytes_per_second
        [void]$regrets.Add([Math]::Max(
            0.0,
            -1.0 * (Get-PercentDifference $predictedValue $winnerValue)))
    }
    [pscustomobject]@{
        accuracy = $correct / [double]$Labels.Count
        regret = Get-Median ([double[]]@($regrets))
    }
}

$trainLabels = @(Get-ContextLabels 'train')
$holdoutLabels = @(Get-ContextLabels 'holdout')
$candidateRules = [Collections.Generic.List[object]]::new()
foreach ($feature in @('legal_write_average', 'source_segment_average')) {
    $values = @($trainLabels.$feature | Sort-Object -Unique)
    if ($values.Count -lt 2) {
        continue
    }
    for ($index = 0; $index -lt $values.Count - 1; $index++) {
        $threshold = ([double]$values[$index] +
            [double]$values[$index + 1]) / 2.0
        foreach ($low in @('A', 'B', 'C')) {
            foreach ($high in @('A', 'B', 'C')) {
                if ($low -ceq $high) {
                    continue
                }
                $rule = [pscustomobject][ordered]@{
                    feature = $feature
                    threshold = $threshold
                    low_cell = $low
                    high_cell = $high
                }
                $training = Measure-Rule $rule $trainLabels
                $holdout = Measure-Rule $rule $holdoutLabels
                $rule | Add-Member -NotePropertyName training `
                    -NotePropertyValue $training
                $rule | Add-Member -NotePropertyName holdout `
                    -NotePropertyValue $holdout
                [void]$candidateRules.Add($rule)
            }
        }
    }
}
$bestRule = @($candidateRules |
    Sort-Object `
        @{ Expression = { $_.training.regret }; Ascending = $true },
        @{ Expression = { $_.training.accuracy }; Descending = $true },
        feature, threshold, low_cell, high_cell |
    Select-Object -First 1)
$winnerKinds = @($trainLabels.winner | Sort-Object -Unique)
$hasHoldout = $holdoutLabels.Count -ge 2
$materialTrainEffect = @($effectEstimates |
    Where-Object {
        $_.split -ceq 'train' -and
        $_.effect_id -in @(
            'batch_main_b_vs_a',
            'buffer_main_c_vs_a') -and
        $_.classification -ceq 'material_positive'
    }).Count -gt 0
$justified = $bestRule.Count -eq 1 -and
    $trainLabels.Count -ge 3 -and
    $hasHoldout -and
    $winnerKinds.Count -ge 2 -and
    $materialTrainEffect -and
    [double]$bestRule[0].training.accuracy -ge 0.75 -and
    [double]$bestRule[0].holdout.accuracy -ge (2.0 / 3.0) -and
    [double]$bestRule[0].training.regret -le
        [double]$campaign.analysis.practical_goodput_percent -and
    [double]$bestRule[0].holdout.regret -le
        [double]$campaign.analysis.practical_goodput_percent

$conclusion = if ($justified) {
    'shadow_candidate'
}
elseif ($hasHoldout) {
    'no_stable_rule'
}
else {
    'more_context_required'
}
$ruleId = if ($justified) {
    'rule.send_composition.shadow.v1'
}
else {
    $null
}
$ruleText = if ($justified) {
    '{0} >= {1:R} ? {2} : {3}' -f
        $bestRule[0].feature,
        [double]$bestRule[0].threshold,
        $bestRule[0].high_cell,
        $bestRule[0].low_cell
}
else {
    $null
}
$readiness = switch ($conclusion) {
    'shadow_candidate' {
        'measurement_completed_shadow_candidate_ready'
    }
    'no_stable_rule' {
        'measurement_completed_no_stable_rule'
    }
    default {
        'measurement_completed_more_context_required'
    }
}

$analysis = [pscustomobject][ordered]@{
    schema_version =
        'adaptive-runtime-send-composition-performance-analysis-v1'
    document_id = "analysis.send_composition.performance.$(
        ([string]$projection.manifest_ref.content_sha256).Substring(0,12))"
    document_version = 1
    content_sha256 = '0' * 64
    projection_ref = New-DocumentReference $projection
    run_counts = [pscustomobject][ordered]@{
        total = $rows.Count
        eligible = @($rows |
            Where-Object classification -EQ 'performance_eligible').Count
        inactive = @($rows |
            Where-Object classification -EQ 'inactive_control').Count
        equivalent = @($rows |
            Where-Object classification -EQ 'expected_equivalent').Count
        excluded = @($rows |
            Where-Object {
                $_.classification -in @(
                    'activation_missing',
                    'failed_correctness')
            }).Count
    }
    workload_results = $workloadResults
    effect_estimates = $effectEstimates
    selector_assessment = [pscustomobject][ordered]@{
        conclusion = $conclusion
        rule_id = $ruleId
        rule_text = $ruleText
        permitted_inputs = if ($justified) {
            @(
                if ($bestRule[0].feature -ceq
                    'legal_write_average') {
                    'legal_eligible_write_count'
                }
                else {
                    'source_segment_count'
                }
            )
        } else {
            @('legal_eligible_write_count', 'source_segment_count')
        }
        training_accuracy =
            if ($bestRule.Count -eq 1) {
                [double]$bestRule[0].training.accuracy
            } else { 0.0 }
        training_median_regret_percent =
            if ($bestRule.Count -eq 1) {
                [double]$bestRule[0].training.regret
            } else { 0.0 }
        holdout_accuracy =
            if ($bestRule.Count -eq 1) {
                [double]$bestRule[0].holdout.accuracy
            } else { 0.0 }
        holdout_median_regret_percent =
            if ($bestRule.Count -eq 1) {
                [double]$bestRule[0].holdout.regret
            } else { 0.0 }
        shadow_implementation_authorized = $justified
    }
    measurement_readiness = $readiness
    active_behavior_authorization = $false
    production_activation_authorization = $false
    trace_references = $campaign.trace_references
}
[void](Set-AdaptiveRuntimeDocumentHash $analysis)
Assert-AnalysisCondition (
    Test-AdaptiveRuntimeJsonSchema $analysis (
        Join-Path $RepositoryRoot `
            'schemas\adaptive-runtime-send-composition-performance-analysis-v1.schema.json')
) 'performance_analysis_schema_invalid'
Assert-AnalysisCondition (
    Test-AdaptiveRuntimeDocumentHash $analysis
) 'performance_analysis_hash_mismatch'
Write-AdaptiveRuntimeCanonicalDocument $analysis $OutputPath

if ($PassThru) {
    $analysis
}
else {
    [pscustomobject][ordered]@{
        analysis_path = [IO.Path]::GetFullPath($OutputPath)
        analysis_sha256 = [string]$analysis.content_sha256
        measurement_readiness = $readiness
        selector_conclusion = $conclusion
        training_context_count = $trainLabels.Count
        holdout_context_count = $holdoutLabels.Count
    } | ConvertTo-Json -Depth 8
}
