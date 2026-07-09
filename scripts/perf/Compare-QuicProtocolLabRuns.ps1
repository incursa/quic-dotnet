[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BaselineRun,

    [Parameter(Mandatory = $true)]
    [string] $CurrentRun,

    [string] $ProtocolLabExecutionRoot = "C:\shared\src\incursa\protocol-lab-internal",

    [string] $RunsRoot,

    [string] $OutputRoot = ".artifacts\perf-triage",

    [string] $RunId = "quic-perf-triage-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [double] $PercentTolerance = 2.0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-RepoRoot {
    $candidate = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $candidate "Incursa.Quic.slnx"))) {
        throw "Could not locate quic-dotnet repository root from '$PSScriptRoot'."
    }

    return [System.IO.Path]::GetFullPath($candidate)
}

function Test-Property {
    param($Object, [string] $Name)

    if ($null -eq $Object) {
        return $false
    }

    return @($Object.PSObject.Properties | ForEach-Object { $_.Name }) -contains $Name
}

function Get-OptionalPropertyValue {
    param($Object, [string] $Name)

    if (Test-Property $Object $Name) {
        return $Object.PSObject.Properties[$Name].Value
    }

    return $null
}

function Get-MedianMetric {
    param($Object, [string] $Name)

    $value = Get-OptionalPropertyValue $Object $Name
    if ($null -eq $value) {
        return $null
    }

    if (Test-Property $value "median") {
        return $value.median
    }

    if ($value -is [pscustomobject]) {
        return $null
    }

    return $value
}

function Get-StringArray {
    param($Value)

    return @($Value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
}

function Get-ObjectArray {
    param($Value)

    if ($null -eq $Value) {
        return @()
    }

    return @($Value)
}

function Get-ObjectPropertyByPath {
    param($Object, [string[]] $Path)

    $current = $Object
    foreach ($segment in $Path) {
        if (-not (Test-Property $current $segment)) {
            return $null
        }

        $current = Get-OptionalPropertyValue $current $segment
        if ($null -eq $current) {
            return $null
        }
    }

    return $current
}

function Format-DiagnosticGroup {
    param($Group)

    if ($null -eq $Group) {
        return $null
    }

    $preferredNames = @(
        "groupKey",
        "type",
        "exceptionType",
        "message",
        "allocatedType",
        "metricName",
        "label",
        "method",
        "attributionFrame",
        "stackTopFrame",
        "firstProjectFrame",
        "mean",
        "max",
        "latest",
        "delta",
        "sampleCount",
        "inclusiveSampleCount",
        "exclusiveSampleCount"
    )

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $preferredNames) {
        $value = Get-OptionalPropertyValue $Group $name
        if ($null -eq $value) {
            continue
        }

        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }

        $parts.Add("$name=$text") | Out-Null
        if ($parts.Count -ge 5) {
            break
        }
    }

    if ($parts.Count -gt 0) {
        return $parts -join "; "
    }

    return ($Group | ConvertTo-Json -Compress -Depth 8)
}

function Get-TopDiagnosticGroups {
    param($Groups, [int] $Count = 3)

    return @(
        Get-ObjectArray $Groups |
            Select-Object -First $Count |
            ForEach-Object { Format-DiagnosticGroup $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    )
}

function Read-EvidenceBundle {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RunRoot
    )

    $bundlePath = Join-Path $RunRoot "evidence-bundle.json"
    if (-not (Test-Path -LiteralPath $bundlePath -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            available = $false
            path = $bundlePath
            document = $null
            cellsByKey = @{}
            hotspotGroupsByKey = @{}
        }
    }

    $document = Get-Content -LiteralPath $bundlePath -Raw | ConvertFrom-Json
    $cellsByKey = @{}
    foreach ($cell in @(Get-ObjectPropertyByPath $document @("cells"))) {
        $scenario = [string](Get-OptionalPropertyValue $cell "scenarioId")
        $implementation = [string](Get-OptionalPropertyValue $cell "implementationId")
        if ([string]::IsNullOrWhiteSpace($scenario) -or [string]::IsNullOrWhiteSpace($implementation)) {
            continue
        }

        $key = "$implementation|$scenario"
        if (-not $cellsByKey.ContainsKey($key)) {
            $cellsByKey[$key] = $cell
        }
    }

    $hotspotGroupsByKey = @{}
    foreach ($group in @(Get-ObjectPropertyByPath $document @("hotspotTrends", "groups"))) {
        $scenario = [string](Get-OptionalPropertyValue $group "scenarioId")
        $implementation = [string](Get-OptionalPropertyValue $group "implementationId")
        if ([string]::IsNullOrWhiteSpace($scenario) -or [string]::IsNullOrWhiteSpace($implementation)) {
            continue
        }

        $key = "$implementation|$scenario"
        if (-not $hotspotGroupsByKey.ContainsKey($key)) {
            $hotspotGroupsByKey[$key] = [System.Collections.Generic.List[object]]::new()
        }

        $hotspotGroupsByKey[$key].Add($group) | Out-Null
    }

    return [pscustomobject][ordered]@{
        available = $true
        path = $bundlePath
        document = $document
        cellsByKey = $cellsByKey
        hotspotGroupsByKey = $hotspotGroupsByKey
    }
}

function New-EvidenceDiagnostics {
    param($Bundle, [string] $Key)

    if ($null -eq $Bundle -or -not $Bundle.available) {
        return [pscustomobject][ordered]@{
            bundleAvailable = $false
            bundlePath = if ($Bundle) { $Bundle.path } else { $null }
            evidenceQualityClass = $null
            evidenceQualityPublishable = $null
            evidenceQualityBlockers = @()
            evidenceQualityWarnings = @()
            qlogStatus = $null
            qlogFileCount = $null
            quicBufferPoolStatus = $null
            quicBufferPoolUnavailableReason = $null
            quicBufferPoolTopMetrics = @()
            allocationAttributionStatus = $null
            allocationAttributionUnavailableReason = $null
            allocationTopGroups = @()
            exceptionAttributionStatus = $null
            exceptionAttributionUnavailableReason = $null
            exceptionTopGroups = @()
            hotspotTrendCount = 0
        }
    }

    $document = $Bundle.document
    $cell = if ($Bundle.cellsByKey.ContainsKey($Key)) { $Bundle.cellsByKey[$Key] } else { $null }
    $hotspotGroups = if ($Bundle.hotspotGroupsByKey.ContainsKey($Key)) { @($Bundle.hotspotGroupsByKey[$Key]) } else { @() }

    $cellAllocation = Get-ObjectPropertyByPath $cell @("diagnostics", "allocationAttribution")
    $cellException = Get-ObjectPropertyByPath $cell @("diagnostics", "exceptionAttribution")
    $cellBufferPool = Get-ObjectPropertyByPath $cell @("diagnostics", "quicBufferPool")
    $cellQlog = Get-ObjectPropertyByPath $cell @("diagnostics", "qlog")

    $hotspotAllocationGroups = @()
    $hotspotExceptionGroups = @()
    foreach ($hotspotGroup in $hotspotGroups) {
        $allocation = Get-OptionalPropertyValue $hotspotGroup "allocationAttribution"
        if ($allocation) {
            $hotspotAllocationGroups += @(Get-OptionalPropertyValue $allocation "topGroups")
        }

        $exception = Get-OptionalPropertyValue $hotspotGroup "exceptionAttribution"
        if ($exception) {
            $hotspotExceptionGroups += @(Get-OptionalPropertyValue $exception "topGroups")
        }
    }

    $allocationTopGroups = @(Get-TopDiagnosticGroups (Get-OptionalPropertyValue $cellAllocation "topGroups"))
    if ($allocationTopGroups.Count -eq 0) {
        $allocationTopGroups = @(Get-TopDiagnosticGroups $hotspotAllocationGroups)
    }

    $exceptionTopGroups = @(Get-TopDiagnosticGroups (Get-OptionalPropertyValue $cellException "topGroups"))
    if ($exceptionTopGroups.Count -eq 0) {
        $exceptionTopGroups = @(Get-TopDiagnosticGroups $hotspotExceptionGroups)
    }

    return [pscustomobject][ordered]@{
        bundleAvailable = $true
        bundlePath = $Bundle.path
        evidenceQualityClass = [string](Get-ObjectPropertyByPath $document @("evidenceQuality", "class"))
        evidenceQualityPublishable = Get-ObjectPropertyByPath $document @("evidenceQuality", "publishable")
        evidenceQualityBlockers = Get-StringArray (Get-ObjectPropertyByPath $document @("evidenceQuality", "blockers"))
        evidenceQualityWarnings = Get-StringArray (Get-ObjectPropertyByPath $document @("evidenceQuality", "warnings"))
        qlogStatus = [string](Get-OptionalPropertyValue $cellQlog "status")
        qlogFileCount = Get-OptionalPropertyValue $cellQlog "fileCount"
        quicBufferPoolStatus = [string](Get-OptionalPropertyValue $cellBufferPool "status")
        quicBufferPoolUnavailableReason = [string](Get-OptionalPropertyValue $cellBufferPool "unavailableReason")
        quicBufferPoolTopMetrics = @(Get-TopDiagnosticGroups (Get-OptionalPropertyValue $cellBufferPool "topMetrics"))
        allocationAttributionStatus = [string](Get-OptionalPropertyValue $cellAllocation "status")
        allocationAttributionUnavailableReason = [string](Get-OptionalPropertyValue $cellAllocation "unavailableReason")
        allocationTopGroups = @($allocationTopGroups)
        exceptionAttributionStatus = [string](Get-OptionalPropertyValue $cellException "status")
        exceptionAttributionUnavailableReason = [string](Get-OptionalPropertyValue $cellException "unavailableReason")
        exceptionTopGroups = @($exceptionTopGroups)
        hotspotTrendCount = $hotspotGroups.Count
    }
}

function Format-StatusMap {
    param($Map)

    if ($null -eq $Map) {
        return "n/a"
    }

    $parts = @(
        $Map.PSObject.Properties |
            Sort-Object { $_.Name } |
            ForEach-Object { "$($_.Name)=$($_.Value)" }
    )
    if ($parts.Count -eq 0) {
        return "n/a"
    }

    return $parts -join ", "
}

function Format-Number {
    param($Value, [string] $Format = "0.###")

    if ($null -eq $Value) {
        return "n/a"
    }

    return ([double]$Value).ToString($Format, [Globalization.CultureInfo]::InvariantCulture)
}

function Format-DeltaPercent {
    param($Value)

    if ($null -eq $Value) {
        return "n/a"
    }

    return ([double]$Value).ToString("+0.##;-0.##;0", [Globalization.CultureInfo]::InvariantCulture) + "%"
}

function Get-DeltaPercent {
    param($Current, $Baseline)

    if ($null -eq $Current -or $null -eq $Baseline -or [double]$Baseline -eq 0) {
        return $null
    }

    return (([double]$Current - [double]$Baseline) / [Math]::Abs([double]$Baseline)) * 100.0
}

function Get-PrimaryMetricName {
    param([string] $Scenario)

    if ($Scenario.StartsWith("quic.transport.", [StringComparison]::OrdinalIgnoreCase)) {
        return "throughputBytesPerSecond"
    }

    return "requestsPerSecond"
}

function Resolve-RunRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Run,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedRunsRoot,

        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedProtocolLabExecutionRoot
    )

    $candidatePaths = [System.Collections.Generic.List[string]]::new()
    $candidatePaths.Add((Resolve-FullPath -Path $Run -BasePath $RepoRoot)) | Out-Null
    $candidatePaths.Add((Join-Path $ResolvedRunsRoot $Run)) | Out-Null
    $candidatePaths.Add((Join-Path (Join-Path $ResolvedProtocolLabExecutionRoot ".artifacts\runs") $Run)) | Out-Null

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath (Join-Path $candidatePath "aggregate-results.json") -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidatePath)
        }
    }

    $searchRoots = @(
        (Join-Path $RepoRoot ".artifacts\perf"),
        (Join-Path $ResolvedProtocolLabExecutionRoot ".artifacts\runs")
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }

    foreach ($searchRoot in $searchRoots) {
        $match = Get-ChildItem -LiteralPath $searchRoot -Filter "aggregate-results.json" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { (Split-Path -Leaf (Split-Path -Parent $_.FullName)) -eq $Run } |
            Select-Object -First 1
        if ($match) {
            return [System.IO.Path]::GetFullPath((Split-Path -Parent $match.FullName))
        }
    }

    throw "Could not resolve ProtocolLab run '$Run'. Pass a run root path or a run ID present under '$ResolvedRunsRoot'."
}

function Read-RunRows {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RunRoot
    )

    $aggregatePath = Join-Path $RunRoot "aggregate-results.json"
    $document = Get-Content -LiteralPath $aggregatePath -Raw | ConvertFrom-Json
    $evidenceBundle = Read-EvidenceBundle -RunRoot $RunRoot
    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($aggregate in @($document.aggregates)) {
        $scenario = [string](Get-OptionalPropertyValue $aggregate "scenarioId")
        $implementation = [string](Get-OptionalPropertyValue $aggregate "implementationId")
        if ([string]::IsNullOrWhiteSpace($scenario) -or [string]::IsNullOrWhiteSpace($implementation)) {
            continue
        }

        $validation = Get-OptionalPropertyValue $aggregate "validation"
        $evidence = Get-OptionalPropertyValue $aggregate "evidence"
        $primaryMetric = Get-PrimaryMetricName -Scenario $scenario
        $primaryMetricValue = Get-MedianMetric $aggregate $primaryMetric
        $publishabilityGate = Get-OptionalPropertyValue $aggregate "publishabilityGate"
        $rowKey = "$implementation|$scenario"
        $evidenceDiagnostics = New-EvidenceDiagnostics -Bundle $evidenceBundle -Key $rowKey

        $rows.Add([pscustomobject][ordered]@{
            key = $rowKey
            runId = [string]$document.runId
            generatedAt = [string](Get-OptionalPropertyValue $document "generatedAt")
            runRoot = $RunRoot
            aggregatePath = $aggregatePath
            evidenceBundlePath = if ($evidenceDiagnostics.bundleAvailable) { $evidenceDiagnostics.bundlePath } else { $null }
            implementationId = $implementation
            implementationName = [string](Get-OptionalPropertyValue $aggregate "implementationName")
            scenarioId = $scenario
            protocol = [string](Get-OptionalPropertyValue $aggregate "protocol")
            loadTool = [string](Get-OptionalPropertyValue $aggregate "loadTool")
            loadProfileId = [string](Get-OptionalPropertyValue $aggregate "loadProfileId")
            connections = Get-OptionalPropertyValue $aggregate "connections"
            streamsPerConnection = Get-OptionalPropertyValue $aggregate "streamsPerConnection"
            evidenceClass = if ($evidence) { [string](Get-OptionalPropertyValue $evidence "evidenceClass") } else { $null }
            comparabilityStatus = if ($evidence) { [string](Get-OptionalPropertyValue $evidence "comparabilityStatus") } else { $null }
            validationPassed = if ($validation) { [int](Get-OptionalPropertyValue $validation "passed") } else { 0 }
            validationFailed = if ($validation) { [int](Get-OptionalPropertyValue $validation "failed") } else { 0 }
            validationInfrastructureFailure = if ($validation) { [int](Get-OptionalPropertyValue $validation "infrastructureFailure") } else { 0 }
            benchmarkStatus = Format-StatusMap (Get-OptionalPropertyValue $aggregate "benchmarkExecutionStatuses")
            primaryMetricName = $primaryMetric
            primaryMetricValue = $primaryMetricValue
            requestsPerSecond = Get-MedianMetric $aggregate "requestsPerSecond"
            throughputBytesPerSecond = Get-MedianMetric $aggregate "throughputBytesPerSecond"
            latencyP50Ms = Get-MedianMetric $aggregate "latencyP50Ms"
            latencyP95Ms = Get-MedianMetric $aggregate "latencyP95Ms"
            latencyP99Ms = Get-MedianMetric $aggregate "latencyP99Ms"
            allocationRateBytesPerSecond = Get-MedianMetric $aggregate "counterAllocationRateMean"
            exceptionRate = Get-MedianMetric $aggregate "counterExceptionRateMean"
            gen0Collections = Get-MedianMetric $aggregate "counterGen0CollectionsDelta"
            gen1Collections = Get-MedianMetric $aggregate "counterGen1CollectionsDelta"
            gen2Collections = Get-MedianMetric $aggregate "counterGen2CollectionsDelta"
            cpuMeanPercent = Get-MedianMetric $aggregate "counterCpuMean"
            cpuMaxPercent = Get-MedianMetric $aggregate "counterCpuMax"
            warningCount = [int](Get-OptionalPropertyValue $aggregate "warningCount")
            errorCount = [int](Get-OptionalPropertyValue $aggregate "errorCount")
            failedRequests = [int](Get-OptionalPropertyValue $aggregate "failedRequests")
            timeoutRequests = [int](Get-OptionalPropertyValue $aggregate "timeoutRequests")
            targetProcessMetricsCapturedCount = [int](Get-OptionalPropertyValue $aggregate "targetProcessMetricsCapturedCount")
            targetProcessMetricsMissingCount = [int](Get-OptionalPropertyValue $aggregate "targetProcessMetricsMissingCount")
            countersCapturedCount = [int](Get-OptionalPropertyValue $aggregate "countersCapturedCount")
            countersMissingCount = [int](Get-OptionalPropertyValue $aggregate "countersMissingCount")
            qlogFileCountMedian = Get-OptionalPropertyValue $aggregate "qlogFileCountMedian"
            requestedRepetitions = Get-OptionalPropertyValue $aggregate "requestedRepetitions"
            observedRepetitions = Get-OptionalPropertyValue $aggregate "observedRepetitions"
            relativeRange = Get-OptionalPropertyValue $aggregate "relativeRange"
            publishabilityGateStatus = if ($publishabilityGate) { [string](Get-OptionalPropertyValue $publishabilityGate "status") } else { $null }
            publishabilityBlockers = if ($publishabilityGate) { Get-StringArray (Get-OptionalPropertyValue $publishabilityGate "blockers") } else { @() }
            warnings = Get-StringArray (Get-OptionalPropertyValue $aggregate "warnings")
            failureReasons = Get-StringArray (Get-OptionalPropertyValue $aggregate "failureReasons")
            evidenceDiagnostics = $evidenceDiagnostics
        }) | Out-Null
    }

    return @($rows)
}

function New-MetricComparison {
    param(
        [string] $Name,
        $Baseline,
        $Current,
        [ValidateSet("HigherIsBetter", "LowerIsBetter")]
        [string] $Direction,
        [double] $Tolerance
    )

    $delta = if ($null -ne $Baseline -and $null -ne $Current) { [double]$Current - [double]$Baseline } else { $null }
    $deltaPercent = Get-DeltaPercent -Current $Current -Baseline $Baseline
    $classification = "unavailable"
    if ($null -ne $deltaPercent) {
        if ([Math]::Abs([double]$deltaPercent) -le $Tolerance) {
            $classification = "unchanged"
        }
        elseif ($Direction -eq "HigherIsBetter") {
            $classification = if ($deltaPercent -gt 0) { "improved" } else { "regressed" }
        }
        else {
            $classification = if ($deltaPercent -lt 0) { "improved" } else { "regressed" }
        }
    }
    elseif ($null -ne $Baseline -and $null -ne $Current) {
        if ([double]$Baseline -eq [double]$Current) {
            $classification = "unchanged"
        }
        elseif ($Direction -eq "HigherIsBetter") {
            $classification = if ([double]$Current -gt [double]$Baseline) { "improved" } else { "regressed" }
        }
        else {
            $classification = if ([double]$Current -lt [double]$Baseline) { "improved" } else { "regressed" }
        }
    }

    return [pscustomobject][ordered]@{
        name = $Name
        baseline = $Baseline
        current = $Current
        delta = $delta
        deltaPercent = $deltaPercent
        direction = $Direction
        classification = $classification
    }
}

function Add-StatusSignal {
    param(
        [System.Collections.Generic.List[object]] $Signals,
        [string] $Name,
        $Baseline,
        $Current,
        [ValidateSet("HigherIsBetter", "LowerIsBetter", "EqualIsBetter")]
        [string] $Direction
    )

    $classification = "unchanged"
    if ($Baseline -ne $Current) {
        if ($Direction -eq "EqualIsBetter") {
            $classification = "changed"
        }
        elseif ($Direction -eq "HigherIsBetter") {
            $classification = if ([double]$Current -gt [double]$Baseline) { "improved" } else { "regressed" }
        }
        else {
            $classification = if ([double]$Current -lt [double]$Baseline) { "improved" } else { "regressed" }
        }
    }

    $Signals.Add([pscustomobject][ordered]@{
        name = $Name
        baseline = $Baseline
        current = $Current
        classification = $classification
    }) | Out-Null
}

function Format-MetricForMarkdown {
    param($Metric)

    $baseline = Format-Number $Metric.baseline
    $current = Format-Number $Metric.current
    $delta = Format-DeltaPercent $Metric.deltaPercent
    return "$baseline -> $current ($delta)"
}

$repoRoot = Get-RepoRoot
$resolvedProtocolLabExecutionRoot = Resolve-FullPath -Path $ProtocolLabExecutionRoot -BasePath $repoRoot
if ([string]::IsNullOrWhiteSpace($RunsRoot)) {
    $RunsRoot = Join-Path $resolvedProtocolLabExecutionRoot ".artifacts\runs"
}

$resolvedRunsRoot = Resolve-FullPath -Path $RunsRoot -BasePath $repoRoot
$resolvedOutputRoot = Resolve-FullPath -Path $OutputRoot -BasePath $repoRoot
$reportRoot = Join-Path $resolvedOutputRoot $RunId
New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null

$baselineRoot = Resolve-RunRoot -Run $BaselineRun -ResolvedRunsRoot $resolvedRunsRoot -RepoRoot $repoRoot -ResolvedProtocolLabExecutionRoot $resolvedProtocolLabExecutionRoot
$currentRoot = Resolve-RunRoot -Run $CurrentRun -ResolvedRunsRoot $resolvedRunsRoot -RepoRoot $repoRoot -ResolvedProtocolLabExecutionRoot $resolvedProtocolLabExecutionRoot
$baselineRows = @(Read-RunRows -RunRoot $baselineRoot)
$currentRows = @(Read-RunRows -RunRoot $currentRoot)

$baselineByKey = @{}
foreach ($row in $baselineRows) {
    $baselineByKey[$row.key] = $row
}

$currentByKey = @{}
foreach ($row in $currentRows) {
    $currentByKey[$row.key] = $row
}

$matchingComparisons = [System.Collections.Generic.List[object]]::new()
$missingRows = [System.Collections.Generic.List[object]]::new()
$addedRows = [System.Collections.Generic.List[object]]::new()

foreach ($key in @($baselineByKey.Keys | Sort-Object)) {
    if (-not $currentByKey.ContainsKey($key)) {
        $missingRows.Add($baselineByKey[$key]) | Out-Null
        continue
    }

    $baseline = $baselineByKey[$key]
    $current = $currentByKey[$key]
    $metrics = @(
        New-MetricComparison -Name $baseline.primaryMetricName -Baseline $baseline.primaryMetricValue -Current $current.primaryMetricValue -Direction "HigherIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "latencyP95Ms" -Baseline $baseline.latencyP95Ms -Current $current.latencyP95Ms -Direction "LowerIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "allocationRateBytesPerSecond" -Baseline $baseline.allocationRateBytesPerSecond -Current $current.allocationRateBytesPerSecond -Direction "LowerIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "exceptionRate" -Baseline $baseline.exceptionRate -Current $current.exceptionRate -Direction "LowerIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "cpuMeanPercent" -Baseline $baseline.cpuMeanPercent -Current $current.cpuMeanPercent -Direction "LowerIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "gen0Collections" -Baseline $baseline.gen0Collections -Current $current.gen0Collections -Direction "LowerIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "gen1Collections" -Baseline $baseline.gen1Collections -Current $current.gen1Collections -Direction "LowerIsBetter" -Tolerance $PercentTolerance
        New-MetricComparison -Name "gen2Collections" -Baseline $baseline.gen2Collections -Current $current.gen2Collections -Direction "LowerIsBetter" -Tolerance $PercentTolerance
    )

    $statusSignals = [System.Collections.Generic.List[object]]::new()
    Add-StatusSignal -Signals $statusSignals -Name "validationFailed" -Baseline $baseline.validationFailed -Current $current.validationFailed -Direction "LowerIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "validationInfrastructureFailure" -Baseline $baseline.validationInfrastructureFailure -Current $current.validationInfrastructureFailure -Direction "LowerIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "failedRequests" -Baseline $baseline.failedRequests -Current $current.failedRequests -Direction "LowerIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "timeoutRequests" -Baseline $baseline.timeoutRequests -Current $current.timeoutRequests -Direction "LowerIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "warningCount" -Baseline $baseline.warningCount -Current $current.warningCount -Direction "LowerIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "errorCount" -Baseline $baseline.errorCount -Current $current.errorCount -Direction "LowerIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "observedRepetitions" -Baseline $baseline.observedRepetitions -Current $current.observedRepetitions -Direction "HigherIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "targetProcessMetricsCapturedCount" -Baseline $baseline.targetProcessMetricsCapturedCount -Current $current.targetProcessMetricsCapturedCount -Direction "HigherIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "countersCapturedCount" -Baseline $baseline.countersCapturedCount -Current $current.countersCapturedCount -Direction "HigherIsBetter"
    Add-StatusSignal -Signals $statusSignals -Name "qlogFileCountMedian" -Baseline $baseline.qlogFileCountMedian -Current $current.qlogFileCountMedian -Direction "HigherIsBetter"

    $matchingComparisons.Add([pscustomobject][ordered]@{
        key = $key
        implementationId = $current.implementationId
        scenarioId = $current.scenarioId
        protocol = $current.protocol
        loadTool = $current.loadTool
        baseline = $baseline
        current = $current
        metrics = $metrics
        statusSignals = @($statusSignals)
        improvedMetrics = @($metrics | Where-Object { $_.classification -eq "improved" })
        regressedMetrics = @($metrics | Where-Object { $_.classification -eq "regressed" })
        unchangedMetrics = @($metrics | Where-Object { $_.classification -eq "unchanged" })
        improvedSignals = @($statusSignals | Where-Object { $_.classification -eq "improved" })
        regressedSignals = @($statusSignals | Where-Object { $_.classification -eq "regressed" })
        changedSignals = @($statusSignals | Where-Object { $_.classification -eq "changed" })
        evidenceChanges = @(
            if ($baseline.evidenceClass -ne $current.evidenceClass) {
                "evidenceClass: $($baseline.evidenceClass) -> $($current.evidenceClass)"
            }
            if ($baseline.comparabilityStatus -ne $current.comparabilityStatus) {
                "comparabilityStatus: $($baseline.comparabilityStatus) -> $($current.comparabilityStatus)"
            }
            if ($baseline.publishabilityGateStatus -ne $current.publishabilityGateStatus) {
                "publishabilityGate: $($baseline.publishabilityGateStatus) -> $($current.publishabilityGateStatus)"
            }
            if ($baseline.evidenceDiagnostics.evidenceQualityClass -ne $current.evidenceDiagnostics.evidenceQualityClass) {
                "evidenceQualityClass: $($baseline.evidenceDiagnostics.evidenceQualityClass) -> $($current.evidenceDiagnostics.evidenceQualityClass)"
            }
            if ($baseline.evidenceDiagnostics.evidenceQualityPublishable -ne $current.evidenceDiagnostics.evidenceQualityPublishable) {
                "evidenceQualityPublishable: $($baseline.evidenceDiagnostics.evidenceQualityPublishable) -> $($current.evidenceDiagnostics.evidenceQualityPublishable)"
            }
            if ($baseline.evidenceDiagnostics.allocationAttributionStatus -ne $current.evidenceDiagnostics.allocationAttributionStatus) {
                "allocationAttribution: $($baseline.evidenceDiagnostics.allocationAttributionStatus) -> $($current.evidenceDiagnostics.allocationAttributionStatus)"
            }
            if ($baseline.evidenceDiagnostics.exceptionAttributionStatus -ne $current.evidenceDiagnostics.exceptionAttributionStatus) {
                "exceptionAttribution: $($baseline.evidenceDiagnostics.exceptionAttributionStatus) -> $($current.evidenceDiagnostics.exceptionAttributionStatus)"
            }
            if ($baseline.evidenceDiagnostics.quicBufferPoolStatus -ne $current.evidenceDiagnostics.quicBufferPoolStatus) {
                "quicBufferPool: $($baseline.evidenceDiagnostics.quicBufferPoolStatus) -> $($current.evidenceDiagnostics.quicBufferPoolStatus)"
            }
            $baselineBlockers = @($baseline.publishabilityBlockers) -join ", "
            $currentBlockers = @($current.publishabilityBlockers) -join ", "
            if ($baselineBlockers -ne $currentBlockers) {
                "publishabilityBlockers: $baselineBlockers -> $currentBlockers"
            }
            $baselineQualityBlockers = @($baseline.evidenceDiagnostics.evidenceQualityBlockers) -join ", "
            $currentQualityBlockers = @($current.evidenceDiagnostics.evidenceQualityBlockers) -join ", "
            if ($baselineQualityBlockers -ne $currentQualityBlockers) {
                "evidenceQualityBlockers: $baselineQualityBlockers -> $currentQualityBlockers"
            }
        )
    }) | Out-Null
}

foreach ($key in @($currentByKey.Keys | Sort-Object)) {
    if (-not $baselineByKey.ContainsKey($key)) {
        $addedRows.Add($currentByKey[$key]) | Out-Null
    }
}

$report = [pscustomobject][ordered]@{
    schemaVersion = "incursa.quic.protocol-lab-performance-triage.v1"
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString("O")
    runId = $RunId
    repositoryRoot = $repoRoot
    protocolLabExecutionRoot = $resolvedProtocolLabExecutionRoot
    runsRoot = $resolvedRunsRoot
    baselineRun = $BaselineRun
    currentRun = $CurrentRun
    baselineRunRoot = $baselineRoot
    currentRunRoot = $currentRoot
    percentTolerance = $PercentTolerance
    baselineRowCount = $baselineRows.Count
    currentRowCount = $currentRows.Count
    matchingRowCount = $matchingComparisons.Count
    missingRowCount = $missingRows.Count
    addedRowCount = $addedRows.Count
    comparisons = @($matchingComparisons)
    missingRows = @($missingRows)
    addedRows = @($addedRows)
}

$jsonPath = Join-Path $reportRoot "performance-triage.json"
$markdownPath = Join-Path $reportRoot "performance-triage.md"
$report | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $jsonPath -Encoding utf8NoBOM

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# QUIC ProtocolLab Performance Triage")
$lines.Add("")
$lines.Add("- Run ID: ``$RunId``")
$lines.Add("- Generated: ``$($report.generatedAtUtc)``")
$lines.Add("- Baseline: ``$BaselineRun``")
$lines.Add("- Current: ``$CurrentRun``")
$lines.Add("- Baseline root: ``$baselineRoot``")
$lines.Add("- Current root: ``$currentRoot``")
$lines.Add("- Matching rows: ``$($matchingComparisons.Count)``")
$lines.Add("- Missing rows: ``$($missingRows.Count)``")
$lines.Add("- Added rows: ``$($addedRows.Count)``")
$lines.Add("- JSON: ``$jsonPath``")
$lines.Add("")
$lines.Add("This is a local triage report. It compares retained ProtocolLab aggregate rows and does not upgrade local evidence into publishable benchmark evidence.")
$lines.Add("")
$lines.Add("## Summary")
$lines.Add("")
if ($matchingComparisons.Count -eq 0) {
    $lines.Add("No matching implementation/scenario rows were found.")
}
else {
    $lines.Add("| scenario | implementation | primary metric | p95 | allocation | exceptions | validation | warnings | reps |")
    $lines.Add("| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | --- |")
    foreach ($comparison in @($matchingComparisons | Sort-Object scenarioId, implementationId)) {
        $primary = $comparison.metrics | Where-Object { $_.name -eq $comparison.current.primaryMetricName } | Select-Object -First 1
        $latency = $comparison.metrics | Where-Object { $_.name -eq "latencyP95Ms" } | Select-Object -First 1
        $allocation = $comparison.metrics | Where-Object { $_.name -eq "allocationRateBytesPerSecond" } | Select-Object -First 1
        $exceptions = $comparison.metrics | Where-Object { $_.name -eq "exceptionRate" } | Select-Object -First 1
        $validationText = "$($comparison.baseline.validationFailed)/$($comparison.baseline.validationInfrastructureFailure) -> $($comparison.current.validationFailed)/$($comparison.current.validationInfrastructureFailure)"
        $warningsText = "$($comparison.baseline.warningCount) -> $($comparison.current.warningCount)"
        $repsText = "$($comparison.baseline.observedRepetitions)/$($comparison.baseline.requestedRepetitions) -> $($comparison.current.observedRepetitions)/$($comparison.current.requestedRepetitions)"
        $lines.Add("| ``$($comparison.scenarioId)`` | ``$($comparison.implementationId)`` | $(Format-MetricForMarkdown $primary) | $(Format-MetricForMarkdown $latency) | $(Format-MetricForMarkdown $allocation) | $(Format-MetricForMarkdown $exceptions) | $validationText | $warningsText | $repsText |")
    }
}

$lines.Add("")
$lines.Add("## Improved")
$lines.Add("")
$improvedItems = @(
    foreach ($comparison in @($matchingComparisons)) {
        foreach ($metric in @($comparison.improvedMetrics)) {
            "- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: $($metric.name) improved from $(Format-Number $metric.baseline) to $(Format-Number $metric.current) ($(Format-DeltaPercent $metric.deltaPercent))."
        }
        foreach ($signal in @($comparison.improvedSignals)) {
            "- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: $($signal.name) improved from $($signal.baseline) to $($signal.current)."
        }
    }
)
if ($improvedItems.Count -eq 0) {
    $lines.Add("- No improved signals exceeded the configured tolerance.")
}
else {
    foreach ($item in $improvedItems) {
        $lines.Add([string]$item)
    }
}

$lines.Add("")
$lines.Add("## Regressed Or Noisier")
$lines.Add("")
$regressedItems = @(
    foreach ($comparison in @($matchingComparisons)) {
        foreach ($metric in @($comparison.regressedMetrics)) {
            "- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: $($metric.name) regressed from $(Format-Number $metric.baseline) to $(Format-Number $metric.current) ($(Format-DeltaPercent $metric.deltaPercent))."
        }
        foreach ($signal in @($comparison.regressedSignals)) {
            "- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: $($signal.name) regressed from $($signal.baseline) to $($signal.current)."
        }
        foreach ($signal in @($comparison.changedSignals)) {
            "- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: $($signal.name) changed from $($signal.baseline) to $($signal.current)."
        }
    }
)
if ($regressedItems.Count -eq 0) {
    $lines.Add("- No regressed signals exceeded the configured tolerance.")
}
else {
    foreach ($item in $regressedItems) {
        $lines.Add([string]$item)
    }
}

$lines.Add("")
$lines.Add("## Evidence Quality Changes")
$lines.Add("")
$evidenceItems = @(
    foreach ($comparison in @($matchingComparisons)) {
        foreach ($change in @($comparison.evidenceChanges)) {
            "- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: $change"
        }
    }
)
if ($evidenceItems.Count -eq 0) {
    $lines.Add("- No evidence-class, comparability, publishability, or publishability-blocker changes were detected.")
}
else {
    foreach ($item in $evidenceItems) {
        $lines.Add([string]$item)
    }
}

$lines.Add("")
$lines.Add("## Current Evidence Bundle Diagnostics")
$lines.Add("")
$diagnosticRows = @($matchingComparisons | Sort-Object scenarioId, implementationId)
if ($diagnosticRows.Count -eq 0) {
    $lines.Add("- No matching rows were available for evidence-bundle diagnostics.")
}
else {
    foreach ($comparison in $diagnosticRows) {
        $diagnostics = $comparison.current.evidenceDiagnostics
        if (-not $diagnostics.bundleAvailable) {
            $lines.Add("- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: no ``evidence-bundle.json`` was found next to the current aggregate.")
            continue
        }

        $qualityBlockers = @($diagnostics.evidenceQualityBlockers)
        $qualityText = if ($qualityBlockers.Count -gt 0) { $qualityBlockers -join "; " } else { "none" }
        $allocationReason = if ([string]::IsNullOrWhiteSpace($diagnostics.allocationAttributionUnavailableReason)) { "" } else { " ($($diagnostics.allocationAttributionUnavailableReason))" }
        $exceptionReason = if ([string]::IsNullOrWhiteSpace($diagnostics.exceptionAttributionUnavailableReason)) { "" } else { " ($($diagnostics.exceptionAttributionUnavailableReason))" }
        $bufferReason = if ([string]::IsNullOrWhiteSpace($diagnostics.quicBufferPoolUnavailableReason)) { "" } else { " ($($diagnostics.quicBufferPoolUnavailableReason))" }
        $lines.Add("- ``$($comparison.scenarioId)`` / ``$($comparison.implementationId)``: quality ``$($diagnostics.evidenceQualityClass)``; publishable ``$($diagnostics.evidenceQualityPublishable)``; blockers: $qualityText")
        $lines.Add("  - diagnostics: allocation ``$($diagnostics.allocationAttributionStatus)``$allocationReason; exceptions ``$($diagnostics.exceptionAttributionStatus)``$exceptionReason; buffer pool ``$($diagnostics.quicBufferPoolStatus)``$bufferReason; qlog ``$($diagnostics.qlogStatus)`` files ``$($diagnostics.qlogFileCount)``; hotspot trend groups ``$($diagnostics.hotspotTrendCount)``")
        foreach ($group in @($diagnostics.allocationTopGroups)) {
            $lines.Add("  - allocation hotspot: $group")
        }
        foreach ($group in @($diagnostics.exceptionTopGroups)) {
            $lines.Add("  - exception hotspot: $group")
        }
        foreach ($group in @($diagnostics.quicBufferPoolTopMetrics)) {
            $lines.Add("  - buffer-pool metric: $group")
        }
    }
}

$lines.Add("")
$lines.Add("## Missing Or Added Rows")
$lines.Add("")
if ($missingRows.Count -eq 0 -and $addedRows.Count -eq 0) {
    $lines.Add("- No implementation/scenario rows were added or removed.")
}
foreach ($row in @($missingRows)) {
    $lines.Add("- Missing in current: ``$($row.scenarioId)`` / ``$($row.implementationId)`` from baseline run ``$($row.runId)``.")
}
foreach ($row in @($addedRows)) {
    $lines.Add("- Added in current: ``$($row.scenarioId)`` / ``$($row.implementationId)`` from current run ``$($row.runId)``.")
}

$lines.Add("")
$lines.Add("## Source Files")
$lines.Add("")
$lines.Add("- Baseline aggregate: ``$(Join-Path $baselineRoot "aggregate-results.json")``")
$lines.Add("- Current aggregate: ``$(Join-Path $currentRoot "aggregate-results.json")``")
if (Test-Path -LiteralPath (Join-Path $baselineRoot "evidence-bundle.json") -PathType Leaf) {
    $lines.Add("- Baseline evidence bundle: ``$(Join-Path $baselineRoot "evidence-bundle.json")``")
}
if (Test-Path -LiteralPath (Join-Path $currentRoot "evidence-bundle.json") -PathType Leaf) {
    $lines.Add("- Current evidence bundle: ``$(Join-Path $currentRoot "evidence-bundle.json")``")
}

Set-Content -LiteralPath $markdownPath -Value $lines -Encoding utf8NoBOM

[pscustomobject][ordered]@{
    RunRoot = $reportRoot
    Json = $jsonPath
    Markdown = $markdownPath
    MatchingRows = $matchingComparisons.Count
    MissingRows = $missingRows.Count
    AddedRows = $addedRows.Count
} | ConvertTo-Json
