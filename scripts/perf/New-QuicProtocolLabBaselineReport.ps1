[CmdletBinding()]
param(
    [string] $ProtocolLabExecutionRoot = "C:\shared\src\incursa\protocol-lab-internal",

    [string] $RunsRoot,

    [string[]] $ProtocolLabRunRoot = @(),

    [string] $OutputRoot = ".artifacts\perf-baselines",

    [string] $RunId = "quic-baseline-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [string[]] $ImplementationId = @(),

    [string[]] $ScenarioId = @(
        "http3.payload.bytes.1kb",
        "http3.payload.bytes.64kb",
        "quic.transport.stream-throughput.1mb",
        "quic.transport.multiplex.100x64kb",
        "quic.transport.duplex-streams"
    )
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

function Format-Number {
    param($Value, [string] $Format = "0.###")

    if ($null -eq $Value) {
        return "n/a"
    }

    return ([double]$Value).ToString($Format, [Globalization.CultureInfo]::InvariantCulture)
}

function Format-DeltaPercent {
    param($Current, $Baseline)

    if ($null -eq $Current -or $null -eq $Baseline -or [double]$Baseline -eq 0) {
        return "n/a"
    }

    $delta = (([double]$Current - [double]$Baseline) / [Math]::Abs([double]$Baseline)) * 100.0
    return $delta.ToString("+0.##;-0.##;0", [Globalization.CultureInfo]::InvariantCulture) + "%"
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

function Get-PrimaryMetricName {
    param([string] $Scenario)

    if ($Scenario.StartsWith("quic.transport.", [StringComparison]::OrdinalIgnoreCase)) {
        return "throughputBytesPerSecond"
    }

    return "requestsPerSecond"
}

function Get-BaselineScore {
    param($Row)

    if ($Row.primaryMetricName -eq "throughputBytesPerSecond") {
        return $Row.throughputBytesPerSecond
    }

    return $Row.requestsPerSecond
}

function Get-StringArray {
    param($Value)

    return @($Value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
}

function Expand-StringList {
    param([string[]] $Value)

    foreach ($item in @($Value)) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            continue
        }

        foreach ($part in $item -split ",") {
            $trimmed = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $trimmed
            }
        }
    }
}

function Get-RunDirectories {
    param(
        [string[]] $RequestedRunRoots,
        [string] $ResolvedRunsRoot
    )

    if ($RequestedRunRoots.Count -gt 0) {
        foreach ($runRoot in $RequestedRunRoots) {
            $resolved = Resolve-FullPath -Path $runRoot -BasePath $repoRoot
            if (-not (Test-Path -LiteralPath (Join-Path $resolved "aggregate-results.json") -PathType Leaf)) {
                Write-Warning "Skipping run without aggregate-results.json: $resolved"
                continue
            }

            Get-Item -LiteralPath $resolved
        }

        return
    }

    if (-not (Test-Path -LiteralPath $ResolvedRunsRoot -PathType Container)) {
        throw "Runs root not found: $ResolvedRunsRoot"
    }

    Get-ChildItem -LiteralPath $ResolvedRunsRoot -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "aggregate-results.json") -PathType Leaf }
}

$repoRoot = Get-RepoRoot
$resolvedProtocolLabExecutionRoot = Resolve-FullPath -Path $ProtocolLabExecutionRoot -BasePath $repoRoot
if ([string]::IsNullOrWhiteSpace($RunsRoot)) {
    $RunsRoot = Join-Path $resolvedProtocolLabExecutionRoot ".artifacts\runs"
}

$resolvedRunsRoot = Resolve-FullPath -Path $RunsRoot -BasePath $repoRoot
$resolvedOutputRoot = Resolve-FullPath -Path $OutputRoot -BasePath $repoRoot
$reportRoot = Join-Path $resolvedOutputRoot $RunId
$jsonPath = Join-Path $reportRoot "baseline-report.json"
$markdownPath = Join-Path $reportRoot "baseline-report.md"
New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null

$scenarioSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($id in @(Expand-StringList $ScenarioId)) {
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        [void]$scenarioSet.Add($id)
    }
}

$implementationSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($id in @(Expand-StringList $ImplementationId)) {
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        [void]$implementationSet.Add($id)
    }
}

$rows = New-Object System.Collections.Generic.List[object]
$runDirectories = @(Get-RunDirectories -RequestedRunRoots $ProtocolLabRunRoot -ResolvedRunsRoot $resolvedRunsRoot)
foreach ($runDirectory in $runDirectories) {
    $aggregatePath = Join-Path $runDirectory.FullName "aggregate-results.json"
    $document = Get-Content -LiteralPath $aggregatePath -Raw | ConvertFrom-Json
    $generatedAt = if (Test-Property $document "generatedAt") { [DateTimeOffset]::Parse([string]$document.generatedAt) } else { [DateTimeOffset]::new([DateTime]::SpecifyKind($runDirectory.LastWriteTimeUtc, [DateTimeKind]::Utc)) }
    foreach ($aggregate in @($document.aggregates)) {
        $scenario = [string](Get-OptionalPropertyValue $aggregate "scenarioId")
        if ([string]::IsNullOrWhiteSpace($scenario)) {
            Write-Warning "Skipping aggregate row without scenarioId in $aggregatePath"
            continue
        }
        if ($scenarioSet.Count -gt 0 -and -not $scenarioSet.Contains($scenario)) {
            continue
        }

        $implementation = [string](Get-OptionalPropertyValue $aggregate "implementationId")
        if ($implementationSet.Count -gt 0 -and -not $implementationSet.Contains($implementation)) {
            continue
        }

        $primaryMetric = Get-PrimaryMetricName -Scenario $scenario
        $validation = Get-OptionalPropertyValue $aggregate "validation"
        $evidence = Get-OptionalPropertyValue $aggregate "evidence"
        $row = [ordered]@{
            runId = [string]$document.runId
            generatedAt = $generatedAt.ToUniversalTime().ToString("O")
            runRoot = $runDirectory.FullName
            aggregatePath = $aggregatePath
            implementationId = $implementation
            implementationName = [string](Get-OptionalPropertyValue $aggregate "implementationName")
            scenarioId = $scenario
            scenarioName = [string](Get-OptionalPropertyValue $aggregate "scenarioName")
            protocol = [string](Get-OptionalPropertyValue $aggregate "protocol")
            loadTool = [string](Get-OptionalPropertyValue $aggregate "loadTool")
            evidenceClass = if ($evidence) { [string]$evidence.evidenceClass } else { $null }
            comparabilityStatus = if ($evidence) { [string]$evidence.comparabilityStatus } else { $null }
            validationPassed = if ($validation) { [int]$validation.passed } else { 0 }
            validationFailed = if ($validation) { [int]$validation.failed } else { 0 }
            validationInfrastructureFailure = if ($validation) { [int]$validation.infrastructureFailure } else { 0 }
            benchmarkStatus = Format-StatusMap (Get-OptionalPropertyValue $aggregate "benchmarkExecutionStatuses")
            primaryMetricName = $primaryMetric
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
            qlogFileCountMedian = Get-OptionalPropertyValue $aggregate "qlogFileCountMedian"
            requestedRepetitions = Get-OptionalPropertyValue $aggregate "requestedRepetitions"
            observedRepetitions = Get-OptionalPropertyValue $aggregate "observedRepetitions"
            missingRepetitions = Get-OptionalPropertyValue $aggregate "missingRepetitions"
            relativeRange = Get-OptionalPropertyValue $aggregate "relativeRange"
            connections = Get-OptionalPropertyValue $aggregate "connections"
            streamsPerConnection = Get-OptionalPropertyValue $aggregate "streamsPerConnection"
            publishabilityGateStatus = if ((Test-Property $aggregate "publishabilityGate") -and $aggregate.publishabilityGate) { [string]$aggregate.publishabilityGate.status } else { $null }
            publishabilityBlockers = if ((Test-Property $aggregate "publishabilityGate") -and $aggregate.publishabilityGate) { Get-StringArray $aggregate.publishabilityGate.blockers } else { @() }
            warnings = Get-StringArray (Get-OptionalPropertyValue $aggregate "warnings")
            failureReasons = Get-StringArray (Get-OptionalPropertyValue $aggregate "failureReasons")
        }
        $rows.Add([pscustomobject]$row) | Out-Null
    }
}

$groups = New-Object System.Collections.Generic.List[object]
$groupedRows = $rows |
    Sort-Object scenarioId, implementationId, generatedAt |
    Group-Object scenarioId, implementationId

foreach ($group in $groupedRows) {
    $ordered = @($group.Group | Sort-Object generatedAt -Descending)
    $current = $ordered | Select-Object -First 1
    $previous = $ordered | Select-Object -Skip 1 -First 1
    $best = $ordered |
        Where-Object {
            $_.validationFailed -eq 0 -and
            $_.validationInfrastructureFailure -eq 0 -and
            $_.benchmarkStatus -notmatch "failed="
        } |
        Sort-Object @{ Expression = { Get-BaselineScore $_ }; Descending = $true } |
        Select-Object -First 1
    if (-not $best) {
        $best = $ordered | Sort-Object @{ Expression = { Get-BaselineScore $_ }; Descending = $true } | Select-Object -First 1
    }

    $currentScore = Get-BaselineScore $current
    $previousScore = if ($previous) { Get-BaselineScore $previous } else { $null }
    $bestScore = if ($best) { Get-BaselineScore $best } else { $null }
    $groups.Add([pscustomobject][ordered]@{
        scenarioId = $current.scenarioId
        implementationId = $current.implementationId
        current = $current
        previous = $previous
        best = $best
        primaryMetricName = $current.primaryMetricName
        currentVsPrevious = Format-DeltaPercent $currentScore $previousScore
        currentVsBest = Format-DeltaPercent $currentScore $bestScore
    }) | Out-Null
}

$reportScenarioIds = @(Expand-StringList $ScenarioId | Sort-Object -Unique)
$reportImplementationIds = @(Expand-StringList $ImplementationId | Sort-Object -Unique)
$reportGroups = @($groups.ToArray())
$reportRows = @($rows.ToArray())
$reportRunDirectories = @($runDirectories)

$report = [ordered]@{
    schemaVersion = "incursa.quic.protocol-lab-baseline-report.v1"
    generatedAt = ([DateTimeOffset]::new([DateTime]::UtcNow)).ToString("O")
    runId = $RunId
    protocolLabExecutionRoot = $resolvedProtocolLabExecutionRoot
    runsRoot = $resolvedRunsRoot
    outputRoot = $reportRoot
    scenarioIds = $reportScenarioIds
    implementationIds = $reportImplementationIds
    sourceRunCount = $reportRunDirectories.Count
    rowCount = $reportRows.Count
    groups = $reportGroups
    rows = $reportRows
}

$json = $report | ConvertTo-Json -Depth 32
Set-Content -LiteralPath $jsonPath -Value $json -Encoding utf8NoBOM

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# QUIC ProtocolLab Baseline Report")
$lines.Add("")
$lines.Add("- Run ID: ``$RunId``")
$lines.Add("- Generated: ``$($report.generatedAt)``")
$lines.Add("- ProtocolLab execution root: ``$resolvedProtocolLabExecutionRoot``")
$lines.Add("- Runs scanned: ``$($runDirectories.Count)``")
$lines.Add("- Matching rows: ``$($rows.Count)``")
if ($reportImplementationIds.Count -gt 0) {
    $lines.Add("- Implementation filter: ``$($reportImplementationIds -join ', ')``")
}
$lines.Add("- JSON: ``$jsonPath``")
$lines.Add("")
$lines.Add("This is a local evidence rollup. It does not upgrade local ProtocolLab evidence into publishable benchmark evidence.")
$lines.Add("")
$lines.Add("## Current Baselines")
$lines.Add("")
$lines.Add("| scenario | implementation | shape | evidence | validation | benchmark | primary metric | current | vs previous | vs best | p95 ms | alloc B/s | exceptions/s | reps | source |")
$lines.Add("| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |")
foreach ($group in @($groups | Sort-Object scenarioId, implementationId)) {
    $current = $group.current
    $score = Get-BaselineScore $current
    $validationText = "pass=$($current.validationPassed), fail=$($current.validationFailed), infra=$($current.validationInfrastructureFailure)"
    $shape = "c$($current.connections)-s$($current.streamsPerConnection)"
    $metricLabel = if ($group.primaryMetricName -eq "throughputBytesPerSecond") { "throughput B/s" } else { "requests/s" }
    $lines.Add("| ``$($current.scenarioId)`` | ``$($current.implementationId)`` | ``$shape`` | ``$($current.evidenceClass)`` / ``$($current.comparabilityStatus)`` | ``$validationText`` | ``$($current.benchmarkStatus)`` | ``$metricLabel`` | $(Format-Number $score "0.##") | $($group.currentVsPrevious) | $($group.currentVsBest) | $(Format-Number $current.latencyP95Ms "0.###") | $(Format-Number $current.allocationRateBytesPerSecond "0") | $(Format-Number $current.exceptionRate "0.###") | $($current.observedRepetitions)/$($current.requestedRepetitions) | ``$($current.runId)`` |")
}

$lines.Add("")
$lines.Add("## Attention")
$lines.Add("")
$attentionRows = @($groups | Where-Object {
        $_.current.validationFailed -gt 0 -or
        $_.current.validationInfrastructureFailure -gt 0 -or
        $_.current.benchmarkStatus -match "failed=" -or
        @($_.current.failureReasons).Count -gt 0 -or
        @($_.current.publishabilityBlockers).Count -gt 0
    })
if ($attentionRows.Count -eq 0) {
    $lines.Add("- No current baseline rows reported validation, benchmark, failure-reason, or publishability blockers.")
}
else {
    foreach ($group in $attentionRows | Sort-Object scenarioId, implementationId) {
        $current = $group.current
        $reasons = @()
        if (@($current.failureReasons).Count -gt 0) {
            $reasons += @($current.failureReasons)
        }
        if (@($current.publishabilityBlockers).Count -gt 0) {
            $reasons += @($current.publishabilityBlockers)
        }
        if ($reasons.Count -eq 0) {
            $reasons += "validation/benchmark status needs review"
        }

        $lines.Add("- ``$($current.scenarioId)`` / ``$($current.implementationId)``: $($reasons -join '; ')")
    }
}

$lines.Add("")
$lines.Add("## Source Runs")
$lines.Add("")
foreach ($runDirectory in $runDirectories | Sort-Object Name) {
    $lines.Add("- ``$($runDirectory.Name)``: ``$($runDirectory.FullName)``")
}

Set-Content -LiteralPath $markdownPath -Value $lines -Encoding utf8NoBOM

Write-Host "Baseline report: $markdownPath" -ForegroundColor Green
Write-Host "Baseline JSON: $jsonPath" -ForegroundColor Green
