[CmdletBinding()]
param(
    [string] $OutputRoot = ".artifacts\perf-hotspots",

    [string] $RunId = "quic-h3-hotspots-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [int] $TopCount = 12,

    [Parameter(Mandatory = $true)]
    [string[]] $ProfilePackRoot
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
    param($Value, [string] $Format = "0.##")

    if ($null -eq $Value) {
        return "n/a"
    }

    return ([double]$Value).ToString($Format, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-DeltaPercent {
    param($Current, $Baseline)

    if ($null -eq $Current -or $null -eq $Baseline -or [double]$Baseline -eq 0) {
        return $null
    }

    return (([double]$Current - [double]$Baseline) / [Math]::Abs([double]$Baseline)) * 100.0
}

function Format-DeltaPercent {
    param($Current, $Baseline)

    $delta = Get-DeltaPercent -Current $Current -Baseline $Baseline
    return Format-PercentValue -Value $delta
}

function Format-PercentValue {
    param($Value)

    $delta = $Value
    if ($null -eq $delta) {
        return "n/a"
    }

    return $delta.ToString("+0.##;-0.##;0", [Globalization.CultureInfo]::InvariantCulture) + "%"
}

function Get-Pass {
    param($Profile, [string] $Name)

    return $Profile.passes | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
}

function Get-FirstAggregate {
    param($Pass)

    if ($null -eq $Pass -or [string]::IsNullOrWhiteSpace($Pass.ProtocolLabRunRoot)) {
        return $null
    }

    $aggregatePath = Join-Path $Pass.ProtocolLabRunRoot "aggregate-results.json"
    if (-not (Test-Path -LiteralPath $aggregatePath -PathType Leaf)) {
        return $null
    }

    $aggregate = Get-Content -Path $aggregatePath -Raw | ConvertFrom-Json
    return $aggregate.aggregates | Select-Object -First 1
}

function Read-TopN {
    param(
        [string] $Path,
        [int] $Count
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }

    $items = [System.Collections.Generic.List[object]]::new()
    $lines = Get-Content -Path $Path
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*(\d+)\.\s+(.+?)\s+([0-9.]+%)\s+([0-9.]+%)\s*$') {
            continue
        }

        $items.Add([pscustomobject]@{
            rank = [int]$Matches[1]
            function = $Matches[2].Trim()
            inclusive = $Matches[3]
            exclusive = $Matches[4]
            raw = $line.TrimEnd()
        })

        if ($items.Count -ge $Count) {
            break
        }
    }

    return @($items)
}

function Get-ProfileRow {
    param([string] $Root)

    $resolvedRoot = Resolve-FullPath -Path $Root -BasePath $repoRoot
    $profilePath = Join-Path $resolvedRoot "profile-pack.json"
    if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        throw "profile-pack.json was not found under $resolvedRoot."
    }

    $profile = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
    $counterPass = Get-Pass -Profile $profile -Name "counters"
    $cpuPass = Get-Pass -Profile $profile -Name "cpu-trace"
    $gcPass = Get-Pass -Profile $profile -Name "gc-trace"
    $aggregate = Get-FirstAggregate -Pass $counterPass

    $requestsPerSecond = Get-MedianMetric $aggregate "requestsPerSecond"
    $allocationRate = Get-MedianMetric $aggregate "counterAllocationRateMean"
    $bytesPerRequest = if ($null -ne $requestsPerSecond -and $null -ne $allocationRate -and [double]$requestsPerSecond -ne 0) {
        [double]$allocationRate / [double]$requestsPerSecond
    }
    else {
        $null
    }

    $cpuTopInclusivePath = if ($cpuPass) { Join-Path $cpuPass.ArtifactRoot "topN-inclusive.txt" } else { $null }
    $cpuTopExclusivePath = if ($cpuPass) { Join-Path $cpuPass.ArtifactRoot "topN-exclusive.txt" } else { $null }
    $gcTopInclusivePath = if ($gcPass) { Join-Path $gcPass.ArtifactRoot "topN-inclusive.txt" } else { $null }

    return [pscustomobject]@{
        runId = $profile.runId
        scenarioId = $profile.scenarioId
        profilePackRoot = $resolvedRoot
        protocolLabRoot = $profile.protocolLabRoot
        shape = "c$($profile.connections)-s$($profile.streamsPerConnection)"
        durationSeconds = $profile.durationSeconds
        warmupSeconds = $profile.warmupSeconds
        repetitions = $profile.repetitions
        requestsPerSecond = $requestsPerSecond
        latencyP95Ms = Get-MedianMetric $aggregate "latencyP95Ms"
        allocationRateBytesPerSecond = $allocationRate
        bytesPerRequest = $bytesPerRequest
        gen0CollectionsDelta = Get-MedianMetric $aggregate "counterGen0CollectionsDelta"
        gen1CollectionsDelta = Get-MedianMetric $aggregate "counterGen1CollectionsDelta"
        gen2CollectionsDelta = Get-MedianMetric $aggregate "counterGen2CollectionsDelta"
        cpuMeanPercent = Get-MedianMetric $aggregate "counterCpuMean"
        cpuMaxPercent = Get-MedianMetric $aggregate "counterCpuMax"
        cpuTopInclusivePath = $cpuTopInclusivePath
        cpuTopExclusivePath = $cpuTopExclusivePath
        gcTopInclusivePath = $gcTopInclusivePath
        cpuTopInclusive = if ($cpuTopInclusivePath) { Read-TopN -Path $cpuTopInclusivePath -Count $TopCount } else { @() }
        cpuTopExclusive = if ($cpuTopExclusivePath) { Read-TopN -Path $cpuTopExclusivePath -Count $TopCount } else { @() }
        gcTopInclusive = if ($gcTopInclusivePath) { Read-TopN -Path $gcTopInclusivePath -Count $TopCount } else { @() }
    }
}

function Expand-ProfilePackRoots {
    param([string[]] $Roots)

    $expanded = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $Roots) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }

        $parts = $root -split ';'
        foreach ($part in $parts) {
            if ([string]::IsNullOrWhiteSpace($part)) {
                continue
            }

            $expanded.Add($part.Trim())
        }
    }

    return @($expanded)
}

function Add-TopNSection {
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [string] $Title,
        [object[]] $Items,
        [string] $SourcePath
    )

    $topItems = @(
        foreach ($item in @($Items)) {
            if ($item -is [Array]) {
                foreach ($nestedItem in $item) {
                    if (Test-Property $nestedItem "function") {
                        $nestedItem
                    }
                }
            }
            elseif (Test-Property $item "function") {
                $item
            }
        }
    )
    $Lines.Add("")
    $Lines.Add("### $Title")
    $Lines.Add("")
    if ($topItems.Count -eq 0) {
        if (-not [string]::IsNullOrWhiteSpace($SourcePath)) {
            $firstLine = if (Test-Path -LiteralPath $SourcePath -PathType Leaf) {
                Get-Content -Path $SourcePath -ErrorAction SilentlyContinue |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -First 1
            }
            else {
                $null
            }

            if (-not [string]::IsNullOrWhiteSpace($firstLine) -and $firstLine.StartsWith("[ERROR]", [StringComparison]::Ordinal)) {
                $Lines.Add("TopN report failed: ``$firstLine``")
            }
            else {
                $Lines.Add("No parsed TopN rows were found.")
            }

            $Lines.Add("")
            $Lines.Add("- source: ``$SourcePath``")
        }
        else {
            $Lines.Add("No parsed TopN rows were found.")
        }

        return
    }

    $Lines.Add("- source: ``$SourcePath``")
    $Lines.Add("")
    $Lines.Add("| rank | function | inclusive | exclusive |")
    $Lines.Add("| ---: | --- | ---: | ---: |")
    foreach ($item in $topItems) {
        $function = ([string]$item.function).Replace("|", "\|")
        $Lines.Add("| $($item.rank) | ``$function`` | $($item.inclusive) | $($item.exclusive) |")
    }
}

function New-AdjacentComparisons {
    param([object[]] $Rows)

    $comparisons = [System.Collections.Generic.List[object]]::new()
    for ($index = 1; $index -lt $Rows.Count; $index++) {
        $baseline = $Rows[$index - 1]
        $current = $Rows[$index]
        if ($baseline.scenarioId -ne $current.scenarioId) {
            continue
        }

        $comparisons.Add([pscustomobject]@{
            scenarioId = $current.scenarioId
            baselineRunId = $baseline.runId
            currentRunId = $current.runId
            requestsPerSecondDeltaPercent = Get-DeltaPercent -Current $current.requestsPerSecond -Baseline $baseline.requestsPerSecond
            latencyP95MsDeltaPercent = Get-DeltaPercent -Current $current.latencyP95Ms -Baseline $baseline.latencyP95Ms
            allocationRateDeltaPercent = Get-DeltaPercent -Current $current.allocationRateBytesPerSecond -Baseline $baseline.allocationRateBytesPerSecond
            bytesPerRequestDeltaPercent = Get-DeltaPercent -Current $current.bytesPerRequest -Baseline $baseline.bytesPerRequest
            gen0CollectionsDeltaChange = if ($null -ne $current.gen0CollectionsDelta -and $null -ne $baseline.gen0CollectionsDelta) { [double]$current.gen0CollectionsDelta - [double]$baseline.gen0CollectionsDelta } else { $null }
            gen1CollectionsDeltaChange = if ($null -ne $current.gen1CollectionsDelta -and $null -ne $baseline.gen1CollectionsDelta) { [double]$current.gen1CollectionsDelta - [double]$baseline.gen1CollectionsDelta } else { $null }
            gen2CollectionsDeltaChange = if ($null -ne $current.gen2CollectionsDelta -and $null -ne $baseline.gen2CollectionsDelta) { [double]$current.gen2CollectionsDelta - [double]$baseline.gen2CollectionsDelta } else { $null }
        })
    }

    return @($comparisons)
}

$repoRoot = Get-RepoRoot
$resolvedOutputRoot = Resolve-FullPath -Path $OutputRoot -BasePath $repoRoot
$runRoot = Join-Path $resolvedOutputRoot $RunId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$expandedProfilePackRoots = Expand-ProfilePackRoots -Roots $ProfilePackRoot
$rows = @($expandedProfilePackRoots | ForEach-Object { Get-ProfileRow -Root $_ })
if ($rows.Count -eq 0) {
    throw "No profile packs were supplied."
}

$comparisons = @(New-AdjacentComparisons -Rows $rows)

$manifest = [pscustomobject]@{
    schemaVersion = "incursa.quic.h3-allocation-hotspots.v1"
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString("O")
    runId = $RunId
    repositoryRoot = $repoRoot
    profilePackRoots = @($rows | ForEach-Object { $_.profilePackRoot })
    topCount = $TopCount
    caveats = @(
        "ProtocolLab counter, CPU trace, and GC trace passes are separate runs unless the source profile pack says otherwise.",
        "dotnet-trace report topN provides sampled method-level evidence, not reliable per-type allocation stacks.",
        "Use preserved .nettrace files in PerfView or Visual Studio before making buffer ownership changes."
    )
    profiles = $rows
    adjacentComparisons = $comparisons
}

$jsonPath = Join-Path $runRoot "allocation-hotspots.json"
$markdownPath = Join-Path $runRoot "allocation-hotspots.md"
$manifest | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# QUIC H3 Allocation Hotspots $RunId")
$lines.Add("")
$lines.Add("This report rolls up existing Incursa H3 profile packs into a repeatable hotspot inventory. It is evidence for investigation, not proof that a specific allocation can be removed safely.")
$lines.Add("")
$lines.Add("## Caveats")
$lines.Add("")
foreach ($caveat in $manifest.caveats) {
    $lines.Add("- $caveat")
}

$lines.Add("")
$lines.Add("## Profile Summary")
$lines.Add("")
$lines.Add("| run | scenario | shape | req/s | p95 | alloc rate | B/request | GC delta gen0/gen1/gen2 | CPU mean/max |")
$lines.Add("| --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: |")
foreach ($row in $rows) {
    $lines.Add("| ``$($row.runId)`` | ``$($row.scenarioId)`` | $($row.shape) | $(Format-Number $row.requestsPerSecond) | $(Format-Number $row.latencyP95Ms) ms | $(Format-Number $row.allocationRateBytesPerSecond) B/s | $(Format-Number $row.bytesPerRequest) B | $(Format-Number $row.gen0CollectionsDelta)/$(Format-Number $row.gen1CollectionsDelta)/$(Format-Number $row.gen2CollectionsDelta) | $(Format-Number $row.cpuMeanPercent)% / $(Format-Number $row.cpuMaxPercent)% |")
}

if ($comparisons.Count -gt 0) {
    $lines.Add("")
    $lines.Add("## Adjacent Same-Scenario Deltas")
    $lines.Add("")
    $lines.Add("Adjacent deltas compare each profile with the previous profile only when both rows use the same scenario. Negative allocation and latency deltas are improvements; positive request-rate deltas are improvements.")
    $lines.Add("")
    $lines.Add("| scenario | baseline | current | req/s | p95 | alloc rate | B/request | GC delta gen0/gen1/gen2 |")
    $lines.Add("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |")
    foreach ($comparison in $comparisons) {
        $gen0 = if ($null -eq $comparison.gen0CollectionsDeltaChange) { "n/a" } else { Format-Number $comparison.gen0CollectionsDeltaChange }
        $gen1 = if ($null -eq $comparison.gen1CollectionsDeltaChange) { "n/a" } else { Format-Number $comparison.gen1CollectionsDeltaChange }
        $gen2 = if ($null -eq $comparison.gen2CollectionsDeltaChange) { "n/a" } else { Format-Number $comparison.gen2CollectionsDeltaChange }
        $lines.Add("| ``$($comparison.scenarioId)`` | ``$($comparison.baselineRunId)`` | ``$($comparison.currentRunId)`` | $(Format-PercentValue $comparison.requestsPerSecondDeltaPercent) | $(Format-PercentValue $comparison.latencyP95MsDeltaPercent) | $(Format-PercentValue $comparison.allocationRateDeltaPercent) | $(Format-PercentValue $comparison.bytesPerRequestDeltaPercent) | $gen0/$gen1/$gen2 |")
    }
}

foreach ($row in $rows) {
    $lines.Add("")
    $lines.Add("## $($row.runId)")
    $lines.Add("")
    $lines.Add("- profile pack: ``$($row.profilePackRoot)``")
    $lines.Add("- scenario: ``$($row.scenarioId)``")
    $lines.Add("- allocation rate: $(Format-Number $row.allocationRateBytesPerSecond) B/s")
    $lines.Add("- bytes per request: $(Format-Number $row.bytesPerRequest) B")
    Add-TopNSection -Lines $lines -Title "GC Trace Inclusive TopN" -Items $row.gcTopInclusive -SourcePath $row.gcTopInclusivePath
    Add-TopNSection -Lines $lines -Title "CPU Trace Inclusive TopN" -Items $row.cpuTopInclusive -SourcePath $row.cpuTopInclusivePath
    Add-TopNSection -Lines $lines -Title "CPU Trace Exclusive TopN" -Items $row.cpuTopExclusive -SourcePath $row.cpuTopExclusivePath
}

$lines.Add("")
$lines.Add("## Next Use")
$lines.Add("")
$lines.Add("Use the GC TopN rows to choose a focused trace review target, then inspect the preserved ``trace.nettrace`` files for allocation stacks before changing runtime buffer ownership or pooling behavior.")

Set-Content -Path $markdownPath -Value $lines

[pscustomobject]@{
    RunRoot = $runRoot
    Json = $jsonPath
    Markdown = $markdownPath
    ProfileCount = $rows.Count
} | ConvertTo-Json
