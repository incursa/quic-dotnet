[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ProfilePackRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Format-Value($Value, [string] $Suffix = "") {
    if ($null -eq $Value) {
        return "n/a"
    }

    if ($Value -is [double] -or $Value -is [float] -or $Value -is [decimal]) {
        return ("{0:N2}{1}" -f $Value, $Suffix)
    }

    if ($Value -is [int] -or $Value -is [long]) {
        return ("{0:N0}{1}" -f $Value, $Suffix)
    }

    return "$Value$Suffix"
}

function Get-Median($Metric) {
    if ($null -eq $Metric) {
        return $null
    }

    if ($Metric.PSObject.Properties.Name -contains "median") {
        return $Metric.median
    }

    return $Metric
}

function Add-TopLines([System.Collections.Generic.List[string]] $Lines, [string] $Title, [string] $Path, [int] $Count) {
    $Lines.Add("")
    $Lines.Add("## $Title")
    $Lines.Add("")
    if (-not (Test-Path -LiteralPath $Path)) {
        $Lines.Add("Not available: ``$Path``")
        return
    }

    $Lines.Add("Source: ``$Path``")
    $Lines.Add("")
    $Lines.Add("``````text")
    $selected = Get-Content -Path $Path -ErrorAction SilentlyContinue |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -First $Count
    foreach ($line in $selected) {
        $Lines.Add($line)
    }
    $Lines.Add("``````")
}

$resolvedRoot = (Resolve-Path -LiteralPath $ProfilePackRoot).Path
$profilePath = Join-Path $resolvedRoot "profile-pack.json"
if (-not (Test-Path -LiteralPath $profilePath)) {
    throw "profile-pack.json was not found under $resolvedRoot."
}

$profile = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
$summaryPath = Join-Path $resolvedRoot "summary.md"
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# Incursa H3 Profile Pack $($profile.runId)")
$lines.Add("")
$lines.Add("- run id: ``$($profile.runId)``")
$lines.Add("- scenario: ``$($profile.scenarioId)``")
$lines.Add("- profile pack root: ``$resolvedRoot``")
$lines.Add("- ProtocolLab root: ``$($profile.protocolLabRoot)``")
$lines.Add("- shape: c$($profile.connections)-s$($profile.streamsPerConnection), duration $($profile.durationSeconds)s, warmup $($profile.warmupSeconds)s, repetitions $($profile.repetitions)")
$lines.Add("- target configuration: ``$($profile.targetConfiguration)``")
$lines.Add("- load-tool qlog disabled: ``$($profile.disableLoadToolQlog)``")
$lines.Add("")
$lines.Add("Diagnostic passes are separate ProtocolLab runs unless a pass explicitly says otherwise. Do not compare counters and traces as one shared interval.")

$lines.Add("")
$lines.Add("## Tool Availability")
$lines.Add("")
$lines.Add("| tool | available | version/status |")
$lines.Add("| --- | --- | --- |")
foreach ($tool in $profile.toolVersions) {
    $status = if ($tool.Available) { "yes" } else { "no" }
    $version = if ([string]::IsNullOrWhiteSpace($tool.Version)) { "exit $($tool.ExitCode)" } else { $tool.Version.Replace("`r", " ").Replace("`n", " ") }
    $lines.Add("| ``$($tool.Tool)`` | $status | ``$version`` |")
}

$counterPass = $profile.passes | Where-Object { $_.Name -eq "counters" } | Select-Object -First 1
if ($counterPass) {
    $aggregatePath = Join-Path $counterPass.ProtocolLabRunRoot "aggregate-results.json"
    $lines.Add("")
    $lines.Add("## Benchmark And Counters")
    $lines.Add("")
    $lines.Add("- ProtocolLab run: ``$($counterPass.ProtocolLabRunRoot)``")
    if (Test-Path -LiteralPath $aggregatePath) {
        $aggregate = Get-Content -Path $aggregatePath -Raw | ConvertFrom-Json
        $lines.Add("")
        $lines.Add("| scenario | req/s | p50 | p95 | p99 | alloc rate | B/request | GC delta gen0/gen1/gen2 | CPU mean/max |")
        $lines.Add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |")
        foreach ($item in $aggregate.aggregates) {
            $rps = Get-Median $item.requestsPerSecond
            $allocRate = Get-Median $item.counterAllocationRateMean
            $bytesPerRequest = if ($rps -and $allocRate) { [double]$allocRate / [double]$rps } else { $null }
            $gc0 = Get-Median $item.counterGen0CollectionsDelta
            $gc1 = Get-Median $item.counterGen1CollectionsDelta
            $gc2 = Get-Median $item.counterGen2CollectionsDelta
            $cpuMean = Get-Median $item.counterCpuMean
            $cpuMax = Get-Median $item.counterCpuMax
            $lines.Add("| ``$($item.scenarioId)`` | $(Format-Value $rps) | $(Format-Value (Get-Median $item.latencyP50Ms) " ms") | $(Format-Value (Get-Median $item.latencyP95Ms) " ms") | $(Format-Value (Get-Median $item.latencyP99Ms) " ms") | $(Format-Value $allocRate " B/s") | $(Format-Value $bytesPerRequest " B") | $(Format-Value $gc0)/$(Format-Value $gc1)/$(Format-Value $gc2) | $(Format-Value $cpuMean "%") / $(Format-Value $cpuMax "%") |")
        }
    }
    else {
        $lines.Add("No aggregate-results.json was found for the counter pass.")
    }
}

$cpuPass = $profile.passes | Where-Object { $_.Name -eq "cpu-trace" } | Select-Object -First 1
if ($cpuPass) {
    $lines.Add("")
    $lines.Add("## CPU Trace")
    $lines.Add("")
    $lines.Add("- trace root: ``$($cpuPass.ArtifactRoot)``")
    $lines.Add("- raw trace: ``$(Join-Path $cpuPass.ArtifactRoot "trace.nettrace")``")
    if ($profile.speedscope -and $profile.speedscope.Output) {
        $lines.Add("- Speedscope: ``$($profile.speedscope.Output)``")
    }
    else {
        $lines.Add("- Speedscope: not generated; inspect convert stdout/stderr if the CPU pass succeeded.")
    }
    Add-TopLines $lines "CPU TopN Exclusive Highlights" (Join-Path $cpuPass.ArtifactRoot "topN-exclusive.txt") 12
    Add-TopLines $lines "CPU TopN Inclusive Highlights" (Join-Path $cpuPass.ArtifactRoot "topN-inclusive.txt") 12
}

$gcPass = $profile.passes | Where-Object { $_.Name -eq "gc-trace" } | Select-Object -First 1
if ($gcPass) {
    $lines.Add("")
    $lines.Add("## GC And Allocation Trace")
    $lines.Add("")
    $lines.Add("- trace root: ``$($gcPass.ArtifactRoot)``")
    $lines.Add("- raw trace: ``$(Join-Path $gcPass.ArtifactRoot "trace.nettrace")``")
    Add-TopLines $lines "GC Trace TopN Highlights" (Join-Path $gcPass.ArtifactRoot "topN-inclusive.txt") 14
    $lines.Add("")
    $lines.Add("Allocation event count and top allocated type names are not extracted by this script. ``dotnet-trace report topN`` gives method-level sampled evidence, not reliable per-type allocation stacks. Use PerfView or Visual Studio allocation analysis for System.Byte[] stack attribution.")
}

if ($profile.gcdump) {
    $lines.Add("")
    $lines.Add("## GC Dump")
    $lines.Add("")
    $lines.Add("- status: ``$($profile.gcdump.Status)``")
    $lines.Add("- before: ``$($profile.gcdump.Before)``")
    $lines.Add("- after: ``$($profile.gcdump.After)``")
    $lines.Add("")
    $lines.Add("GC dumps show live heap composition at collection points. They do not prove transient allocation rate and are most useful for retained-object review.")
}

if ($profile.perfview) {
    $lines.Add("")
    $lines.Add("## PerfView")
    $lines.Add("")
    $lines.Add("- status: ``$($profile.perfview.Status)``")
    if ($profile.perfview.Output) {
        $lines.Add("- output: ``$($profile.perfview.Output)``")
    }
    elseif ($profile.perfview.Instructions) {
        $lines.Add("- instructions: ``$($profile.perfview.Instructions)``")
    }
}
else {
    $lines.Add("")
    $lines.Add("## PerfView")
    $lines.Add("")
    $lines.Add("Not requested. For allocation stacks, run the pack with ``-CollectPerfView`` and ``-PerfViewPath`` or open the preserved ``.nettrace`` files in Visual Studio/PerfView.")
}

$lines.Add("")
$lines.Add("## Next Investigation Target")
$lines.Add("")
$lines.Add("Start with manual allocation-stack review of the GC trace in PerfView or Visual Studio. Prior P-phase evidence points at ``System.Byte[]`` packet/STREAM/H3/QPACK ownership boundaries, but this summary does not claim a new bottleneck without stack evidence.")

Set-Content -Path $summaryPath -Value $lines
Get-Content -Path $summaryPath
