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

function Get-ObjectPropertyValue($Object, [string] $Name) {
    if ($null -eq $Object -or -not ($Object.PSObject.Properties.Name -contains $Name)) {
        return $null
    }

    return $Object.$Name
}

function Test-ObjectProperty($Object, [string] $Name) {
    return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name
}

function Format-MetricSummary($Metric) {
    if ($null -eq $Metric) {
        return "n/a"
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @("total", "mean", "max", "latest", "delta")) {
        $value = Get-ObjectPropertyValue $Metric $name
        if ($null -ne $value) {
            $parts.Add("$name $(Format-Value $value)") | Out-Null
        }
    }

    if ($parts.Count -eq 0) {
        return "n/a"
    }

    return ($parts -join ", ")
}

function Find-Metric($Metrics, [string] $MetricName) {
    $matches = @($Metrics | Where-Object { $_.metricName -eq $MetricName } | Select-Object -First 1)
    if ($matches.Count -eq 0) {
        return $null
    }

    return $matches[0]
}

function Add-BufferPoolSummary([System.Collections.Generic.List[string]] $Lines, $Pass) {
    $summaryFile = Get-ChildItem -LiteralPath $Pass.ProtocolLabRunRoot -Recurse -Filter "quic-buffer-pool-summary.json" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    $summaryPath = if ($summaryFile) { $summaryFile.FullName } else { Join-Path $Pass.ProtocolLabRunRoot "quic-buffer-pool-summary.json" }

    $Lines.Add("")
    $Lines.Add("## QUIC Buffer Pool Summary")
    $Lines.Add("")
    $Lines.Add("- Source: ``$summaryPath``")

    if (-not (Test-Path -LiteralPath $summaryPath)) {
        $Lines.Add("- Status: unavailable")
        $Lines.Add("- Reason: ``quic-buffer-pool-summary-missing``")
        return
    }

    $summary = Get-Content -Path $summaryPath -Raw | ConvertFrom-Json
    $Lines.Add("- Status: ``$($summary.status)``")
    $Lines.Add("- Samples: ``$($summary.samples)``")

    if ($summary.available -ne $true) {
        $reason = if (Test-ObjectProperty $summary "unavailableReason") { $summary.unavailableReason } else { "unknown" }
        $Lines.Add("- Reason: ``$reason``")
        if ((Test-ObjectProperty $summary "parseWarnings") -and @($summary.parseWarnings).Count -gt 0) {
            $Lines.Add("- Parse warnings: ``$(@($summary.parseWarnings) -join "`, `")``")
        }
        return
    }

    $Lines.Add("")
    $Lines.Add("| metric | summary |")
    $Lines.Add("| --- | --- |")
    foreach ($metricName in @(
        "incursa.quic.buffer_pool.requested_rents",
        "incursa.quic.buffer_pool.bytes.requested",
        "incursa.quic.buffer_pool.rents",
        "incursa.quic.buffer_pool.bytes.rented",
        "incursa.quic.buffer_pool.returns",
        "incursa.quic.buffer_pool.bytes.returned",
        "incursa.quic.buffer_pool.oversized_rents",
        "incursa.quic.buffer_pool.outstanding.buffers",
        "incursa.quic.buffer_pool.outstanding.bytes")) {
        $metric = Find-Metric $summary.metrics $metricName
        if ($null -ne $metric) {
            $Lines.Add("| ``$metricName`` | $(Format-MetricSummary $metric) |")
        }
    }

    $bucketRows = @($summary.sizeBuckets | Where-Object { @($_.metrics).Count -gt 0 })
    if ($bucketRows.Count -gt 0) {
        $Lines.Add("")
        $Lines.Add("| bucket | requested rents | requested bytes | actual rents | actual bytes rented | oversized rents | peak outstanding bytes | latest outstanding bytes |")
        $Lines.Add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        foreach ($bucket in $bucketRows) {
            $bucketName = if (Test-ObjectProperty $bucket "requestedSizeBucket") { $bucket.requestedSizeBucket } else { $bucket.sizeBucket }
            $requestedRents = Find-Metric $bucket.metrics "incursa.quic.buffer_pool.requested_rents"
            $requestedBytes = Find-Metric $bucket.metrics "incursa.quic.buffer_pool.bytes.requested"
            $actualRents = Find-Metric $bucket.metrics "incursa.quic.buffer_pool.rents"
            $actualBytes = Find-Metric $bucket.metrics "incursa.quic.buffer_pool.bytes.rented"
            $oversizedRents = Find-Metric $bucket.metrics "incursa.quic.buffer_pool.oversized_rents"
            $outstandingBytes = Find-Metric $bucket.metrics "incursa.quic.buffer_pool.outstanding.bytes"
            $Lines.Add("| ``$bucketName`` | $(Format-Value (Get-ObjectPropertyValue $requestedRents "total")) | $(Format-Value (Get-ObjectPropertyValue $requestedBytes "total")) | $(Format-Value (Get-ObjectPropertyValue $actualRents "total")) | $(Format-Value (Get-ObjectPropertyValue $actualBytes "total")) | $(Format-Value (Get-ObjectPropertyValue $oversizedRents "total")) | $(Format-Value (Get-ObjectPropertyValue $outstandingBytes "max")) | $(Format-Value (Get-ObjectPropertyValue $outstandingBytes "latest")) |")
        }
    }
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

    Add-BufferPoolSummary $lines $counterPass
}

$cpuPass = $profile.passes | Where-Object { $_.Name -eq "cpu-trace" } | Select-Object -First 1
if ($cpuPass) {
    $lines.Add("")
    $lines.Add("## CPU Trace")
    $lines.Add("")
    $lines.Add("- trace root: ``$($cpuPass.ArtifactRoot)``")
    $lines.Add("- raw trace: ``$(Join-Path $cpuPass.ArtifactRoot "trace.nettrace")``")
    if ((Test-ObjectProperty $profile "speedscope") -and (Test-ObjectProperty $profile.speedscope "Output") -and $profile.speedscope.Output) {
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
    if ((Test-ObjectProperty $profile.perfview "Output") -and $profile.perfview.Output) {
        $lines.Add("- output: ``$($profile.perfview.Output)``")
    }
    elseif ((Test-ObjectProperty $profile.perfview "Instructions") -and $profile.perfview.Instructions) {
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
