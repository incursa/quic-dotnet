[CmdletBinding()]
param(
    [ValidateSet('h2load', 'oha')]
    [string]$Tool = 'h2load',
    [string]$BaseUrl = 'https://localhost:4433',
    [int]$Requests = 100000,
    [int]$Streams = 100,
    [switch]$Insecure
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-RequestsPerSecond {
    param([string]$Text)
    if ($Text -match 'requests/sec:\s*([0-9.]+)') {
        return $Matches[1]
    }

    if ($Text -match 'finished in .*?,\s*([0-9.]+)\s*req/s') {
        return $Matches[1]
    }

    if ($Text -match 'Requests/sec:\s*([0-9.]+)') {
        return $Matches[1]
    }

    return ''
}

function Get-Percentile {
    param([string]$Text, [string]$Percentile)
    if ($Text -match "(?m)^\s*$Percentile%\s+in\s+([^\r\n]+)$") {
        return $Matches[1].Trim()
    }

    if ($Text -match "(?i)p$Percentile\s*[:=]\s*([0-9.]+\s*\w+)") {
        return $Matches[1].Trim()
    }

    return ''
}

function Get-Errors {
    param([string]$Text)
    if ($Text -match 'status code distribution:[\s\S]*?\[(4\d\d|5\d\d)\]\s+(\d+)') {
        return "$($Matches[1])=$($Matches[2])"
    }

    if ($Text -match 'Non-2xx or 3xx responses:\s*(\d+)') {
        return $Matches[1]
    }

    if ($Text -match 'failed:\s*(\d+)') {
        return $Matches[1]
    }

    return ''
}

$endpoints = @('/plaintext', '/json', '/api/status')
$concurrencyLevels = @(16, 64, 256)
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$artifactRoot = Join-Path (Join-Path '.artifacts' 'http3-benchmarks') "compare-$timestamp"
New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

$rows = New-Object System.Collections.Generic.List[object]

foreach ($endpoint in $endpoints) {
    foreach ($concurrency in $concurrencyLevels) {
        $url = $BaseUrl.TrimEnd('/') + '/' + $endpoint.TrimStart('/')
        $safeEndpoint = $endpoint.Trim('/').Replace('/', '_')
        $outputPath = Join-Path $artifactRoot "$Tool-$safeEndpoint-c$concurrency.txt"

        switch ($Tool) {
            'h2load' {
                $arguments = @('--h3', '-n', $Requests.ToString(), '-c', $concurrency.ToString(), '-m', $Streams.ToString(), $url)
                if ($Insecure) {
                    $arguments = @('-k') + $arguments
                }
            }
            'oha' {
                $arguments = @('--http-version', '3', '-n', $Requests.ToString(), '-c', $concurrency.ToString(), $url)
                if ($Insecure) {
                    $arguments = @('--disable-tls-verify') + $arguments
                }
            }
        }

        $commandLine = $Tool + ' ' + (($arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
        Write-Host $commandLine
        $commandLine | Set-Content -LiteralPath (Join-Path $artifactRoot "$Tool-$safeEndpoint-c$concurrency.command.txt")
        & $Tool @arguments 2>&1 | Tee-Object -FilePath $outputPath
        $exitCode = $LASTEXITCODE
        $text = Get-Content -LiteralPath $outputPath -Raw

        $rows.Add([pscustomobject]@{
            Endpoint = $endpoint
            Concurrency = $concurrency
            RequestsPerSecond = Get-RequestsPerSecond $text
            P50 = Get-Percentile $text '50'
            P95 = Get-Percentile $text '95'
            P99 = Get-Percentile $text '99'
            Errors = Get-Errors $text
            ExitCode = $exitCode
            Output = $outputPath
        })
    }
}

$summaryPath = Join-Path $artifactRoot 'summary.md'
$summary = New-Object System.Collections.Generic.List[string]
$summary.Add('# HTTP/3 Benchmark Summary')
$summary.Add('')
$summary.Add("| endpoint | concurrency | requests/sec | p50 | p95 | p99 | errors | exit | raw |")
$summary.Add("| --- | ---: | ---: | --- | --- | --- | --- | ---: | --- |")
foreach ($row in $rows) {
    $summary.Add("| $($row.Endpoint) | $($row.Concurrency) | $($row.RequestsPerSecond) | $($row.P50) | $($row.P95) | $($row.P99) | $($row.Errors) | $($row.ExitCode) | $($row.Output) |")
}

$summary | Set-Content -LiteralPath $summaryPath
Write-Host "Summary: $summaryPath"
