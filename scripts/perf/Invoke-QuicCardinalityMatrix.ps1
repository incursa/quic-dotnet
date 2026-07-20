[CmdletBinding()]
param(
    [ValidateSet('download', 'upload', 'duplex')]
    [string] $Scenario = 'download',

    [ValidateSet('FixedTotalBytes', 'FixedPerStream')]
    [string[]] $Modes = @('FixedTotalBytes', 'FixedPerStream'),

    [string] $Cardinality = '1,4,8,16,24,32,64,128,256,512,1024',

    [ValidateRange(1, [int]::MaxValue)]
    [int] $TotalBytesPerWave = 3MB,

    [ValidateRange(1, [int]::MaxValue)]
    [int] $BytesPerStream = 1MB,

    [ValidateRange(1, [int]::MaxValue)]
    [int] $MaximumFixedPerStreamCardinality = 128,

    [ValidateRange(1, [int]::MaxValue)]
    [int] $MaximumRegressionCardinality = 32,

    [ValidateRange(1, 100)]
    [int] $Samples = 5,

    [ValidateRange(1, 300)]
    [int] $DurationSeconds = 2,

    [ValidateRange(1, 300)]
    [int] $WarmupSeconds = 1,

    [ValidateSet('Incursa', 'SystemNet')]
    [string[]] $Implementations = @('Incursa'),

    [bool] $Diagnostics = $true,

    [switch] $IncludeExtremeFixedPerStream,

    [switch] $NoBuild,

    [string] $OutputRoot
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputRoot = Join-Path $repoRoot ".artifacts\performance\quic-cardinality-$timestamp"
}

$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

if (-not $NoBuild) {
    & dotnet build (Join-Path $repoRoot 'benchmarks\Incursa.Quic.Benchmarks.csproj') -c Release --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark build failed with exit code $LASTEXITCODE."
    }
}

$benchmarkAssembly = Join-Path $repoRoot 'benchmarks\bin\Release\net10.0\Incursa.Quic.Benchmarks.dll'
if (-not (Test-Path -LiteralPath $benchmarkAssembly)) {
    throw "Benchmark assembly not found at '$benchmarkAssembly'."
}

$cardinalityValues = @(
    $Cardinality.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object {
            $parsed = 0
            if (-not [int]::TryParse($_.Trim(), [ref]$parsed)) {
                throw "Cardinality value '$($_.Trim())' is not an integer."
            }

            $parsed
        }
)
$invalidCardinality = $cardinalityValues | Where-Object { $_ -le 0 }
if ($invalidCardinality) {
    throw 'Every cardinality value must be positive.'
}

$startedUtc = [DateTimeOffset]::UtcNow
$cells = [System.Collections.Generic.List[object]]::new()
$implementationValue = $Implementations -join ','

foreach ($mode in $Modes) {
    foreach ($streamCount in ($cardinalityValues | Sort-Object -Unique)) {
        if ($mode -eq 'FixedPerStream' -and
            -not $IncludeExtremeFixedPerStream -and
            $streamCount -gt $MaximumFixedPerStreamCardinality) {
            $cells.Add([pscustomobject]@{
                mode = $mode
                connections = 1
                streamsPerConnection = $streamCount
                payloadBytes = $BytesPerStream
                aggregateBytesPerWave = [long]$streamCount * $BytesPerStream
                status = 'skipped_stress_only'
                reason = "Use -IncludeExtremeFixedPerStream to run above $MaximumFixedPerStreamCardinality streams."
                exitCode = $null
                resultPath = $null
                stdoutPath = $null
                stderrPath = $null
            })
            continue
        }

        $payloadBytes = if ($mode -eq 'FixedTotalBytes') {
            if (($TotalBytesPerWave % $streamCount) -ne 0) {
                throw "TotalBytesPerWave ($TotalBytesPerWave) must be divisible by cardinality $streamCount."
            }

            [int]($TotalBytesPerWave / $streamCount)
        }
        else {
            $BytesPerStream
        }

        if ($payloadBytes -le 0) {
            throw "Cardinality $streamCount produces a non-positive payload."
        }

        $cellName = '{0}-c{1}-b{2}' -f $mode.ToLowerInvariant(), $streamCount, $payloadBytes
        $resultPath = Join-Path $OutputRoot "$cellName.json"
        $stdoutPath = Join-Path $OutputRoot "$cellName.stdout.log"
        $stderrPath = Join-Path $OutputRoot "$cellName.stderr.log"
        $arguments = @(
            $benchmarkAssembly,
            '--transport-loopback',
            '--implementations', $implementationValue,
            '--scenarios', $Scenario,
            '--payload-sizes', $payloadBytes.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--connections', '1',
            '--concurrency', $streamCount.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--samples', $Samples.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--duration-seconds', $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--warmup-seconds', $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
            '--diagnostics', $Diagnostics.ToString().ToLowerInvariant(),
            '--label', "cardinality-$cellName",
            '--json', $resultPath
        )

        Write-Host "Running $mode with one connection x $streamCount streams, payload $payloadBytes bytes."
        $cellStartedUtc = [DateTimeOffset]::UtcNow
        & dotnet @arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
        $resultExists = Test-Path -LiteralPath $resultPath
        $status = if ($exitCode -ne 0 -or -not $resultExists) {
            if ($streamCount -gt $MaximumRegressionCardinality) {
                'stress_only_failed'
            }
            else {
                'failed'
            }
        }
        elseif ($streamCount -gt $MaximumRegressionCardinality) {
            'stress_only_completed'
        }
        else {
            'completed'
        }
        $cells.Add([pscustomobject]@{
            mode = $mode
            connections = 1
            streamsPerConnection = $streamCount
            payloadBytes = $payloadBytes
            aggregateBytesPerWave = [long]$streamCount * $payloadBytes
            startedUtc = $cellStartedUtc
            endedUtc = [DateTimeOffset]::UtcNow
            status = $status
            reason = if ($status -eq 'failed') {
                'Regression-ready cell failed; inspect retained logs before acceptance.'
            }
            elseif ($status -eq 'stress_only_failed') {
                'Stress-only cell failed; inspect retained logs before attribution.'
            }
            elseif ($status -eq 'stress_only_completed') {
                "Cardinality exceeds the c$MaximumRegressionCardinality regression-ready ceiling."
            }
            else {
                $null
            }
            exitCode = $exitCode
            resultPath = if ($resultExists) { $resultPath } else { $null }
            stdoutPath = $stdoutPath
            stderrPath = $stderrPath
        })
    }
}

$manifest = [ordered]@{
    schemaVersion = 1
    startedUtc = $startedUtc
    endedUtc = [DateTimeOffset]::UtcNow
    repoRoot = $repoRoot
    benchmarkAssembly = $benchmarkAssembly
    scenario = $Scenario
    modes = $Modes
    cardinality = $cardinalityValues
    implementations = $Implementations
    samples = $Samples
    durationSeconds = $DurationSeconds
    warmupSeconds = $WarmupSeconds
    diagnostics = $Diagnostics
    totalBytesPerWave = $TotalBytesPerWave
    bytesPerStream = $BytesPerStream
    maximumFixedPerStreamCardinality = $MaximumFixedPerStreamCardinality
    maximumRegressionCardinality = $MaximumRegressionCardinality
    extremeFixedPerStreamIncluded = [bool]$IncludeExtremeFixedPerStream
    classification = 'local_diagnostic'
    cells = $cells
}

$manifestPath = Join-Path $OutputRoot 'cardinality-manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Host "Cardinality evidence written to $manifestPath"

if ($cells.Where({ $_.status -in @('failed', 'stress_only_failed') }).Count -gt 0) {
    exit 1
}
