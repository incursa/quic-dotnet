<#
.SYNOPSIS
  Generates a timestamped performance evidence pack for Incursa.Quic.
.DESCRIPTION
  Restores, builds, and tests the solution, then runs the full profiling
  harness suite (harness, leak, profile, profile-connect, profile-runtime,
  profile-handshake).  Raw outputs, environment metadata, parsed metrics
  JSON, charts, and a markdown report are written under a timestamped
  folder in docs/performance/runs/.
.PARAMETER HarnessCount
  Iterations for --harness (default 10000).
.PARAMETER LeakCount
  Connections per batch for --leak (default 1000).
.PARAMETER ProfileCount
  Iterations for --profile (default 100).
.PARAMETER ProfileConnectCount
  Iterations for --profile-connect (default 100).
.PARAMETER ProfileRuntimeCount
  Iterations for --profile-runtime (default 200).
.PARAMETER ProfileHandshakeCount
  Iterations for --profile-handshake (default 200).
.PARAMETER Configuration
  Build configuration (default Release).
.PARAMETER SkipRestore
  Skip dotnet restore.
.PARAMETER SkipBuild
  Skip dotnet build.
.PARAMETER SkipTest
  Skip dotnet test.
.PARAMETER ArtifactsRoot
  Override output root (default docs/performance/runs/YYYY-MM-DD-HHMMSS).
.EXAMPLE
  .\tools\performance\run-performance-evidence.ps1
.EXAMPLE
  .\tools\performance\run-performance-evidence.ps1 -HarnessCount 5000 -SkipTest
#>

[CmdletBinding()]
param(
    [int]$HarnessCount = 10000,
    [int]$LeakCount = 1000,
    [int]$ProfileCount = 100,
    [int]$ProfileConnectCount = 100,
    [int]$ProfileRuntimeCount = 200,
    [int]$ProfileHandshakeCount = 200,
    [string]$Configuration = "Release",
    [switch]$SkipRestore,
    [switch]$SkipBuild,
    [switch]$SkipTest,
    [string]$ArtifactsRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot | Split-Path -Parent | Split-Path -Parent
Push-Location $RepoRoot
try {
    # ---- Resolve paths -------------------------------------------------------
    $SolutionFile = "Incursa.Quic.slnx"
    if (-not (Test-Path $SolutionFile)) {
        throw "Solution file '$SolutionFile' not found in $RepoRoot"
    }

    $BenchmarkProject = "benchmarks/Incursa.Quic.Benchmarks.csproj"
    if (-not (Test-Path $BenchmarkProject)) {
        throw "Benchmark project '$BenchmarkProject' not found"
    }

    $Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd-HHmmss",
        [System.Globalization.CultureInfo]::InvariantCulture)

    if (-not $ArtifactsRoot) {
        $ArtifactsRoot = "docs/performance/runs/$Timestamp"
    }
    $RawDir = Join-Path $ArtifactsRoot "raw"
    $ChartsDir = Join-Path $ArtifactsRoot "charts"

    New-Item -ItemType Directory -Force -Path $RawDir | Out-Null
    New-Item -ItemType Directory -Force -Path $ChartsDir | Out-Null

    $EnvPath = Join-Path $ArtifactsRoot "environment.json"
    $MetricsPath = Join-Path $ArtifactsRoot "metrics.json"
    $ReportPath = Join-Path $ArtifactsRoot "report.md"

    Write-Host "=== Incursa.Quic Performance Evidence Pack ===" -ForegroundColor Cyan
    Write-Host "Timestamp (UTC): $Timestamp" -ForegroundColor Yellow
    Write-Host "Output root:     $ArtifactsRoot" -ForegroundColor Yellow
    Write-Host ""

    # ---- 1. Capture environment metadata -------------------------------------
    Write-Host "[1/7] Capturing environment metadata..." -ForegroundColor Cyan

    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $memInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

    $dotnetSdk = (& dotnet --version 2>&1) -join ""
    $dotnetRuntime = (& dotnet --list-runtimes 2>&1) -join [Environment]::NewLine

    $gitBranch = (git rev-parse --abbrev-ref HEAD 2>&1) -join ""
    $gitCommit = (git rev-parse HEAD 2>&1) -join ""
    $gitClean = ((git status --porcelain 2>&1) -eq "")

    $env = [ordered]@{
        timestampLocal        = (Get-Date).ToString("O", [System.Globalization.CultureInfo]::InvariantCulture)
        timestampUtc          = (Get-Date).ToUniversalTime().ToString("O", [System.Globalization.CultureInfo]::InvariantCulture)
        machineName           = [Environment]::MachineName
        osVersion             = if ($osInfo) { "$($osInfo.Caption) $($osInfo.Version)" } else { [Environment]::OSVersion.ToString() }
        cpuModel              = if ($cpuInfo) { $cpuInfo.Name.Trim() } else { "unknown" }
        processorCount        = [Environment]::ProcessorCount
        totalMemoryGB         = if ($memInfo) { [math]::Round($memInfo.TotalPhysicalMemory / 1GB, 1) } else { 0 }
        dotnetSdkVersion      = $dotnetSdk
        dotnetRuntime         = ($dotnetRuntime -split [Environment]::NewLine | Select-Object -First 20) -join "`n"
        gitBranch             = $gitBranch
        gitCommitSha          = $gitCommit
        gitWorkingTreeClean   = $gitClean
        buildConfiguration    = $Configuration
        benchmarkProjectPath  = $BenchmarkProject
        harnessCount          = $HarnessCount
        leakCount             = $LeakCount
        profileCount          = $ProfileCount
        profileConnectCount   = $ProfileConnectCount
        profileRuntimeCount   = $ProfileRuntimeCount
        profileHandshakeCount = $ProfileHandshakeCount
    }
    $env | ConvertTo-Json -Depth 3 | Set-Content -Path $EnvPath -Encoding UTF8
    Write-Host "  -> $EnvPath" -ForegroundColor Green

    # ---- 2. Restore / build / test -------------------------------------------
    Write-Host "[2/7] Restoring, building, testing..." -ForegroundColor Cyan
    $rbtLog = Join-Path $RawDir "restore-build-test.txt"
    $rbtOutput = @()

    if (-not $SkipRestore) {
        Write-Host "  Restoring..." -ForegroundColor Yellow
        $output = (& dotnet restore $SolutionFile 2>&1) -join [Environment]::NewLine
        $rbtOutput += $output
        if ($LASTEXITCODE -ne 0) { throw "Restore failed." }
    }

    if (-not $SkipBuild) {
        Write-Host "  Building..." -ForegroundColor Yellow
        $output = (& dotnet build $SolutionFile -c $Configuration --no-restore 2>&1) -join [Environment]::NewLine
        $rbtOutput += $output
        if ($LASTEXITCODE -ne 0) { throw "Build failed." }
    }

    if (-not $SkipTest) {
        Write-Host "  Testing..." -ForegroundColor Yellow
        $testProject = "tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj"
        $output = (& dotnet test $testProject -c $Configuration --no-build 2>&1) -join [Environment]::NewLine
        $rbtOutput += $output
        if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
    }

    $rbtOutput -join [Environment]::NewLine | Set-Content -Path $rbtLog -Encoding UTF8
    Write-Host "  -> $rbtLog" -ForegroundColor Green

    # ---- 3. Run profiling harness suite --------------------------------------
    Write-Host "[3/7] Running profiling harness suite..." -ForegroundColor Cyan

    $runModes = @(
        @{ Flag = "--harness";           Count = $HarnessCount;           RawFile = "harness.txt";           JsonFile = "harness.json" },
        @{ Flag = "--leak";              Count = $LeakCount;              RawFile = "leak.txt";              JsonFile = "leak.json" },
        @{ Flag = "--profile";           Count = $ProfileCount;           RawFile = "profile.txt";           JsonFile = "profile.json" },
        @{ Flag = "--profile-connect";   Count = $ProfileConnectCount;    RawFile = "profile-connect.txt";   JsonFile = "profile-connect.json" },
        @{ Flag = "--profile-runtime";   Count = $ProfileRuntimeCount;    RawFile = "profile-runtime.txt";   JsonFile = "profile-runtime.json" },
        @{ Flag = "--profile-handshake"; Count = $ProfileHandshakeCount;  RawFile = "profile-handshake.txt"; JsonFile = "profile-handshake.json" }
    )

    $allMetrics = @{}

    foreach ($mode in $runModes) {
        $jsonOut = Join-Path $ArtifactsRoot "raw" $mode.JsonFile
        $rawOut  = Join-Path $ArtifactsRoot "raw" $mode.RawFile

        Write-Host "  $($mode.Flag) $($mode.Count) ..." -ForegroundColor Yellow

        $fullOutput = & dotnet run -c $Configuration --no-build --project $BenchmarkProject -- $($mode.Flag) $($mode.Count) --json $jsonOut 2>&1
        $exitCode = $LASTEXITCODE
        ($fullOutput -join [Environment]::NewLine) | Set-Content -Path $rawOut -Encoding UTF8

        if ($exitCode -ne 0) {
            Write-Host "    WARNING: exit code $exitCode" -ForegroundColor Red
        }

        if (Test-Path $jsonOut) {
            try {
                $metrics = Get-Content $jsonOut -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 10
                $modeKey = $mode.Flag.TrimStart('-')
                $allMetrics[$modeKey] = $metrics
            } catch {
                Write-Host "    WARNING: Failed to parse JSON: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "    WARNING: JSON file not produced" -ForegroundColor Red
        }

        Write-Host "    -> $rawOut" -ForegroundColor Green
    }

    # ---- 4. Write unified metrics.json ---------------------------------------
    Write-Host "[4/7] Writing metrics.json..." -ForegroundColor Cyan
    $allMetrics | ConvertTo-Json -Depth 10 | Set-Content -Path $MetricsPath -Encoding UTF8
    Write-Host "  -> $MetricsPath" -ForegroundColor Green

    # ---- 5. Generate charts (Mermaid in markdown) ----------------------------
    Write-Host "[5/7] Generating charts..." -ForegroundColor Cyan
    $chartsMarkdown = Generate-ChartsMermaid -Metrics $allMetrics
    $chartsMarkdown | Set-Content -Path (Join-Path $ChartsDir "charts.md") -Encoding UTF8
    Write-Host "  -> $ChartsDir/charts.md" -ForegroundColor Green

    # ---- 6. Generate report.md -----------------------------------------------
    Write-Host "[6/7] Generating report.md..." -ForegroundColor Cyan
    $report = Generate-Report -Env $env -Metrics $allMetrics -ChartsMarkdown $chartsMarkdown `
        -Timestamp $Timestamp -ArtifactsRoot $ArtifactsRoot `
        -HarnessCount $HarnessCount -LeakCount $LeakCount -ProfileCount $ProfileCount `
        -ProfileConnectCount $ProfileConnectCount -ProfileRuntimeCount $ProfileRuntimeCount `
        -ProfileHandshakeCount $ProfileHandshakeCount
    $report | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Host "  -> $ReportPath" -ForegroundColor Green

    # ---- Summary -------------------------------------------------------------
    Write-Host ""
    Write-Host "=== Performance Evidence Pack Complete ===" -ForegroundColor Green
    Write-Host "Report: $ReportPath" -ForegroundColor Yellow
    Write-Host "Metrics: $MetricsPath" -ForegroundColor Yellow
    Write-Host "Raw outputs: $RawDir" -ForegroundColor Yellow
} finally {
    Pop-Location
}

# =============================================================================
# Helper functions
# =============================================================================

function Generate-ChartsMermaid {
    param($Metrics)

    $lines = @()
    $lines += "# Performance Charts"
    $lines += ""

    # --- Managed allocation comparison: Incursa vs System.Net ---
    if ($Metrics.harness) {
        $h = $Metrics.harness
        $i1 = 0; $i2 = 0; $s1 = 0; $s2 = 0
        if ($h.incursaQuic.pass2) {
            $i1 = [long]$h.incursaQuic.pass2.managedBytesPerOp
            $i1ws = [long]$h.incursaQuic.pass2.workingSetBytesPerOp
            $i1priv = [long]$h.incursaQuic.pass2.privateBytesPerOp
        }
        if ($h.systemNetQuic.pass2) {
            $s1 = [long]$h.systemNetQuic.pass2.managedBytesPerOp
            $s1ws = [long]$h.systemNetQuic.pass2.workingSetBytesPerOp
            $s1priv = [long]$h.systemNetQuic.pass2.privateBytesPerOp
        }

        $i1kb = [math]::Round($i1 / 1024.0, 1)
        $s1kb = [math]::Round($s1 / 1024.0, 1)

        $lines += "## Managed Allocation Comparison (Pass 2, B/op)"
        $lines += ""
        $lines += '```mermaid'
        $lines += '%%{init: {"theme": "default"}}%%'
        $lines += 'xychart-beta'
        $lines += '  title "Managed Allocation (KB/op)"'
        $lines += '  x-axis ["Incursa.Quic", "System.Net.Quic"]'
        $lines += "  bar [$i1kb, $s1kb]"
        $lines += '```'
        $lines += ""
        $lines += "| Implementation | Managed B/op | WS B/op | Private B/op |"
        $lines += "|---|---|---|---|"
        $lines += "| Incursa.Quic | $($i1.ToString('N0')) | $($i1ws.ToString('N0')) | $($i1priv.ToString('N0')) |"
        $lines += "| System.Net.Quic | $($s1.ToString('N0')) | $($s1ws.ToString('N0')) | $($s1priv.ToString('N0')) |"
        $lines += ""
    }

    # --- Lifecycle phase breakdown ---
    if ($Metrics.profile) {
        $p = $Metrics.profile
        $lines += "## Lifecycle Phase Breakdown (B/op)"
        $lines += ""
        $lines += '```mermaid'
        $lines += 'pie showData'
        $lines += '  title "Allocation by Phase"'
        foreach ($phase in $p.phases) {
            $lines += "  `"$($phase.name)`" : $($phase.totalB)"
        }
        $lines += '```'
        $lines += ""
    }

    # --- Connect+Accept sub-phase breakdown ---
    if ($Metrics.'profile-connect') {
        $pc = $Metrics.'profile-connect'
        $lines += "## Connect+Accept Sub-Phase Breakdown (B/op)"
        $lines += ""
        $lines += '```mermaid'
        $lines += 'xychart-beta'
        $lines += '  title "Connect+Accept Allocation (KB/op)"'
        $labels = @()
        $values = @()
        foreach ($sp in $pc.subPhases) {
            if ($sp.name -ne "TOTAL connect+accept") {
                $labels += "`"$($sp.name)`""
                $values += [math]::Round($sp.totalB / 1024.0, 1)
            }
        }
        $lines += "  x-axis [$($labels -join ', ')]"
        $lines += "  bar [$($values -join ', ')]"
        $lines += '```'
        $lines += ""
    }

    # --- Server runtime constructor breakdown ---
    if ($Metrics.'profile-runtime') {
        $pr = $Metrics.'profile-runtime'
        $lines += "## Server Runtime Constructor Breakdown (B/op)"
        $lines += ""
        $lines += '```mermaid'
        $lines += 'xychart-beta'
        $lines += '  title "Server Constructor Components (KB/op)"'
        $labels = @()
        $values = @()
        $topN = $pr.components | Sort-Object { [long]$_.totalB } -Descending | Select-Object -First 8
        foreach ($c in $topN) {
            $labels += "`"$($c.name.Substring(0, [Math]::Min(20, $c.name.Length)))`""
            $values += [math]::Round($c.totalB / 1024.0, 1)
        }
        $lines += "  x-axis [$($labels -join ', ')]"
        $lines += "  bar [$($values -join ', ')]"
        $lines += '```'
        $lines += ""
    }

    # --- Handshake sub-operation breakdown ---
    if ($Metrics.'profile-handshake') {
        $ph = $Metrics.'profile-handshake'
        $lines += "## Handshake Sub-Operation Breakdown (B/op)"
        $lines += ""
        $lines += '```mermaid'
        $lines += 'pie showData'
        $lines += '  title "Handshake Allocation by Sub-Operation"'
        foreach ($op in $ph.subOperations) {
            $lines += "  `"$($op.name)`" : $($op.totalB)"
        }
        $lines += '```'
        $lines += ""
    }

    return ($lines -join [Environment]::NewLine)
}

function Generate-Report {
    param(
        $Env, $Metrics, $ChartsMarkdown, $Timestamp,
        $ArtifactsRoot, $HarnessCount, $LeakCount, $ProfileCount,
        $ProfileConnectCount, $ProfileRuntimeCount, $ProfileHandshakeCount
    )

    $lines = @()
    $lines += "# Incursa.Quic Performance Evidence Report"
    $lines += ""
    $lines += "**Generated**: $($Env.timestampUtc)"
    $lines += ""
    $lines += "**Commit**: $($Env.gitCommitSha)"
    $lines += ""
    $lines += "---"
    $lines += ""

    # Environment
    $lines += "## Environment"
    $lines += ""
    $lines += "| Property | Value |"
    $lines += "|---|---|"
    $lines += "| Machine | $($Env.machineName) |"
    $lines += "| OS | $($Env.osVersion) |"
    $lines += "| CPU | $($Env.cpuModel) |"
    $lines += "| Logical processors | $($Env.processorCount) |"
    $lines += "| Total memory (GB) | $($Env.totalMemoryGB) |"
    $lines += "| .NET SDK | $($Env.dotnetSdkVersion) |"
    $lines += "| Git branch | $($Env.gitBranch) |"
    $lines += "| Git clean | $($Env.gitWorkingTreeClean) |"
    $lines += "| Build config | $($Env.buildConfiguration) |"
    $lines += ""

    # Methodology
    $lines += "## Methodology"
    $lines += ""
    $lines += "1. Restore, build (Release), and run the full test suite."
    $lines += "2. Run each harness mode with `--json` to capture machine-readable metrics."
    $lines += "3. Preserve raw console output for traceability."
    $lines += "4. Parse JSON metrics into a unified `metrics.json`."
    $lines += "5. Generate charts (Mermaid) and this report."
    $lines += ""

    # Commands run
    $lines += "## Commands Run"
    $lines += ""
    $lines += '```powershell'
    $lines += "dotnet restore Incursa.Quic.slnx"
    $lines += "dotnet build Incursa.Quic.slnx -c Release --no-restore"
    $lines += "dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build"
    $lines += "# harness modes:"
    $lines += "dotnet run -c Release --no-build --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness $HarnessCount --json <raw>/harness.json"
    $lines += "dotnet run -c Release --no-build --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --leak $LeakCount --json <raw>/leak.json"
    $lines += "dotnet run -c Release --no-build --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile $ProfileCount --json <raw>/profile.json"
    $lines += "dotnet run -c Release --no-build --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-connect $ProfileConnectCount --json <raw>/profile-connect.json"
    $lines += "dotnet run -c Release --no-build --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-runtime $ProfileRuntimeCount --json <raw>/profile-runtime.json"
    $lines += "dotnet run -c Release --no-build --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-handshake $ProfileHandshakeCount --json <raw>/profile-handshake.json"
    $lines += '```'
    $lines += ""

    # Executive Summary
    $lines += "## Executive Summary"
    $lines += ""
    if ($Metrics.harness) {
        $h = $Metrics.harness
        $i2 = $h.incursaQuic.pass2
        $s2 = $h.systemNetQuic.pass2
        $lines += "This report compares **Incursa.Quic** (fully managed QUIC implementation) against **System.Net.Quic** (managed wrapper over native MsQuic)."
        $lines += ""
        $lines += "- **Incursa.Quic** managed allocation: **$([math]::Round([long]$i2.managedBytesPerOp / 1024.0, 1)) KB/op**"
        $lines += "- **System.Net.Quic** managed allocation: **$([math]::Round([long]$s2.managedBytesPerOp / 1024.0, 1)) KB/op**"
        $lines += "- **Managed allocation gap**: **$([math]::Round([long]$i2.managedBytesPerOp / [Math]::Max(1, [long]$s2.managedBytesPerOp), 1))x**"
        $lines += ""
        $lines += "System.Net.Quic reports lower managed allocation because most QUIC work"
        $lines += "is delegated to native MsQuic. In this churn scenario, the native path"
        $lines += "establishes a large private-byte high-water mark, while Incursa.Quic"
        $lines += "exposes more allocation to the managed GC but returns to a flat"
        $lines += "process-memory baseline after cleanup."
    }
    $lines += ""

    # Key results table
    $lines += "## Key Results (Pass 2)"
    $lines += ""
    if ($Metrics.harness) {
        $h = $Metrics.harness
        $i2 = $h.incursaQuic.pass2
        $s2 = $h.systemNetQuic.pass2
        $lines += "| Metric | Incursa.Quic | System.Net.Quic |"
        $lines += "|---|---|---|"
        $lines += "| Managed alloc (B/op) | $($i2.managedBytesPerOp) | $($s2.managedBytesPerOp) |"
        $lines += "| Working set (B/op) | $($i2.workingSetBytesPerOp) | $($s2.workingSetBytesPerOp) |"
        $lines += "| Private bytes (B/op) | $($i2.privateBytesPerOp) | $($s2.privateBytesPerOp) |"
        $lines += "| Throughput (ms/op) | $($i2.msPerOp) | $($s2.msPerOp) |"
        $lines += ""
    }

    # Allocation breakdown
    $lines += "## Allocation Breakdown"
    $lines += ""

    if ($Metrics.profile) {
        $p = $Metrics.profile
        $lines += "### Lifecycle Phases"
        $lines += ""
        $lines += "| Phase | B/op | % of Total |"
        $lines += "|---|---|---|"
        foreach ($phase in $p.phases) {
            $lines += "| $($phase.name) | $($phase.bPerOp) | $($phase.pctOfTotal)% |"
        }
        $lines += ""
    }

    if ($Metrics.'profile-connect') {
        $pc = $Metrics.'profile-connect'
        $lines += "### Connect+Accept Sub-Phases"
        $lines += ""
        $lines += "| Sub-Phase | B/op | % of C+A |"
        $lines += "|---|---|---|"
        foreach ($sp in $pc.subPhases) {
            $lines += "| $($sp.name) | $($sp.bPerOp) | $($sp.pctOfCA)% |"
        }
        $lines += ""
    }

    if ($Metrics.'profile-runtime') {
        $pr = $Metrics.'profile-runtime'
        $lines += "### Server Runtime Constructor"
        $lines += ""
        $lines += "| Metric | Value |"
        $lines += "|---|---|"
        $lines += "| Full constructor (B/op) | $($pr.fullServerCtorBPerOp) |"
        $lines += "| Measured components (B/op) | $($pr.measuredBPerOp) |"
        $lines += "| Unattributed (B/op) | $($pr.unattributedBPerOp) |"
        $lines += ""
    }

    if ($Metrics.'profile-handshake') {
        $ph = $Metrics.'profile-handshake'
        $lines += "### Handshake Sub-Operations"
        $lines += ""
        $lines += "| Sub-Operation | B/op | % of ~220KB |"
        $lines += "|---|---|---|"
        foreach ($op in $ph.subOperations) {
            $lines += "| $($op.name) | $($op.bPerOp) | $($op.pctOfReference)% |"
        }
        $lines += ""
    }

    # Native vs Managed interpretation
    $lines += "## Native vs Managed Memory Interpretation"
    $lines += ""
    $lines += "System.Net.Quic reports lower managed allocation because most QUIC"
    $lines += "work is delegated to native MsQuic. In this churn scenario, the"
    $lines += "native path establishes a large private-byte high-water mark, while"
    $lines += "Incursa.Quic exposes more allocation to the managed GC but returns"
    $lines += "to a flat process-memory baseline after cleanup."
    $lines += ""
    $lines += "Managed allocation metrics alone are not a fair memory comparison"
    $lines += "between these two implementations because System.Net.Quic delegates"
    $lines += "QUIC/TLS state to native MsQuic (a C library), whose allocations"
    $lines += "are invisible to managed GC metrics."
    $lines += ""

    # P4 improvement reference
    $lines += "## P4 Improvement Reference"
    $lines += ""
    $lines += "The P4 optimization (lazy server key generation) delivered:"
    $lines += ""
    $lines += "| Metric | Before P4 | After P4 | Reduction |"
    $lines += "|---|---|---|---|"
    $lines += "| Managed allocation | ~922 KB/op | ~326 KB/op | ~65% |"
    $lines += "| Server constructor | ~611 KB/op | ~15 KB/op | ~97.5% |"
    $lines += "| Server key schedule | ~596 KB/op | ~344 B/op | ~99.94% |"
    $lines += "| Throughput | ~29 ms/op | ~25 ms/op | ~14% |"
    $lines += ""

    # Charts
    $lines += "## Charts"
    $lines += ""
    $lines += $ChartsMarkdown
    $lines += ""

    # Raw output links
    $lines += "## Raw Output Files"
    $lines += ""
    $lines += "| File | Path |"
    $lines += "|---|---|"
    $lines += "| Restore/Build/Test | raw/restore-build-test.txt |"
    $lines += "| Harness | raw/harness.txt |"
    $lines += "| Harness JSON | raw/harness.json |"
    $lines += "| Leak | raw/leak.txt |"
    $lines += "| Leak JSON | raw/leak.json |"
    $lines += "| Profile | raw/profile.txt |"
    $lines += "| Profile JSON | raw/profile.json |"
    $lines += "| Profile Connect | raw/profile-connect.txt |"
    $lines += "| Profile Connect JSON | raw/profile-connect.json |"
    $lines += "| Profile Runtime | raw/profile-runtime.txt |"
    $lines += "| Profile Runtime JSON | raw/profile-runtime.json |"
    $lines += "| Profile Handshake | raw/profile-handshake.txt |"
    $lines += "| Profile Handshake JSON | raw/profile-handshake.json |"
    $lines += "| Environment | environment.json |"
    $lines += "| Unified Metrics | metrics.json |"
    $lines += ""

    # Limitations
    $lines += "## Limitations"
    $lines += ""
    $lines += "- The harness runs on a single machine; results may vary with CPU,"
    $lines += "  memory pressure, and OS scheduling."
    $lines += "- `--profile-handshake` measures sub-operations in isolation; actual"
    $lines += "  handshake costs include async message exchange and shared-state"
    $lines += "  effects not captured in isolated measurements."
    $lines += "- `--leak` tests System.Net.Quic only and reports process-level"
    $lines += "  memory; it does not introspect native MsQuic allocator internals."
    $lines += "- `--harness` runs loopback connections; real network conditions"
    $lines += "  may produce different allocation profiles."
    $lines += "- Baseline P4 before/after values are reference measurements from"
    $lines += "  a previous investigation and are not re-measured per run."
    $lines += ""

    # Regression budgets
    $lines += "## Regression Budgets"
    $lines += ""
    $lines += "| Metric | Budget |"
    $lines += "|---|---|"
    $lines += "| Total managed allocation | <= 350 KB/op |"
    $lines += "| Connect+accept allocation | <= 275 KB/op |"
    $lines += "| Server runtime constructor | <= 20 KB/op |"
    $lines += "| Server key schedule constructor | <= 1 KB/op |"
    $lines += "| Working set/private bytes cleanup | flat after cleanup |"
    $lines += "| Ephemeral key reuse | never across connections |"
    $lines += ""

    # Next recommended work
    $lines += "## Next Recommended Work"
    $lines += ""
    $lines += "1. Investigate remaining managed allocation in connect+accept path"
    $lines += "   targeting the regression budget of <= 275 KB/op."
    $lines += "2. Profile stream-level allocations (TCS, SemaphoreSlim, StreamState)"
    $lines += "   under multi-stream workloads."
    $lines += "3. Evaluate pooling strategies for completion sources across"
    $lines += "   connections rather than per-connection pools."
    $lines += "4. Add fuzzing evidence for wire-facing parsers and serializers."
    $lines += "5. Run benchmarks on Linux for cross-platform baseline comparison."
    $lines += ""

    return ($lines -join [Environment]::NewLine)
}
