# Performance Evidence

## How to Run

Generate a timestamped performance evidence pack:

```powershell
.\tools\performance\run-performance-evidence.ps1
```

With custom iteration counts:

```powershell
.\tools\performance\run-performance-evidence.ps1 -HarnessCount 5000 -SkipTest
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-HarnessCount` | 10000 | Iterations for two-pass harness |
| `-LeakCount` | 1000 | Connections per batch for plateau test |
| `-ProfileCount` | 100 | Iterations for lifecycle phase profile |
| `-ProfileConnectCount` | 100 | Iterations for connect+accept sub-phase profile |
| `-ProfileRuntimeCount` | 200 | Iterations for server runtime constructor profile |
| `-ProfileHandshakeCount` | 200 | Iterations for handshake sub-operation profile |
| `-Configuration` | Release | Build configuration |
| `-SkipRestore` | false | Skip dotnet restore |
| `-SkipBuild` | false | Skip dotnet build |
| `-SkipTest` | false | Skip dotnet test |

## Harness Modes

### `--harness N`
Two-pass throughput + allocation measurement. Reports managed B/op, working set B/op, and private bytes B/op for both Incursa.Quic and System.Net.Quic. Pass 1 includes JIT/cache warmup; pass 2 is the settled measurement.

### `--leak N`
Live-then-dispose plateau test for native retention. Creates N System.Net.Quic connections, captures memory, disposes, waits 10s, captures again. Two batches distinguish warmup from cumulative retention.

### `--profile N`
Allocation profiler per lifecycle phase. Breaks connect/accept/dispose into listener, connect+accept, and close+dispose buckets.

### `--profile-connect N`
Connect+accept sub-phase breakdown via direct component construction. Measures client/server runtime construction, initial packet protection, TLS key schedule, and remaining handshake processing.

### `--profile-runtime N`
Server runtime constructor micro-profile. Breaks `QuicConnectionRuntime` constructor into named sub-components.

### `--profile-handshake N`
TLS handshake sub-operation measurement in isolation. Reports allocation from CRYPTO frames, WrapHandshakeMessage, transcript, HKDF, certificate, AesGcm, and packet buffers.

## Where Reports Are Stored

```
docs/performance/runs/YYYY-MM-DD-HHMMSS/
  raw/
    harness.txt
    harness.json
    leak.txt
    leak.json
    profile.txt
    profile.json
    profile-connect.txt
    profile-connect.json
    profile-runtime.txt
    profile-runtime.json
    profile-handshake.txt
    profile-handshake.json
    restore-build-test.txt
  environment.json
  metrics.json
  report.md
  charts/
    charts.md
```

## Interpreting Metrics

### Managed Allocation
Bytes allocated on the managed heap as reported by `GC.GetTotalAllocatedBytes(precise: true)`. High values indicate GC pressure. Incursa.Quic is fully managed, so all QUIC/TLS allocations appear here. System.Net.Quic delegates QUIC work to native MsQuic, so managed allocation alone undercounts its total memory impact.

### Working Set
The set of memory pages currently resident in physical RAM for the process (`Process.WorkingSet64`). Includes both managed and native allocations. Growth that persists after cleanup may indicate native retainers.

### Private Bytes
Memory allocated exclusively to the process that cannot be shared with other processes (`Process.PrivateMemorySize64`). This is the closest managed-accessible metric to total process memory footprint and includes native heap allocations made by MsQuic.

### Comparing Implementations
System.Net.Quic reports lower managed allocation because most QUIC work is delegated to native MsQuic. In churn scenarios, the native path establishes a large private-byte high-water mark, while Incursa.Quic exposes more allocation to the managed GC but returns to a flat process-memory baseline after cleanup. Neither implementation is "better" in absolute terms -- they represent different trade-offs between managed GC pressure and native memory footprint.

## Regression Budgets

| Metric | Budget |
|---|---|
| Total managed allocation | <= 350 KB/op |
| Connect+accept allocation | <= 275 KB/op |
| Server runtime constructor | <= 20 KB/op |
| Server key schedule constructor | <= 1 KB/op |
| Working set/private bytes cleanup | flat after cleanup |
| Ephemeral key reuse | never across connections |

A run that exceeds any budget should be investigated before the change is merged.
