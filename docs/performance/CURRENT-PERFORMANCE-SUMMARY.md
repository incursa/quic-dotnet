# Incursa.Quic Current Performance Summary

**Date**: 2026-05-30
**Source evidence**: [`docs/performance/runs/2026-05-30-154005/report.md`](runs/2026-05-30-154005/report.md)
**Commit**: `2d49d3de`

---

## Summary

Incursa.Quic is now approximately 3.6x the managed allocation of System.Net.Quic in connection-churn testing, down from ~10.4x before the P4 lazy server key generation optimization. The single largest managed allocation hotspot -- eager server key generation -- was eliminated. All remaining allocation metrics are within regression budgets. The remaining work is structural runtime infrastructure, not TLS micro-operations.

---

## What We Measured

A non-BDN allocation harness ran 6 profiling modes against a Release build on a Windows workstation (AMD Ryzen 9 3950X, 32 logical processors, 96 GB RAM, .NET SDK 10.0.204):

| Mode | Iterations | Metric |
|---|---|---|
| `--harness` | 2,000 | Two-pass throughput + managed/WS/private per operation |
| `--leak` | 200 | System.Net.Quic live-then-dispose plateau test |
| `--profile` | 100 | Lifecycle phase breakdown |
| `--profile-connect` | 100 | Connect+accept sub-phase breakdown |
| `--profile-runtime` | 100 | Server runtime constructor component breakdown |
| `--profile-handshake` | 100 | TLS handshake sub-operation isolation |

Each mode captures managed allocation (`GC.GetTotalAllocatedBytes`), working set, and private bytes. The comparison includes System.Net.Quic for the harness and leak modes.

---

## Key Results

| Metric | Incursa.Quic | System.Net.Quic |
|---|---|---|
| Managed allocation (pass 2) | **325 KB/op** | 91 KB/op |
| Throughput (pass 2) | **24.7 ms/op** | 25.1 ms/op |
| Working set delta (pass 2) | ~2.6 KB/op | ~2.3 MB/op |
| Private bytes delta (pass 2) | ~2.5 KB/op | ~2.5 MB/op |
| Cleanup behavior | Flat baseline | Native high-water retained |

| Sub-metric | Value |
|---|---|
| Connect+accept phase allocation | 257 KB/op |
| Server runtime constructor | 15.1 KB/op |
| Server key schedule constructor | 344 B/op |
| Lifecycle: connect+accept | 76.1% of total |
| Lifecycle: listener | 13.9% of total |
| Lifecycle: close+dispose | 10.0% of total |

---

## What Improved

The P4 optimization introduced lazy, selected-group server key generation in `QuicTlsKeySchedule`. Previously, the server constructor eagerly generated a complete ECDHE key pair, costing ~596 KB/op.

| Metric | Before P4 (historical) | After P4 (measured) | Reduction |
|---|---|---|---|
| Server key schedule | 596,611 B/op | 344 B/op | **99.94%** |
| Server runtime constructor | 611,371 B/op | ~15,100 B/op | **97.5%** |
| Connect+accept phase | 851,807 B/op | ~256,737 B/op | **69.9%** |
| Total managed allocation | ~922 KB/op | ~325 KB/op | **~65%** |
| Throughput | ~29 ms/op | ~24.7 ms/op | **~15% improvement** |

The security invariant that ECDHE/X25519 private keys are never reused across connections was preserved.

The remaining ~325 KB/op is distributed across structurally necessary allocations in the connection runtime, handshake pipeline, and packet processing infrastructure. Isolated TLS sub-operations (HKDF, AesGcm, SHA256, packet scratch buffers) collectively account for only ~18 KB/op -- less than 6% of the total. Further micro-optimization of these TLS primitives would yield marginal improvements.

---

## How to Interpret the System.Net.Quic Comparison

The comparison shows that managed allocation alone is not a complete memory metric when comparing a fully managed QUIC implementation against a native-backed implementation.

System.Net.Quic reports lower managed allocation (~91 KB/op) because most QUIC/TLS work is delegated to native MsQuic. MsQuic allocates connection state, TLS context, congestion control, flow control, and packet buffers in native memory, which is invisible to `GC.GetTotalAllocatedBytes`. The native cost appears instead in the process working set and private bytes metrics, where System.Net.Quic retains ~2.3--2.5 MB/op after `CloseAsync`/`DisposeAsync`. This is native allocator high-water behavior, not a cumulative leak -- batch 2 of the plateau test showed slightly lower retention than batch 1.

Incursa.Quic exposes more allocation to the managed GC (~325 KB/op), but this allocation is ephemeral Gen0 garbage that is fully reclaimed. Working set and private bytes return to a flat baseline after cleanup (residual ~2.5 KB/op). This is a different cost profile: higher GC pressure versus higher native memory footprint. Neither profile is automatically preferable; they represent different engineering tradeoffs.

---

## Current Regression Budgets

| Metric | Budget | Current | Status |
|---|---|---|---|
| Total managed allocation | <= 350 KB/op | ~325 KB/op | PASS |
| Connect+accept allocation | <= 275 KB/op | ~257 KB/op | PASS |
| Server runtime constructor | <= 20 KB/op | ~15 KB/op | PASS |
| Server key schedule constructor | <= 1 KB/op | ~0.34 KB/op | PASS |
| WS/private cleanup | flat after cleanup | ~2.5 KB/op residual | PASS |
| Ephemeral key reuse | never across connections | Confirmed | PASS |

---

## What This Proves

- The largest managed allocation hotspot in Incursa.Quic was correctly identified and resolved.
- P4 delivered a 65% reduction in managed churn per connection, bringing the implementation into the same order of magnitude as System.Net.Quic on this metric.
- The remaining allocation is structural runtime infrastructure, not a single oversized contributor.
- Incursa.Quic returns to a flat process-memory baseline after connection teardown in the tested churn scenario.
- The project has a repeatable measurement harness and a documented regression budget framework.

---

## What This Does Not Prove

- This is not a production-readiness claim. Production workloads involve long-running connections, concurrent streams, real network conditions, and diverse failure modes not captured by loopback churn testing.
- The System.Net.Quic native high-water behavior is not classified as a leak or defect. It is a known characteristic of the MsQuic allocator.
- Throughput numbers from this churn scenario do not predict steady-state data transfer throughput.
- The harness does not validate protocol correctness, interop, or RFC conformance.
- Results are from a single machine and OS (Windows). Linux and other platforms may differ.

---

## Next Work

1. **Packet-pipeline profiling**: The ~222 KB/op "remaining handshake processing" bucket is the largest unattributed allocation. Profiling handshake message assembly, CRYPTO frame encoding, and packet serialization is the most promising next step.

2. **Steady-state scenarios**: Extend measurement to data transfer workloads (stream reads/writes, ACK processing, congestion control behavior).

3. **ProtocolLab validation**: Validate throughput and latency with real ProtocolLab scenarios and external load drivers (e.g., `h2load` against HTTP/3 endpoints).

4. **Linux baseline**: Run the same harness on Linux to establish cross-platform baselines.

5. **Multi-stream profiling**: Profile per-stream allocations under concurrent stream workloads.

---

## Link to Full Evidence Report

- **Full report**: [`docs/performance/runs/2026-05-30-154005/report.md`](runs/2026-05-30-154005/report.md)
- **Raw artifacts**: [`docs/performance/runs/2026-05-30-154005/raw/`](runs/2026-05-30-154005/raw/)
- **Charts**: [`docs/performance/runs/2026-05-30-154005/charts/charts.md`](runs/2026-05-30-154005/charts/charts.md)
- **Performance analysis**: [`PERFORMANCE-ANALYSIS.md`](../../PERFORMANCE-ANALYSIS.md)
- **Allocation analysis**: [`docs/analysis/incursa-quic-allocation-analysis.md`](../analysis/incursa-quic-allocation-analysis.md)
- **Harness README**: [`docs/performance/README.md`](../README.md)
- **Report runner**: [`tools/performance/run-performance-evidence.ps1`](../../tools/performance/run-performance-evidence.ps1)
