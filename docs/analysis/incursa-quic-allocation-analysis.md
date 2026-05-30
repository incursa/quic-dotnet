# Incursa.Quic Allocation Analysis

> **Date**: 2026-05-29
>
> **Purpose**: Compare Incursa.Quic managed allocation behavior against System.Net.Quic/MsQuic.
> Determine whether the ~900 KB/op seen in BenchmarkDotNet is a real memory problem or a measurement artifact.

---

## Harness

A non-BDN allocation harness lives at `benchmarks/QuicAllocationHarness.cs`. It reports managed allocation, working set, and private bytes per operation using `GC.GetTotalAllocatedBytes`, `Process.WorkingSet64`, and `Process.PrivateMemorySize64` with `Process.Refresh()`.

### Commands

```powershell
# Two-pass throughput + allocation measurement (default 2000, recommended 10000)
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness 10000

# Live-then-dispose plateau test for native retention (default 1000)
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --leak 1000
```

### Flags

| Flag | Description |
|------|-------------|
| `--harness N` | Two-pass allocation + throughput measurement. Both Incursa.Quic and System.Net.Quic. |
| `--leak N` | Plateau test: create N connections, measure live memory, close+dispose, measure retained. Two batches. |

---

## Key Findings

### Managed allocation is not comparable between implementations

BenchmarkDotNet's `Allocated` column tracks only managed GC heap allocations. System.Net.Quic delegates expensive state (QUIC connection, TLS, packet I/O) to native MsQuic (C implementation). MsQuic's allocations are invisible to managed GC metrics.

| Metric | Incursa.Quic | System.Net.Quic | Note |
|--------|-------------|-----------------|------|
| **Managed alloc/op** | ~922 KB | ~84 KB | Incursa exposes QUIC/TLS to managed heap |
| **Working set Δ/op** | ~0 B (pass 2) | ~2.3 MB | MsQuic native allocator retains memory |
| **Private bytes Δ/op** | ~0 B (pass 2) | ~2.5 MB | Native heap not returned to OS on dispose |

### Plateau test (10,000 connections harvest)

```text
Incursa.Quic  pass 1/2   922,250 B/op managed    3,154 B/op ws     2,155 B/op priv
Incursa.Quic  pass 2/2   922,010 B/op managed     -478 B/op ws      -522 B/op priv
```

Incursa.Quic allocates ~922 KB/op of managed memory. Pass 2 shows working set and private bytes flat or slightly negative — all allocation is ephemeral Gen0 garbage that is fully reclaimed.

### System.Net.Quic plateau test

```text
Batch 1 — 1000 live connections:
  priv: +2,660 MB  ws: +2,490 MB
  after close+dispose+10s: priv retained: 2,632 MB  (99% retained)

Batch 2 — 1000 more connections:
  priv: +2,540 MB  ws: +2,370 MB
  after close+dispose+10s: priv retained: 2,505 MB  (slightly less — reuses segments)
```

System.Net.Quic's native MsQuic allocator retains OS memory pages after `CloseAsync`/`DisposeAsync`. Only ~1% of the allocated native memory is returned to the OS. This is **not a leak** — batch 2 retained is slightly less, not additive — but it creates a ~2.5 MB/op native heap high-water mark.

### Conclusions

1. **Incursa.Quic problem**: GC throughput, not a leak. The ~922 KB/op managed allocation is ephemeral and fully collected, but creates Gen0 collection pressure that contributes to the ~30% throughput gap.

2. **System.Net.Quic problem**: Native memory high-water mark of ~2.5 MB/op that is invisible to managed GC metrics but shows up in `PrivateMemorySize64`. This is allocator retention, not a leak.

3. **BenchmarkDotNet comparison is structurally unfair**: Managed allocation alone cannot compare a fully managed QUIC stack to one that delegates expensive state to native code.

---

## Current Baseline (2026-05-29)

### Incursa.Quic — `--harness 10000`

```text
  pass 1/2   922,250 B/op managed    3,154 B/op ws     2,155 B/op priv    28.877 ms/op
  pass 2/2   922,010 B/op managed     -478 B/op ws      -522 B/op priv    29.248 ms/op
```

Mean: **~922 KB/op managed**, flat private/working set.

### System.Net.Quic — `--harness 2000` (reference)

```text
  pass 1/2   84,558 B/op managed   2,319,311 B/op ws   2,495,091 B/op priv  26.873 ms/op
  pass 2/2   84,242 B/op managed   2,317,294 B/op ws   2,492,772 B/op priv  22.404 ms/op
```

---

## Optimization Target

Reduce Incursa.Quic managed allocation churn during connect/accept/dispose without weakening correctness, security, diagnostics, or interop.

### Priority Order

| Priority | Area | Est. Allocation | Approach |
|----------|------|-----------------|----------|
| **A** | Packet scratch buffers | ~50-100 KB/op | Reuse per-connection scratch buffers instead of `new byte[1200]` each operation |
| **B** | CRYPTO frame `.ToArray()` copies | ~6-10 KB/op | Avoid unnecessary copying in `QuicCryptoBuffer.TryAddFrame` |
| **C** | Transcript/handshake builders | ~2-6 KB/op | Reuse/reset `ArrayBufferWriter` during handshake |
| **D** | HKDF/TLS temporary arrays | ~1-2 KB/op | Replace small `new byte[n]` with `stackalloc` where safe |
| **E** | Runtime object graph | ~20-40 KB/op | Structural allocation reduction (lower priority) |

### Measurement Protocol

After each meaningful optimization group:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness 10000
```

If changes affect pooling or retention:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --leak 1000
```

### Security Constraints

- Clear sensitive buffers before returning to `ArrayPool<byte>`.
- Do not expose pooled buffers outside their safe lifetime.
- Do not hold `Span<T>` or `Memory<T>` references beyond valid lifetime.
- Do not reuse buffers across concurrent operations without explicit ownership.
- Prefer `stackalloc` only for small, bounded buffers.
- Key material (AEAD keys, HKDF intermediates) must be cleared or never shared.
