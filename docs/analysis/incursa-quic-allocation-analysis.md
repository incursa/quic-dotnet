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

---

## Server Runtime Constructor Micro-Profile

Added 2026-05-29. Uses `--profile-runtime N` mode that creates each `QuicConnectionRuntime` sub-component independently and measures allocation via `GC.GetTotalAllocatedBytes`.

### Command

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-runtime 200
```

### Results (200 iterations)

```text
Component                                        B/op   % of server ctor
QuicTlsKeySchedule (server)                     596,611           97.6%
QuicTlsTransportBridgeDriver (server)           599,188           98.0%
collections (dicts, queues, lists)                4,208            0.7%
channels (inbox + stream ids)                     2,480            0.4%
QuicTransportTlsBridgeState                       2,272            0.4%
QuicRecoveryController                              656            0.1%
field-init state objects                            512            0.1%
QuicConnectionStreamRegistry                        472            0.1%
QuicConnectionPeerConnectionIdState                 472            0.1%
QuicConnectionPathState                             416            0.1%
QuicConnectionIssuedConnectionIdState               280            0.0%
QuicConnectionLifecycleTimerState                   232            0.0%
QuicAddressValidationTokenProtector                 144            0.0%
QuicStreamObserverDirectory                         136            0.0%
QuicApplicationSendQueue                             64            0.0%
QuicHandshakeFlowCoordinator                         64            0.0%
QuicConnectionApplicationAckState                    32            0.0%
QuicConnectionVersionProfile                         32            0.0%
QuicConnectionDiagnosticsState                        0            0.0%

Full server runtime constructor:        611,284 B/op
QuicTlsKeySchedule (server) alone:      596,611 B/op  (97.6%)
```

### Key Finding

The `QuicTlsKeySchedule` server constructor is responsible for **597 KB/op — 97.6% of the full server runtime construction**. Everything else combined is ~15 KB.

The server key schedule constructor creates:
1. `ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)` — P-256 key pair
2. `ExportUncompressedPoint(localKeyPair.ExportParameters(true))` — exports public key material
3. `QuicTlsX25519.TryCreateKeyPair(...)` — X25519 key pair (server only)
4. `NormalizeApplicationProtocols(...)` — ALPN list copy

The 597 KB vs the client variant's ~2 KB is driven by the .NET crypto stack's internal allocations for `ECDiffieHellman.Create()` and `ExportParameters(true)` — not by visible managed byte arrays in the constructor code itself.

### Scope Classification

**Important**: ECDHE/X25519 private keys are TLS 1.3 ephemeral key shares. RFC 8446 requires fresh key shares per handshake for forward secrecy. They must **not** be reused across connections.

| Component | Current Scope | Safe Target Scope | Notes |
|-----------|---------------|-------------------|-------|
| ECDHE/X25519 private keys | Per-connection | Per-connection or single-use pregen pool | Do NOT reuse across connections — breaks forward secrecy |
| ALPN normalization / supported groups / cipher suites | Per-connection | Listener/server config | Safe to cache if immutable |
| Certificate chain bytes / encoded transport param templates | Per-connection | Listener/server config | Safe to move to listener scope |
| Public key-share encoding | Per-connection | Per-key-share | Can be precomputed with single-use key |
| `ExportParameters(true)` result | Per-connection | Avoid entirely if possible | Exports private key material to managed memory |
| Transcript / traffic secrets | Per-connection | Per-connection | Must not be shared |

### Safe Optimization Targets

Based on the 597 KB/op finding, the safe targets in priority order:

1. **Lazy-generate only the selected key-share group.** If the server creates both P-256 and X25519 keys before knowing which group the client supports, that is likely the primary allocation waste. TLS 1.3 servers send exactly one selected key share in `ServerHello`, matching one of the client's offered groups.

2. **Do not call `ExportParameters(true)` unless absolutely required.** That exports private key material into managed objects. If the code only needs the public point for the `ServerHello` key share, try `ExportParameters(false)`. If it needs to compute the shared secret, keep the private key inside the crypto object and use the platform ECDH derive API.

3. **Consider a single-use key-share pre-generation pool.** A listener can pre-generate fresh key shares in the background and hand each one to exactly one connection. This moves the allocation/latency cost out of the accept path without reusing keys.

4. **Move immutable TLS config to listener scope.** ALPN normalization, supported group lists, certificate chain bytes, and encoded transport parameter templates are all safe to cache at the listener level.

### Revised Priority

| Priority | Target | Allocation | Action |
|----------|--------|------------|--------|
| **P4** | Safe server key schedule allocation reduction | **597 KB/op** | Prove whether both P-256 and X25519 are created; generate only the selected group; avoid `ExportParameters(true)`; consider single-use key-share pool |
| **P2** | Handshake processing | 220 KB/op | Packet buffers, CRYPTO copies, HKDF temps (secondary) |
| **P3** | Immutable config to listener scope | Negligible per-op | Move ALPN, supported groups, cert chain, transport param templates to listener |
| **—** | All other runtime state | ~15 KB/op | Negligible — not worth targeting |

**Key principle**: Do not cache ephemeral private keys. Cache immutable config, lazily generate only the selected key share, and consider a single-use pre-generated key-share pool if accept-path latency/allocation remains a concern.
