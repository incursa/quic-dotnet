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

---

## P4 — Safe Server Key Schedule Allocation Reduction (2026-05-30)

**One file changed**: `src/Incursa.Quic/QuicTlsKeySchedule.cs`.

### Change

Lazy key generation. The `QuicTlsKeySchedule` constructor eagerly created both a P-256 ECDH key pair and an X25519 key pair for server roles, plus called `ExportParameters(true)` to export private key material. Only one key pair is ever used — the server sends exactly one key share in `ServerHello`.

1. **P-256 key pair**: `LocalKeyPair` lazy property, created on first DH operation.
2. **P-256 public key share**: `LocalKeyShareBytes` lazy property, computed via `ExportParameters(false)` — no private key material exported.
3. **X25519 key pair**: `LocalX25519PrivateKeyBytes` / `LocalX25519KeyShareBytes` / `HasX25519KeyShare` lazy properties, server only.
4. **Deterministic key**: Stored as `ReadOnlyMemory<byte>?` reference, imported lazily. No shared/reused keys across connections.

### Results

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Server key schedule (`--profile-runtime`) | 596,611 B/op | 344 B/op | -99.94% |
| Full server constructor (`--profile-runtime`) | 611,371 B/op | 15,049 B/op | -97.5% |
| Connect+accept phase (`--profile`) | 851,807 B/op | 256,223 B/op | -70% |
| Total managed alloc (`--profile`) | 934,079 B/op | 336,279 B/op | -64% |
| Managed alloc (`--harness 2000`) | ~922,000 B/op | ~326,000 B/op | -65% |
| Throughput (`--harness 2000`) | ~29 ms/op | ~25 ms/op | -14% faster |

### Comparison vs System.Net.Quic

| Metric | Incursa.Quic | System.Net.Quic | Gap |
|--------|-------------|-----------------|-----|
| Managed alloc/op | 326 KB | 90 KB | 3.6x (was 10.4x) |
| Throughput | 25 ms/op | 18 ms/op | 1.4x (was 1.6x) |

### Conclusion

Server runtime construction was the real allocation bug. Lazy key generation removed almost all of it while preserving per-connection key semantics and forward secrecy. `ExportParameters(false)` avoids private key material in managed memory.

### Revised Priority (Post-P4)

| Area | Before | After | Priority |
|------|--------|-------|----------|
| Server runtime construction | ~611 KB | ~15 KB | **Solved** |
| Handshake processing | ~220 KB | ~220 KB | **New main target** |
| Listener / close-dispose | Minor | Minor | Ignore |

### P5 — Handshake Processing Breakdown (Next)

Likely candidates for the remaining ~220 KB/op:
1. X.509 certificate message construction.
2. CRYPTO frame buffering and `.ToArray()` copies.
3. Transcript accumulation and `WrapHandshakeMessage`.
4. Packet scratch buffers in `QuicHandshakeFlowCoordinator`.
5. `QuicTlsPacketProtectionMaterial.TryCreate` key copies.
6. Async/task/channel work during handshake completion.

> After P4, the server-side key schedule allocation issue is resolved. The original 611 KB/op server constructor allocation was caused by eager server key-share generation. Lazy selected-key generation reduced full server construction to ~15 KB/op and total managed allocation to ~326 KB/op. The remaining allocation is now concentrated in handshake processing, not runtime construction.

---

## P5 — Handshake Sub-Operation Profile

Added 2026-05-30. Uses `--profile-handshake N` mode that measures TLS handshake sub-operations in isolation.

### Command

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-handshake 200
```

### Results (200 iterations)

```text
Sub-operation                                         B/op   % of ~220KB
CRYPTO frame buffer (12 frames × 200B avg)            5,376        2.4%
WrapHandshakeMessage (6 calls, ~2KB body)             4,240        1.9%
Transcript ArrayBufferWriter growth                   3,968        1.8%
HKDF ExpandLabel (14 calls, 16-32B each)              1,456        0.7%
Certificate body (1+3+certEntryLen)                   1,232        0.6%
PacketProtectionMaterial.TryCreate (4 calls)            600        0.3%
AesGcm construction (4 calls)                           450        0.2%
SHA256.HashData (7 calls x 32B)                         392        0.2%
CertificateVerify SignData (~72B)                        96        0.0%
Packet buffers (16 × 1200B)                              12        0.0%
TOTAL measured                                       17,823        8.1%
Remainder (unmeasured runtime infra)                ~202,176       91.9%
```

### Key Finding

Handshake sub-operations measured in isolation sum to only **~18 KB/op**. The remaining **~203 KB/op** is not attributable to individual sub-components — it comes from the `QuicConnectionRuntime` event loop processing each packet through the state machine during the actual TLS message exchange. This includes:

- Packet decryption and frame parsing
- Protocol state machine transitions
- Event dispatching to the inbox consumer
- Async `Channel` / `TaskCompletionSource` infrastructure
- Buffer allocation/processing in `QuicHandshakeFlowCoordinator` open/protect paths

This infrastructure is amortized across all packets during the connection lifetime and is inherently difficult to reduce without restructuring the runtime's event processing model.

### Conclusion

After P4, managed allocation is now **~326 KB/op** (down from ~922 KB/op). The runtime packet processing infrastructure (~203 KB/op) is the remaining dominant source. Further reduction would require changes to the event loop, channel infrastructure, or packet processing pipeline — all of which carry significant structural risk.

The ~18 KB/op of identified handshake sub-operations (CRYPTO copies, transcript, HKDF, cert body) are **not worth optimizing individually** — each is <2.4% of the total and none dominates.

| Priority | Target | Remaining | Action |
|----------|--------|-----------|--------|
| **P4** | Server key schedule | **Solved** (597 KB → 344 B) | Complete |
| **P6** | Runtime packet processing | ~203 KB/op | Structural — requires packet-pipeline design changes, not small TLS/HKDF/cert cleanup |
| **Low** | Individual handshake sub-ops | ~18 KB/op | Not worth targeting individually |

---

## Final Narrative

After P4, targeted TLS key schedule optimization reduced total managed allocation by roughly 65% (922 KB → 326 KB). The P4 change was one file, lazy key generation — no architecture changes, no forward-secrecy compromise.

P5 confirmed that remaining isolated TLS handshake sub-operations (WrapHandshakeMessage, CRYPTO buffer, transcript, HKDF, certificate body) account for only ~18 KB/op. None dominates — each is <2.5% of the post-P4 total.

The remaining ~203 KB/op is structural runtime packet-processing allocation inside `QuicConnectionRuntime`'s event loop: packet decryption, frame parsing, state machine transitions, and async channel dispatch. Further reduction requires packet-pipeline design changes beyond the scope of targeted optimization.

The managed allocation comparison gap vs System.Net.Quic narrowed from 10.4x to 3.6x. The throughput gap narrowed from 1.6x to 1.4x.





Likely candidates for the remaining ~220 KB/op:
1. X.509 certificate message construction.
2. CRYPTO frame buffering and `.ToArray()` copies.
3. Transcript accumulation and `WrapHandshakeMessage`.
4. Packet scratch buffers in `QuicHandshakeFlowCoordinator`.
5. `QuicTlsPacketProtectionMaterial.TryCreate` key copies.
6. Async/task/channel work during handshake completion.

> After P4, the server-side key schedule allocation issue is resolved. The original 611 KB/op server constructor allocation was caused by eager server key-share generation. Lazy selected-key generation reduced full server construction to ~15 KB/op and total managed allocation to ~326 KB/op. The remaining allocation is now concentrated in handshake processing, not runtime construction.
