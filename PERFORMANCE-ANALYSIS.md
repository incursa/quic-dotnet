# Incursa.Quic Performance Analysis

> **Date**: 2026-05-29
>
> **Scope**: Allocation sources, throughput opportunities, and correctness blockers across the entire codebase.

---

## Table of Contents

1. [Tier 1 — Correctness Blocker](#tier-1--correctness-blocker)
2. [Tier 2 — Per-Connection Allocations](#tier-2--per-connection-allocations)
3. [Tier 3 — Per-Stream Allocations](#tier-3--per-stream-allocations)
4. [Tier 4 — Per-Operation/Per-Packet Allocations](#tier-4--per-operationper-packet-allocations)
5. [Tier 5 — Structural Patterns](#tier-5--structural-patterns)
6. [Summary & Priority Actions](#summary--priority-actions)

---

## Tier 1 — Correctness Blocker

### The `InvalidOperationException("The connection is not established.")` on request/response benchmark

The `LoopbackRequestResponseOnEstablishedConnection` benchmark fails because `OpenOutboundStreamAsync` checks:

```csharp
// QuicConnectionRuntime.cs ~line 1148
if (phase != QuicConnectionPhase.Active || activePath is null)
{
    throw new InvalidOperationException("The connection is not established.");
}
```

The benchmark's `GlobalSetup` calls `PrepareIncursaQueuedWriteStreamsAsync`, which:
1. Opens a **unidirectional** outbound stream
2. Writes 8 bytes to it
3. Accepts the stream on the server side
4. Reads the 8 bytes on the server

After this setup, the connection must still be `Active` and `activePath` must be non-null for `RunIncursaRequestResponseAsync` to succeed. The fact that it fails suggests one of:

- **Premature connection close**: Something in the queued-write setup sequence causes the connection to transition out of `Active` (to `Closing`, `Draining`, or `Discarded`). This would happen if an error occurs during stream data processing — possibly a protocol error or an unexpected frame that causes `DiscardConnection` to be called.

- **Active path reset**: If `activePath` is set to `null` somewhere during stream cleanup or path validation failure.

**Root cause investigation needed**: Add a trace or check what `phase` and `activePath` are at the point of failure. Look at whether the queued-write stream's close (during setup) triggers a connection-level state transition due to unexpected behavior (e.g., the stream's `Dispose` calling into connection-level cleanup prematurely).

This blocks all other optimization work for the request/response scenario.

---

## Tier 2 — Per-Connection Allocations

### 1. `pendingStreamOpenTypes` (`ConcurrentDictionary<long, QuicStreamType>`) alongside `pendingStreamOpenRequests`

**File**: `QuicConnectionRuntime.cs` lines 60-61

```csharp
private readonly ConcurrentDictionary<long, StreamOpenRequestCompletionSource> pendingStreamOpenRequests = new();
private readonly ConcurrentDictionary<long, QuicStreamType> pendingStreamOpenTypes = new();
```

`pendingStreamOpenTypes` stores redundant keys. The stream type (`QuicStreamType`) could be embedded in `StreamOpenRequestCompletionSource` itself, eliminating one dictionary per connection.

**Savings**: ~200-400 bytes per connection (dictionary object + backing arrays + per-entry overhead).

### 2. Three separate `ConcurrentQueue` pools for completion sources

**File**: `QuicConnectionRuntime.cs` lines 64-66

```csharp
private readonly ConcurrentQueue<StreamOpenRequestCompletionSource> streamOpenRequestCompletionSourcePool = new();
private readonly ConcurrentQueue<StreamActionRequestCompletionSource> streamActionRequestCompletionSourcePool = new();
private readonly ConcurrentQueue<DatagramSendRequestCompletionSource> datagramSendRequestCompletionSourcePool = new();
```

These three pools could share a single pool of `IValueTaskSource` objects, or use a shared `ObjectPool<T>` at a higher level. Each `ConcurrentQueue` allocates an internal lock, nodes, and segments.

### 3. `QueuedInboundStreamIds` (`HashSet<ulong>`) duplicates `inboundStreamIds` Channel tracking

**File**: `QuicConnectionRuntime.cs` line 68

```csharp
private readonly HashSet<ulong> queuedInboundStreamIds = [];
```

This `HashSet` duplicates what `inboundStreamIds` (the `Channel<ulong>`) already tracks. Either the Channel is sufficient, or a single `HashSet<ulong>` + signaling (e.g., `SemaphoreSlim`) could replace the Channel entirely.

### 4. `QuicReceiveBufferPool` — per-pool allocation

The `QuicReceiveBufferPool` constructor allocates 3 arrays plus a `Dictionary<byte[], int>` with reference-equality comparer per pool instance. This is a one-time cost per connection, so it's acceptable but adds to the ~900 KB total.

### 5. `List<BufferedEstablishmentHandshakePacket>` pre-allocation

**File**: `QuicConnectionRuntime.cs` line 72

```csharp
private readonly List<BufferedEstablishmentHandshakePacket> bufferedEstablishmentHandshakePackets = [];
```

This list starts empty and grows as establishment handshake packets are buffered. It's bounded by `MaximumBufferedEstablishmentHandshakePackets` (8), but starts at capacity 0 and resizes up. Pre-sizing to 8 would eliminate 3-4 resize allocations.

### 6. `QuicCryptoBuffer` — `List<Entry>` resizing

The `QuicCryptoBuffer` constructor creates a `List<Entry>` (`entries = []`) pre-allocated with capacity 0. As CRYPTO frames arrive, this list grows and reallocates during handshake. For a typical handshake with 4-8 CRYPTO frames, this means 2-3 list expansions. Pre-sizing to 8 would eliminate the resize allocations.

---

## Tier 3 — Per-Stream Allocations

### 1. `QuicStream` — Two `TaskCompletionSource<object?>` objects

**File**: `QuicStream.cs` (around lines 23-24)

```csharp
private readonly TaskCompletionSource<object?> readsClosed = new(TaskCreationOptions.RunContinuationsAsynchronously);
private readonly TaskCompletionSource<object?> writesClosed = new(TaskCreationOptions.RunContinuationsAsynchronously);
```

Each `TaskCompletionSource<T>` allocates:
- The `TaskCompletionSource` object itself (~56 bytes)
- The `Task<T>` object (~72 bytes for `Task<object?>`)
- Plus continuations when awaited

**Fix**: Lazy-initialize these in the `ReadsClosed`/`WritesClosed` getters. For callers that never await them (common for simple request/response patterns), this saves ~256 bytes per stream.

```csharp
private TaskCompletionSource<object?>? readsClosed;
private TaskCompletionSource<object?>? writesClosed;

internal Task ReadsClosed => (readsClosed ??= new(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
internal Task WritesClosed => (writesClosed ??= new(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
```

### 2. `SemaphoreSlim readGate` and `writeGate`

**File**: `QuicStream.cs` (around lines 25-26)

```csharp
private readonly SemaphoreSlim readGate = new(0, int.MaxValue);
private readonly SemaphoreSlim writeGate = new(1, 1);
```

Each `SemaphoreSlim` allocates a `ManualResetEvent` internally (~40 bytes) + a `lock` object + the `SemaphoreSlim` itself (~32 bytes).

- `readGate` with `(0, int.MaxValue)` is initially blocked, released when data arrives — this is genuinely needed.
- `writeGate` with `(1, 1)` is a binary mutex. For the **common single-writer case**, this could be replaced with a lightweight `SpinLock` or `Interlocked.CompareExchange`-based gate, avoiding allocation entirely.

### 3. `StreamState` class allocation per stream

**File**: `QuicConnectionStreamState.cs` around line 1103

Each stream open creates a `new StreamState(...)` which is a `sealed class` containing:
- 2× `QuicByteRangeSet` (each has internal state)
- 2× `List<BufferedSegment>` (with backing arrays, empty initially)
- ~20 fields (value types, but object header alone is ~32 bytes)

For a single-stream benchmark this is negligible. For high-throughput scenarios with many short-lived streams, this heap pressure accumulates. Consider whether `StreamState` could be a `struct` or pooled.

### 4. Stream data triple-copy on receive

The receive path for stream data has three copies:

1. **Socket → `byte[]`**: via `QuicReceiveBufferPool.Rent`
2. **Decrypted payload → `QuicStreamFrame.StreamData`**: via `.ToArray()` slice in the frame parser
3. **`InsertReadableBytes` → `CreateBufferedSegment`**: via `QuicBufferPool.RentBytes(length)` + `data.CopyTo`

**Fix**: The intermediate `QuicStreamFrame` (a `readonly ref struct`) already holds `ReadOnlyMemory<byte>`. The problem is that the frame parser calls `.ToArray()` on it (e.g., `QuicFrameCodec.cs`). If the frame parser could pass the rented `byte[]` slice through to `CreateBufferedSegment` without the intermediate `ToArray()`, one copy (and its allocation) is eliminated.

---

## Tier 4 — Per-Operation/Per-Packet Allocations

### 1. `SentPackets.Values.Any()` — LINQ allocation on ACK path

**File**: `QuicConnectionRuntime.Protocol.cs` at or around line 2544

```csharp
|| sendRuntime.SentPackets.Values.Any(...)
```

`Dictionary<TKey, TValue>.ValueCollection.Any()` allocates a `ValueCollection.Enumerator` struct plus any lambda closures. On the ACK processing path (every received ACK frame), this is a hot-path allocation.

**Fix**: Replace with a manual `foreach` loop that breaks on match:

```csharp
|| AnySentPacketMatches(...)

// Helper
private bool AnySentPacketMatches(Func<...> predicate)
{
    foreach (var packet in sendRuntime.SentPackets.Values)
    {
        if (predicate(packet)) return true;
    }
    return false;
}
```

### 2. `TryRetryPendingStreamOpenRequests` — `.ToArray()` + sort

**File**: `QuicConnectionRuntime.Streams.cs` line 176

```csharp
KeyValuePair<long, QuicStreamType>[] pendingRequests = pendingStreamOpenTypes.ToArray();
Array.Sort(pendingRequests, ...);
```

This allocates a `KeyValuePair<long, QuicStreamType>[]` every time stream limits increase and pending opens need retry. The dictionary contains at most a few entries (stream open rate is limited by flow control), so `stackalloc` + manual sort or simply iterating without sorting would be cheaper.

### 3. `CompletePendingStreamOpenRequests` / `CompletePendingDatagramSendRequests` — `.ToArray()` enumeration

**File**: `QuicConnectionRuntime.Streams.cs` lines 4544, 4609

```csharp
foreach (KeyValuePair<long, ...> entry in pendingStreamOpenRequests.ToArray())
```

These `.ToArray()` calls produce an array snapshot to avoid modification during enumeration. For terminal cleanup (called once per connection at dispose), this is acceptable. But if these are also called on error paths during normal operation, they add allocation.

### 4. `pendingStreamActionRequests` — `Dictionary<long, ...>` + dedicated lock

**File**: `QuicConnectionRuntime.cs` lines 62-63, 67

```csharp
private readonly Dictionary<long, StreamActionRequestCompletionSource> pendingStreamActionRequests = new();
private readonly object pendingStreamActionRequestsGate = new();
```

Allocated per-connection but only used if concurrent stream writes happen. Could be lazy-allocated on first stream write.

### 5. `newTokenEmissionsByRemoteAddress` — `Dictionary<string, ...>`

**File**: `QuicConnectionRuntime.cs` line 70

```csharp
private readonly Dictionary<string, QuicConnectionNewTokenEmissionRecord> newTokenEmissionsByRemoteAddress = new(StringComparer.Ordinal);
```

Allocated per-connection but only populated on the server side after handshake completion when NEW_TOKEN frames are sent. Could be lazy-allocated on first emission.

### 6. `ReadOnlyMemory<byte>.ToArray()` calls in stream processing

**File**: `QuicConnectionRuntime.Streams.cs` lines 2997, 3259, 3435, 3484, 4487

Multiple `.ToArray()` calls on `ReadOnlyMemory<byte>` slices produce fresh `byte[]` allocations:

- Line 2997: `destinationConnectionId = parsedDestinationConnectionId.ToArray();` — new `byte[]` per routing packet
- Line 3259: `cryptoPayload = cryptoFrame.CryptoData.ToArray();` — new `byte[]` per CRYPTO frame
- Line 3435: `retryToken = ...ToArray();` — one-time
- Line 3484: `plaintextPayload = openedPacket.Memory.Slice(...).ToArray();` — per packet on receive
- Line 4487: `byte[] ownedDatagram = datagram.ToArray();` — per received datagram

Most of these are architecturally necessary for ownership, but each represents a hot-path allocation that should be scrutinized.

### 7. `KeyValuePair<...>[]` in `pendingStreamOpenRequests.ToArray()`

Same pattern as #2 above — the `ToArray()` on `ConcurrentDictionary` allocates a full copy. These happen on the cleanup path but also on retry paths during normal operation.

### 8. `Stack<T>.ToArray()` / `Queue<T>.ToArray()` usage

Check if any internal `Stack<T>` or `Queue<T>` collections call `.ToArray()` to produce enumeration snapshots. Each call allocates a new `T[]`.

### 9. `QuicConnectionEffectAccumulator.ToArray()` overflow to `List<QuicConnectionEffect>`

The effect accumulator optimizes for 0-4 effects inline, but when the 5th effect fires it creates a `List<QuicConnectionEffect>` with capacity 8. The lifecycle path (`AppendLifecycleTimerEffects`) can produce more than 4 effects in terminal transitions, triggering this allocation. This happens once per connection (at terminal), so it's acceptable.

### 10. `ReadOnlyMemory<byte>.ToArray()` in `QuicDatagramFrame`

**File**: `QuicFrameCodec.cs` — datagram frame parsing calls `.ToArray()` on the payload before buffering. Combined with the subsequent `QuicBufferPool.RentBytes` + `CopyTo` in the runtime, datagram payloads are copied twice on receive.

### 11. `tlsState.HandshakeKeysAvailable` pattern

**File**: `QuicConnectionRuntime.Lifecycle.cs` — `RefreshCurrentProbeTimeoutMicros` accesses `tlsState.HandshakeKeysAvailable` which may do work internally. Check whether this is a cached flag or a computed property that allocates.

### 12. `StringComparer.Ordinal` in `newTokenEmissionsByRemoteAddress`

Creating a `StringComparer.Ordinal` instance is cheap (singleton), but `Dictionary<string, ...>` itself with string keys involves `GetHashCode()` on the string key for every lookup — this is unavoidable but worth noting.

---

## Tier 5 — Structural Patterns

### 1. Lock granularity in `QuicConnectionStreamState`

**File**: `QuicConnectionStreamState.cs`

The entire `QuicConnectionStreamState` uses a single `lock (syncRoot)` for all operations. Every `TryReadStreamData`, `TryReserveSendCapacity`, `TryReceiveStreamFrame` contends on the same lock. For single-stream benchmarks this doesn't matter — but for real workloads with many concurrent streams, this becomes a bottleneck.

**Consideration**: Could the `sentRanges` / `receivedRanges` per-stream be lock-free using `Interlocked` operations or `ReaderWriterLockSlim`?

### 2. Channel-based event delivery

The `Channel<QuicConnectionEvent> inbox` (unbounded capacity) is the primary mechanism for consumer-to-runtime communication. Each event is a `struct` (no per-event allocation), but the `Channel` itself has overhead — the ring buffer, lock, `AsyncOperation` objects for readers.

For high-throughput scenarios, a lock-free `SingleConsumerQueue<T>` + `ManualResetValueTaskSource<T>` pattern would be more efficient. This would be a major refactor but could significantly reduce per-connection allocation and improve latency.

### 3. TLS key schedule — `new byte[n]` instead of `ArrayPool<byte>`

**File**: `QuicTlsKeySchedule.cs`

Many handshake message constructions use `new byte[n]` (lines 409, 1956, 2000, 2298, 2311, 2418, 2536, 2623, 2672, 2684). These are TLS handshake messages serialized once per connection, so the absolute allocation is amortized. But using `ArrayPool<byte>.Shared.Rent(n)` and returning the arrays after use would reduce GC pressure from ~2-4 KB of temporary byte arrays per handshake.

**Caveat**: Some of these buffers are kept for the connection's lifetime:
```csharp
private ReadOnlyMemory<byte>? initialBootstrapClientHelloBytes;
private ReadOnlyMemory<byte>? ownedResumptionTicketBytes;
private ReadOnlyMemory<byte>? ownedResumptionTicketNonce;
private ReadOnlyMemory<byte>? resumptionMasterSecret;
```

If these are only needed for diagnostics or resumption, they could be freed after handshake confirmation (~100-200ms into the connection).

### 4. Deferred/lazy allocation opportunities

| Field | Current | Proposed | Savings |
|-------|---------|----------|---------|
| `inboundDatagrams` Channel | Always allocated | Allocate only if `MaxDatagramFrameSize > 0` | ~128+ bytes per connection |
| `pendingStreamActionRequests` Dictionary | Always allocated | Lazy-allocate on first stream write | ~128+ bytes per connection |
| `newTokenEmissionsByRemoteAddress` Dictionary | Always allocated (server) | Lazy-allocate on first NEW_TOKEN emission | ~96+ bytes per connection without tokens |
| `pendingStreamOpenTypes` Dictionary | Always allocated | Eliminate entirely by embedding in completion source | ~200+ bytes per connection |
| `queuedInboundStreamIds` HashSet | Always allocated | Remove if redundant with Channel | ~96+ bytes per connection |

### 5. `Func<QuicConnectionEvent, bool>? localApiEventDispatcher` delegate allocation

**File**: `QuicConnectionRuntime.cs` line 152

```csharp
private Func<QuicConnectionEvent, bool>? localApiEventDispatcher;
```

If this is set to a lambda or method group, each assignment allocates a delegate. If it's set once and lives for the connection lifetime, this is a one-time cost. But if it's reset or reassigned (e.g., on each event dispatch), it becomes a per-operation allocation.

### 6. Thread-static or pool-based `IValueTaskSource` reuse

The `StreamOpenRequestCompletionSource`, `StreamActionRequestCompletionSource`, and `DatagramSendRequestCompletionSource` are already pooled per-connection via `ConcurrentQueue`. But these pools don't share across connections. For server scenarios with many connections, a global `ObjectPool<T>` of these completion sources would reduce the per-connection memory overhead.

### 7. `ConcurrentQueue` vs `ConcurrentBag` for completion source pools

`ConcurrentQueue` is thread-safe and preserves ordering, but for a pool where order doesn't matter, `ConcurrentBag` can be more efficient under high contention (thread-local caching). However, for the common single-threaded consumer case, a simple `Stack<T>` or `Queue<T>` with a lock would be faster and lighter.

---

## Summary & Priority Actions

| Priority | Area | Current Issue | Fix | Estimated Savings |
|----------|------|--------------|-----|-------------------|
| **P0** | Phase transition bug | `InvalidOperationException` on request/response benchmark | Investigate why phase drops from `Active` after queued-write stream setup | Unlocks measurement |
| **P1** | `TaskCompletionSource` in `QuicStream` | 2× TCS per stream (~256 B) | Lazy init in `ReadsClosed`/`WritesClosed` getters | ~256 B per stream → ~0 B |
| **P1** | `SemaphoreSlim writeGate` | Mutex allocation per stream (~72 B) | Lightweight spin-based gate | ~72 B per stream → ~0 B |
| **P2** | `pendingStreamOpenTypes` redundant dictionary | 1 dict per connection (~200 B) | Embed `QuicStreamType` in `StreamOpenRequestCompletionSource` | ~200 B per connection |
| **P2** | Stream data triple-copy on receive | 3× per-payload allocation | Eliminate intermediate `.ToArray()` in frame parser | ~66% of receive-path allocation |
| **P2** | `ConcurrentQueue` pools consolidation | 3 pool objects per connection | Shared `ObjectPool<T>` or single pooled type | ~3 objects per connection |
| **P3** | `SentPackets.Values.Any()` LINQ | Enumerator alloc per ACK | Manual `foreach` + break | ~48 B per ACK frame |
| **P3** | `TryRetryPendingStreamOpenRequests` — `.ToArray()` + sort | Alloc per stream-limit change | `stackalloc` or manual iteration | 128+ B per retry batch |
| **P3** | `bufferedEstablishmentHandshakePackets` list resize | 3-4 resizes per connection | Pre-size to 8 | ~256 B per connection |
| **P4** | `TlsKeySchedule` — `new byte[n]` | 2-4 KB temps per handshake | `ArrayPool<byte>.Shared.Rent` | ~2 KB per connection |
| **P4** | `QuicCryptoBuffer` list resize | 2-3 resizes per handshake | Pre-size to 8 | ~256 B per connection |
| **P5** | Lazy `inboundDatagrams` Channel | Always allocated | Only allocate if datagram feature enabled | ~128 B per connection |
| **P5** | Lazy `newTokenEmissionsByRemoteAddress` dict | Always allocated on server | Lazy on first NEW_TOKEN emission | ~96 B per connection |

### Key Metric: Per-Stream Allocation Breakdown (Current)

| Component | Allocation | Scope |
|-----------|-----------|-------|
| `QuicStream` object | ~72 B | Per stream |
| `readsClosed` TCS + Task | ~128 B | Per stream |
| `writesClosed` TCS + Task | ~128 B | Per stream |
| `readGate` SemaphoreSlim | ~72 B | Per stream |
| `writeGate` SemaphoreSlim | ~72 B | Per stream |
| `StreamState` object | ~64 B | Per stream |
| **Total baseline per stream** | **~536 B** | **Per stream** |

With P1 fixes (lazy TCS + lightweight write gate), this drops to **~208 B per stream**.

### Key Metric: Per-Connection Allocation Breakdown (Current)

| Component | Allocation | Scope |
|-----------|-----------|-------|
| 3× `ConcurrentQueue` pools | ~240 B | Per connection |
| 3× `ConcurrentDictionary` | ~400 B | Per connection |
| 1× `Dictionary<long, ...>` | ~128 B | Per connection |
| 1× `HashSet<ulong>` | ~96 B | Per connection |
| 1× `Dictionary<string, ...>` | ~96 B | Per connection |
| 2× `Channel<T>` | ~256 B | Per connection |
| `List<...>` (empty) | ~32 B | Per connection |
| Various state objects | ~400 B | Per connection |
| **Total baseline per connection** | **~1,648 B** | **Per connection** |

With all P2-P5 fixes, this could drop to **~800-1,000 B per connection**.

---

---

## Allocation Comparison: Incursa.Quic vs System.Net.Quic

Added 2026-05-29 after harness enhancement.  Full details in `docs/analysis/incursa-quic-allocation-analysis.md`.

### Key Finding

Managed allocation is not directly comparable between implementations because System.Net.Quic delegates expensive QUIC/TLS state to native MsQuic (C library), whose allocations are invisible to managed GC metrics (`GC.GetTotalAllocatedBytes`, BenchmarkDotNet `Allocated` column).

### Measurement Tool

A non-BDN harness was added at `benchmarks/QuicAllocationHarness.cs` that reports managed allocation, working set, and private bytes per operation.

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness 10000
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --leak 1000
```

### Results (10,000-iteration harness)

| Metric | Incursa.Quic | System.Net.Quic |
|--------|-------------|-----------------|
| **Managed allocated/op** | ~922 KB | ~84 KB |
| **Working set Δ/op** (pass 2) | ~0 B | ~2.3 MB |
| **Private bytes Δ/op** (pass 2) | ~0 B | ~2.5 MB |
| **Throughput** | ~29 ms/op | ~22 ms/op |

Incursa.Quic allocates 922 KB/op managed, but working set and private bytes are flat across passes — all allocation is ephemeral Gen0 garbage that is fully reclaimed.

System.Net.Quic allocates only 84 KB/op managed, but native MsQuic retains ~2.5 MB/op in private bytes after `CloseAsync`/`DisposeAsync`. The plateau test confirms this is native allocator high-water behavior (not a leak — batch 2 retained is slightly less, not additive).

### Conclusion

| Implementation | Cost type | Real concern |
|---|---|---|
| **Incursa.Quic** | ~922 KB/op managed churn, fully reclaimed | GC throughput (Gen0 collections), ~30% time gap |
| **System.Net.Quic** | ~84 KB/op managed, ~2.5 MB/op native high-water | Process memory footprint, invisible to managed metrics |

The optimization target for Incursa.Quic is **reducing Gen0 churn**, not fixing a memory leak. The 922 KB/op is spread across hundreds of small allocations (TLS handshake body builders, packet buffers, HKDF intermediates, crypto contexts, runtime construction). No single source dominates.

### Changes Applied (2026-05-29)

| Change | Files | Status |
|--------|-------|--------|
| Tier 2 per-connection allocation fixes | `QuicConnectionRuntime.cs`, `QuicCryptoBuffer.cs` | Applied |
| P0 phase transition diagnostics | `QuicConnectionRuntime.cs`, `QuicConnectionRuntime.Lifecycle.cs`, `QuicConnectionRuntime.Routing.cs` | Applied |
| P1 lazy TCS + lazy writeGate in QuicStream | `QuicStream.cs` | Applied |
| P2 investigation — stream path avoids .ToArray() | `QuicCryptoBuffer.cs` reverted, no change needed | Investigated, no action |
| P4 ArrayPool for TLS scratch buffers | `QuicTlsKeySchedule.cs` (lines 409, 1956, 2298, 2326) | Applied |
| Allocation harness | `benchmarks/QuicAllocationHarness.cs`, `benchmarks/Program.cs` | Applied |
| Analysis document | `docs/analysis/incursa-quic-allocation-analysis.md` | Created |

### Remaining Opportunities

The following areas were investigated but not changed because the allocations escape via `out` parameters (buffers cannot be pooled at the allocation site) or the estimated savings are negligible (~1% of 922 KB):

- Packet scratch buffers in `QuicHandshakeFlowCoordinator` — 8 `new byte[...]` sites, all escape via `out`
- CRYPTO frame `Entry` struct range-slice allocations in `QuicCryptoBuffer` — complex refactoring for ~1% savings
- HKDF temporary arrays — 23 call sites, mixed ownership patterns, ~1-2 KB total
- Runtime object graph construction — structural, requires major refactoring

## Benchmark Infrastructure Issue

The "NA" results in BenchmarkDotNet are caused by duplicate `.csproj` files in the search path due to `.artifacts/` directories containing staged copies. This is a build infrastructure issue, not a code issue, but it prevents all benchmarks (including the successful ones) from running.

**Fix**: Either:
1. Run benchmarks from a clean checkout
2. Add an `ArtifactsPath` attribute or use `--artifacts` CLI argument pointing outside the repo
3. Delete `.artifacts/network-simulator-*` directories before running benchmarks
