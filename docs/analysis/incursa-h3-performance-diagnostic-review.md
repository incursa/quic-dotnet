# Incursa H3 Performance Diagnostic Review

This is an investigation-phase review of Incursa QUIC + HTTP/3 performance using ProtocolLab Phase 2I/2J local artifacts and a static source audit. It intentionally does not optimize the implementation, change benchmark classification, delete tests, loosen validation, or bypass protocol behavior.

## Summary

ProtocolLab shows a real investigation target: Incursa HTTP/3 is much slower than Kestrel on tiny HTTP/3 endpoints in both external-reference h2load and managed-lab runs. Plaintext and JSON are close for Incursa, and the TechEmpower sample precomputes both response bodies, so JSON serialization is not the first suspect. The dominant cost is more likely in the shared QUIC/H3 request-response path: packet receive/routing, packet protection, stream dispatch/state, HTTP/3 frame parsing/writing, QPACK/header work, request/response object construction, stream writes, packetization, and UDP send scheduling.

Confidence is medium that the gap is server-side and shared-path dominated. Confidence is low that a single specific bottleneck can be named from the current artifacts because CPU, GC/allocation, queue depth, flush/send counts, and packetization counters are missing or unreliable.

## Benchmark Evidence Used

Reviewed primary summary:

- `C:\src\incursa\protocol-lab\docs\analysis\incursa-h3-phase2j-performance-review.md`

Reviewed supporting artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-h2load-phase2i\summary.md`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-h2load-phase2i\aggregate-results.json`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-h2load-phase2i\phase2j-analysis-summary.md`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-managed-phase2i\summary.md`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-managed-phase2i\aggregate-results.json`

External-reference h2load gap:

| scenario | Kestrel req/s | Incursa req/s | Kestrel/Incursa |
| --- | ---: | ---: | ---: |
| `http.core.plaintext` | 22,747.5 | 2,579.8 | 8.82x |
| `http.core.json` | 22,462.9 | 2,787.4 | 8.06x |

Managed-lab gap:

| scenario | Kestrel req/s | Incursa req/s | Kestrel/Incursa |
| --- | ---: | ---: | ---: |
| `http.core.plaintext` | 30,138.4 | 1,789.3 | 16.84x |
| `http.core.json` | 28,284.9 | 1,638.8 | 17.26x |

Plaintext vs JSON behavior:

- Kestrel h2load plaintext and JSON are close.
- Incursa h2load plaintext and JSON are close, with JSON slightly faster in that local run.
- Managed-lab Incursa plaintext and JSON are also close.
- The Incursa sample precomputes static plaintext and JSON bodies, so per-request JSON serialization is not present on the benchmarked path.

Process metrics limitations:

- Process metrics are captured for all h2load and managed cells, but CPU deltas are not trustworthy for CPU-per-request because the target command uses `dotnet run`, which can capture the wrapper process instead of the actual server process.
- The recorded working set and thread counts do not explain the throughput gap by themselves.
- Load-generator CPU, host isolation, and network isolation are explicitly not controlled well enough for publishable comparisons.

Qlog availability:

- External-reference h2load cells have qlogs: 16 `.sqlog` files per cell, matching the 16 h2load connections.
- Managed-lab cells do not have qlogs.
- Kestrel qlogs are larger in total because Kestrel completes many more requests. Incursa qlogs appear larger per completed request, but the qlogs have not been parsed, so this is only an inventory clue.

Current missing measurements:

- trustworthy target process CPU attached to the actual server process
- allocation rate and GC counts during H3 cells
- thread-pool and scheduler activity
- request, stream, frame, QPACK, write, final-write, packet, and UDP-send counters
- queue depth or contention indicators
- flush/send and packetization shape per response
- qlog-derived stream/frame/packet ratios

## Request-Response Path Map

Detailed path map: `docs/analysis/incursa-h3-request-response-path.md`.

High-level path:

1. `QuicListenerHost.ReceiveLoopAsync` receives one UDP datagram and copies it into a new array.
2. `QuicConnectionRuntimeEndpoint.ReceiveDatagram` classifies and routes the packet through connection-ID dictionaries.
3. `QuicConnectionRuntimeHost.TryPostEvent` posts to `QuicConnectionRuntimeShard`.
4. `QuicConnectionRuntime.Protocol.TryHandleApplicationPacketReceived` opens protected packets and parses ACK/STREAM/control frames.
5. Stream data is committed to `QuicConnectionStreamState` and surfaced through `QuicStream`.
6. `Http3Server.AcceptStreamsAsync` accepts request streams and starts `HandleRequestStreamAsync`.
7. `Http3Server.ReadRequestAsync` uses `Http3FrameReader` and `ConnectionQPackState` to parse HEADERS/DATA and decode QPACK.
8. `Http3Request` is allocated and the TechEmpower handler dispatches `/plaintext` or `/json`.
9. `Http3ServerResponse` is allocated; response headers are rebuilt and encoded.
10. `Http3FrameWriter` creates HEADERS/DATA frame bytes.
11. `QuicStream.WriteFinalAsync` posts stream data into the runtime.
12. `QuicConnectionRuntime.Streams.HandleWriteStreamAction` reserves flow-control credit, builds STREAM payload, protects a packet, records recovery state, and emits `QuicConnectionSendDatagramEffect`.
13. `QuicListenerHost.SendDatagram` sends the protected packet on the UDP socket.

## Static Hot-Path Audit

Scan execution checklist:

- `new byte[` checked in `src/Incursa.Quic`, `src/Incursa.Quic.Http3`, `src/Incursa.Qpack`, and `samples/Incursa.Http3.Samples.TechEmpower`.
- `new MemoryStream` checked in the same scope.
- `.ToArray()` checked in the same scope.
- `Encoding.UTF8.GetString` and `Encoding.UTF8.GetBytes` checked in the same scope.
- LINQ patterns `.Select`, `.Where`, `.OrderBy`, `.GroupBy`, `.SelectMany` checked in the same scope.
- `lock (` checked in the same scope.
- `ConcurrentDictionary` checked in the same scope.
- `Channel` checked in the same scope.
- `Task.Run` checked in the same scope.
- `WriteAsync` and `FlushAsync` checked in the same scope.
- `DateTimeOffset.UtcNow` and RFC1123 date formatting checked in the same scope.

The optional helper script added in this review can rerun the candidate search:

```powershell
pwsh -NoProfile -File scripts/analysis/Find-HotPathPatterns.ps1
```

Most recent candidate-count snapshot from that script against the default scope:

- `new byte[]`: 77
- `new MemoryStream`: 0
- `.ToArray()`: 220

The script output is only a candidate list. It is useful for choosing where to
inspect next, not proof that any site is a bottleneck.

## Top Suspected Bottleneck Categories

### Likely Serious

1. Per-datagram copy before runtime routing
   - Files/classes/methods: `QuicListenerHost.ReceiveLoopAsync`.
   - Evidence: received bytes are copied from the pooled socket buffer into a fresh datagram array before `endpoint.ReceiveDatagram`.
   - Why it matters: this is per UDP datagram and is on every packet receive.
   - Caveat: ownership may require copying. Measure allocation rate before changing.

2. Per-frame and per-request HTTP/3 allocations
   - Files/classes/methods: `Http3FrameReader.Read`, `Http3Server.ReadRequestAsync`, `Http3Server.WriteBufferedResponseFramesAsync`, `Http3FrameWriter.WriteFrame`.
   - Evidence: frame reader appends/copies pending bytes, creates payload arrays and frame objects; frame writer returns arrays; buffered response writes can allocate frame arrays and then another combined array.
   - Why it matters: every tiny request still pays frame parsing, header frame, data frame, and result-array costs.
   - Caveat: small bodies make this easy to overstate without allocation counters.

3. Stream write to protected packet to UDP send is likely too granular
   - Files/classes/methods: `Http3Server.WriteFinalFrameBytesAsync`, `QuicStream.WriteFinalCoreAsync`, `QuicConnectionRuntime.Streams.HandleWriteStreamAction`, `TryProtectAndAccountStreamApplicationPayload`, `QuicListenerHost.SendDatagram`.
   - Evidence: the tiny response path writes a final stream payload, then runtime builds and protects a packet and emits one send effect. There is no visible UDP send batching.
   - Why it matters: high request/sec tiny responses are sensitive to per-response packetization, protection, recovery accounting, and send calls.
   - Caveat: this needs write/final-write/packet/UDP-send counters, not source inspection alone.

4. Runtime scheduling and dictionary routing are on every packet
   - Files/classes/methods: `QuicConnectionRuntimeEndpoint`, `QuicConnectionRuntimeHost`, `QuicConnectionRuntimeShard`.
   - Evidence: route state uses multiple `ConcurrentDictionary` instances; each received packet posts a connection event into a channel consumed by the shard.
   - Why it matters: per-packet scheduler and concurrent-collection overhead can dominate tiny-payload benchmarks.
   - Caveat: the shard model may be necessary for correctness and isolation. Measure queue depth, processing rate, and contention before changing.

5. Response header and QPACK work is rebuilt per request
   - Files/classes/methods: `TechEmpowerHandler.Payload`, `Http3Server.BuildResponseHeaders`, `EncodeResponseFieldSection`, `FindStaticFieldLineIndex`, `FindStaticNameIndex`, `WriteRawString`.
   - Evidence: each response formats `date`, formats content length, builds `QPackFieldLine[]`, scans the QPACK static table, and encodes strings into new byte arrays.
   - Why it matters: plaintext and JSON responses are tiny, so repeated header work can be a visible fraction of request cost.
   - Caveat: date/header correctness and ownership must be preserved.

### Possible

1. QPACK request decode and header validation allocation
   - Files/classes/methods: `ConnectionQPackState.DecodeRequestHeadersAsync`, `QPackDecoder.DecodeFieldSection`, `Http3HeaderValidator.ValidateRequestHeaders`.
   - Notes: decoded field lines and strings are allocated per HEADERS frame. h2load's request header behavior should be measured before blaming QPACK.

2. `Http3Request` and `Http3ServerResponse` defensive copies
   - Files/classes/methods: `Http3Request` constructor, `Http3ServerResponse` constructor.
   - Notes: both copy `ReadOnlyMemory<byte>` into arrays. For empty request bodies and static response bodies this may be avoidable later, but it is currently an ownership boundary.

3. Per-request `DateTimeOffset.UtcNow.ToString("R", InvariantCulture)`
   - Files/classes/methods: `TechEmpowerHandler.Payload`.
   - Notes: date formatting is shared by plaintext and JSON and commonly optimized by production HTTP servers. It is still only a possible contributor until measured.

4. `QuicApplicationSendQueue` sorting and array creation
   - Files/classes/methods: `QuicApplicationSendQueue.GetSortedQueuedWrites`, `BuildDistinctStreamIds`, `FlushPendingApplicationSends`.
   - Notes: this matters only if the tiny response path queues and flushes pending sends often. It may be low-impact if final writes bypass delayed send.

5. Stream read/write semaphore churn
   - Files/classes/methods: `QuicStream.ReadCoreAsync`, `WriteCoreAsync`, `WriteFinalCoreAsync`.
   - Notes: `SemaphoreSlim` gates protect correctness. Their cost may matter under high tiny-request concurrency.

### Low Confidence

1. Dynamic QPACK blocked-stream machinery
   - Files/classes/methods: `ConnectionQPackState`, `QPackDecoder.DecodeEncoderStream`.
   - Notes: probably not dominant for the static h2load request pattern unless h2load sends dynamic-table-dependent headers.

2. Sample route dispatch
   - Files/classes/methods: `TechEmpowerHandler.HandleAsync`, `HandleGet`, `StripQuery`.
   - Notes: branch and string compare overhead is small relative to the rest of the path.

3. Disabled diagnostics logging
   - Files/classes/methods: `Http3Server.Emit`, `QuicListenerHost.Emit*`, QUIC diagnostic helpers.
   - Notes: most emitters check `IsEnabled` first. No evidence yet that disabled diagnostics are serious.

4. JSON body generation
   - Files/classes/methods: `TechEmpowerPayloads`.
   - Notes: response bytes are static and precomputed, so JSON serialization is probably fine for these benchmarks.

### Probably Fine

1. Startup certificate generation
   - Files/classes/methods: `Program.CreateSelfSignedCertificate`.
   - Notes: startup-only, not steady-state request path.

2. Startup H3 control/QPACK stream creation
   - Files/classes/methods: `Http3Server.OpenRequiredUnidirectionalStreamsAsync`.
   - Notes: connection setup path, not per request after the connection is warm.

## Specific Files/Classes/Methods To Inspect Next

1. `src/Incursa.Quic/QuicConnectionRuntime.Streams.cs` - `HandleWriteStreamAction`, `FlushPendingApplicationSends`, `TryProtectAndAccountStreamApplicationPayload`, `TryBuildOutboundStreamPayload`.
2. `src/Incursa.Quic.Http3/Http3Server.cs` - `ReadRequestAsync`, `WriteResponseAsync`, `WriteBufferedResponseFramesAsync`, `EncodeResponseFieldSection`.
3. `src/Incursa.Quic/QuicListenerHost.cs` - `ReceiveLoopAsync`, `SendDatagram`.
4. `src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs` and `QuicConnectionRuntimeShard.cs` - route lookup and channel handoff.
5. `src/Incursa.Qpack/QPackDecoder.cs` and `src/Incursa.Quic.Http3/Http3FrameReader.cs` - decode/frame allocation path.

## Instrumentation Points For Later

Suggested counters, behind an explicit diagnostic flag or `Meter`/EventCounter path:

- requests started/completed
- H3 requests/sec
- H3 headers decoded/encoded
- H3 DATA frames sent
- QPACK encode/decode operations
- QUIC streams opened/completed
- stream reads/writes/final writes
- flush calls or final-write calls
- packets sent/received
- UDP sends/receives
- bytes copied where measurable
- buffer-pool rent/return counts
- per-request allocation estimate if easy
- shard queue depth or posted/processed work-item counts
- stream write wait time or contention indicators if available

## Missing Measurements

The current evidence cannot separate:

- CPU-bound packet protection/parsing from allocation-bound frame/header work
- per-request allocation from per-packet allocation
- stream write calls from protected packet count
- protected packet count from UDP send count
- scheduler/channel overhead from protocol processing
- QPACK/header cost from QUIC transport cost
- target server CPU from `dotnet run` wrapper CPU

## Lower-Level Benchmark Plan

These are proposed measurement slices only. They should use the existing
BenchmarkDotNet project shape under `benchmarks/`, keep correctness semantics
unchanged, and include allocation columns wherever practical.

1. QUIC varint parse/write
   - Existing anchor: `benchmarks/QuicVariableLengthIntegerBenchmarks.cs`.
   - Measure representative 1, 2, 4, and 8 byte values, sequential decode over
     packet-like buffers, and write into caller-provided spans.
   - Goal: confirm the varint primitive is not dominating frame and packet
     parsing.

2. QUIC frame parse/write
   - Existing anchor: `benchmarks/QuicFrameCodecBenchmarks.cs`.
   - Add or extend cases for the exact request/response mix: STREAM, ACK,
     MAX_DATA, MAX_STREAM_DATA, CONNECTION_CLOSE, and small DATAGRAM only if it
     stays separate from H3 request response claims.
   - Goal: measure frame codec cost and allocation for tiny STREAM-heavy
     packets.

3. Packet builder and packet protection
   - Existing anchors: `QuicInitialPacketProtectionBenchmarks`,
     `QuicHandshakePacketProtectionBenchmarks`, and runtime packet-build helpers
     in `QuicConnectionRuntime.Streams.cs`.
   - Add a 1-RTT STREAM payload build/protect benchmark using established test
     packet-protection material and small payload sizes matching `/plaintext`
     and `/json`.
   - Goal: isolate STREAM payload build, packet protection, recovery accounting,
     and protected packet allocation.

4. Stream write path
   - Existing anchors: `QuicConnectionStreamStateBenchmarks` and
     `QuicPublicApiStreamTransferBenchmarks`.
   - Add a runtime-level benchmark for `WriteFinalStreamAsync` over an active
     in-memory/loopback connection shape, plus a lower-level benchmark around
     `HandleWriteStreamAction` if the internal seam can be exercised without
     weakening correctness.
   - Goal: count awaits, task completions, queue posts, send effects, and
     allocations per tiny response write.

5. HTTP/3 frame write
   - New likely benchmark class: `Http3FrameWriterBenchmarks`.
   - Measure `WriteHeaders`, `WriteData`, and the current combined
     HEADERS+DATA response framing shape for the plaintext and JSON bodies.
   - Goal: separate H3 frame array/copy cost from QUIC packet cost.

6. QPACK/header encode
   - New or extended benchmark class: `QPackFieldSectionBenchmarks`.
   - Measure current response field-section encoding for the benchmark headers,
     static table lookup, literal string encoding, and request HEADERS decode
     using captured h2load request header bytes if available.
   - Goal: test whether repeated static-table scans, `QPackFieldLine[]`
     creation, and string-to-byte encoding are meaningful.

7. Plaintext response generation
   - New likely benchmark class: `Http3TechEmpowerResponseBenchmarks`.
   - Measure `TechEmpowerHandler.HandleAsync` for `GET /plaintext`, including
     `Http3ServerResponse` construction and response header construction, but
     not QUIC transport.
   - Goal: bound sample-handler overhead and date/content-length/header
     allocation.

8. JSON response generation
   - Same benchmark class as plaintext, using `GET /json`.
   - Keep the existing static JSON body semantics. Do not add serializer work
     unless the benchmark scenario itself changes.
   - Goal: confirm JSON remains close to plaintext below the transport layer.

## Recommended Next Measurement Phase

Primary next step: add opt-in `Meter` counters to the Incursa HTTP/3 and QUIC request path, then run the existing ProtocolLab h2load cell while collecting `dotnet-counters` against the actual Incursa server process.

Why this one first:

- It answers whether the tiny response path is producing too many stream writes, final writes, protected packets, UDP sends, QPACK operations, and frame allocations per request.
- It can be added behind an explicit diagnostic flag without changing benchmark classification or protocol behavior.
- It directly targets the shared plaintext/JSON path that the current evidence implicates.

Keep this phase measurement-only. Do not optimize or rewrite anything until counters show which category is actually dominant.

## Suggested Codex Prompt For Next Phase

```text
Add opt-in Incursa H3/QUIC request-path Meter counters for measurement only. Keep protocol behavior, benchmark classification, validation, and tests unchanged. Counters should be disabled unless an explicit diagnostic flag is set. Count requests started/completed, H3 headers decoded/encoded, DATA frames sent, QPACK encode/decode operations, stream writes/final writes, protected packets sent, packets received, UDP sends/receives, and shard work items posted/processed where low-risk. Add focused tests proving counters are opt-in and do not alter behavior. Then run dotnet build and the repo's normal test command. Do not optimize the implementation.
```

## Conclusion

Top suspected bottleneck category: shared QUIC/H3 request-response overhead, especially per-request/frame/header allocations plus per-response stream-write/packetization/send scheduling.

Confidence level: medium that the shared path is the right target; low that any one source-level finding is the measured bottleneck.

No code behavior changed by this review.
