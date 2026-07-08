# QUIC Performance Improvement Wishlist

This is a pragmatic backlog for improving Incursa.Quic performance evidence, runtime efficiency, and benchmark trustworthiness. Each item includes the finish line so we can tell when it is actually done.

## Progress Notes

- 2026-07-08: `152fda3c` removed disabled application-send diagnostic string allocations on the stream write hot path. Source-backed ProtocolLab profile pack `codex-h3-1kb-post-log-handler-20260708a` showed `http3.payload.bytes.1kb` request rate +2.24%, p95 -0.92%, allocation rate -29.97%, and bytes/request -31.51% versus `codex-h3-1kb-post-data-frame-20260708a`.
- 2026-07-08: `7c083271` added a queued inbound stream accept fast path. Source-backed ProtocolLab profile pack `codex-h3-1kb-post-accept-fastpath-20260708a` showed request rate +11.28%, p95 -18.03%, and bytes/request -1.17% versus `codex-h3-1kb-post-log-handler-20260708a`; allocation rate rose +9.98% while total throughput increased.
- 2026-07-08: exception attribution run `codex-exception-attribution-post-accept-fastpath-20260708a` for `http3.payload.bytes.64kb` passed ProtocolLab validation and benchmark with 22,992 EventPipe events, zero lost events, and zero first-chance exceptions.
- 2026-07-08: CoreProtocolLab smoke lane now defaults HTTP/3 to `http3.core.status` and raw QUIC to `quic.transport.multiplex.100x64kb`. Smoke run `codex-core-lane-status-smoke-20260708a` passed both ProtocolLab cells; the heavier `http3.payload.bytes.64kb` managed-load run remains a confidence/profile pressure scenario after surfacing premature-response shutdown noise under the one-second smoke window.
- 2026-07-08: baseline reporting now supports `-ImplementationId` filtering so Incursa current baselines can be reviewed separately from peer implementation/declaration inventory rows.
- 2026-07-08: allocation hotspot rollup `codex-h3-1kb-hotspots-20260708a` compared the post-data-frame, post-log-handler, and post-accept-fastpath 1KB H3 profile packs. The latest row held bytes/request roughly flat at 11,613 B while increasing request rate to 4,661 req/s and lowering p95 to 69.85 ms.
- 2026-07-08: `07bbc6d` in `protocol-lab-internal` fixed source-backed H3 benchmark builds so implementation targets are built with `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT` already set, and hardened managed H3 load deadlines so started requests drain under `HttpClient.Timeout`. `505bef2f` in `quic-dotnet` enforced path maximum datagram size for stream sends, aborts failed HTTP/3 response writes instead of disposing partial responses as FIN, and raised HTTP/3 response QUIC write chunks to 4 KiB. Source-backed repeat run `codex-h3-64kb-c1s1-source-repeat-20260708a` passed 3/3 `http3.payload.bytes.64kb` cells with 4,217/4,217 requests and 0 failures.
- 2026-07-08: exception attribution wrapper now uses the generic source-backed ProtocolLab benchmark path for both HTTP/3 and raw QUIC, emits `incursa.quic.exception-attribution-run.v2` run metadata with commit/source-mode/load-shape fields, and analyzes every emitted `trace.nettrace`. Smoke evidence: `codex-exception-attribution-generic-h3-20260708d` passed `http3.payload.bytes.64kb` with 1 trace, 28,830 events, 0 lost events, and 2,387 first-chance exceptions; `codex-exception-attribution-generic-raw-20260708a` passed `quic.transport.stream-throughput.1mb` with 1 trace, 17,875 events, 0 lost events, and 354 first-chance exceptions.
- 2026-07-08: duplicate FIN completion over already closed send states is now idempotent inside the runtime while post-FIN data writes still throw. Focused requirement test `REQ_QUIC_RFC9000_S2P4_0004` passed, and raw QUIC attribution run `codex-exception-attribution-raw-finish-idempotent-20260708b` passed `quic.transport.stream-throughput.1mb` with 1 trace, 16,546 events, 0 lost events, and 17 first-chance exceptions; the previous `The writable side is already completed.` group disappeared.
- 2026-07-08: inbound stream and DATAGRAM queues now complete without faulting while preserving stored terminal exceptions for public API translation. Focused API/stream tests passed, and H3 attribution run `codex-exception-attribution-h3-nonfaulting-queues-20260708a` passed `http3.payload.bytes.64kb` with 1 trace, 30,742 events, 0 lost events, and a single runtime `OperationCanceledException` group with no Incursa frame; the prior Incursa-attributed terminal accept/read groups disappeared.
- 2026-07-08: the raw ProtocolLab server now uses the internal non-throwing stream accept/read APIs through explicit friend access, preserving public API terminal exceptions for user code while keeping the source-backed performance harness off the public exception path. Focused raw-server build and package-template test passed; raw attribution run `codex-exception-attribution-raw-try-server-20260708a` passed `quic.transport.stream-throughput.1mb` and removed the prior terminal `AcceptInboundStreamSlowAsync` and `ReadCoreAsync` groups from the raw server trace.
- 2026-07-08: outbound ECN marking is now gated on receive-side ECN metadata support, and socket-option failures that prove an ECN option unsupported are cached process-wide. Focused ECN/recovery tests passed, and raw attribution run `codex-exception-attribution-raw-ecn-disabled-20260708a` passed `quic.transport.stream-throughput.1mb` with 1 trace, 14,745 events, 0 lost events, and 1 first-chance exception; the prior `QuicSocketEcnControl.TrySetSocketOption` group disappeared.
- 2026-07-08: performance lane runs now emit `lane-summary.json` with schema `incursa.quic.performance-lane-summary.v1`, preserving lane identity, git state, load shape, selected commands, ProtocolLab run roots, validation/benchmark health, failure categories, metric medians/ranges, relative ranges, and publishability blockers. Dry-run proof `codex-lane-json-dryrun-20260708g` emitted failure category `none` and a UTC `generatedAtUtc` timestamp; source-backed core smoke proof `codex-lane-json-smoke-20260708a` passed HTTP/3 `http3.core.status` and raw QUIC `quic.transport.multiplex.100x64kb`, each with validation passed, benchmark succeeded, observed repetitions 1/1, and failure category `none`.
- 2026-07-08: connection runtime inbox shutdown and internal stream-accept cancellation now use non-throwing completion paths while preserving the public accept cancellation exception contract. Focused tests passed, and H3 attribution improved from `codex-exception-attribution-h3-current-20260708a` at 7,631 first-chance exceptions to `codex-exception-attribution-h3-tryaccept-cancel-20260708a` at 1 first-chance exception for the same source-backed `http3.payload.bytes.64kb` load shape.
- 2026-07-08: HTTP/3 lifecycle diagnostics now have an optional fast path for metrics-only sinks, and the ProtocolLab Incursa HTTP/3 adapter uses it for active request counters. Focused HTTP/3 diagnostics tests passed. Short source-backed profile pack `codex-h3-1kb-lifecycle-fastpath-20260708b` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists `EmitRequestStartedDiagnostic` as an allocation source, while `Http3Server.EmitFrame(...)` remains a separate diagnostic-event allocation target. This was a single local validation sample, not publishable benchmark evidence.
- 2026-07-08: HTTP/3 diagnostics now support kind-aware filtering, and the ProtocolLab Incursa HTTP/3 adapter suppresses frame, QPACK, settings, stream, and response lifecycle diagnostics it does not consume. Focused filter/lifecycle diagnostics tests passed. Short source-backed profile pack `codex-h3-1kb-diagnostic-filter-20260708a` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists `EmitFrame`, lifecycle diagnostic helpers, or `Http3DiagnosticEvent` allocations. The next observed allocation lead is unidirectional stream handling/string construction. This was a single local validation sample, not publishable benchmark evidence.
- 2026-07-08: server-side unidirectional stream type parsing now lets `Http3StreamDispatcher` report consumed stream-type bytes, avoiding the previous server-side stream-type buffer/copy before handing initial payload to control/QPACK stream handling. Focused dispatcher/server tests passed; a first broad server-class run saw close-path timeouts under load, but the affected close-path tests passed when rerun directly. Short source-backed profile pack `codex-h3-1kb-uni-stream-type-20260708a` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists the previous `String.Concat` allocation entry, while the short-run allocation rate stayed effectively flat versus `codex-h3-1kb-diagnostic-filter-20260708a`.
- 2026-07-08: `Http3ServerResponse.CreateFromImmutableBodyAndHeaders` now lets callers with immutable header collections avoid the defensive header copy, and the ProtocolLab Incursa HTTP/3 adapter uses it for per-response benchmark headers. Focused response factory tests and source-backed adapter build passed. Short source-backed profile pack `codex-h3-1kb-response-header-borrow-20260708a` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists the previous `Enumerable.ICollectionToArray` or response-header copy entries, while the short-run allocation rate remained roughly flat.
- 2026-07-08: performance triage script `Compare-QuicProtocolLabRuns.ps1` now compares two retained ProtocolLab aggregate runs by implementation/scenario and emits markdown plus JSON for validation, benchmark status, throughput/request rate, latency, allocation, GC, exceptions, CPU, warnings, repetitions, qlog/counter presence, and evidence quality changes.
- 2026-07-08: `Invoke-QuicPerformanceLane.ps1` now accepts explicit HTTP/3 and raw QUIC connection/stream load-shape overrides so confidence lanes can run high-concurrency small-payload scenarios such as `http3.payload.bytes.1kb` at c32 without editing the script.
- 2026-07-08: confidence run `codex-lane-h3-c32-confidence-20260708a` proved `http3.payload.bytes.1kb` at c32 with 9/9 validation and benchmark success, median 6,759.981 requests/s, p95 5.845 ms, and captured counters for all repetitions. The paired raw QUIC cell failed 3/9 repetitions, so the lane wrapper now supports `-SkipHttp3ProtocolLab` and `-SkipRawQuicProtocolLab` to produce focused confidence evidence without coupling unrelated instability.
- 2026-07-08: exception attribution run `codex-exception-attribution-h3-c32-20260708a` for the same H3 c32 small-payload shape passed validation with 19,148 trace events, zero lost events, and zero first-chance exceptions. Treat the confidence-lane counter exception-rate field as suspect for this shape unless a matching exception trace reproduces it.
- 2026-07-08: raw QUIC attribution run `codex-exception-attribution-raw-multiplex-c1-20260708a` passed validation for `quic.transport.multiplex.100x64kb` with 102,866 trace events, zero lost events, and 21,211 first-chance exceptions. The dominant cancellation group had no Incursa frame; Incursa-attributed groups were 3 AES-GCM authentication tag misses and 2 remote-close socket exceptions. Do not treat this as a proven quic-dotnet hot-path fix until a trace points the cancellation group at an Incursa call path.
- 2026-07-08: exception attribution schema v2 now classifies groups as project-attributed, external-attributed, runtime-only, or runtime-only-cancellation and reports actionable exception counts separately from total first-chance exceptions. Reanalysis of retained H3 64KB trace `codex-exception-attribution-h3-64kb-current-20260708a` found 2,392 first-chance exceptions, all `runtime-only-cancellation`, with zero actionable/project-attributed exceptions. This keeps channel cancellation noise visible without treating it as a quic-dotnet hot-path fix.
- 2026-07-08: schema v2 reanalysis of retained raw QUIC trace `codex-exception-attribution-raw-multiplex-c1-20260708a` found 21,211 first-chance exceptions, but only 5 actionable/project-attributed exceptions: 3 authentication tag misses and 2 remote-close socket exceptions. The remaining 21,206 were runtime-only cancellation. Treat broad exception-count work as mostly closed for this slice; future cleanup should target newly project-attributed groups, not aggregate cancellation totals.
- 2026-07-08: `d18bd3b` in `protocol-lab-internal` caches immutable Incursa HTTP/3 adapter responses for `/plaintext`, `/json`, and fixed `/bytes/{1kb,64kb,1mb}` benchmark paths so the harness no longer rebuilds response objects and headers for every static payload request. Focused source-backed smoke `codex-h3-1kb-static-response-cache-smoke-20260708a` passed validation and benchmark execution for `http3.payload.bytes.1kb` at c16-s10 with 4,138 req/s and p95 86.9 ms; this is validation evidence only, not a publishable performance comparison.
- 2026-07-08: `492eafeb` made immutable `Http3ServerResponse` instances lazily cache their encoded HEADERS frame so static benchmark responses do not re-run QPACK field-section encoding and HTTP/3 HEADERS frame allocation on every request. Focused response factory tests and source-backed profile pack `codex-h3-1kb-response-owned-headers-frame-cache-profile-20260708a` passed. Versus `codex-h3-1kb-static-response-cache-profile-20260708a`, the local single-run sample reduced bytes/request from 10,795.93 B to 10,435.61 B and p95 from 70.40 ms to 59.66 ms, while request rate fell from 4,959.75 to 4,533.13 req/s. Treat this as allocation/latency evidence, not a publishable throughput claim.
- 2026-07-08: immutable small fixed-body responses now cache the complete single DATA frame when the body fits within one response write chunk, avoiding one per-request frame allocation and one response-body write call for 1KB static payloads. Focused response factory tests and source-backed profile pack `codex-h3-1kb-small-data-frame-cache-profile-20260708a` passed. Versus `codex-h3-1kb-response-owned-headers-frame-cache-profile-20260708a`, the local single-run sample reduced bytes/request from 10,435.61 B to 9,374.16 B and allocation rate from 47.31 MB/s to 41.72 MB/s, with request rate down 1.83% and p95 higher. A 3-repetition source-backed repeat `codex-h3-1kb-small-data-frame-cache-repeat-20260708a` passed validation and benchmark execution 3/3, with median 4,433 req/s, median p95 78.19 ms, and median allocation rate 40.76 MB/s; variance blocked publishable claims.
- 2026-07-08: ACK processing now streams ACK ranges directly instead of materializing a per-ACK `HashSet<ulong>` plus `List<ulong>` before acknowledging sent packets. Focused ACK/ACK-codec tests and source-backed profile pack `codex-h3-1kb-ack-streaming-profile-20260708a` passed. Versus `codex-h3-1kb-small-data-frame-cache-profile-20260708a`, the local single-run sample removed the prior `HandleAckFrame` allocation groups from allocation attribution, reduced bytes/request by 22.86%, reduced allocation rate by 16.00%, reduced p95 by 14.81%, and raised request rate by 8.89%. Treat this as local diagnostic evidence, not publishable benchmark evidence.
- 2026-07-08: deadline scheduler stale-entry compaction now clears and rebuilds the existing priority queue instead of allocating a new queue during compaction. Focused CRT deadline scheduler tests and source-backed profile pack `codex-h3-1kb-scheduler-clear-profile-20260708a` passed. Versus `codex-h3-1kb-ack-streaming-profile-20260708a`, the local single-run sample removed the prior `CompactStaleEntriesIfNeeded` priority-queue array allocation group, reduced allocation rate by 17.71%, and reduced bytes/request by 12.78%; request rate and p95 moved the wrong way in the same single sample, so treat this as allocation-only diagnostic evidence.
- 2026-07-08: AES header protection now reuses the packet-protection context's ECB encryptor and fixed scratch buffers instead of calling one-shot `Aes.EncryptEcb` for each packet. Focused packet-protection/RFC 9001 tests and source-backed profile pack `codex-h3-1kb-aes-hp-reuse-profile-20260708a` passed. Versus `codex-h3-1kb-scheduler-clear-profile-20260708a`, the local single-run sample removed the prior `TryGenerateHeaderProtectionMask` `BasicSymmetricCipherLiteBCrypt` and `SafeKeyHandle` allocation groups, reduced bytes/request by 1.28%, and raised request rate by 3.43%; allocation rate rose 2.10% with the higher request rate, so treat this as local diagnostic evidence.
- 2026-07-08: ACK generation now scans `SortedList` receipts by indexed keys/values instead of key/value enumeration for ACK scheduling and ECN selection. Focused ACK/RFC 9000 tests and source-backed profile pack `codex-h3-1kb-ackgen-indexed-profile-20260708a` passed. Versus `codex-h3-1kb-aes-hp-reuse-profile-20260708a`, the local single-run sample reduced bytes/request by 2.20%, reduced p95 by 2.92%, and raised request rate by 2.68%; the GC trace lost managed stack attribution, so treat the missing ACK-generation enumerator group as weaker evidence than the metric movement.
- 2026-07-08: HTTP/3 header validation now returns a readonly value-type `Http3HeaderValidationResult` instead of allocating a tiny reference object for every successful request/response header validation. Focused HTTP/3/RFC 9114/RFC 9220 tests and source-backed profile pack `codex-h3-1kb-header-validation-result-struct-profile-20260708b` passed. Versus `codex-h3-1kb-ackgen-indexed-profile-20260708a`, local triage `codex-h3-1kb-header-validation-result-struct-compare-20260708b` showed request rate +4.25%, p95 -12.79%, allocation rate -4.71%, CPU mean -13.52%, gen0 collections 10 -> 6, and gen1 collections 2 -> 0; the counter exception-rate field and gen2 count moved the wrong way in this single sample, and the CPU TopN report hit an EventPipe read error, so treat this as local diagnostic evidence rather than publishable performance proof.
- 2026-07-08: `Http3FrameReader.Read` now avoids the temporary `List<Http3Frame>` for zero-frame and single-frame reads while preserving the public array return contract. Focused HTTP/3 frame/RFC 9114 tests passed. Short BenchmarkDotNet artifacts `codex-h3-frame-reader-single-array-baseline-20260708a` and `codex-h3-frame-reader-single-array-20260708a` showed single plaintext HEADERS reads dropping from 224 B to 136 B allocated, JSON HEADERS from 216 B to 128 B, fragmented plaintext HEADERS from 408 B to 288 B, and server-like headers-only request reads from 952 B to 864 B. Source-backed ProtocolLab spot check `codex-h3-1kb-frame-reader-single-array-profile-20260708a` passed `http3.payload.bytes.1kb` at c16-s10 with 4,865.25 req/s, p95 66.35 ms, 28,747,391.33 B/s allocation rate, and 0 failed/timeout requests. Treat timing movement as microbenchmark/local diagnostic evidence only.
- 2026-07-08: static `QPackDecoder.DecodeFieldSection(ReadOnlySpan<byte>)` now decodes directly from the caller span instead of copying the encoded field section to a temporary array before decoding. Focused QPACK/HTTP/3 field-section tests passed. Short BenchmarkDotNet artifacts `codex-qpack-static-decode-span-baseline-20260708a` and `codex-qpack-static-decode-span-20260708a` showed common static response decode allocations dropping from 792 B to 696 B and Appendix B.1 static-name-reference decode allocations dropping from 656 B to 568 B. Treat timing movement as microbenchmark evidence only; the server hot path already uses sink-based QPACK decoding.
- 2026-07-08: client response sequence validation now has an internal owned-header path so decoded QPACK response headers can be retained without a second defensive `ToArray()` copy, matching the existing request validator pattern while preserving the public copy-on-receive behavior. Focused HTTP/3 header/client/RFC 9114 tests passed. Short BenchmarkDotNet artifact `codex-response-sequence-owned-headers-20260708a` added direct client response validator coverage and measured the public defensive-copy path at 152 B/op versus 48 B/op for the owned path. Treat timing movement as microbenchmark evidence only.
- 2026-07-08: CRYPTO buffer dequeue now allocates the retained-entry list lazily, so fully consumed contiguous drain paths clear or remove consumed entries without allocating a temporary retained list. Focused CRYPTO buffer/RFC 9000/RFC 9002/CRT tests passed. Short BenchmarkDotNet artifacts `codex-crypto-buffer-lazy-retained-baseline-20260708a` and `codex-crypto-buffer-lazy-retained-20260708a` showed `BufferAndDrainMinimumCryptoStream` allocations dropping from 158.97 KB to 156.91 KB without overlap and from 177.31 KB to 175.24 KB with overlap. Treat timing movement as noisy local microbenchmark evidence only.
- 2026-07-08: CRYPTO buffer insertion now reuses a per-buffer scratch entry list instead of allocating a temporary `List<Entry>` for every frame insert. Focused CRYPTO buffer/RFC 9000/RFC 9002/CRT tests passed. Short BenchmarkDotNet artifacts `codex-crypto-buffer-lazy-retained-20260708a` and `codex-crypto-buffer-insert-scratch-20260708a` showed `BufferAndDrainMinimumCryptoStream` allocations dropping from 156.91 KB to 152.39 KB without overlap and from 175.24 KB to 159.02 KB with overlap. Timing moved in the right direction in this local short run, but treat timing movement as local microbenchmark evidence only.
- 2026-07-08: server-side HTTP/3 unidirectional stream handling now passes the initial payload slice as `ReadOnlyMemory<byte>` instead of copying it to a temporary array before immediate control/QPACK processing. `Incursa.Quic.Http3` Release build passed, the four close-path HTTP/3 tests that timed out in a broad filtered run passed on exact rerun, and source-backed smoke lane `local-quic-perf-20260708171756` passed HTTP/3 `http3.core.status` ProtocolLab validation and benchmark execution. Treat this as a correctness/proof cleanup for a small allocation site, not a publishable performance claim.
- 2026-07-08: H3 profile-pack trace passes now stop before the ProtocolLab target process tears down and propagate trace collection failures into the wrapper exit code instead of silently accepting truncated traces. The previous retained trace `codex-h3-1kb-current-profile-20260708a` failed `dotnet-trace` stop with `ServerNotAvailableException`, produced a conversion `Read past end of stream`, and parsed zero managed methods. Verification run `codex-h3-1kb-gctrace-symbolized-c16-20260708a` completed `dotnet-trace` with exit code 0; allocation analysis `codex-h3-1kb-gctrace-symbolized-c16-allocations-20260708a` parsed 800 managed methods, attributed 155,220,416 sampled bytes to project frames, and produced actionable Incursa/QPACK stack groups. This is tooling-quality evidence, not a runtime performance claim.
- 2026-07-08: pending stream-write retry now rents its sorted snapshot from `ArrayPool` instead of using LINQ `ToArray()` while mutating the pending request dictionary. `Incursa.Quic` Release build passed, focused stream/runtime tests passed 156/156, and source-backed H3 GC-trace analysis removed the prior sampled `TryRetryPendingStreamWriteRequests` `KeyValuePair<long, StreamActionRequestCompletionSource>[]` group seen in `codex-h3-1kb-gctrace-symbolized-c16-allocations-20260708a` from the post-change top 60 in `codex-h3-1kb-pending-write-pool-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: pending stream flow-control credit flush now rents its mutation-safe snapshot from `ArrayPool` instead of using LINQ `ToArray()`. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 255/255, and source-backed H3 GC-trace analysis removed the prior sampled `TryFlushPendingFlowControlCreditUpdates` dictionary enumerator allocation seen in `codex-h3-1kb-pending-write-pool-allocations-20260708a` from the post-change top 60 in `codex-h3-1kb-flow-credit-pool-allocations-20260708a`. The same trace still shows `QuicConnectionSendDatagramEffect` allocation from the flow-control send path, so this closes only the snapshot allocation. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: readable stream buffering now bypasses the scratch merge list when inserting the first segment or appending after the current buffered tail. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 537/537, and source-backed H3 GC-trace analysis reduced the sampled `InsertReadableBytes` `BufferedSegment[]` scratch-capacity group from 57 events in `codex-h3-1kb-flow-credit-pool-allocations-20260708a` to 28 events in `codex-h3-1kb-buffered-direct-paths-allocations-20260708a`. The group still exists for overlapping/interleaved inserts, so this is a partial allocation reduction. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: combined flow-control credit flush no longer uses LINQ `First()` to pick the pending stream-credit frame. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 255/255, and source-backed H3 GC-trace analysis removed the sampled `TryFlushPendingFlowControlCreditUpdates` `Enumerator<ulong, QuicMaxStreamDataFrame>` group seen in `codex-h3-1kb-buffered-direct-paths-allocations-20260708a` from `codex-h3-1kb-flow-credit-no-linq-first-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: pending stream-write retry now uses a local insertion sort over its rented snapshot instead of `Array.Sort(..., IComparer)`. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 255/255, and source-backed H3 GC-trace analysis removed the sampled `TryRetryPendingStreamWriteRequests` `System.Comparison<KeyValuePair<long, StreamActionRequestCompletionSource>>` group seen in `codex-h3-1kb-flow-credit-no-linq-first-allocations-20260708a` from `codex-h3-1kb-pending-retry-insertion-sort-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: sender ACK processing now removes acknowledged packets by indexed `SortedList` scan instead of allocating a temporary acknowledged-packet-number list after enumeration. `Incursa.Quic` Release build passed and focused ACK/congestion tests passed 81/81. Source-backed H3 GC-trace analysis removed the sampled `QuicSenderFlowController.TryProcessAckFrame` `Enumerator<ulong, SentPacketState>` group seen in `codex-h3-1kb-pending-retry-insertion-sort-allocations-20260708a` from `codex-h3-1kb-sender-ack-indexed-removal-allocations-20260708a`. A broader RFC9000/RFC9002 filter still surfaced two existing ECN path-validation test failures unrelated to this ACK path. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.

## 1. Finish Expected Terminal Exception Cleanup

The HTTP/3 terminal-flow cleanup reduced local exception pressure materially, but traces still show terminal `Incursa.Quic.QuicException: The connection terminated` as the dominant remaining first-chance exception source.

Done when:

- A source-backed ProtocolLab `http3.payload.bytes.64kb` trace identifies the remaining throw sites by method.
- Expected connection shutdown no longer uses exceptions for normal HTTP/3 request, stream, accept, write, read, and cleanup paths.
- Public API terminal behavior still throws where the public contract requires it.
- Focused public-vs-internal terminal-flow tests prove both contracts.
- Local ProtocolLab exception counters are consistently near zero for successful short HTTP/3 h2load runs, excluding genuine cancellation/tool shutdown noise.

## 2. Build Permanent Trace-Site Attribution

Current exception attribution relied on temporary trace parsing and prior diagnostic instrumentation. We need a repeatable tool that tells us where exception pressure comes from without patching production code.

Done when:

- A repo script can run a ProtocolLab scenario with EventPipe exception capture.
- The script emits a markdown and JSON summary grouped by exception type, message, and managed stack top frame.
- It works for HTTP/3 and raw QUIC scenarios.
- The output is stored under `.artifacts/perf/` with run ID, git commit, scenario, load shape, and source-root/package mode.
- The script is documented in `scripts/perf/README.md`.

## 3. Add Stable ProtocolLab Performance Lanes

Single local runs are useful diagnostics but not stable enough for real performance claims. We need a repeatable lane that separates smoke, confidence, and publishable evidence.

Done when:

- Smoke lane runs one short local source-backed HTTP/3 and raw QUIC scenario.
- Confidence lane runs at least three repetitions and reports variance.
- Publishable lane runs on isolated lab hardware with explicit CPU, memory, network, and load-generator controls.
- Reports clearly label each result as diagnostic, confidence, or publishable.
- A failing lane distinguishes validation failure, benchmark failure, infrastructure failure, and performance regression.

## 4. Establish Baseline Dashboards For Key Scenarios

We need a small set of benchmark scenarios that represent the real performance story instead of chasing one-off runs.

Done when:

- ProtocolLab tracks current baselines for:
  - `http3.payload.bytes.1kb`
  - `http3.payload.bytes.64kb`
  - `quic.transport.stream-throughput.1mb`
  - high-concurrency HTTP/3 small payload
  - raw QUIC stream fanout
- Each baseline includes requests/sec or throughput, latency percentiles, allocation rate, GC counts, exception rate, and validation status.
- Baselines are compared against the previous accepted run and the best known run.
- Regressions are visible in the public report site or an internal generated report.

## 5. Reduce HTTP/3 Allocation Pressure

The next likely gains are in request/response frame handling, buffer ownership, QPACK field materialization, and per-request object churn.

Done when:

- Allocation traces identify the top HTTP/3 allocation sites for 1KB and 64KB payload scenarios.
- At least the top three avoidable allocation sources have targeted fixes or are explicitly accepted with rationale.
- Benchmarks show lower allocation rate without throughput or correctness regressions.
- Full HTTP/3 tests pass after each allocation-focused change.

## 6. Tighten Stream Lifecycle Cleanup

Stream disposal, final-write completion, read-side completion, and observer notification are still complicated. They are likely hiding both exception pressure and extra work.

Done when:

- Stream disposal has non-throwing internal cleanup paths for expected terminal states.
- Stream observer unregister, capacity release, and read/write completion are idempotent and covered by focused tests.
- ProtocolLab shutdown traces do not show repeated terminal cleanup exceptions.
- Stream lifecycle tests cover normal EOF, reset, connection close, disposal, and cancellation separately.

## 7. Add Raw QUIC Performance Proof

HTTP/3 tells us end-to-end behavior, but raw QUIC scenarios are needed to isolate transport performance from QPACK and HTTP/3 framing.

Done when:

- `quic-dotnet-raw-dev` package/source mode can run raw stream throughput scenarios reliably.
- Raw QUIC scenarios report throughput, allocation, GC, exception count, and validation.
- At least one raw stream-throughput scenario is part of the smoke lane.
- HTTP/3 regressions can be compared against raw QUIC results to locate whether the problem is transport or application framing.

## 8. Compare Against External Implementations Honestly

Performance only matters relative to known-good peers, but comparisons need matching scenarios and honest caveats.

Done when:

- ProtocolLab runs comparable scenarios against at least quic-go and one C/Rust implementation where available.
- Comparison reports only include cells with matching protocol, workload, load tool, resource controls, and validation.
- Unsupported or non-comparable cells are explicitly labeled instead of hidden.
- Public reports show Incursa results beside comparable peers with warnings when evidence is local or non-isolated.

## 9. Build Regression Gates Without Premature Hard Thresholds

We need automated protection from obvious regressions, but local noise makes strict thresholds risky.

Done when:

- Smoke gates fail only on validation failure, infrastructure failure, or extreme metric changes.
- Confidence gates report performance movement but do not block without enough repetitions.
- Publishable gates can enforce thresholds once lab variance is understood.
- Threshold rules are checked into source control and reviewed like code.

## 10. Improve Counter And Trace Artifact Import

ProtocolLab captures useful artifacts, but analysis still requires manual spelunking.

Done when:

- Counter summaries, trace summaries, qlog status, validation proof, and benchmark metrics are imported into a single evidence document.
- Reports include links to raw artifacts.
- Exception type/count and allocation hot spots are first-class report fields.
- The public site can show whether a run is diagnostic, confidence, or publishable.

## 11. Make Source-Backed And Package-Backed Runs Equivalent

Source-backed runs are good for development, but package-backed controller jobs are the long-term boundary.

Done when:

- The same scenario can run source-backed locally and package-backed on the controller with matching implementation identity.
- Package manifests record the exact quic-dotnet commit, package version, build mode, and supported scenario list.
- A package-backed run can reproduce the smoke lane on lab hardware.
- Differences between source-backed and package-backed results are understood and documented.

## 12. Add Public API Stream Transfer Benchmarks

Existing public comparison work is mostly connection establishment. We need public stream transfer workloads that compare real user-facing APIs.

Done when:

- BenchmarkDotNet includes public facade stream upload, download, bidirectional echo, and many-stream workloads.
- Incursa and `System.Net.Quic` are compared only where both can run the same public workload honestly.
- The benchmark does not use internal runtime helpers.
- Results are documented separately from HTTP/3 and raw internal transport benchmarks.

## 13. Profile Scheduler, Timers, And Send Queue Hot Paths

If throughput stalls under concurrency, likely culprits include send queue ordering, timer processing, ACK/loss effects, and packet assembly.

Done when:

- CPU traces identify top runtime hot paths under raw QUIC and HTTP/3 concurrency.
- Send queue and timer hot paths have BenchmarkDotNet microbenchmarks tied to real ProtocolLab scenarios.
- Changes show improvement in both microbenchmarks and at least one end-to-end scenario.
- No protocol scheduling semantics are weakened to gain speed.

## 14. Improve Buffer Pool Diagnostics And Tuning

Buffer reuse is central to reducing allocations, but pool behavior needs better visibility.

Done when:

- Buffer pool diagnostics can be enabled per ProtocolLab run without code changes.
- Reports show rent/return counts, misses, peak outstanding buffers, oversized rents, and retained memory.
- The default pool sizes are justified by scenario evidence.
- Pool tuning improves allocation rate without increasing retained memory unreasonably.

## 15. Keep Requirement Trace And Performance Evidence Connected

Performance changes can accidentally weaken protocol behavior. Every optimization should preserve traceability.

Done when:

- Performance fixes that alter runtime behavior cite the nearest requirement/spec/verification artifact.
- Verification artifacts distinguish correctness evidence from performance evidence.
- Full test, focused requirement-home tests, ProtocolLab validation, and diff hygiene are recorded before commit.
- Known standing SpecTrace validation backlog is separated from new-change validation.

## 16. Build A Small “Performance Triage” Command

We need one command that answers “what got slower, what got noisier, and why should I care?”

Done when:

- A script accepts two ProtocolLab run IDs and compares validation, throughput, latency, allocation, GC, exceptions, CPU, and warnings.
- It emits a concise markdown report with improved/regressed/unchanged sections.
- It highlights evidence quality changes such as missing counters, missing qlogs, or lower repetition count.
- It is used in performance PR closeout.

## Suggested Order

1. Finish terminal exception attribution and cleanup.
2. Add permanent exception/trace-site tooling.
3. Establish stable smoke and confidence ProtocolLab lanes.
4. Attack HTTP/3 allocation hot spots.
5. Add raw QUIC and public API stream-transfer baselines.
6. Move repeatable evidence onto package-backed lab/controller runs.
