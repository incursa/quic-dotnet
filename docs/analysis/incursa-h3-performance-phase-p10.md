# Incursa H3 Performance Phase P10

Date: 2026-05-27

Phase: Incursa H3 Performance Phase P10: allocation attribution refresh after P4-P9

Scope: attribution only. No protocol behavior, benchmark semantics, QUIC scheduling, packetization, UDP send behavior, request validation, or response generation changes were made in this phase.

## P4-P9 Recap

P4-P9 made narrow, benchmark-guarded allocation reductions:

| phase | target | result |
| --- | --- | --- |
| P4 | HTTP/3 response buffering | `ResponseFrames_EncodeAndBufferPlaintext` dropped by about 752 B/op. |
| P5 | response field-section encoding | selected response/header paths dropped by about 120 B/op. |
| P6 | request frame materialization | frame-reader header paths dropped by about 64-72 B/op. |
| P7 | QPACK/request header decode | request decode/materialization microbenchmarks dropped by about 3.5 KB/op. |
| P8 | no-body request writer lifecycle | delayed body writer allocation, but no material microbenchmark reduction. |
| P9 | duplicate validator header copy | server-owned validator path dropped request lifecycle benchmarks by about 120 B/op. |

Those reductions are correct and worth keeping, but the external h2load path still allocates about 40 KB/request. That means the remaining allocation source is not explained by the narrow response/header/request microbenchmarks alone.

## Evidence Reviewed

Existing documents:

- `docs/analysis/incursa-h3-performance-phase-p2.md`
- `docs/analysis/incursa-h3-performance-phase-p3.md`
- `docs/analysis/incursa-h3-performance-phase-p7.md`
- `docs/analysis/incursa-h3-performance-phase-p8.md`
- `docs/analysis/incursa-h3-performance-phase-p9.md`

Existing ProtocolLab refresh:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-h2load-p4-p7-refresh`

The P4-P7 refresh still showed Incursa around 39.5-40.3 KB/request:

| scenario | median req/s | median allocation rate | B/request estimate | Gen0 | Gen1 | Gen2 | note |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| JSON | 2,548.1 | 102,613,656 B/s | 40,271 | 132 | 41 | 4 | unstable local run |
| Plaintext | 3,405.8 | 134,608,696 B/s | 39,523 | 171 | 54 | 5 | unstable local run |

## Tooling

`PerfView` was not available on `PATH`.

Repo-local `dotnet-trace` was available:

```text
9.0.661903+d7b455b46332b31fd9ba3a3f3e020387984c511a
```

Available profiles included:

- `dotnet-sampled-thread-time`
- `gc-verbose`
- `gc-collect`
- `dotnet-common`

`dotnet-counters` was not available from the quic-dotnet local tool manifest. ProtocolLab's run output still resolved counter capture from its own repo-local setup, and the fresh P10 runs captured counters successfully.

## Fresh P10 Runs

Fresh Incursa-only h2load runs used:

- implementation: `incursa-http3`
- protocol: `h3`
- load tool: `h2load`
- load tool mode: `docker`
- connections: 16
- streams per connection: 10
- duration: 10 seconds
- warmup: 2 seconds
- repetitions: 1
- counters: enabled

Commands:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 1 -CaptureCounters -TraceMode gc-allocation -TraceArtifactRoot .artifacts\perf\incursa-h3-p10\plaintext-gc-allocation -RunId local-incursa-h3-p10-plaintext-gc-20260527
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 1 -CaptureCounters -TraceMode gc-allocation -TraceArtifactRoot .artifacts\perf\incursa-h3-p10\json-gc-allocation -RunId local-incursa-h3-p10-json-gc-20260527
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 1 -CaptureCounters -TraceMode cpu -TraceArtifactRoot .artifacts\perf\incursa-h3-p10\plaintext-cpu -RunId local-incursa-h3-p10-plaintext-cpu-20260527
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 1 -CaptureCounters -TraceMode cpu -TraceArtifactRoot .artifacts\perf\incursa-h3-p10\json-cpu -RunId local-incursa-h3-p10-json-cpu-20260527
```

Fresh counter summary:

| run | scenario | req/s | p50 ms | p95 ms | p99 ms | allocation rate | B/request estimate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `local-incursa-h3-p10-plaintext-gc-20260527` | plaintext | 3,100.6 | 35.00 | 45.39 | 52.40 | 126,475,752.57 B/s | 40,791 |
| `local-incursa-h3-p10-json-gc-20260527` | JSON | 3,237.4 | 33.43 | 44.67 | 52.94 | 128,903,561.71 B/s | 39,817 |
| `local-incursa-h3-p10-plaintext-cpu-20260527` | plaintext | 3,092.4 | 22.15 | 28.51 | 32.98 | 125,126,113.71 B/s | 40,462 |
| `local-incursa-h3-p10-json-cpu-20260527` | JSON | 2,878.7 | 34.29 | 42.83 | 51.90 | 119,023,962.86 B/s | 41,346 |

The fresh runs reproduce the post-P9 range: about 39.8-41.3 KB/request.

## Artifact Paths

ProtocolLab runs:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p10-plaintext-gc-20260527`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p10-json-gc-20260527`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p10-plaintext-cpu-20260527`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p10-json-cpu-20260527`

Trace artifacts:

- `.artifacts\perf\incursa-h3-p10\plaintext-gc-allocation`
- `.artifacts\perf\incursa-h3-p10\json-gc-allocation`
- `.artifacts\perf\incursa-h3-p10\plaintext-cpu`
- `.artifacts\perf\incursa-h3-p10\json-cpu`

Allocation analyzer outputs:

- `.artifacts\perf\incursa-h3-p10\plaintext-gc-allocation-analysis\allocation-summary.md`
- `.artifacts\perf\incursa-h3-p10\json-gc-allocation-analysis\allocation-summary.md`

## CPU Trace Summary

CPU topN remains dominated by waits and I/O polling rather than Incursa application methods:

| scenario | top exclusive CPU samples |
| --- | --- |
| plaintext | `LowLevelLifoSemaphore.WaitForSignal` 35.27%, `WaitHandle.WaitOneNoCheck` 18.34%, `PortableThreadPool+IOCompletionPoller.Poll` 14.90%, `GetQueuedCompletionStatus` 14.08% |
| JSON | `LowLevelLifoSemaphore.WaitForSignal` 32.28%, `GetQueuedCompletionStatus` 20.88%, `WaitHandle.WaitOneNoCheck` 17.85%, `PortableThreadPool+IOCompletionPoller.Poll` 14.54% |

Incursa frames appear but are not top CPU consumers:

- `QuicConnectionRuntime.TryHandleApplicationPacketReceived`: about 1.6% inclusive.
- `Socket.SendTo`: about 0.7% inclusive.
- `AesGcm.Encrypt`: about 0.4% inclusive.
- `QuicVariableLengthInteger.TryParse`: about 0.1% exclusive.

This matches P2: CPU topN is not a clean optimization target in this local setup.

## Allocation-by-Type Findings

The artifact-local TraceEvent analyzer observed CLR `GCAllocationTick` events in both fresh `gc-verbose` traces. The exposed payload totals are close to the counter-derived allocation totals for the trace interval, so this is useful directional evidence.

Plaintext:

| type | sampled bytes | approximate share |
| --- | ---: | ---: |
| `System.Byte[]` | 916,778,848 | 47.5% |
| `Incursa.Quic.QuicAckFrame` | 205,697,296 | 10.7% |
| `<ReadAsync>d__54` | 156,076,640 | 8.1% |
| `Incursa.Qpack.QPackFieldLine[]` | 84,014,264 | 4.4% |
| `Entry[System.UInt64][]` | 38,172,528 | 2.0% |
| `ValueTuple<QuicConnectionRuntimeScheduledTimerEntry,QuicConnectionTimerPriority>[]` | 37,822,760 | 2.0% |
| `Enumerator<ulong,QuicRecoverySentPacketState>` | 30,175,864 | 1.6% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 27,935,976 | 1.4% |
| `QuicConnectionEffect[]` | 23,458,992 | 1.2% |
| `Http3Request` | 21,857,544 | 1.1% |

JSON:

| type | sampled bytes | approximate share |
| --- | ---: | ---: |
| `System.Byte[]` | 905,480,120 | 45.9% |
| `Incursa.Quic.QuicAckFrame` | 214,210,096 | 10.9% |
| `<ReadAsync>d__54` | 145,178,808 | 7.4% |
| `Incursa.Qpack.QPackFieldLine[]` | 94,551,168 | 4.8% |
| `ValueTuple<QuicConnectionRuntimeScheduledTimerEntry,QuicConnectionTimerPriority>[]` | 37,806,400 | 1.9% |
| `Entry[System.UInt64][]` | 35,710,840 | 1.8% |
| `Http3Request` | 33,907,544 | 1.7% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 32,624,344 | 1.7% |
| `Enumerator<ulong,QuicRecoverySentPacketState>` | 31,880,416 | 1.6% |
| `QuicConnectionEffect[]` | 21,854,720 | 1.1% |

The dominant remaining allocation category is now broad transport/request lifecycle allocation, especially:

- `byte[]` copies and temporary buffers.
- QUIC ACK frame model allocation.
- stream read async state machine/task allocation.
- QPACK field-line arrays, now smaller but still visible.
- per-request diagnostics events allocated before the diagnostics enabled check.
- effect arrays and runtime timer/recovery collection churn.

## Allocation Call-Stack Findings

`dotnet-trace report topN` over the `gc-verbose` traces produced method-level attribution. It should be treated as sampled GC-profile evidence, not a precise allocation-by-type call-stack report.

Plaintext top GC-profile methods:

| method | inclusive | exclusive |
| --- | ---: | ---: |
| `Http3Server.HandleRequestStreamAsync` | 62.24% | 7.80% |
| `Http3Server.ReadRequestAsync` / state machine | 32.57% | 24.07% |
| `Byte[].ToArray` | 12.19% | 12.19% |
| `Array.Resize` | 9.39% | 9.39% |
| `QuicStream.ReadAsync` | 6.94% | 6.87% |
| `QuicFrameCodec.TryParseAckFrame` | 2.15% | 2.15% |

JSON top GC-profile methods:

| method | inclusive | exclusive |
| --- | ---: | ---: |
| `Http3Server.HandleRequestStreamAsync` / state machine | 66.18% | 0.37% |
| `QuicConnectionRuntime.AcceptInboundStreamAsync` | 56.30% | 5.41% |
| `Http3Server.ReadRequestAsync` / state machine | 45.91% | 26.98% |
| `QuicStream.ReadAsync` | 17.73% | 17.65% |
| `Byte[].ToArray` | 15.14% | 15.14% |
| `Array.Resize` | 3.73% | 3.73% |
| `QuicFrameCodec.TryParseAckFrame` | 2.35% | 2.35% |

The artifact-local analyzer extracted allocation-by-type data, but could not extract allocation call stacks from the `.nettrace`/`.etlx` pair. The attempt failed with:

```text
TraceLog call-stack extraction failed: FileNotFoundException: Could not find trace.nettrace.etl
```

The raw traces and `dotnet-trace report topN` outputs are preserved. If exact allocation call stacks by type are required before code changes, the next tooling step is manual PerfView or Visual Studio allocation analysis against the preserved `trace.nettrace` files, or a dedicated TraceEvent analyzer that correctly opens EventPipe `.nettrace` call-stack data.

## Source Correlation

The measured types line up with several source areas:

- `System.Byte[]`: many hot-path `ToArray()`/`new byte[]` locations remain across HTTP/3 frame parsing, QPACK decode/encode, QUIC datagram receive/send, packet/stream payload construction, diagnostics snapshots, and TLS/crypto material.
- `QuicAckFrame`: `QuicFrameCodec.TryParseAckFrame` currently allocates a `QuicAckFrame` before confirming the frame type and allocates `QuicAckRange[]` based on `ackRangeCount`.
- `<ReadAsync>d__54`: `QuicStream.ReadAsync` is an async override that delegates to `ReadCoreAsync`; the request path calls it repeatedly.
- `QPackFieldLine[]`: QPACK decode still returns owned arrays, but after P7/P9 this is no longer the dominant bucket.
- `Http3DiagnosticEvent`: `Http3Server` constructs diagnostic event records before `Emit` checks `diagnosticsSink?.IsEnabled`.

These are correlations, not optimization proof. P10 did not change any of them.

## Conclusion

Top remaining allocation category after P10: **shared QUIC/H3 transport and stream lifecycle allocation**, dominated by `byte[]` buffers/copies and QUIC ACK frame model allocation, with request-side async/read processing as the main method-level overlap.

Confidence: **medium-high** for the allocation categories by type; **medium** for method-level attribution; **low** for exact per-type call stacks because PerfView/VS allocation-stack analysis was not available in this phase.

More request-header micro-optimization is not justified as the next step. QPACK/header arrays remain visible, but they are far smaller than `byte[]`, `QuicAckFrame`, and stream async allocation in the fresh traces.

## Recommended P11

Select exactly one target: **packet/frame object allocation reduction**.

Recommended P11 prompt:

```text
Continue Incursa H3 Performance Phase P11: benchmark-guarded QUIC ACK frame and packet/frame allocation reduction.

Use the P10 traces as the starting evidence. Focus only on measured packet/frame allocation sources, especially QuicFrameCodec.TryParseAckFrame, QuicAckFrame, QuicAckRange[], and packet/frame byte[] materialization that appears in the h2load path.

Do not change HTTP/3 response generation, request header/QPACK semantics, QUIC scheduling, UDP send behavior, or ProtocolLab benchmark semantics.

Before optimizing:
- add/identify byte-level behavior tests for ACK parsing/formatting, ACK_ECN, invalid ACK frames, ack range bounds, and packet frame parsing behavior;
- add BenchmarkDotNet baselines for ACK parse/write and representative packet frame parse loops;
- run ProtocolLab Incursa-only h3 h2load with counters only if the microbenchmark allocation reduction is meaningful.

Optimize one narrow measured packet/frame allocation source only. Preserve exact RFC behavior and all validation semantics.
```

## Validation

Commands run:

- `dotnet build`
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`
- `git diff --check`
- PowerShell parser check for `scripts\perf\*.ps1`

Results:

- `dotnet build`: passed with 0 warnings and 0 errors.
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 5 trace-link failures and 2 DoQ cancellation exact-type failures.
- `git diff --check`: passed.
- PowerShell parser check: passed.

The test failures match the known pre-existing family:

- `REQ_QUIC_INT_0030.Http3RunnerCellIsTraceLinkedAcrossCanonicalArtifacts`
- `REQ_QUIC_RFC9114_S4_0001.LowLevelMalformedSequenceTestsAreTraceLinked`
- `REQ_QUIC_INT_0029.XquicResidualIsTraceOwnedBeforeRuntimePromotion`
- `REQ_QUIC_INT_0029.XquicResidualDoesNotWeakenTheAdvisoryBoundary`
- `REQ_QUIC_INT_0032.H3SpecPipelineIsTraceLinkedAcrossCanonicalArtifacts`
- `DoqStreamLifecycleTests.QueryCancellationAbortsReadSideAndLeavesConnectionUsable`
- `DoqStreamLifecycleTests.CancellationVolumeLimitClosesConnectionWithExcessiveLoad`

No new failure family was introduced by P10.
