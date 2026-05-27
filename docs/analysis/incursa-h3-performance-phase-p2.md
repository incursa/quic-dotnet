# Incursa H3 Performance Phase P2: dotnet-trace CPU and allocation evidence

Date: 2026-05-27

Scope: measurement only. No protocol, sample, benchmark, or correctness behavior was changed.

## P1 recap

P1 established that ProtocolLab can run Incursa HTTP/3 through the external-reference `h2load` harness and can capture repo-local `dotnet-counters` data against the actual Incursa TechEmpower sample process. The P1 counter runs showed Incursa allocating roughly 90-92 MB/s during both `/plaintext` and `/json` h2load runs, and plaintext/JSON had similar runtime shape. That kept JSON serialization out of the first-suspect position and pointed at shared QUIC/H3 request-response processing.

P1 did not capture CPU or allocation stack traces because `dotnet-trace` was not installed or otherwise resolvable.

## Tooling setup

`dotnet-trace` was provisioned as a repo-local .NET tool:

```powershell
dotnet tool install dotnet-trace --local
dotnet tool run dotnet-trace --version
dotnet tool run dotnet-trace -- list-profiles
```

Resolved version:

```text
9.0.661903+d7b455b46332b31fd9ba3a3f3e020387984c511a
```

Available profiles observed:

```text
dotnet-common
dotnet-sampled-thread-time
gc-verbose
gc-collect
cpu-sampling (collect-linux)
thread-time (collect-linux)
```

`scripts/perf/Collect-IncursaH3Trace.ps1` now resolves `dotnet-trace` in this order:

1. explicit tool path
2. repo-local `dotnet tool run dotnet-trace --`
3. `dotnet-trace` from `PATH`
4. unavailable with a recorded blocker

The trace wrapper now supports `cpu` and `gc-allocation` modes. On this Windows host, CPU mode selected `dotnet-sampled-thread-time`; GC/allocation mode selected `gc-verbose`.

`scripts/perf/Run-ProtocolLabIncursaH3H2Load.ps1` can now start an Incursa-only ProtocolLab run and attach the trace wrapper once ProtocolLab emits the diagnostic target process ID.

## Commands run

Tool and parser checks:

```powershell
dotnet tool install dotnet-trace --local
dotnet tool run dotnet-trace --version
dotnet tool run dotnet-trace -- list-profiles
dotnet tool run dotnet-trace -- report topN --help
pwsh -NoProfile -File scripts\perf\Collect-IncursaH3Trace.ps1 -ProcessId $PID -DurationSeconds 1 -Mode cpu -ArtifactRoot .artifacts\perf\incursa-h3-p2\tool-check\cpu-self-test
```

ProtocolLab h2load trace runs:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 1 -CaptureCounters -TraceMode cpu -TraceArtifactRoot .artifacts\perf\incursa-h3-p2\plaintext-cpu -RunId local-incursa-h3-p2-plaintext-cpu-20260527
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 1 -CaptureCounters -TraceMode cpu -TraceArtifactRoot .artifacts\perf\incursa-h3-p2\json-cpu -RunId local-incursa-h3-p2-json-cpu-20260527
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext -DurationSeconds 5 -WarmupSeconds 1 -Repetitions 1 -CaptureCounters -TraceMode gc-allocation -TraceArtifactRoot .artifacts\perf\incursa-h3-p2\plaintext-gc-allocation -RunId local-incursa-h3-p2-plaintext-gc-20260527
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.json -DurationSeconds 5 -WarmupSeconds 1 -Repetitions 1 -CaptureCounters -TraceMode gc-allocation -TraceArtifactRoot .artifacts\perf\incursa-h3-p2\json-gc-allocation -RunId local-incursa-h3-p2-json-gc-20260527
```

## Artifacts

Trace artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\plaintext-cpu`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\json-cpu`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\plaintext-gc-allocation`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\json-gc-allocation`

Each trace folder contains the raw `.nettrace`, command text, stdout/stderr, selected profile notes, topN reports, and trace summary JSON.

ProtocolLab run artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p2-plaintext-cpu-20260527`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p2-json-cpu-20260527`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p2-plaintext-gc-20260527`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p2-json-gc-20260527`

## ProtocolLab results

These are local shared-host samples for profiling direction only, not publishable benchmark results.

| run | scenario | shape | requests/s | allocation rate mean | GC delta gen0/gen1/gen2 | exception rate mean |
| --- | --- | --- | ---: | ---: | --- | ---: |
| plaintext CPU | `http.core.plaintext` | c16-s10, 10s/2s | 2501.8 | 119,471,268 B/s | 155 / 47 / 4 | 65/s |
| JSON CPU | `http.core.json` | c16-s10, 10s/2s | 2790.2 | 128,355,474 B/s | 166 / 52 / 4 | 10.667/s |
| plaintext GC | `http.core.plaintext` | c16-s10, 5s/1s | 2113.4 | 85,683,355 B/s | 66 / 17 / 2 | 58.667/s |
| JSON GC | `http.core.json` | c16-s10, 5s/1s | 2277.8 | 90,417,814 B/s | 68 / 19 / 3 | 72/s |

The P2 counter shape remains consistent with P1: both scenarios allocate heavily, and JSON does not show a distinct runtime profile that would make JSON serialization the leading bottleneck.

## CPU top-stack summary

CPU traces were captured successfully, but `dotnet-trace report topN` for the sampled-thread-time traces was dominated by idle/wait and runtime polling frames:

- `Interop+Kernel32.GetQueuedCompletionStatus`: 26.62% plaintext, 25.08% JSON exclusive
- `LowLevelLifoSemaphore.WaitForSignal`: 25.35% plaintext, 22.77% JSON exclusive
- `WaitHandle.WaitOneNoCheck`: 18.05% plaintext, 19.66% JSON exclusive
- `PortableThreadPool+IOCompletionPoller.Poll`: 14.94% plaintext, 16.19% JSON exclusive
- `Monitor.Wait`: 5.01% plaintext, 5.42% JSON exclusive

Measured Incursa frames did appear, but not as dominant CPU-exclusive stacks in the CPU reports:

- `QuicConnectionRuntime.TryHandleApplicationPacketReceived`: 1.56% plaintext inclusive, 1.73% JSON inclusive, about 0.10-0.11% exclusive
- `QuicVariableLengthInteger.TryParse`: 0.11% plaintext exclusive
- `Socket.SendTo`: 0.68% plaintext exclusive, 0.59% JSON exclusive
- `AesGcm.Encrypt`: 0.35% plaintext exclusive, 0.42% JSON exclusive

Interpretation: the CPU topN report did not isolate a dominant Incursa CPU method. The report is still useful because it confirms the server process was traced, but this first CPU collection is not enough to name a CPU-bound protocol method.

## GC/allocation trace summary

GC/allocation traces were captured with `gc-verbose`. The raw `.nettrace` files are preserved. `dotnet-trace report topN` can produce method topN from these traces, but it does not provide a complete object-allocation attribution table. Treat these results as strong directional evidence for hot methods under the GC profile, not as a full allocation flame graph.

Plaintext `gc-verbose` topN:

- `Array.Resize`: 43.2% exclusive
- `Http3Server.<ReadRequestAsync>d__35.MoveNext`: 22.91% inclusive, 19.13% exclusive
- `Encoding.GetBytes`: 10.97% exclusive
- `QuicStream.ReadAsync`: 2.90% inclusive, 2.89% exclusive
- `Http3Server.WriteBufferedResponseFramesAsync`: 2.36% inclusive, 2.12% exclusive
- `QuicFrameCodec.TryParseAckFrame`: 1.94% exclusive
- `Byte[].ToArray`: 1.23% exclusive
- `Http3Server.<HandleRequestStreamAsync>d__34.MoveNext`: 70.0% inclusive
- `Http3Server.<WriteResponseAsync>d__43.MoveNext`: 46.3% inclusive

JSON `gc-verbose` topN:

- `Http3Server.<ReadRequestAsync>d__35.MoveNext`: 47.04% inclusive, 42.58% exclusive
- `Array.Resize`: 19.35% exclusive
- `StringBuilder.ToString`: 10.34% exclusive
- `Byte[].ToArray`: 5.88% exclusive
- `QuicStream.ReadAsync`: 3.12% inclusive, 3.10% exclusive
- `Http3Server.WriteBufferedResponseFramesAsync`: 2.11% inclusive, 2.02% exclusive
- `QuicFrameCodec.TryParseAckFrame`: 1.90% exclusive
- `Http3Server.<HandleRequestStreamAsync>d__34.MoveNext`: 68.72% inclusive
- `QuicConnectionRuntime.<WriteStreamAsync>d__258.MoveNext`: 35.49% inclusive

The JSON-only `StringBuilder.ToString` entry is expected sample/application JSON path work, but the larger overlap remains shared H3 request/response processing.

## Source overlap

### Measured hot path

- `src/Incursa.Quic.Http3/Http3Server.cs`
  - `HandleRequestStreamAsync`
  - `ReadRequestAsync`
  - `WriteResponseAsync`
  - `WriteBufferedResponseFramesAsync`

These methods appeared directly in the `gc-verbose` topN reports for both plaintext and JSON.

### Likely allocation source

- `Http3Server.ReadRequestAsync`: creates `Http3FrameReader`, `Http3RequestMessageValidator`, `ArrayBufferWriter<byte>`, and a request read buffer per request stream.
- `Http3Server.WriteBufferedResponseFramesAsync`: creates an `ArrayBufferWriter<byte>`, appends HEADERS and DATA frames, then calls `writer.WrittenSpan.ToArray()` before the final stream write.
- `Http3Server.BuildResponseHeaders` and `EncodeResponseFieldSection`: materialize response header lists and encoded field sections per response; `EncodeResponseFieldSection` returns `writer.WrittenSpan.ToArray()`.
- `Http3FrameReader.Read`: appends into a new pending byte array, copies every complete frame payload with `ToArray()`, stores parsed frames in a `List<Http3Frame>`, and returns a new frame array.
- `QuicConnectionRuntime.TryBuildOutboundStreamPayload`: allocates a padded byte array for each outbound STREAM payload.
- `QuicConnectionRuntime.FlushPendingApplicationSends`: sorts queued writes through `pendingRequests.ToArray()`, builds a combined payload array, and builds distinct stream ID arrays for each queued flush.
- `QuicApplicationSendQueue.GetSortedQueuedWrites`: copies queued writes into an array before sorting.

### Possible contributor

- `QPackEncoder`/`QPackDecoder`: prior static review found `ToArray()` and encoding/decoding allocations, and response header encoding flows through QPACK-like field section encoding. The P2 topN reports did not directly surface `QPackEncoder` or `QPackDecoder` as named dominant frames.
- `QuicListenerHost.SendDatagram` and UDP send path: `Socket.SendTo` appeared in CPU topN, but not enough to identify UDP send batching as the leading issue from P2 alone.
- `QuicConnectionRuntimeEndpoint` / `QuicConnectionRuntimeShard`: route lookup and channel handoff remain plausible, but were not observed as top named stacks in the P2 reports.

### Not observed in this trace

- `QPackDecoder` was not a top named method.
- `Http3FrameReader` was not a top named method, though its allocation pattern remains relevant because `ReadRequestAsync` was measured and `Http3FrameReader.Read` performs per-frame array/list materialization.
- `QuicListenerHost.ReceiveLoopAsync`, `QuicConnectionRuntimeEndpoint`, and `QuicConnectionRuntimeShard` were not top named methods in `dotnet-trace report topN`.

## Current bottleneck hypothesis

Top suspected category after P2:

> Allocation-heavy shared HTTP/3 request/response processing, with measured concentration in `Http3Server.ReadRequestAsync` and `Http3Server.WriteBufferedResponseFramesAsync`, plus likely supporting allocations in frame materialization, response header/field-section generation, STREAM payload construction, and queued stream-send batching.

Confidence: medium-high for allocation-heavy shared H3 processing as the next target; medium for the exact allocation source ranking because `dotnet-trace report topN` did not provide an object-allocation table.

## What remains inconclusive

- CPU bottleneck: the sampled CPU topN traces were dominated by runtime wait/poller frames and did not isolate a single CPU-heavy Incursa method.
- Allocation attribution: raw `gc-verbose` traces were captured, but the built-in `dotnet-trace report topN` output does not replace PerfView or Visual Studio allocation-stack analysis.
- UDP batching: `Socket.SendTo` appeared, but P2 does not prove one-send-per-small-frame as the primary bottleneck.
- QUIC send queue vs H3 frame generation: both remain plausible, but P2 moves the first follow-up toward the measured H3 request/response methods.

## Recommended P3

Phase P3 should be measurement-first and should not optimize yet.

Recommended focus:

1. Open the P2 `gc-verbose` traces in PerfView or Visual Studio and produce allocation-by-type and allocation-call-stack reports.
2. Add a small, opt-in diagnostic counter set around `Http3Server.ReadRequestAsync`, `WriteResponseAsync`, `WriteBufferedResponseFramesAsync`, `Http3FrameReader.Read`, and `QuicConnectionRuntime.TryBuildOutboundStreamPayload` if PerfView/VS cannot resolve enough source-level attribution.
3. Build a narrow BenchmarkDotNet suite for:
   - `Http3FrameReader.Read` HEADERS/DATA parsing
   - response header field-section generation
   - `WriteBufferedResponseFramesAsync` frame materialization shape
   - `TryBuildOutboundStreamPayload`
   - queued-send flush batching
4. Only after allocation stacks are ranked, choose one optimization target and preserve protocol correctness tests before editing runtime behavior.

Suggested next prompt:

```text
You are working in C:\src\incursa\quic-dotnet.

Continue Incursa H3 Performance Phase P3: allocation attribution and microbench baselines.

Use the P2 artifacts under .artifacts/perf/incursa-h3-p2 and docs/analysis/incursa-h3-performance-phase-p2.md.

This is still measurement-first. Do not optimize protocol behavior yet.

Goals:
1. Analyze the P2 gc-verbose traces with PerfView or Visual Studio tooling if available and produce allocation-by-type and allocation-call-stack summaries.
2. If external allocation analysis is blocked, add only opt-in diagnostic counters needed to count H3 frame materializations, response buffer materializations, STREAM payload allocations, and queued send flushes.
3. Add a small BenchmarkDotNet project or benchmark plan for Http3FrameReader.Read, response field-section encoding, WriteBufferedResponseFramesAsync frame materialization, TryBuildOutboundStreamPayload, and FlushPendingApplicationSends.
4. Update docs/analysis/incursa-h3-performance-phase-p3.md with measured allocation rankings, benchmark baselines or blockers, and one recommended optimization target.
5. Run dotnet build, dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj, git diff --check, and script parser checks.
```
