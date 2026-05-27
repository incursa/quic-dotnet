# Incursa H3 Performance Phase P3: allocation attribution and microbenchmark baselines

Date: 2026-05-27

Scope: measurement and baseline creation only. No protocol behavior, sample behavior, benchmark semantics, or correctness checks were changed.

## Evidence reviewed

- `docs/analysis/incursa-h3-performance-phase-p2.md`
- `docs/analysis/incursa-h3-performance-phase-p1.md`
- `docs/analysis/incursa-h3-performance-diagnostic-review.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\plaintext-cpu`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\json-cpu`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\plaintext-gc-allocation`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p2\json-gc-allocation`

P2 established:

- ProtocolLab h2load H3 runs and runtime counters work against the actual Incursa TechEmpower server process.
- `dotnet-trace` is available as a repo-local tool.
- CPU topN traces are dominated by wait and I/O-poller frames, not by a single Incursa CPU method.
- GC-profile method topN points into shared HTTP/3 request/response processing.
- Plaintext and JSON remain similar enough that JSON serialization is not the first bottleneck.

## P2 trace summary

CPU topN dominant frames:

| frame | plaintext exclusive | JSON exclusive |
| --- | ---: | ---: |
| `Interop+Kernel32.GetQueuedCompletionStatus` | 26.62% | 25.08% |
| `LowLevelLifoSemaphore.WaitForSignal` | 25.35% | 22.77% |
| `WaitHandle.WaitOneNoCheck` | 18.05% | 19.66% |
| `PortableThreadPool+IOCompletionPoller.Poll` | 14.94% | 16.19% |
| `Monitor.Wait` | 5.01% | 5.42% |

Incursa CPU frames were present but not dominant:

- `QuicConnectionRuntime.TryHandleApplicationPacketReceived`: 1.56% plaintext inclusive, 1.73% JSON inclusive.
- `QuicVariableLengthInteger.TryParse`: 0.11% plaintext exclusive.
- `Socket.SendTo`: 0.68% plaintext exclusive, 0.59% JSON exclusive.
- `AesGcm.Encrypt`: 0.35% plaintext exclusive, 0.42% JSON exclusive.

GC-profile method topN indicators:

| frame | plaintext | JSON |
| --- | ---: | ---: |
| `Http3Server.<ReadRequestAsync>d__35.MoveNext` | 22.91% inclusive / 19.13% exclusive | 47.04% inclusive / 42.58% exclusive |
| `Array.Resize` | 43.2% exclusive | 19.35% exclusive |
| `Byte[].ToArray` | 1.23% exclusive | 5.88% exclusive |
| `Http3Server.WriteBufferedResponseFramesAsync` | 2.36% inclusive / 2.12% exclusive | 2.11% inclusive / 2.02% exclusive |
| `QuicStream.ReadAsync` | 2.90% inclusive | 3.12% inclusive |
| `QuicFrameCodec.TryParseAckFrame` | 1.94% exclusive | 1.90% exclusive |

Trace limitation: `dotnet-trace report topN` provides method time from the trace, not allocation-by-type or allocation-by-call-stack attribution.

## Allocation-by-type attempt

CLI tooling attempted:

```powershell
where.exe PerfView
dotnet tool run dotnet-trace -- report --help
dotnet run --project .artifacts\perf\incursa-h3-p3\trace-analyzer -- .artifacts\perf\incursa-h3-p2\plaintext-gc-allocation\trace.nettrace .artifacts\perf\incursa-h3-p3\plaintext-gc-allocation-analysis
dotnet run --project .artifacts\perf\incursa-h3-p3\trace-analyzer -- .artifacts\perf\incursa-h3-p2\json-gc-allocation\trace.nettrace .artifacts\perf\incursa-h3-p3\json-gc-allocation-analysis
```

Results:

- PerfView was not found on `PATH`.
- The installed `dotnet-trace report` command only exposes `topN`.
- An artifact-only TraceEvent analyzer could open the `.nettrace` files, but observed zero events with allocation payloads in the saved `gc-verbose` traces.
- The first package-add attempt for the artifact analyzer hit the private Incursa NuGet source with HTTP 403; retrying with the public NuGet source succeeded for the artifact-local project.

Artifact outputs:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p3\plaintext-gc-allocation-analysis\allocation-summary.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p3\json-gc-allocation-analysis\allocation-summary.md`

Current allocation-by-type result: blocked. The existing P2 `gc-verbose` traces did not expose allocation tick/sample events through this CLI path.

Current allocation-call-stack result: blocked. A PerfView or Visual Studio allocation-stack pass is still needed, or P4 should collect a new allocation trace with explicit allocation sampling keywords if the current `gc-verbose` profile is insufficient.

## BenchmarkDotNet baselines added

Added benchmark suite:

- `benchmarks/Http3AllocationPathBenchmarks.cs`

Project references added:

- `src/Incursa.Quic.Http3`
- `src/Incursa.Qpack`

The suite uses `[MemoryDiagnoser]` and covers:

- `Http3FrameReader.Read` for single-frame and fragmented HEADERS shapes.
- Public QPACK field-section encoding as the closest non-invasive equivalent to `Http3Server.EncodeResponseFieldSection`.
- Response HEADERS/DATA frame buffering as the closest non-invasive equivalent to `Http3Server.WriteBufferedResponseFramesAsync`.
- QUIC STREAM payload construction using existing `Incursa.Quic.Benchmarks` access to `Incursa.Quic` internals.
- Queued application-send combine and stream-ID materialization shape using `QuicApplicationSendQueue`.

Private `Http3Server` methods were not exposed or rewritten. `Http3FrameReader.Append`, `Http3FrameReader.SlicePending`, `Http3Server.BuildResponseHeaders`, `Http3Server.EncodeResponseFieldSection`, and `Http3Server.WriteBufferedResponseFramesAsync` remain private, so the benchmark uses public or already-internal-accessible equivalents and documents that limitation.

## Benchmark commands

Initial root-launched BDN runs were blocked because BenchmarkDotNet found duplicate staged `Incursa.Quic.Benchmarks.csproj` files under `.artifacts\network-simulator-*`. Re-running from the `benchmarks` directory with `--inProcess` avoided generated-project discovery and produced usable local baselines.

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project Incursa.Quic.Benchmarks.csproj -- `
  --job Dry `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p3\bdn-dry-inprocess `
  --inProcess

dotnet run -c Release --project Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p3\bdn-short-inprocess `
  --inProcess
```

Benchmark report:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p3\bdn-short-inprocess\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

## Benchmark results

BenchmarkDotNet v0.15.8, ShortRun, in-process toolchain, .NET 10.0.8, memory diagnoser.

| benchmark | mean | Gen0 | allocated |
| --- | ---: | ---: | ---: |
| `FrameReader_ReadPlaintextHeaders` | 97.15 ns | 0.0353 | 296 B |
| `FrameReader_ReadJsonHeaders` | 87.37 ns | 0.0334 | 280 B |
| `FrameReader_ReadFragmentedPlaintextHeaders` | 135.26 ns | 0.0477 | 400 B |
| `ResponseHeaders_EncodePlaintextFieldSection` | 787.85 ns | 0.0648 | 544 B |
| `ResponseHeaders_EncodeJsonFieldSection` | 927.75 ns | 0.0648 | 544 B |
| `ResponseFrames_BufferPlaintext` | 107.92 ns | 0.0696 | 584 B |
| `ResponseFrames_BufferJson` | 110.43 ns | 0.0745 | 624 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 1,198.60 ns | 0.1812 | 1,520 B |
| `QuicStreamPayload_BuildPlaintextResponsePayload` | 35.49 ns | 0.0153 | 128 B |
| `QuicStreamPayload_BuildJsonResponsePayload` | 42.50 ns | 0.0162 | 136 B |
| `QuicStreamPayload_CombineTwoQueuedPayloads` | 243.40 ns | 0.0763 | 640 B |

These isolated numbers do not sum to the observed 34-36 KB/request estimate from the external h2load path. That means either:

- the largest per-request allocations are still outside these isolated helpers,
- the request path loops through additional stream/runtime/TLS/channel objects not covered here,
- the ProtocolLab counter estimate includes per-packet, per-connection, diagnostics, exceptions, or runtime allocations outside the benchmarked helper paths,
- or allocation sampling needs stronger call-stack attribution before the top source can be named.

## Source review findings

### Measured

- `Http3Server.ReadRequestAsync`: measured in P2 GC-profile method topN for both plaintext and JSON.
- `Http3Server.HandleRequestStreamAsync`: measured as a high inclusive frame in both P2 GC-profile traces.
- `Http3Server.WriteResponseAsync`: measured as high inclusive in the plaintext GC-profile trace.
- `Http3Server.WriteBufferedResponseFramesAsync`: measured in P2 GC-profile topN and reproduced by the isolated response-buffering benchmark shape.
- `Http3FrameReader.Read`: not directly named in P2 topN, but isolated benchmark confirms allocation per request HEADERS parse, with higher allocation for fragmented input.
- `QPackEncoder.EncodeFieldSection`: isolated benchmark shows 544 B/op for the public static response header encoding equivalent.
- `QuicApplicationSendQueue` queued-send combine shape: isolated benchmark shows 640 B/op when two queued payloads are selected, copied, and stream IDs are materialized.

### Likely

- `Http3Server.ReadRequestAsync` allocates `Http3FrameReader`, `Http3RequestMessageValidator`, `ArrayBufferWriter<byte>`, and a request read buffer per request stream.
- `Http3FrameReader.Read` appends into a new byte array, copies frame payloads with `ToArray`, stores frame objects in a `List<Http3Frame>`, and returns a frame array.
- `Http3Server.BuildResponseHeaders` and `EncodeResponseFieldSection` materialize response header arrays and encoded bytes per response.
- `Http3Server.WriteBufferedResponseFramesAsync` builds an aggregate response buffer, calls `Http3FrameWriter.WriteData` for body chunks, then calls `writer.WrittenSpan.ToArray()`.
- `Http3FrameWriter.WriteFrame` returns `writer.WrittenSpan.ToArray()` for every standalone frame.

### Possible

- `QuicConnectionRuntime.TryBuildOutboundStreamPayload` allocates one padded stream payload per write. The isolated helper shape is small for these tiny responses, but the full runtime path still adds protection, recovery, effect, and send work.
- `QuicConnectionRuntime.FlushPendingApplicationSends` allocates sorted queued write arrays, combined payload arrays, and distinct stream ID arrays when delayed sends are flushed.
- `QPackDecoder` and request header validation may allocate decoded field lines and strings, but P3 still lacks allocation-by-type/call-stack evidence.
- Exception activity remains suspicious from P1/P2 counters and could account for hidden allocations if expected cancellation/connection-abort paths throw during the h2load loop.

### Low confidence

- UDP send batching is not proven as the dominant allocation source. P2 CPU topN saw `Socket.SendTo`, but P3 did not add packet/send counters.
- Endpoint routing and shard channel handoff remain plausible shared-path overhead, but neither P2 nor P3 isolated their allocation cost.

## Current conclusion

P3 did not obtain full allocation-by-type or allocation-call-stack attribution from the existing traces. The strongest measured evidence remains:

1. P2 runtime counters show roughly 90-128 MB/s allocation during Incursa-only h2load runs.
2. P2 GC-profile topN names `Http3Server.ReadRequestAsync`, `HandleRequestStreamAsync`, `WriteResponseAsync`, and `WriteBufferedResponseFramesAsync`.
3. P3 microbenchmarks reproduce measurable allocations in frame reader, response field-section encoding, response frame buffering, STREAM payload creation, and queued-send combine shapes.

Top measured isolated allocation source in P3:

- `ResponseFrames_EncodeAndBufferPlaintext`: 1,520 B/op.

Top optimization candidate after P3:

- `Http3Server` response generation and buffering, specifically the chain of response header field-section encoding, HEADERS frame creation, DATA frame creation, aggregate response buffer creation, and final `ToArray`.

Reasoning:

- It is directly in the P2 measured method stack.
- It has the highest isolated P3 allocation/op among the new benchmarks.
- It is shared by plaintext and JSON.
- It is narrower than changing QUIC packetization, scheduler, channel, or UDP send behavior.
- It can be optimized later without changing benchmark semantics if the next phase preserves exact header/body/frame behavior.

Confidence:

- Medium-high that shared H3 request/response allocation remains the right bottleneck category.
- Medium that response generation/buffering is the right first optimization slice.
- Low that P3 has identified the total dominant allocation source, because allocation-by-type/call-stack attribution is still blocked.

## Recommended P4

P4 should be the first optimization phase only if it remains narrow and benchmark-guarded.

Recommended P4 prompt:

```text
You are working in C:\src\incursa\quic-dotnet.

Continue Incursa H3 Performance Phase P4: benchmark-guarded response-buffer allocation reduction.

Use:
- docs/analysis/incursa-h3-performance-phase-p3.md
- benchmarks/Http3AllocationPathBenchmarks.cs
- .artifacts/perf/incursa-h3-p3/bdn-short-inprocess/results/Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md

This phase may optimize only the narrow HTTP/3 response generation/buffering path if correctness and benchmark semantics are preserved.

Do not change ProtocolLab benchmark semantics.
Do not hardcode benchmark responses.
Do not loosen protocol correctness.
Do not change request parsing, QPACK decode, QUIC packetization, scheduling, or UDP send behavior in this phase.

Before editing, run the existing Http3AllocationPathBenchmarks Short baseline and record the result.

Target only:
- Http3Server.WriteResponseAsync
- Http3Server.WriteBufferedResponseFramesAsync
- Http3Server.EncodeResponseFieldSection / BuildResponseHeaders if needed
- Http3FrameWriter.WriteFrame only if the change is behavior-preserving and covered by existing tests.

Goal:
Reduce allocated bytes/op in ResponseFrames_EncodeAndBufferPlaintext and related response frame benchmarks while preserving HTTP/3 frame bytes and existing tests.

Validation:
- dotnet build
- dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
- dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
- dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --inProcess
- git diff --check
- PowerShell parser check for scripts/perf/*.ps1

Update docs/analysis/incursa-h3-performance-phase-p4.md with before/after benchmark numbers, exact behavior-preservation evidence, and whether ProtocolLab should be rerun.
```
