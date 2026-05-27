# Incursa H3 Performance Phase P12

Date: 2026-05-27

Phase: Incursa H3 Performance Phase P12: System.Byte[] packet and stream buffer allocation attribution

Scope: attribution-first byte-array work with one narrow stream receive-buffer optimization. No HTTP/3 semantics, QPACK behavior, ACK/loss recovery semantics, QUIC scheduling, UDP send behavior, ProtocolLab benchmark semantics, or route/sample behavior were intentionally changed.

## P11 Recap

P11 reduced a measured QUIC ACK parse allocation source:

| benchmark | P10/P11 before | P11 after |
| --- | ---: | ---: |
| `ParseAckNoAdditionalRanges` | 200 B | 88 B |
| `ParseAckEcnNoAdditionalRanges` | 200 B | 88 B |
| `ParseAckThenStreamSequence` | 200 B | 88 B |
| `ParseAckMultipleRanges` | 296 B | 208 B |

P11 focused ACK/frame behavior tests passed, and the full test suite introduced no new persistent failure family. ProtocolLab counters were directionally lower but noisy, and no fresh allocation-by-type trace was collected after P11.

## Current End-to-End Baseline

Latest Incursa-only ProtocolLab counter run reviewed:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p11-counters-20260527`

P11 aggregate counter summary:

| scenario | median req/s | median allocation rate | median B/request estimate | Gen0 | Gen1 | Gen2 | note |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| JSON | 2,672.9 | 95,694,385 B/s | 35,536 | 122 | 38 | 4 | req/s varied 26.3% |
| Plaintext | 3,549.2 | 121,995,614 B/s | 34,373 | 155 | 49 | 5 | req/s varied 71.3%; one major outlier |

The P11 counter run is useful directional evidence, but it is too noisy to treat as a precise end-to-end allocation baseline.

## Byte[] Attribution

Exact allocation call stacks remain blocked because PerfView is not available on `PATH`, and the P10 artifact-local TraceEvent stack extraction could not open the generated call-stack data correctly. Repo-local `dotnet-trace` is available, but prior `dotnet-trace report topN` output did not provide precise `System.Byte[]` allocation call stacks.

P10 allocation-by-type remains the strongest allocation evidence:

| type | approximate sampled allocation share |
| --- | ---: |
| `System.Byte[]` | 46-48% |
| `Incursa.Quic.QuicAckFrame` | 10.7-10.9% before P11 |
| `<ReadAsync>d__54` | 7.4-8.1% |
| `Incursa.Qpack.QPackFieldLine[]` | 4.4-4.8% |

Source review identified a bounded, reproducible `byte[]` stream receive-buffer source:

- `QuicConnectionStreamState.TryReceiveStreamFrame` copies `frame.StreamData` into an owned `byte[]`.
- `InsertReadableBytes` then used range slicing, such as `data[dataIndex..(dataIndex + tailLength)]`, when adding readable segments.
- In the common append case where the segment covers the whole just-owned array, that range slice creates a second `byte[]` copy of the same payload.

This is a measured microbenchmark target, but not proven to be the dominant remaining end-to-end `System.Byte[]` source.

## Benchmark Additions

Added `benchmarks/QuicByteBufferAllocationBenchmarks.cs` with memory diagnostics for:

- `StreamReceive_SinglePayloadFrame`
- `StreamReceive_TwoContiguousPayloadFrames`

These benchmarks parse STREAM frames, receive them into `QuicConnectionStreamState`, and read the bytes back out to keep the receive-buffer behavior observable.

P12 before artifacts:

- `.artifacts\perf\incursa-h3-p12\bdn-before`
- `.artifacts\perf\incursa-h3-p12\bdn-before-bytebuffer`

P12 after artifacts:

- `.artifacts\perf\incursa-h3-p12\bdn-after`

## Selected Optimization Target

Selected target: stream receive-buffer segment insertion in `QuicConnectionStreamState.InsertReadableBytes`.

Change:

- added `CreateBufferedSegment`;
- when a buffered segment covers the entire already-owned `byte[]`, keep that array instead of slicing and copying it again;
- when a buffered segment covers only part of the array, continue copying to preserve the existing ownership and first-payload-wins behavior for overlaps/retransmissions.

This avoids one duplicate `byte[]` allocation on the common full-segment append path while keeping the existing safe ownership model.

## Behavior-Preservation Tests

Added `tests/Incursa.Quic.Tests/QuicStreamReceiveBufferTests.cs`:

- single STREAM payload reads back exact bytes;
- contiguous STREAM frames read back in order;
- partial read preserves unread tail bytes and FIN completion;
- conflicting duplicate data preserves the first payload.

These tests cover the selected receive-buffer behavior and the ownership-sensitive retransmission/overlap case.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicStreamReceiveBufferTests"
```

Result: passed, 4/4.

## Benchmark Results

Before command for existing allocation suites:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p12\bdn-before --inProcess
```

Before command for the new byte-buffer benchmark after adding the benchmark but before production changes:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicByteBufferAllocationBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p12\bdn-before-bytebuffer --inProcess
```

After command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicByteBufferAllocationBenchmarks*" "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p12\bdn-after --inProcess
```

Selected byte-buffer before/after:

| benchmark | before mean | after mean | mean delta | before allocated | after allocated | allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `StreamReceive_SinglePayloadFrame` | 403.4 ns | 358.0 ns | -45.4 ns | 1.25 KB | 1.22 KB | about -0.03 KB |
| `StreamReceive_TwoContiguousPayloadFrames` | 665.5 ns | 528.3 ns | -137.2 ns | 1.41 KB | 1.35 KB | about -0.06 KB |

The allocation reduction is real but small because the benchmark payloads are tiny. Larger STREAM payloads would avoid a larger duplicate copy, but ProtocolLab `/plaintext` and `/json` request frames are also small enough that this cannot explain the remaining 33-36 KB/request signal.

Selected unchanged carry-forward checks:

| benchmark | before allocated | after allocated |
| --- | ---: | ---: |
| `ParseAckNoAdditionalRanges` | 88 B | 88 B |
| `ParseAckMultipleRanges` | 208 B | 208 B |
| `FrameReader_ReadPlaintextHeaders` | 224 B | 224 B |
| `RequestHeaders_DecodeValidateMaterialize_Plaintext` | 1,288 B | 1,288 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 648 B | 648 B |

Mean-time changes in the `Short` BDN run are directional only because the operations are sub-microsecond and the error bars are wide. There was no obvious runtime regression in the selected benchmark.

## ProtocolLab Counter Decision

ProtocolLab was not rerun in P12.

Reason: the selected byte-buffer benchmark allocation drop was only about 0.03-0.06 KB/op for tiny STREAM payload shapes, while the latest P11 ProtocolLab counter run was noisy and the remaining end-to-end allocation signal is tens of KB/request. A fresh h2load run would be unlikely to isolate this small change from local run noise.

## Whether System.Byte[] Allocation Moved

In the selected microbenchmark, yes: the stream receive-buffer path now avoids one duplicate `byte[]` copy when the inserted segment covers the whole owned payload array.

End-to-end, not measured in P12. No fresh allocation-by-type trace was collected, so the P10 `System.Byte[]` share remains the best type-level evidence.

## Worth Keeping

Yes, but this is a small cleanup rather than a major P12 win. The change is behavior-preserved, keeps the safe owned-buffer model, and removes a confirmed duplicate byte-array copy. It does not explain the remaining end-to-end allocation signal.

## Remaining Suspected Allocation Sources

Top remaining suspected source: broad `System.Byte[]` packet/stream/request buffers and copies, especially sources not isolated by this tiny receive-buffer benchmark.

High-value remaining candidates:

- `QuicStream.ReadAsync` / `ReadCoreAsync` async lifecycle and repeated read loops;
- packet protection/open/build byte arrays;
- outbound STREAM payload construction and queued-send combine buffers;
- per-packet receive datagram and plaintext payload ownership;
- diagnostics event allocation and qlog/protocol proof artifacts when enabled;
- recovery/timer/effect arrays from the P10 type list.

## Recommended P13

Select exactly one target: **QuicStream.ReadAsync and stream read lifecycle allocation attribution**.

Recommended P13 prompt:

```text
Continue Incursa H3 Performance Phase P13: QuicStream.ReadAsync and stream read lifecycle allocation attribution.

Use P10 allocation-by-type evidence and P12 byte-buffer results as the starting point. Focus on the <ReadAsync>d__54 allocation bucket and QuicStream.ReadAsync / ReadCoreAsync during the Incursa H3 request path.

This phase is attribution-first. Add focused benchmarks and behavior tests for stream reads over already-buffered data, partial reads, end-of-stream, cancellation, abort, and flow-control credit update behavior. Optimize only one measured async/read lifecycle source if it is bounded and semantics-preserving.

Do not change HTTP/3 semantics, QPACK behavior, ACK/loss recovery semantics, QUIC scheduling, UDP send behavior, ProtocolLab benchmark semantics, or request/response sample behavior.
```

## Validation

Commands run:

- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`
- `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p12\bdn-before --inProcess`
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicStreamReceiveBufferTests"`
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`
- `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicByteBufferAllocationBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p12\bdn-before-bytebuffer --inProcess`
- `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicByteBufferAllocationBenchmarks*" "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p12\bdn-after --inProcess`
- `dotnet build`
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`
- `git diff --check`
- PowerShell parser check for `scripts\perf\*.ps1`

Results:

- `dotnet build`: passed with 0 warnings and 0 errors.
- Focused `QuicStreamReceiveBufferTests`: passed, 4/4.
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed with 0 warnings and 0 errors.
- Selected BenchmarkDotNet runs completed and wrote reports under `.artifacts\perf\incursa-h3-p12`.
- `git diff --check`: passed.
- PowerShell parser check: passed.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 7 failures, matching the known persistent baseline: 5 trace-link failures and 2 DoQ cancellation exact-type failures.

No intermittent DoQ timeout appeared in the final full test run. No new persistent failure family was introduced by P12.
