# Incursa H3 Performance Phase P11

Date: 2026-05-27

Phase: Incursa H3 Performance Phase P11: QUIC ACK/frame allocation attribution and reduction

Scope: narrow ACK/frame allocation reduction. No HTTP/3 semantics, QPACK behavior, ProtocolLab benchmark semantics, QUIC scheduling, QUIC packetization, UDP send behavior, ACK validation semantics, or loss-recovery behavior were intentionally changed.

## P10 Recap

P10 refreshed allocation attribution after P4-P9 and found that Incursa H3 still allocated about 39.8-41.3 KB/request under Incursa-only ProtocolLab h2load runs.

P10 allocation-by-type evidence pointed at:

| type | approximate sampled allocation share |
| --- | ---: |
| `System.Byte[]` | 46-48% |
| `Incursa.Quic.QuicAckFrame` | 10.7-10.9% |
| `<ReadAsync>d__54` | 7.4-8.1% |
| `Incursa.Qpack.QPackFieldLine[]` | 4.4-4.8% |

The next target was shared QUIC/H3 frame allocation rather than another request-header micro-optimization.

## ACK/Frame Benchmark Additions

Added `benchmarks/QuicFrameAllocationBenchmarks.cs` with memory diagnostics for:

- `ParseAckNoAdditionalRanges`
- `ParseAckMultipleRanges`
- `ParseAckEcnNoAdditionalRanges`
- `ParseAckThenStreamSequence`
- `FormatAckNoAdditionalRanges`
- `FormatAckMultipleRanges`

The benchmark shapes cover common ACK frames, ACK_ECN, multiple ACK ranges, and a representative ACK + STREAM parse sequence.

Artifacts:

- `.artifacts\perf\incursa-h3-p11\bdn-before`
- `.artifacts\perf\incursa-h3-p11\bdn-after`

## Selected Optimization Target

Selected target: `QuicFrameCodec.TryParseAckFrame`.

Before P11, `TryParseAckFrame` allocated:

- a placeholder `QuicAckFrame` at method entry, even before the frame type was confirmed;
- a final `QuicAckFrame` for the parsed ACK;
- a fresh zero-length `QuicAckRange[]` for the common no-additional-ranges case.

P11 reduced only that materialization overhead:

- removed the placeholder `QuicAckFrame` allocation by assigning the `out` frame only on successful parse;
- used the shared empty array for `ackRangeCount == 0`;
- kept the final owned `QuicAckFrame` and owned range array when ranges are present.

This preserves the existing parsed ACK model and does not change ACK range validation, ACK_ECN handling, consumed-byte accounting, or formatting behavior.

## Behavior-Preservation Tests

Added focused ACK/frame tests in `tests/Incursa.Quic.Tests/QuicAckFrameCodecUnitTests.cs`:

- common ACK with no additional ranges preserves fields and exact formatted bytes;
- ACK with multiple ranges preserves range ordering and exact formatted bytes;
- ACK_ECN with no additional ranges preserves ECN counts and exact formatted bytes;
- ACK + STREAM sequence preserves parse ordering and STREAM payload bytes;
- unsupported frame type still fails without consuming bytes.

Existing ACK tests continue to cover:

- round-trip parse/format with ranges and optional ECN counts;
- truncated input rejection;
- invalid first ACK range rejection;
- impossible additional ACK range layout rejection.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAckFrameCodecUnitTests"
```

Result: passed, 11/11 tests.

## Benchmark Results

Command shape:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p11\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p11\bdn-after --inProcess
```

The first attempted BDN invocation used duplicate `--filter` switches and failed argument parsing. The rerun above used one `--filter` option with both patterns and completed.

ACK/frame before/after:

| benchmark | before mean | after mean | mean delta | before allocated | after allocated | allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `ParseAckNoAdditionalRanges` | 65.10 ns | 52.72 ns | -12.38 ns | 200 B | 88 B | -112 B |
| `ParseAckMultipleRanges` | 132.09 ns | 117.13 ns | -14.96 ns | 296 B | 208 B | -88 B |
| `ParseAckEcnNoAdditionalRanges` | 88.57 ns | 77.06 ns | -11.51 ns | 200 B | 88 B | -112 B |
| `ParseAckThenStreamSequence` | 96.84 ns | 84.49 ns | -12.35 ns | 200 B | 88 B | -112 B |
| `FormatAckNoAdditionalRanges` | 20.82 ns | 22.98 ns | +2.16 ns | 0 B | 0 B | 0 B |
| `FormatAckMultipleRanges` | 58.74 ns | 57.44 ns | -1.30 ns | 0 B | 0 B | 0 B |

The selected ACK parse path improved by 88-112 B/op with no material runtime regression in the ACK parse benchmarks. ACK formatting allocation stayed at 0 B/op.

Selected HTTP/3 allocation-path benchmarks were unchanged, as expected:

| benchmark | before allocated | after allocated |
| --- | ---: | ---: |
| `FrameReader_ReadPlaintextHeaders` | 224 B | 224 B |
| `FrameReader_ReadJsonHeaders` | 216 B | 216 B |
| `RequestHeaders_DecodePlaintextFieldSection` | 1,080 B | 1,080 B |
| `RequestHeaders_DecodeJsonFieldSection` | 1,064 B | 1,064 B |
| `RequestHeaders_DecodeValidateMaterialize_Plaintext` | 1,288 B | 1,288 B |
| `RequestHeaders_DecodeValidateMaterialize_Json` | 1,272 B | 1,272 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 648 B | 648 B |

## ProtocolLab Counter Refresh

Because the ACK/frame microbenchmark allocation drop was meaningful, ProtocolLab was rerun with counters enabled.

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext,http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -CaptureCounters -RunId local-incursa-h3-p11-counters-20260527
```

Artifact path:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p11-counters-20260527`

Aggregate median summary:

| scenario | median req/s | median p50 | median p95 | median p99 | median allocation rate | median B/request estimate | Gen0 | Gen1 | Gen2 | note |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| JSON | 2,672.9 | 25.84 ms | 36.57 ms | 44.30 ms | 95,694,385 B/s | 35,536 | 122 | 38 | 4 | req/s varied 26.3% |
| Plaintext | 3,549.2 | 24.66 ms | 34.30 ms | 42.26 ms | 121,995,614 B/s | 34,373 | 155 | 49 | 5 | req/s varied 71.3% |

Per-repetition B/request estimates:

| scenario | rep | req/s | allocation rate | B/request estimate |
| --- | ---: | ---: | ---: | ---: |
| JSON | 1 | 2,672.9 | 94,983,379 B/s | 35,536 |
| JSON | 2 | 2,662.5 | 95,694,385 B/s | 35,942 |
| JSON | 3 | 3,364.7 | 117,050,705 B/s | 34,788 |
| Plaintext | 1 | 1,166.2 | 114,774,634 B/s | 98,418 |
| Plaintext | 2 | 3,697.2 | 123,518,809 B/s | 33,409 |
| Plaintext | 3 | 3,549.2 | 121,995,614 B/s | 34,373 |

The post-P11 counter run moved below the P10 39.8-41.3 KB/request range for JSON and for the stable plaintext repetitions, but the local h2load run was noisy. This should be treated as directional evidence only, not proof that the ACK change alone removed several KB/request end to end.

## Whether QuicAckFrame Allocation Moved

In the isolated benchmark, yes. ACK parse allocation dropped:

- no-extra-ranges ACK: 200 B/op to 88 B/op;
- ACK_ECN no-extra-ranges: 200 B/op to 88 B/op;
- ACK + STREAM sequence: 200 B/op to 88 B/op;
- multiple ranges: 296 B/op to 208 B/op.

P11 did not rerun GCAllocationTick allocation-by-type tracing after the change, so there is no fresh end-to-end type-share measurement proving the `QuicAckFrame` bucket moved in ProtocolLab. The microbenchmark reduction is consistent with one fewer `QuicAckFrame` allocation and avoiding the empty range array in the common no-range case.

## Whether System.Byte[] Allocation Moved

No direct by-type refresh was collected in P11. The HTTP/3 allocation-path microbenchmarks stayed unchanged, and the ProtocolLab counter run reports only total allocation rate. `System.Byte[]` remains the top suspected allocation category from P10 until a fresh by-type trace proves otherwise.

## Worth Keeping

Yes. The change is narrow, behavior-preserved by byte-level ACK tests, and reduces the measured ACK parse allocation by 88-112 B/op. It does not address the dominant remaining `byte[]` allocation category, but it removes a confirmed transport-frame allocation source without changing protocol semantics.

## Remaining Suspected Allocation Sources

Top remaining category: `System.Byte[]` copies and temporary buffers across packet/stream/request processing.

Other visible categories from P10 that still need attribution:

- `QuicStream.ReadAsync` async state machine/task lifecycle;
- packet and stream payload byte materialization;
- diagnostics event allocation in HTTP/3 request handling;
- recovery/timer/effect array churn;
- remaining QPACK/header arrays, now smaller than the transport and byte-buffer buckets.

## Recommended P12

Select exactly one target: **System.Byte[] packet/stream buffer copy attribution and reduction**.

Recommended P12 prompt:

```text
Continue Incursa H3 Performance Phase P12: System.Byte[] packet and stream buffer allocation attribution.

Use P10 allocation-by-type evidence and P11 ACK-frame results as the starting point. This phase is attribution-first and may optimize only one measured byte[] source after tests and microbenchmarks.

Focus on byte[] copies and temporary buffers in:
- QUIC packet parse/build paths;
- stream payload materialization;
- QuicStream.ReadAsync / ReadCoreAsync;
- Http3Server.ReadRequestAsync byte[] handoff points;
- ToArray and Array.Resize sites that overlap the ProtocolLab h2load path.

Before optimizing, collect or derive allocation-by-call-stack evidence for System.Byte[] if possible, add focused byte-level behavior tests, and add BenchmarkDotNet baselines for the selected byte[] path.

Do not change HTTP/3 semantics, QPACK behavior, ACK/loss recovery semantics, QUIC scheduling, UDP send behavior, or ProtocolLab benchmark semantics.
```

## Validation

Commands run in this phase:

- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`
- `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p11\bdn-before --inProcess`
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAckFrameCodecUnitTests"`
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`
- `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicFrameAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p11\bdn-after --inProcess`
- `pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext,http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -CaptureCounters -RunId local-incursa-h3-p11-counters-20260527`

Final validation commands and full-suite result are recorded in the final response for this phase.

Final validation result:

- `dotnet build`: passed with 0 warnings and 0 errors.
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAckFrameCodecUnitTests"`: passed, 11/11.
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed with 0 warnings and 0 errors.
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 8 failures.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

Full test failure classification:

- 5 trace-link failures matched the known pre-existing trace-link family.
- 2 DoQ cancellation exact-type failures matched the known pre-existing family.
- 1 DoQ timeout in `DoqStreamLifecycleTests.DanglingStreamLimitClosesConnectionWithExcessiveLoad` passed when rerun individually and is classified as intermittent DoQ lifecycle noise, consistent with the prior intermittent DoQ timeout observations.

No new persistent failure family was introduced by P11.
