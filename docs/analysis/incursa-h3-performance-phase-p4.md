# Incursa H3 Performance Phase P4: benchmark-guarded response-buffer allocation reduction

Date: 2026-05-27

Scope: first narrow optimization phase. ProtocolLab benchmark semantics, request parsing, QPACK decode, QUIC packetization, QUIC scheduling, and UDP send behavior were not changed.

## P3 recap

P3 established that the isolated response generation and buffering path was the highest measured microbenchmark allocation source:

- `ResponseFrames_EncodeAndBufferPlaintext`: 1,520 B/op.
- `ResponseFrames_BufferPlaintext`: 584 B/op.
- `ResponseFrames_BufferJson`: 624 B/op.
- `ResponseHeaders_EncodePlaintextFieldSection`: 544 B/op.
- `ResponseHeaders_EncodeJsonFieldSection`: 544 B/op.

This did not explain the full external h2load allocation estimate of roughly 34-36 KB/request, but it was directly inside the P2 measured `Http3Server.WriteResponseAsync` / `WriteBufferedResponseFramesAsync` stack and was narrow enough to optimize without changing protocol behavior.

## Optimization attempted

Changed only the HTTP/3 non-streaming response frame composition path:

- Added `IBufferWriter<byte>` HEADERS and DATA frame writer helpers in `Http3FrameWriter`.
- Added `Http3FrameWriter.GetFrameLength` so callers can pre-size a combined response frame buffer.
- Updated `Http3Server.WriteBufferedResponseFramesAsync` to write HEADERS and DATA directly into one pre-sized `ArrayBufferWriter<byte>`.
- Kept the final owned `byte[]` materialization before `QuicStream.WriteFinalAsync`, preserving the current stream write ownership contract.

The optimization removes intermediate standalone frame byte arrays for the buffered non-streaming response path. It does not special-case `/plaintext` or `/json`, does not hardcode full wire responses, and still uses QPACK field-section encoding and HTTP/3 frame length/type encoding.

Changed files and methods:

- `src/Incursa.Quic.Http3/Http3FrameWriter.cs`
  - `WriteData(IBufferWriter<byte>, ReadOnlySpan<byte>)`
  - `WriteHeaders(IBufferWriter<byte>, ReadOnlySpan<byte>)`
  - `GetFrameLength(ulong, int)`
- `src/Incursa.Quic.Http3/Http3Server.cs`
  - `WriteResponseAsync`
  - `WriteBufferedResponseFramesAsync`
- `benchmarks/Http3AllocationPathBenchmarks.cs`
  - response buffering benchmark helpers updated to match the optimized direct frame composition shape.

## Behavior-preservation tests

Added byte-level tests in `tests/Incursa.Quic.Tests/Http3FrameLayerTests.cs`:

- `FrameWriter_BufferWriterHeadersMatchesStandaloneHeadersFrame`
- `FrameWriter_BufferWriterDataMatchesStandaloneDataFrame`
- `FrameWriter_BufferWriterResponseSequenceMatchesStandaloneHeadersAndData`

These tests verify:

- HEADERS frame bytes are unchanged for plaintext and JSON response header sets.
- DATA frame bytes are unchanged for plaintext and JSON response bodies.
- Combined HEADERS + DATA sequences exactly match the prior standalone-frame composition.
- Decoded content-type headers remain correct.
- Response body bytes are exactly unchanged.
- The combined buffer has no extra or missing bytes.

Focused test command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~Http3FrameLayerTests
```

Result: passed, 24/24 tests.

## Benchmark commands

Before:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p4\bdn-before `
  --inProcess
```

After:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p4\bdn-after `
  --inProcess
```

Benchmark reports:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p4\bdn-before\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p4\bdn-after\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

Environment:

- BenchmarkDotNet v0.15.8.
- ShortRun, in-process toolchain.
- .NET SDK 10.0.204.
- .NET runtime 10.0.8.
- Windows 11 10.0.26200.8328.

## Before/after BDN results

| benchmark | before mean | after mean | mean delta | before alloc | after alloc | alloc delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `ResponseHeaders_EncodePlaintextFieldSection` | 719.99 ns | 727.38 ns | +1.0% | 544 B | 544 B | 0 B |
| `ResponseHeaders_EncodeJsonFieldSection` | 710.24 ns | 662.29 ns | -6.8% | 544 B | 544 B | 0 B |
| `ResponseFrames_BufferPlaintext` | 97.62 ns | 53.55 ns | -45.1% | 584 B | 224 B | -360 B |
| `ResponseFrames_BufferJson` | 110.71 ns | 49.54 ns | -55.3% | 624 B | 240 B | -384 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 943.37 ns | 758.18 ns | -19.6% | 1,520 B | 768 B | -752 B |

Primary success metric:

- `ResponseFrames_EncodeAndBufferPlaintext` allocation decreased by 752 B/op, roughly 49.5%.

Secondary metrics:

- `ResponseFrames_BufferPlaintext` allocation decreased by 360 B/op, roughly 61.6%.
- `ResponseFrames_BufferJson` allocation decreased by 384 B/op, roughly 61.5%.
- Response header field-section encoding allocation stayed unchanged at 544 B/op.
- No meaningful mean-time regression was observed in the targeted frame buffering benchmarks. ShortRun timing variance is high, so allocation is the stronger signal.

## ProtocolLab rerun

Because the target microbenchmark allocation dropped meaningfully, an Incursa-only ProtocolLab h2load rerun was performed.

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -Scenarios http.core.plaintext,http.core.json `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -RunId local-incursa-h3-p4-h2load-20260527
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p4-h2load-20260527\summary.md`

Result:

- Six h2load cells succeeded.
- Validation passed 6/6.
- Target process metrics were captured.
- Runtime counters were disabled or missing for all six cells, so this run cannot compare allocation rate against the P2/P3 counter evidence.

Aggregate results:

| scenario | requests/s median | requests/s best | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `http.core.json` | 2,460.5 | 2,608.1 | 28.035 ms | 35.230 ms | 45.458 ms |
| `http.core.plaintext` | 2,394.6 | 2,745.8 | 37.502 ms | 42.915 ms | 46.858 ms |

Interpretation:

- The ProtocolLab run is a useful behavior and gross-regression check.
- It does not show a clear end-to-end throughput improvement because local h2load variance remains high and runtime counters were not captured.
- The microbenchmark result is still worth keeping because it removes real intermediate frame allocations from a measured P2/P3 response path and byte-level tests preserve wire equivalence.

## Validation

Commands:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~Http3FrameLayerTests
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
git diff --check
$errors = @(); Get-ChildItem scripts\perf\*.ps1 | ForEach-Object { [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$parseErrors) > $null; $errors += $parseErrors }; if ($errors.Count -gt 0) { $errors | Format-List; exit 1 }
```

Results:

- Benchmark project build: passed.
- Focused HTTP/3 frame-layer tests: passed.
- Full `dotnet build`: passed with 0 warnings and 0 errors.
- `git diff --check`: passed. It printed a line-ending warning for `.config/dotnet-tools.json`, which was introduced by the repo-local tool manifest from P2 and is not a whitespace error.
- PowerShell parser check for `scripts/perf/*.ps1`: passed.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with the known pre-existing family:
  - five trace-link assertion failures,
  - two DoQ cancellation exact-type failures.

No new test failure family was introduced. The total passed count increased because P4 added new frame-layer tests.

## Conclusion

P4 reduced the isolated response frame generation/buffering allocation without changing the HTTP/3 wire bytes covered by the new tests.

The change is worth keeping:

- It removes intermediate frame allocations from a P2/P3 measured response method path.
- It cuts the top P3 isolated allocation source by roughly half.
- It improves or preserves targeted benchmark time and allocation metrics.
- It does not change ProtocolLab semantics or protocol behavior.

Top suspected bottleneck category after P4:

- Allocation-heavy shared HTTP/3 processing remains the leading category.

Top remaining suspected allocation sources:

1. `Http3Server.ReadRequestAsync` request-side frame/header materialization.
2. `Http3FrameReader.Read` payload `ToArray`, frame object creation, and frame-array materialization.
3. `Http3Server.BuildResponseHeaders` and `EncodeResponseFieldSection` response header array and QPACK encoding allocations.
4. `QPackEncoder.EncodeFieldSection` repeated static response header encoding.
5. `QuicConnectionRuntime.Streams.cs` stream payload creation and queued-send combine path.

Confidence:

- High that P4 reduced the intended isolated response buffering allocation.
- Medium-high that shared HTTP/3 request/response allocation is still the right bottleneck category.
- Medium that the next best target is request read/frame materialization or response field-section encoding.
- Low that P4 alone should move external h2load throughput materially, because its savings are small compared with the estimated full request allocation.

## Recommended P5 prompt

```text
You are working in C:\src\incursa\quic-dotnet.

Continue Incursa H3 Performance Phase P5: request frame materialization and response header encoding allocation attribution.

Context:
P4 reduced the isolated response frame generation/buffering path from 1,520 B/op to 768 B/op for ResponseFrames_EncodeAndBufferPlaintext, preserving byte-level HEADERS/DATA behavior. ProtocolLab h2load validation still passed, but runtime counters were not captured and there was no clear end-to-end throughput movement.

Goal:
Reduce or precisely attribute the next shared HTTP/3 allocation source without changing protocol semantics.

Focus targets:
1. Http3Server.ReadRequestAsync
2. Http3FrameReader.Read / Append / SlicePending
3. Http3Server.BuildResponseHeaders / EncodeResponseFieldSection
4. QPackEncoder.EncodeFieldSection static response header path

Required approach:
- Add byte-level behavior tests before optimizing.
- Extend BenchmarkDotNet baselines for the selected target.
- Prefer request-frame materialization or response field-section encoding; do not touch QUIC packetization, scheduling, UDP send, or ProtocolLab semantics.
- Preserve all wire behavior and existing tests.
- Run dotnet build, dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj, selected benchmarks, git diff --check, and PowerShell parser checks.
- If ProtocolLab is rerun, ensure runtime counters are enabled so allocation-rate deltas can be compared.
```
