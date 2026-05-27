# Incursa H3 Performance Phase P5: response field-section allocation reduction

Date: 2026-05-27

Scope: one narrow HTTP/3 response header/QPACK field-section encoding optimization. ProtocolLab semantics, request parsing, QUIC packetization, QUIC scheduling, and UDP send behavior were not changed.

## P4 recap

P4 reduced the HTTP/3 response frame buffering path:

- `ResponseFrames_BufferPlaintext`: 584 B/op to 224 B/op.
- `ResponseFrames_BufferJson`: 624 B/op to 240 B/op.
- `ResponseFrames_EncodeAndBufferPlaintext`: 1,520 B/op to 768 B/op.

P4 preserved byte-level HEADERS/DATA frame behavior and the full test suite continued to fail only with the known pre-existing family:

- five trace-link failures,
- two DoQ cancellation exact-type failures.

P4 ProtocolLab h2load validation passed, but runtime counters were not captured, so it did not prove an end-to-end allocation-rate change.

## Post-P4 counter signal

Before P5 production edits, ProtocolLab was rerun with runtime counters enabled.

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -Scenarios http.core.plaintext,http.core.json `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -CaptureCounters `
  -RunId local-incursa-h3-p5-counters-before-20260527
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p5-counters-before-20260527\summary.md`

Counter result:

| scenario | requests/s median | p50 | p95 | p99 | allocation rate mean | estimated B/request | CPU mean | GC delta gen0/gen1/gen2 | thread pool queue max | exception rate mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `http.core.json` | 3,581.4 | 24.375 ms | 35.139 ms | 44.507 ms | 158,721,500 B/s | 44,318 B | 68.806% | 204 / 65 / 5 | 1 | 81.5 |
| `http.core.plaintext` | 3,591.1 | 21.865 ms | 31.054 ms | 39.027 ms | 160,810,066 B/s | 44,780 B | 71.484% | 207 / 66 / 5 | 1 | 30.667 |

This run is higher throughput than the older P1/P2 90-92 MB/s counter signal, so absolute MB/s is not directly comparable by itself. Normalized per request, the allocation signal remained roughly 44-45 KB/request before P5.

## Selected optimization target

Selected target:

- response header/QPACK field-section encoding.

Files and methods:

- `src/Incursa.Qpack/QPackStringLiteral.cs`
  - `QPackStringLiteral.Write`
- `src/Incursa.Quic.Http3/Http3Server.cs`
  - `EncodeResponseFieldSection`
  - `WriteLiteralWithStaticNameReference`
  - `WriteStringLiteral`
  - `WriteRawString`
  - new local `WriteInteger`

Why this target was selected:

- The request frame materialization path still owns frame object and payload lifetime and would be more invasive.
- P4 left the response field-section benchmark at 544 B/op.
- Both `QPackStringLiteral.Write` and the server response encoder wrote strings by allocating temporary `byte[]` values from `Encoding.GetBytes`.
- The server response encoder also allocated temporary integer byte arrays through `QPackInteger.Encode`.
- The change can preserve identical QPACK field-section bytes while removing intermediate arrays.

Static scan checklist for the selected files:

- `Encoding.GetBytes`: present in `QPackStringLiteral.Write` and `Http3Server.WriteRawString`.
- `QPackInteger.Encode`: present in `Http3Server.EncodeResponseFieldSection` helpers.
- `ToArray`: still present for final owned field-section output and other non-selected paths.
- `Array.Resize`: not present in selected encoder methods.
- `MemoryStream`: not present in selected encoder methods.
- LINQ: not present in selected encoder methods.

## Behavior-preservation tests

Added byte-level tests in `tests/Incursa.Quic.Tests/Http3FrameLayerTests.cs`:

- `QPackEncoder_ResponseFieldSectionBytesStayStable`

The test locks down exact field-section bytes for:

- plaintext TechEmpower-style response headers,
- JSON TechEmpower-style response headers.

It also decodes the resulting field section and verifies:

- `:status` remains `200`,
- `server` remains `incursa`,
- `date` remains `Wed, 27 May 2026 15:00:00 GMT`,
- `content-type` remains unchanged,
- `content-length` remains unchanged,
- no extra or missing fields appear.

Focused test command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~Http3FrameLayerTests
```

Result: passed, 26/26 tests.

## Optimization implemented

Implemented:

- `QPackStringLiteral.Write` now uses `Encoding.GetByteCount` plus span-based `Encoding.GetBytes(ReadOnlySpan<char>, Span<byte>)` directly into the destination buffer.
- `Http3Server.WriteRawString` now uses the same span-based string write.
- `Http3Server.EncodeResponseFieldSection` now writes QPACK prefixed integers directly into the existing `IBufferWriter<byte>` instead of allocating temporary arrays with `QPackInteger.Encode`.

Kept unchanged:

- final owned `byte[]` field-section output,
- QPACK integer format,
- QPACK string literal format,
- static table lookup behavior,
- header ordering,
- header field content,
- ProtocolLab route semantics.

## Microbenchmark commands

Before:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p5\bdn-before `
  --inProcess
```

After:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p5\bdn-after `
  --inProcess
```

Reports:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p5\bdn-before\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p5\bdn-after\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

## Before/after microbenchmarks

| benchmark | before mean | after mean | mean delta | before alloc | after alloc | alloc delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `FrameReader_ReadPlaintextHeaders` | 79.78 ns | 69.56 ns | -12.8% | 296 B | 296 B | 0 B |
| `FrameReader_ReadJsonHeaders` | 75.15 ns | 72.64 ns | -3.3% | 280 B | 280 B | 0 B |
| `FrameReader_ReadFragmentedPlaintextHeaders` | 132.82 ns | 134.08 ns | +0.9% | 400 B | 400 B | 0 B |
| `ResponseHeaders_EncodePlaintextFieldSection` | 705.34 ns | 720.61 ns | +2.2% | 544 B | 424 B | -120 B |
| `ResponseHeaders_EncodeJsonFieldSection` | 685.19 ns | 678.78 ns | -0.9% | 544 B | 424 B | -120 B |
| `ResponseFrames_BufferPlaintext` | 46.96 ns | 49.96 ns | +6.4% | 224 B | 224 B | 0 B |
| `ResponseFrames_BufferJson` | 47.83 ns | 49.76 ns | +4.0% | 240 B | 240 B | 0 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 851.09 ns | 812.01 ns | -4.6% | 768 B | 648 B | -120 B |

Primary success metric:

- `ResponseHeaders_EncodePlaintextFieldSection` and `ResponseHeaders_EncodeJsonFieldSection` dropped by 120 B/op, from 544 B/op to 424 B/op.

Secondary signal:

- `ResponseFrames_EncodeAndBufferPlaintext` dropped by 120 B/op, from 768 B/op to 648 B/op.

Interpretation:

- The selected allocation was reduced.
- Mean timing is effectively neutral within ShortRun variance for the selected field-section rows.
- Non-selected frame reader and stream payload allocation rows were unchanged.

## After ProtocolLab counters

Because the selected microbenchmark allocation dropped meaningfully, ProtocolLab was rerun with counters enabled.

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -Scenarios http.core.plaintext,http.core.json `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -CaptureCounters `
  -RunId local-incursa-h3-p5-counters-after-20260527
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p5-counters-after-20260527\summary.md`

Result:

- six h2load cells succeeded,
- validation passed 6/6,
- runtime counters captured 6/6.

| scenario | before alloc rate | after alloc rate | before requests/s | after requests/s | before B/request | after B/request | B/request delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `http.core.json` | 158,721,500 B/s | 149,866,311 B/s | 3,581.4 | 3,606.4 | 44,318 B | 41,556 B | -6.2% |
| `http.core.plaintext` | 160,810,066 B/s | 153,522,770 B/s | 3,591.1 | 3,751.8 | 44,780 B | 40,920 B | -8.6% |

Latency and CPU comparison:

| scenario | before p50 / p95 / p99 | after p50 / p95 / p99 | before CPU mean | after CPU mean |
| --- | --- | --- | ---: | ---: |
| `http.core.json` | 24.375 / 35.139 / 44.507 ms | 21.974 / 28.499 / 34.508 ms | 68.806% | 67.188% |
| `http.core.plaintext` | 21.865 / 31.054 / 39.027 ms | 15.567 / 21.546 / 28.363 ms | 71.484% | 66.629% |

Runtime diagnostics comparison:

| scenario | before GC delta gen0/gen1/gen2 | after GC delta gen0/gen1/gen2 | before queue max | after queue max | before exception rate | after exception rate |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `http.core.json` | 204 / 65 / 5 | 191 / 62 / 5 | 1 | 1 | 81.5 | 52.333 |
| `http.core.plaintext` | 207 / 66 / 5 | 196 / 64 / 5 | 1 | 1 | 30.667 | 43 |

Interpretation:

- The after counter run moved in the expected direction for allocation rate and normalized allocated bytes/request.
- The run is still local shared-host evidence, not publishable benchmark evidence.
- The absolute throughput and latency changes should be treated as directional only.

## Validation

Commands:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~Http3FrameLayerTests
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
git diff --check
$errors = @(); Get-ChildItem scripts\perf\*.ps1 | ForEach-Object { $tokens = $null; $parseErrors = $null; [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) > $null; if ($parseErrors) { $errors += $parseErrors } }; if ($errors.Count -gt 0) { $errors | Format-List; exit 1 }
```

Results:

- Benchmark project build: passed.
- Focused HTTP/3 frame-layer tests: passed, 26/26.
- Full `dotnet build`: passed with 0 warnings and 0 errors.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 7 known pre-existing failures:
  - `REQ_QUIC_INT_0032.H3SpecPipelineIsTraceLinkedAcrossCanonicalArtifacts`
  - `REQ_QUIC_INT_0029.XquicResidualIsTraceOwnedBeforeRuntimePromotion`
  - `REQ_QUIC_INT_0029.XquicResidualDoesNotWeakenTheAdvisoryBoundary`
  - `REQ_QUIC_RFC9114_S4_0001.LowLevelMalformedSequenceTestsAreTraceLinked`
  - `REQ_QUIC_INT_0030.Http3RunnerCellIsTraceLinkedAcrossCanonicalArtifacts`
  - `DoqStreamLifecycleTests.QueryCancellationAbortsReadSideAndLeavesConnectionUsable`
  - `DoqStreamLifecycleTests.CancellationVolumeLimitClosesConnectionWithExcessiveLoad`
- Full test pass count: 5,895 passed, 7 failed, 5,902 total.
- `git diff --check`: passed. It printed the existing `.config/dotnet-tools.json` line-ending warning.
- PowerShell parser check for `scripts/perf/*.ps1`: passed.

No new failure family was introduced.

## Conclusion

The P5 change is worth keeping.

Evidence:

- Byte-level field-section tests preserve plaintext and JSON response header bytes.
- The selected BDN field-section rows dropped from 544 B/op to 424 B/op.
- The combined encode+buffer row dropped from 768 B/op to 648 B/op.
- ProtocolLab counters moved from roughly 44-45 KB/request to roughly 41-42 KB/request in the same local c16/s10 h2load shape.
- Build passed and full-suite failures matched the known baseline family.

Behavior changed:

- No intended external behavior change.

Protocol semantics changed:

- No. QPACK field-section bytes are locked by tests and unchanged for the selected response shapes.

Top remaining suspected allocation sources:

1. `Http3Server.ReadRequestAsync` request-side frame/header materialization.
2. `Http3FrameReader.Read` payload `ToArray`, frame object creation, and frame-array materialization.
3. `Http3Server.BuildResponseHeaders` response header collection materialization.
4. Final owned `byte[]` field-section and response frame output arrays.
5. `QuicConnectionRuntime.Streams.cs` stream payload creation and queued-send combine path.

Confidence:

- High that P5 reduced the selected response field-section allocation.
- Medium that the ProtocolLab counter improvement is attributable to this change, because the run was local shared-host but both before and after runs used the same counter-enabled shape.
- Medium-high that request frame materialization is now the best next target.

## Recommended P6 prompt

```text
You are working in C:\src\incursa\quic-dotnet.

Continue Incursa H3 Performance Phase P6: request frame materialization allocation reduction.

Context:
P4 reduced response frame buffering allocation. P5 reduced response field-section encoding allocation from 544 B/op to 424 B/op and ProtocolLab counters moved from roughly 44-45 KB/request to roughly 41-42 KB/request in the Incursa-only c16/s10 h2load shape.

Primary goal:
Reduce or precisely attribute request-side HTTP/3 frame materialization allocation while preserving exact HTTP/3 parsing behavior.

Focus targets:
- Http3Server.ReadRequestAsync
- Http3FrameReader.Read
- Http3FrameReader.Append
- Http3FrameReader.SlicePending
- QPackDecoder.DecodeFieldSection only if required by request header materialization evidence

Required approach:
- Establish a fresh before microbenchmark baseline.
- Add byte-level parser behavior tests before optimizing.
- Preserve fragmented HEADERS behavior, multiple-frame ordering, invalid-frame exceptions, unknown/reserved frame behavior, and no extra/missing payload bytes.
- Optimize only one narrow request-frame materialization path.
- Do not touch response generation, QUIC packetization, QUIC scheduling, UDP send, or ProtocolLab semantics.
- Run focused tests, dotnet build, full test project, selected BenchmarkDotNet benchmarks, git diff --check, PowerShell parser checks, and ProtocolLab counters only if the microbenchmark allocation moves meaningfully.
```
