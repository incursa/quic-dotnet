# Incursa H3 Performance Phase P6: request frame materialization allocation reduction

Date: 2026-05-27

Scope: one narrow HTTP/3 request frame materialization optimization in `Http3FrameReader`. ProtocolLab semantics, response generation, response header/QPACK encoding, QUIC packetization, QUIC scheduling, UDP send behavior, and sample endpoint behavior were not changed.

## P5 recap

P5 reduced response header/QPACK field-section allocation:

- `ResponseHeaders_EncodePlaintextFieldSection`: 544 B/op to 424 B/op.
- `ResponseHeaders_EncodeJsonFieldSection`: 544 B/op to 424 B/op.
- `ResponseFrames_EncodeAndBufferPlaintext`: 768 B/op to 648 B/op.

P5 ProtocolLab counters moved in the expected direction:

- JSON: about 41,556 B/request after P5.
- Plaintext: about 40,920 B/request after P5.

The remaining top suspected allocation source after P5 was the request-side frame materialization path:

- `Http3Server.ReadRequestAsync`
- `Http3FrameReader.Read`
- `Http3FrameReader.Append`
- `Http3FrameReader.SlicePending`

## Selected optimization target

Selected target:

- `Http3FrameReader.Read` when there are no pending partial frame bytes.

Files and methods:

- `src/Incursa.Quic.Http3/Http3FrameReader.cs`
  - `Read`
  - existing `Append`
  - existing `SlicePending`
- `tests/Incursa.Quic.Tests/Http3FrameLayerTests.cs`

Why this target was selected:

- The P5/P6 benchmark suite already isolated `Http3FrameReader.Read` allocation.
- The common benchmark request shape supplies a complete small HEADERS frame in one buffer.
- Before P6, `Read` always copied the incoming source into `pending` through `Append`, even when `pending` was empty and the source contained complete frame bytes.
- The parser still needs to produce owned frame payload bytes, so the safe bounded reduction is to avoid only the unnecessary full-input copy.

Allocation sources reviewed:

- `Append`: allocates a combined `byte[]` whenever source is non-empty.
- `Read`: allocates frame payload bytes with `ToArray`.
- `SlicePending`: allocates pending remainder bytes with `ToArray`.
- `Read`: materializes `List<Http3Frame>` and then a result array.
- `ParsePushPromise` and `ParseSettings`: have additional non-selected allocations for those frame types.

Planned reduction before editing:

- Parse directly from the caller-provided `ReadOnlySpan<byte>` when no pending bytes exist.
- Continue using `Append` when a partial frame is already pending.
- Continue copying incomplete remainders into owned pending storage.
- Continue copying completed frame payloads into owned `byte[]` values.
- Keep frame array materialization and all validation behavior unchanged.

## Behavior-preservation tests

Added focused byte-level parser tests in `tests/Incursa.Quic.Tests/Http3FrameLayerTests.cs`:

- `FrameReader_ParsesSingleHeadersFramePayloadExactly`
- `FrameReader_FragmentedHeadersFramePreservesPayloadAndPendingBytes`
- `FrameReader_PreservesCompleteFrameBeforePartialFrameUntilCompletion`
- `FrameReader_PreservesUnknownReservedAndDataFrameOrdering`
- `FrameReader_TruncatedPayloadStaysPendingUntilCompletionFails`

These cover:

- single HEADERS frame payload bytes,
- fragmented HEADERS pending behavior,
- multiple frames preserving ordering,
- DATA payload bytes,
- unknown frame handling,
- reserved frame handling,
- invalid truncated payload behavior,
- partial frame buffering,
- no extra or missing payload bytes.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~Http3FrameLayerTests
```

Result: passed, 31/31 tests.

## Optimization implemented

Implemented:

- `Http3FrameReader.Read` now checks whether `pending` is empty.
- If `pending` is empty, it parses directly from `source`.
- If `pending` is not empty, it keeps the old combined-buffer path through `Append`.
- If parsing stops with an incomplete frame and there was no prior pending buffer, it copies only the unread remainder into `pending`.
- If parsing consumes all readable bytes, it clears `pending`.

Kept unchanged:

- payload ownership for parsed frames,
- returned `Http3Frame[]`,
- frame object model,
- invalid frame length checks,
- truncated end-of-stream behavior,
- unknown/reserved frame handling,
- fragmented frame behavior,
- HTTP/3 request semantics.

## Microbenchmark commands

Before:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p6\bdn-before `
  --inProcess
```

After:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p6\bdn-after `
  --inProcess
```

Reports:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p6\bdn-before\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p6\bdn-after\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

## Before/after microbenchmarks

| benchmark | before mean | after mean | mean delta | before alloc | after alloc | alloc delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `FrameReader_ReadPlaintextHeaders` | 88.25 ns | 73.52 ns | -16.7% | 296 B | 224 B | -72 B |
| `FrameReader_ReadJsonHeaders` | 90.38 ns | 71.30 ns | -21.1% | 280 B | 216 B | -64 B |
| `FrameReader_ReadFragmentedPlaintextHeaders` | 156.77 ns | 139.25 ns | -11.2% | 400 B | 400 B | 0 B |
| `ResponseHeaders_EncodePlaintextFieldSection` | 689.37 ns | 674.55 ns | -2.1% | 424 B | 424 B | 0 B |
| `ResponseHeaders_EncodeJsonFieldSection` | 668.37 ns | 680.89 ns | +1.9% | 424 B | 424 B | 0 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 851.08 ns | 805.57 ns | -5.3% | 648 B | 648 B | 0 B |

Primary success metric:

- `FrameReader_ReadPlaintextHeaders` dropped by 72 B/op.
- `FrameReader_ReadJsonHeaders` dropped by 64 B/op.

Secondary signal:

- Fragmented frame allocation did not change, as expected, because incomplete data still requires owned pending storage.
- Non-selected response rows did not change in allocation.
- ShortRun timing moved lower for the selected rows, but timing should remain directional only.

## ProtocolLab counter rerun

Because the selected microbenchmark allocation dropped meaningfully, ProtocolLab was rerun with counters enabled.

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -Scenarios http.core.plaintext,http.core.json `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -CaptureCounters `
  -RunId local-incursa-h3-p6-counters-after-20260527
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p6-counters-after-20260527\summary.md`

Result:

- six h2load cells succeeded,
- validation passed 6/6,
- runtime counters captured 6/6.

| scenario | P5 alloc rate | P6 alloc rate | P5 requests/s | P6 requests/s | P5 B/request | P6 B/request | B/request delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `http.core.json` | 149,866,311 B/s | 143,387,407 B/s | 3,606.4 | 3,463.1 | 41,556 B | 41,404 B | -151 B |
| `http.core.plaintext` | 153,522,770 B/s | 140,414,262 B/s | 3,751.8 | 3,326.4 | 40,920 B | 42,212 B | +1,292 B |

Latency and CPU comparison:

| scenario | P5 p50 / p95 / p99 | P6 p50 / p95 / p99 | P5 CPU mean | P6 CPU mean |
| --- | --- | --- | ---: | ---: |
| `http.core.json` | 21.974 / 28.499 / 34.508 ms | 25.319 / 34.677 / 43.530 ms | 67.188% | 67.913% |
| `http.core.plaintext` | 15.567 / 21.546 / 28.363 ms | 20.688 / 30.951 / 38.642 ms | 66.629% | 68.527% |

Runtime diagnostics comparison:

| scenario | P5 GC delta gen0/gen1/gen2 | P6 GC delta gen0/gen1/gen2 | P5 queue max | P6 queue max | P5 exception rate | P6 exception rate |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `http.core.json` | 191 / 62 / 5 | 182 / 58 / 5 | 1 | 1 | 52.333 | 55.167 |
| `http.core.plaintext` | 196 / 64 / 5 | 180 / 56 / 5 | 1 | 0 | 43 | 36.833 |

Interpretation:

- The microbenchmark proved the selected single-buffer request frame allocation was reduced.
- The P6 local ProtocolLab counter run did not prove a consistent end-to-end normalized allocation reduction.
- JSON moved slightly down in B/request; plaintext moved up because throughput was lower enough to offset the lower aggregate allocation rate.
- This is plausible for a 64-72 B/op isolated win inside a roughly 41 KB/request local signal.
- The change is still worth keeping because it removes an unnecessary copy in the common complete-frame path, has focused parser tests, and has no observed isolated benchmark regression.

## Validation

Commands:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~Http3FrameLayerTests
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p6\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p6\bdn-after --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext,http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -CaptureCounters -RunId local-incursa-h3-p6-counters-after-20260527
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
git diff --check
$errors = @(); Get-ChildItem scripts\perf\*.ps1 | ForEach-Object { $tokens = $null; $parseErrors = $null; [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) > $null; if ($parseErrors) { $errors += $parseErrors } }; if ($errors.Count -gt 0) { $errors | Format-List; exit 1 }; 'PowerShell parser check passed.'
```

Results:

- Benchmark project build before edit: passed.
- Focused HTTP/3 frame-layer tests after test additions: passed, 31/31.
- Benchmark project build after production edit: passed.
- BenchmarkDotNet before/after runs completed.
- ProtocolLab counter rerun completed with validation passed 6/6 and counters captured 6/6.
- Full `dotnet build`: passed with 0 warnings and 0 errors.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 7 known pre-existing failures:
  - `REQ_QUIC_INT_0032.H3SpecPipelineIsTraceLinkedAcrossCanonicalArtifacts`
  - `REQ_QUIC_RFC9114_S4_0001.LowLevelMalformedSequenceTestsAreTraceLinked`
  - `REQ_QUIC_INT_0029.XquicResidualIsTraceOwnedBeforeRuntimePromotion`
  - `REQ_QUIC_INT_0029.XquicResidualDoesNotWeakenTheAdvisoryBoundary`
  - `REQ_QUIC_INT_0030.Http3RunnerCellIsTraceLinkedAcrossCanonicalArtifacts`
  - `DoqStreamLifecycleTests.QueryCancellationAbortsReadSideAndLeavesConnectionUsable`
  - `DoqStreamLifecycleTests.CancellationVolumeLimitClosesConnectionWithExcessiveLoad`
- Full test result: 5,900 passed, 7 failed, 0 skipped.
- The failure set matches the known pre-existing family: 5 trace-link failures and 2 DoQ cancellation exact-type failures.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

## Remaining suspected allocation sources

Highest-value remaining sources after P6:

1. `Http3Server.ReadRequestAsync`: per-request `Http3FrameReader`, `Http3RequestMessageValidator`, request body `ArrayBufferWriter<byte>`, read buffer, async loop, decoded header materialization.
2. `QPackDecoder.DecodeFieldSection`: request header string creation and field-list materialization.
3. `Http3FrameReader.Read`: payload `ToArray`, `List<Http3Frame>`, result array, fragmented pending combine/copy.
4. `Http3Server.HandleRequestStreamAsync`: request/response object lifetime and dispatch state machine overhead.
5. QUIC stream delivery path: `HandleWriteStreamAction`, `TryBuildOutboundStreamPayload`, and queued-send combine shape remain allocation-bearing according to earlier P3/P4 baselines.

## Recommended P7 prompt

Continue Incursa H3 Performance Phase P7: request header decode and request object allocation attribution.

Use P6 as the baseline. Do not change QUIC packetization, scheduling, UDP send, response buffering, or ProtocolLab semantics. First add or extend microbenchmarks around `QPackDecoder.DecodeFieldSection` and the `Http3Server.ReadRequestAsync` request header materialization shape for TechEmpower-style GET `/plaintext` and `/json` requests. Add behavior-preservation tests for decoded pseudo-header/header semantics, invalid QPACK/header behavior, and request body handling. Optimize only if a single bounded allocation source is proven, with before/after BDN and ProtocolLab counters.
