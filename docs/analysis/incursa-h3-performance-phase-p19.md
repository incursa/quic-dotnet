# Incursa H3 Performance Phase P19

Date: 2026-05-28

## Scope

Phase P19 reduced the server-owned QPACK request field-line materialization allocation. The change is limited to the HTTP/3 server request path and internal QPACK decode plumbing.

Guardrails held:

- QPACK public decode APIs keep returning caller-owned arrays.
- QPACK wire semantics are unchanged.
- HTTP/3 request validation semantics are unchanged.
- ProtocolLab benchmark semantics are unchanged.
- No `/plaintext`, `/json`, h2load, or TechEmpower special casing was added.
- QUIC scheduling, UDP send, packet protection, ACK/loss recovery, and QPACK dynamic table semantics were not changed.

## P18 Recap

P18 was measurement/documentation only. It confirmed the P17 `Http3Server.ReadRequestAsync` 16 KiB scratch buffer allocation was gone from the modeled request-read path, and fresh Incursa-only ProtocolLab counters showed:

| Scenario | P18 B/request range |
| --- | ---: |
| `http.core.json` | 21.1-22.2 KB/request |
| `http.core.plaintext` | 21.1-21.6 KB/request |

P18 post-P17 allocation traces selected `Incursa.Qpack.QPackFieldLine[]` as the next target:

| Scenario | Sampled bytes | Share |
| --- | ---: | ---: |
| `http.core.plaintext` | 630,965,304 | 19.8% |
| `http.core.json` | 633,102,256 | 19.6% |

The first source candidate was `QPackDecoder.DecodeAvailableFieldSection`, where the public decode path returns `fields.WrittenSpan.ToArray()`.

## Ownership Analysis

APIs that return `QPackFieldLine[]` before and after P19:

- `QPackDecoder.DecodeFieldSection(ReadOnlySpan<byte>)`.
- `QPackDecoder.DecodeFieldSection(ReadOnlyMemory<byte>)`.
- `QPackDecoder.DecodeFieldSection(ulong, ReadOnlyMemory<byte>)` through `QPackFieldSectionDecodeResult.FieldLines`.
- unblocked field sections returned after encoder-stream progress.

Public callers require defensive ownership. P19 therefore leaves the public array-returning APIs unchanged.

The HTTP/3 server request path does not require the public `ToArray()` result for unblocked request field sections. It validates the decoded headers, materializes the request, and retains only read-only request header ownership. That path can consume fields through private server-owned storage without exposing mutable storage to callers.

Blocked QPACK field sections still retain the previous array-returning completion path. The optimized path applies to the normal unblocked h2load request path measured in P18.

## Selected Design

Selected design: internal sink-style decode path.

Implementation shape:

- added an internal QPACK decode overload that writes decoded fields to an `IBufferWriter<QPackFieldLine>`;
- kept all public QPACK decode APIs unchanged;
- added an HTTP/3-owned field-line buffer and read-only list wrapper;
- changed the HTTP/3 server request path to use the internal sink decode path for unblocked request headers;
- changed request validation storage from `QPackFieldLine[]` to `IReadOnlyList<QPackFieldLine>` while retaining the public defensive-copy path.

No pooled `QPackFieldLine[]` storage is used in P19. The server-owned path still owns a private backing array, so there is no returned-pool lifetime or clearing decision. This reduces one materialization array without introducing mutable pooled storage into request objects.

## Behavior Tests

New focused tests were added in `tests\Incursa.Quic.Tests\Http3HeaderValidationTests.cs` for:

- valid GET `/plaintext` request decode, validation, and materialization;
- valid GET `/json` request decode, validation, and materialization;
- preservation of `:method`, `:scheme`, `:authority`, and `:path`;
- preservation of regular headers;
- duplicate pseudo-header rejection;
- missing required pseudo-header rejection;
- pseudo-header-after-regular-header rejection;
- malformed QPACK/header field-section rejection;
- public QPACK decode API returning caller-owned mutable-safe arrays;
- server-owned optimized path not exposing mutable array storage.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests"
```

Result: passed, 58/58.

## BenchmarkDotNet

Before command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\bdn-before `
  --inProcess
```

After command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\bdn-after `
  --inProcess
```

Artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\bdn-before`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\bdn-after`

Selected results:

| Benchmark | Before allocated | After allocated | Delta |
| --- | ---: | ---: | ---: |
| `RequestHeaders_DecodePlaintextFieldSection` | 1,080 B | 1,096 B | +16 B |
| `RequestHeaders_DecodeJsonFieldSection` | 1,064 B | 1,080 B | +16 B |
| `RequestHeaders_DecodeAndValidatePlaintext` | 1,168 B | 664 B | -504 B |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | 1,288 B | 752 B | -536 B |
| `RequestHeaders_DecodeValidateMaterialize_Plaintext` | 1,288 B | 752 B | -536 B |
| `RequestHeaders_DecodeValidateMaterialize_Json` | 1,272 B | 736 B | -536 B |
| `RequestLifecycle_HeadersOnlyGetPlaintext` | 1,288 B | 752 B | -536 B |
| `RequestLifecycle_HeadersOnlyGetJson` | 1,272 B | 736 B | -536 B |
| `ReadRequestAsync_HeadersOnlyGetPlaintext` | 1,696 B | 1,112 B | -584 B |
| `ReadRequestAsync_HeadersOnlyGetJson` | 1,672 B | 1,088 B | -584 B |
| `ReadRequestAsync_FragmentedHeaders` | 1,848 B | 1,264 B | -584 B |
| `ReadRequestAsync_HeadersAndSmallData` | 2,504 B | 1,888 B | -616 B |

Interpretation:

- Public QPACK decode rows intentionally did not improve because public defensive array behavior is preserved.
- Server-shaped decode/validate/materialize rows improved by about 0.5 KB/op.
- Request-read rows improved by about 0.6 KB/op.
- The remaining server-owned `Http3FieldLineBuffer` still allocates a private backing `QPackFieldLine[]`, so P19 reduces but does not eliminate `QPackFieldLine[]`.

## ProtocolLab Counters

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext,http.core.json `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -RunId local-incursa-h3-p19-counters-20260528 `
  -CaptureCounters
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p19-counters-20260528`

All 6 validation and benchmark cells passed. Runtime counters were captured for all 6 cells.

| Scenario | Req/s median | p50 ms | p95 ms | p99 ms | Allocation rate median | B/request est. | CPU mean/max | GC gen0/gen1/gen2 | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `http.core.json` | 3,547.3 | 24.633 | 34.881 | 40.164 | 77,053,556 B/s | 21,722 B | 68.1% / 135.9% | 96 / 30 / 4 | 0 |
| `http.core.plaintext` | 3,671.8 | 15.381 | 23.665 | 32.086 | 78,371,769 B/s | 21,344 B | 67.6% / 153.1% | 98 / 31 / 4 | 0 |

Comparison against P18:

- JSON remained in the same 21.1-22.2 KB/request band.
- Plaintext remained in the same 21.1-21.6 KB/request band.
- The BDN drop is real in the isolated server request path, but this local h2load counter run does not show a clear end-to-end B/request movement beyond existing run noise.

Warnings remain local-run warnings: shared host, no CPU isolation, no network isolation, host-docker-internal rewrite, missing load-generator metrics, no repeated stable median, and single-machine measurement.

## Allocation Trace Refresh

One post-change plaintext allocation trace was collected:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 30 `
  -WarmupSeconds 2 `
  -Repetitions 1 `
  -RunId local-incursa-h3-p19-plaintext-gc-20260528 `
  -CaptureCounters `
  -TraceMode gc-allocation `
  -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\plaintext-gc-allocation `
  -TraceDurationSeconds 40
```

Artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\plaintext-gc-allocation\trace.nettrace`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\plaintext-byte-stack-analysis\byte-stack-summary.md`

Top sampled types in the P19 plaintext trace:

| Type | Count | Sampled bytes | Share |
| --- | ---: | ---: | ---: |
| `Incursa.Qpack.QPackFieldLine[]` | 5,132 | 546,893,096 | 16.6% |
| `System.Byte[]` | 4,525 | 482,220,280 | 14.6% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 1,415 | 150,812,624 | 4.6% |
| `System.Object` | 1,377 | 146,729,032 | 4.5% |
| `Entry<System.UInt64>[]` | 1,009 | 107,534,648 | 3.3% |

The sampled `QPackFieldLine[]` share moved from P18 plaintext 19.8% to P19 plaintext 16.6%. It did not disappear. This is expected because the optimized path still uses one private server-owned `QPackFieldLine[]` backing buffer; it removes the additional exact public materialization array from the unblocked server request path.

TraceEvent stack extraction again returned empty call stacks, so this trace should be treated as type-level allocation evidence only. PerfView or Visual Studio is still needed for source-line allocation attribution.

## Validation

Commands run:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\bdn-after --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p19-counters-20260528 -CaptureCounters
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext -Connections 16 -StreamsPerConnection 10 -DurationSeconds 30 -WarmupSeconds 2 -Repetitions 1 -RunId local-incursa-h3-p19-plaintext-gc-20260528 -CaptureCounters -TraceMode gc-allocation -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p19\plaintext-gc-allocation -TraceDurationSeconds 40
dotnet run --project .artifacts\perf\incursa-h3-p17\trace-byte-stack-analyzer\trace-byte-stack-analyzer.csproj -- .artifacts\perf\incursa-h3-p19\plaintext-gc-allocation\trace.nettrace .artifacts\perf\incursa-h3-p19\plaintext-byte-stack-analysis
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
git diff --check
$errors = @()
Get-ChildItem -Path scripts\perf -Filter *.ps1 | ForEach-Object {
  $tokens = $null
  $parseErrors = $null
  $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors) {
    $errors += $parseErrors | ForEach-Object { "$($_.Extent.File):$($_.Extent.StartLineNumber):$($_.Message)" }
  }
}
if ($errors.Count -gt 0) { $errors; exit 1 } else { 'PowerShell parser check passed for scripts\perf\*.ps1' }
```

Results:

- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed.
- BDN before and after runs: passed.
- ProtocolLab Incursa-only counters: 6/6 cells passed, 0 errors.
- P19 plaintext allocation trace: passed, TraceEvent analysis completed.
- `dotnet build`: passed with 0 warnings and 0 errors.
- focused `Http3HeaderValidationTests`: passed, 58/58.
- full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with known baseline only: 5 trace-link failures and 2 DoQ cancellation exact-type failures; 5,956 passed, 7 failed, 5,963 total.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

## Decision

The P19 change is worth keeping for the isolated server request path. It removes one request-header field-line array materialization from unblocked server request handling while preserving public QPACK defensive-copy behavior and HTTP/3 request semantics.

It is not a large enough change to move local ProtocolLab B/request conclusively. The remaining `QPackFieldLine[]` allocation is still visible because the server-owned path allocates its private backing buffer per request.

## Remaining Allocation Sources

Current post-P19 plaintext type-level allocation evidence still shows:

- `QPackFieldLine[]` as the top sampled type at 16.6%;
- `System.Byte[]` at 14.6%, with empty stacks in EventPipe/TraceEvent;
- `Http3DiagnosticEvent` at 4.6%;
- recovery/ACK/effect collection allocations below those top buckets.

## Recommended P20 Prompt

Continue Incursa H3 Performance Phase P20: decide the next post-P19 allocation target from fresh evidence.

Work in `C:\src\incursa\quic-dotnet`.

Context:

- P17 removed the per-request 16 KiB `Http3Server.ReadRequestAsync` scratch buffer allocation.
- P18 selected `QPackFieldLine[]` as the new top sampled type.
- P19 added an internal server-owned QPACK sink decode path and reduced server-shaped request decode/materialize allocation by about 0.5 KB/op.
- P19 preserved public QPACK array-returning API behavior.
- P19 ProtocolLab counters remained around 21.3-21.7 KB/request in local c16/s10 h2load.
- P19 plaintext allocation trace still shows `QPackFieldLine[]` as the top sampled type at 16.6%, with `System.Byte[]` at 14.6%.
- EventPipe/TraceEvent stack extraction is still empty, so source-line attribution requires Visual Studio or PerfView.

Primary goal:

Collect or inspect enough post-P19 evidence to select exactly one bounded P20 allocation target. Optimize only if the source is clear, behavior-testable, and not dependent on stale pre-P19 profiling data.

Candidate targets to evaluate:

1. The remaining server-owned `QPackFieldLine[]` backing buffer allocation, possibly with careful pooling or a small fixed inline buffer if behavior and lifetime are provably safe.
2. `System.Byte[]` sources, but only after Visual Studio or PerfView source-line attribution identifies the dominant call stack.
3. `Http3DiagnosticEvent` allocation when diagnostics are disabled, if source review confirms events are constructed before `IsEnabled` checks and behavior tests can prove diagnostics remain unchanged when enabled.

Required validation:

- add behavior tests before optimization;
- add or extend focused BDN rows before and after;
- run Incursa-only ProtocolLab counters if BDN moves meaningfully;
- run `dotnet build`, focused tests, full test project, benchmark build, `git diff --check`, and PowerShell parser checks;
- classify failures against the known 5 trace-link and 2 DoQ cancellation exact-type failures.
