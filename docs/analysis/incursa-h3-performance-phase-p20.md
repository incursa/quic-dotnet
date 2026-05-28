# Incursa H3 Performance Phase P20

Date: 2026-05-28

## Scope

Phase P20 reduced the response-side HTTP/3 QPACK field-line builder allocation. The change is limited to `Http3Server.BuildResponseHeaders` and the benchmark/test seams needed to prove response wire behavior.

Guardrails held:

- request decoding was not changed;
- QPACK wire semantics were not changed;
- public QPACK APIs were not changed;
- QUIC scheduling, UDP send, packet protection, ACK/loss recovery, and ProtocolLab semantics were not changed;
- no `/plaintext`, `/json`, h2load, or TechEmpower special casing was added.

## Allocation Evidence

Fresh Visual Studio allocation profiling after P19 showed a response-side source:

```text
System.Array.Resize<T>
  -> Http3Server.WriteField(IBufferWriter<QPackFieldLine>, QPackFieldLine)
  -> Http3Server.BuildResponseHeaders(Http3ServerResponse)
  -> Http3Server.WriteResponseAsync(...)
```

Observed allocation:

| Source | Allocations | Bytes | Approx. per response |
| --- | ---: | ---: | ---: |
| `System.Array.Resize<T>` under `Http3Server.WriteField` | 16,948 | 69,825,760 | 4,120 B |

The exact source was the previous default `ArrayBufferWriter<QPackFieldLine>` in `BuildResponseHeaders`. The first `WriteField` called `GetSpan(1)` on a default writer, causing an internal resize to the writer default capacity before the builder later returned `headers.WrittenSpan.ToArray()`.

For the TechEmpower plaintext and JSON response path, the expected response field count is five:

1. `:status`
2. `server`
3. `date`
4. `content-type`
5. `content-length`

The headers are known before building because `Http3ServerResponse.Headers` is already materialized as an `IReadOnlyList<QPackFieldLine>`.

## Selected Optimization

Selected design: exact-sized response field-line array.

`BuildResponseHeaders` now:

- counts one synthetic `:status` plus non-`:status` response headers;
- allocates `new QPackFieldLine[headerCount]`;
- writes `:status` at index zero;
- copies regular response headers in their existing order;
- skips duplicate caller-supplied `:status` headers as before.

The removed path was the response-local `ArrayBufferWriter<QPackFieldLine>` and `WriteField` helper. No pooling is used, so there is no returned-pool lifetime or clearing decision. The exact array is private to the response build/encode operation and is not exposed through a public QPACK API.

## Behavior Tests

Focused response behavior tests were added in `tests\Incursa.Quic.Tests\Http3FrameLayerTests.cs`:

- `ServerResponseBuilder_PreservesTechEmpowerFieldSectionAndFrameBytes`
- `ServerResponseBuilder_PreservesCustomHeadersAndSkipsDuplicateStatus`

The tests cover plaintext and JSON response field-section bytes, HEADERS frame bytes, DATA frame bytes, combined response bytes, `:status`, `server`, `date`, `content-type`, `content-length`, custom headers, duplicate status skipping, decoded QPACK headers, and observable header ordering.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3FrameLayerTests"
```

Result: passed, 36/36.

## BenchmarkDotNet

Before command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*ResponseHeaders*" "*ResponseFrames*" "*ResponsePipeline*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p20\bdn-before `
  --inProcess
```

After command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*ResponseHeaders*" "*ResponseFrames*" "*ResponsePipeline*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p20\bdn-after `
  --inProcess
```

Artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p20\bdn-before`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p20\bdn-after`

Selected results:

| Benchmark | Before mean | Before allocated | After mean | After allocated | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ResponseHeaders_BuildPlaintextHeaders` | 347.21 ns | 4,288 B | 45.65 ns | 104 B | -4,184 B |
| `ResponseHeaders_BuildJsonHeaders` | 405.50 ns | 4,288 B | 42.62 ns | 104 B | -4,184 B |
| `ResponseHeaders_EncodePlaintextFieldSection` | 877.12 ns | 424 B | 800.79 ns | 424 B | 0 B |
| `ResponseHeaders_EncodeJsonFieldSection` | 918.15 ns | 424 B | 826.74 ns | 424 B | 0 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 854.04 ns | 648 B | 910.19 ns | 648 B | 0 B |
| `ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload` | 1,023.90 ns | 680 B | 973.36 ns | 680 B | 0 B |
| `ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload` | 891.64 ns | 696 B | 942.40 ns | 696 B | 0 B |

Interpretation:

- The targeted builder allocation dropped from 4,288 B/op to 104 B/op.
- The `Array.Resize<T>` path disappeared from the targeted builder because `BuildResponseHeaders` no longer uses `ArrayBufferWriter<QPackFieldLine>`.
- The remaining 104 B/op is the exact five-entry `QPackFieldLine[]` returned to the response encoder.
- Downstream encode/frame/pipeline rows are intentionally flat because P20 did not change byte encoding or frame buffering.

## ProtocolLab Counters

Incursa-only command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext,http.core.json `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -RunId local-incursa-h3-p20-counters-20260528 `
  -CaptureCounters
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p20-counters-20260528`

All 6 validation and benchmark cells passed. Runtime counters were captured for all 6 cells.

| Scenario | Req/s median | p50 ms | p95 ms | p99 ms | Allocation rate median | B/request est. | CPU mean/max | GC gen0/gen1/gen2 | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `http.core.json` | 2,503.8 | 26.69 | 36.79 | 43.04 | 50,962,197 B/s | 20,354 B | 67.0% / 164.1% | 64 / 19 / 4 | 0 |
| `http.core.plaintext` | 2,603.6 | 24.88 | 36.68 | 43.01 | 51,272,938 B/s | 19,693 B | 67.6% / 159.4% | 64 / 20 / 4 | 0 |

Comparison against P19 Incursa-only counters:

| Scenario | P19 B/request | P20 B/request | Delta |
| --- | ---: | ---: | ---: |
| `http.core.json` | 21,722 B | 20,354 B | -1,368 B |
| `http.core.plaintext` | 21,344 B | 19,693 B | -1,651 B |

The B/request movement is directionally consistent with the BDN builder improvement, but the run also had lower request throughput than P19. Treat the ProtocolLab counter result as local shared-host evidence, not a stable throughput claim.

Kestrel-vs-Incursa refresh command:

```powershell
dotnet run --project src\Incursa.ProtocolLab.Cli -- run `
  --implementations kestrel-http3,incursa-http3 `
  --scenarios http.core.plaintext,http.core.json `
  --protocol h3 `
  --load-tool h2load `
  --load-tool-mode docker `
  --connections 16 `
  --streams-per-connection 10 `
  --duration 10 `
  --warmup 2 `
  --repetitions 3 `
  --capture-counters `
  --counter-refresh-interval 1 `
  --output C:\src\incursa\protocol-lab\.artifacts\runs `
  --run-id local-h3-kestrel-incursa-p20-counters-20260528
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-p20-counters-20260528`

All 12 cells passed with counters:

| Implementation | Scenario | Req/s median | p50 ms | p95 ms | p99 ms | Allocation rate median | B/request est. | CPU mean/max | GC gen0/gen1/gen2 | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `incursa-http3` | `http.core.json` | 2,490.2 | 31.08 | 40.77 | 46.73 | 51,769,847 B/s | 20,789 B | 66.8% / 150.0% | 63 / 20 / 4 | 0 |
| `kestrel-http3` | `http.core.json` | 22,607.1 | 6.86 | 10.74 | 13.94 | 66,045,211 B/s | 2,921 B | 129.1% / 354.7% | 44 / 0 / 0 | 0 |
| `incursa-http3` | `http.core.plaintext` | 2,451.7 | 35.40 | 46.56 | 52.99 | 50,331,275 B/s | 20,529 B | 66.9% / 148.4% | 63 / 19 / 4 | 0 |
| `kestrel-http3` | `http.core.plaintext` | 23,514.1 | 6.60 | 10.09 | 13.42 | 69,993,005 B/s | 2,977 B | 138.2% / 409.4% | 46 / 0 / 0 | 0 |

Known local-run warnings remain: shared host, no CPU isolation, no network isolation, host-docker-internal rewrite, missing load-generator metrics, no repeated stable median, and single-machine measurement.

## Profiler Refresh

No fresh Visual Studio or dotMemory allocation profile was captured during P20. The targeted BDN benchmark proves the `Array.Resize<T>` builder path is gone for `BuildResponseHeaders`; manual profiler refresh is still needed to confirm the response-side source no longer appears in end-to-end allocation attribution.

`QPackFieldLine[]` did not disappear completely. P20 intentionally keeps one exact response-owned array because the response encoder consumes an `IReadOnlyList<QPackFieldLine>`. The array size is now proportional to the actual response header count instead of the `ArrayBufferWriter<T>` default growth size.

## Validation

Commands run:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponseHeaders*" "*ResponseFrames*" "*ResponsePipeline*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p20\bdn-before --inProcess
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3FrameLayerTests"
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponseHeaders*" "*ResponseFrames*" "*ResponsePipeline*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p20\bdn-after --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p20-counters-20260528 -CaptureCounters
dotnet run --project src\Incursa.ProtocolLab.Cli -- run --implementations kestrel-http3,incursa-http3 --scenarios http.core.plaintext,http.core.json --protocol h3 --load-tool h2load --load-tool-mode docker --connections 16 --streams-per-connection 10 --duration 10 --warmup 2 --repetitions 3 --capture-counters --counter-refresh-interval 1 --output C:\src\incursa\protocol-lab\.artifacts\runs --run-id local-h3-kestrel-incursa-p20-counters-20260528
dotnet build
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3FrameLayerTests"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~SupportedLoopbackBidirectionalStreamWriteAbortAfterPeerEofWithoutLocalWrites_ReportsTheReleasedPeerStreamCapacityOnce"
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

- `dotnet build`: passed, 0 warnings, 0 errors.
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed, 0 warnings, 0 errors.
- focused `Http3FrameLayerTests`: passed, 36/36.
- full test project: failed with 8 failures, 5 known trace-link failures, 2 known DoQ cancellation exact-type failures, and 1 loopback socket bind failure.
- the loopback socket bind failure passed when rerun individually, so it is classified as intermittent/environmental rather than a new P20 failure family.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

## Remaining Allocation Sources

The next target should not be selected from stale P18/P19 attribution alone. P20 reduced the response builder source and shifted Incursa local counters into roughly the 19.7-20.8 KB/request range in the P20 runs. The next phase should collect a fresh post-P20 allocation profile before optimizing.

Likely sources to check:

- remaining `System.Byte[]` stacks;
- remaining exact `QPackFieldLine[]` request/response arrays;
- `Http3DiagnosticEvent` allocation if diagnostics are disabled;
- packet build/protection buffers;
- UDP receive/datagram ownership.

## Recommended P21 Prompt

Continue Incursa H3 Performance Phase P21: post-P20 allocation attribution and next dominant source selection.

Work in `C:\src\incursa\quic-dotnet`.

P20 removed the large response header builder `Array.Resize<T>` allocation by replacing the default `ArrayBufferWriter<QPackFieldLine>` response builder with an exact-sized `QPackFieldLine[]`. BDN showed `ResponseHeaders_BuildPlaintextHeaders` and `ResponseHeaders_BuildJsonHeaders` drop from 4,288 B/op to 104 B/op. Incursa-only ProtocolLab counters moved to about 19.7-20.4 KB/request, with local Kestrel-vs-Incursa refresh showing Incursa about 20.5-20.8 KB/request.

Primary goal: collect fresh post-P20 allocation evidence and select the new dominant bounded allocation source. Do not optimize from stale P18/P19 profile data. Do not change request decoding, QPACK wire semantics, public QPACK APIs, QUIC scheduling, UDP send, packet protection, ACK/loss recovery, or ProtocolLab semantics. If one source is clearly dominant and behavior-testable, add tests first and optimize only that source; otherwise document the next measurement required.
