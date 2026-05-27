# Incursa H3 Performance Phase P9: Request Header Materialization And Duplicate-Copy Reduction

Date: 2026-05-27

## Scope

Phase P9 targeted one bounded duplicate-copy/header-materialization source in the request header path. It did not change response generation, QPACK wire semantics, request validation semantics, QUIC packetization, QUIC scheduling, UDP send behavior, ProtocolLab benchmark semantics, or endpoint/sample behavior.

## P8 Recap

P8 delayed request body writer allocation until the first DATA frame. That hypothesis was real, but the selected path did not materially reduce isolated allocations or justify a ProtocolLab rerun. P8 left the top suspected allocation source in duplicate request header materialization across QPACK decode, request validation, and `Http3Request` construction.

## Evidence Reviewed

- P9 pre-edit full benchmark artifact: `.artifacts/perf/incursa-h3-p9/bdn-before/results/Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- P9 stage-isolation before artifact: `.artifacts/perf/incursa-h3-p9/bdn-before-stages/results/Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- P9 stage-isolation after artifact: `.artifacts/perf/incursa-h3-p9/bdn-after-stages/results/Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- P9 full after artifact: `.artifacts/perf/incursa-h3-p9/bdn-after/results/Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

## Stage-Isolation Benchmark Findings

The P9 stage split showed a narrow duplicate header materialization source:

| Benchmark | Before mean | Before alloc | After mean | After alloc | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| `RequestHeaders_DecodeOnly_Plaintext` | 270.50 ns | 1048 B | 212.76 ns | 1048 B | 0 B |
| `RequestHeaders_ValidateOnly_Plaintext` | 142.65 ns | 120 B | 151.35 ns | 120 B | 0 B |
| `RequestHeaders_ValidatorReceiveOnly_Plaintext` | 180.64 ns | 240 B | 191.35 ns | 240 B | 0 B |
| `RequestHeaders_OwnedValidatorReceiveOnly_Plaintext` | n/a | n/a | 160.11 ns | 120 B | -120 B versus public copy path |
| `RequestHeaders_MaterializeOnly_Plaintext` | 17.54 ns | 72 B | 19.16 ns | 72 B | 0 B |
| `RequestHeaders_DecodeValidateOnly_Plaintext` | 438.23 ns | 1168 B | 420.30 ns | 1168 B | 0 B |
| `RequestHeaders_DecodeValidateMaterialize_Plaintext` | 551.95 ns | 1408 B | 547.95 ns | 1288 B | -120 B |
| `RequestHeaders_DecodeValidateMaterialize_Json` | 611.54 ns | 1392 B | 625.11 ns | 1272 B | -120 B |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | 754.41 ns | 1408 B | 548.32 ns | 1288 B | -120 B |

The full after benchmark produced the same allocation shape:

| Benchmark | P9 before alloc | P9 after alloc | Delta |
| --- | ---: | ---: | ---: |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | 1408 B | 1288 B | -120 B |
| `RequestLifecycle_HeadersOnlyGetPlaintext` | 1408 B | 1288 B | -120 B |
| `RequestLifecycle_HeadersOnlyGetJson` | 1392 B | 1272 B | -120 B |
| `RequestLifecycle_GetWithEmptyData` | 1912 B | 1792 B | -120 B |

Short-run mean timings were noisy. The reliable P9 success signal is allocation reduction, not CPU time.

## Confirmed Duplicate Materialization Source

`QPackDecoder.DecodeFieldSection` returns a request-owned `QPackFieldLine[]`. Before P9, `Http3Server.ProcessRequestFrameAsync` passed that array through the public `Http3RequestMessageValidator.ReceiveHeaders(IReadOnlyList<QPackFieldLine>)` API, which intentionally defensive-copied with `ToArray()`. That copy is correct for arbitrary public callers but unnecessary for the server-owned decode result.

The confirmed duplicate source is therefore the extra validator-owned field-line array allocation in the server path after QPACK decode.

## Selected Optimization Target

Selected target: avoid one duplicate decoded field-line array copy between QPACK decode and request validator storage in the server-owned request path.

Implementation:

- Added `Http3RequestMessageValidator.ReceiveOwnedHeaders(QPackFieldLine[] fieldSection, ...)` as an internal API.
- Kept public `ReceiveHeaders(IReadOnlyList<QPackFieldLine>, ...)` defensive-copy behavior unchanged.
- Changed `Http3Server.ProcessRequestFrameAsync` to pass the freshly decoded owned array to `ReceiveOwnedHeaders`.
- Added benchmark access to the internal HTTP/3 path with `InternalsVisibleTo("Incursa.Quic.Benchmarks")`.

This keeps the ownership boundary explicit: public caller-owned header collections are copied; server-owned decoder arrays are stored directly after validation.

## Behavior-Preservation Tests

Added focused tests in `Http3HeaderValidationTests`:

- `DecodeValidateAndMaterializeRequest_TechEmpowerGet_PreservesRequestSemantics` for `/plaintext` and `/json`.
- `RequestSequence_PublicReceiveHeadersCopiesMutableInput` to lock the public defensive-copy contract.

Existing focused HTTP/3 minimal server tests were rerun and passed, including HEADERS-only, DATA-bearing, fragmented, empty DATA, multiple DATA, and invalid DATA-before-HEADERS behavior from P8.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests|FullyQualifiedName~Http3MinimalServerTests"
```

Result: passed, 66 tests.

## Commands Run

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p9\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*RequestHeaders*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p9\bdn-before-stages --inProcess
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests|FullyQualifiedName~Http3MinimalServerTests"
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*RequestHeaders*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p9\bdn-after-stages --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p9\bdn-after --inProcess
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~DoqFatalProtocolErrorTests.ServerTreatsInboundUnidirectionalStreamAsFatalProtocolErrorAndClosesConnection"
git diff --check
PowerShell parser check for scripts\perf\*.ps1
```

## Validation Result

- `dotnet build`: passed.
- Focused HTTP/3 request/header tests: passed, 66 tests.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 8 failures.
  - 5 trace-link failures: pre-existing known family.
  - 2 DoQ cancellation exact-type failures: pre-existing known family.
  - 1 DoQ fatal-protocol timeout: intermittent family already observed in P8; passed when rerun individually.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

No P9 request/header failure family was introduced.

## ProtocolLab Counter Rerun

ProtocolLab was not rerun in P9. The isolated allocation reduction is 120 B/op in the server-shaped request lifecycle benchmarks, which is correct but small against the roughly 40 KB/request P7/P8 end-to-end allocation signal. A counter rerun would likely be dominated by noise at this phase.

## Is The Change Worth Keeping?

Yes. The change removes one measured duplicate array allocation from the real server-owned request header path while preserving public defensive-copy behavior and request semantics. The reduction is narrow and not expected to materially move h2load counters by itself.

## Remaining Suspected Allocation Sources

1. QPACK request decode itself remains roughly 1032-1080 B/op for the TechEmpower request fixture.
2. `Http3HeaderValidator.ValidateRequestHeaders` still allocates about 120 B/op, likely from content-length tracking even when no `content-length` field is present.
3. `Http3Request` still allocates about 72 B/op for the request object and empty body copy semantics.
4. `Http3Server.ReadRequestAsync` still has per-request async/reader/validator/request lifecycle allocations not fully isolated by P9.
5. End-to-end ProtocolLab still shows a much larger allocation signal than the isolated request/response microbenchmarks explain, so broader stream scheduling/async and QUIC/H3 loop attribution remains necessary.

## Recommended P10 Prompt

Continue Incursa H3 Performance Phase P10: request validation allocation reduction and end-to-end attribution refresh.

Use P9 evidence showing that the server-owned validator receive path reduced request lifecycle allocation by 120 B/op but did not explain the remaining roughly 40 KB/request signal. Target exactly one measured source after adding behavior tests:

- Inspect and benchmark `Http3HeaderValidator.ValidateRequestHeaders`, especially content-length tracking and pseudo-header validation allocations.
- Preserve all invalid-header and duplicate/missing pseudo-header behavior.
- Do not change QPACK wire semantics, response generation, QUIC packetization, QUIC scheduling, UDP send behavior, or ProtocolLab semantics.
- If validation allocation drops meaningfully, rerun ProtocolLab Incursa-only H3 h2load with runtime counters.
- If validation allocation is not a safe target, use dotnet-trace/PerfView allocation attribution on the P9 build to find the next non-microbenchmark source behind the remaining end-to-end allocation.
