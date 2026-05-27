# Incursa H3 Performance Phase P8

Phase P8 targeted no-body GET request lifecycle allocation in `Http3Server.ReadRequestAsync`. The phase remained bounded to request-side body-buffer lifecycle. It did not change response generation, QPACK encode/decode semantics, QUIC packetization, scheduling, UDP send behavior, endpoint/sample behavior, or ProtocolLab benchmark semantics.

## P7 Recap

P7 reduced request-side QPACK/header decode allocations:

| Benchmark | P7 before allocated | P7 after allocated |
| --- | ---: | ---: |
| `RequestHeaders_DecodePlaintextFieldSection` | 4,632 B | 1,048 B |
| `RequestHeaders_DecodeJsonFieldSection` | 4,616 B | 1,032 B |
| `RequestHeaders_DecodeAndValidatePlaintext` | 4,800 B | 1,168 B |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | 4,992 B | 1,408 B |

ProtocolLab counters moved generally downward after P7, but the remaining end-to-end allocation signal stayed around 40 KB/request.

## Confirmed Allocation Source

Source review confirmed that `Http3Server.ReadRequestAsync` allocated an `ArrayBufferWriter<byte>` body writer before observing any DATA frame:

```csharp
ArrayBufferWriter<byte> body = new();
```

This hypothesis was only partially confirmed. The writer object was allocated eagerly, but `ArrayBufferWriter<byte>` backing byte storage was already lazy and was not allocated until body data was written. For HEADERS-only GET requests, the avoidable allocation was therefore just the body writer object, not a large byte buffer.

`Http3Request` already exposes an empty body for HEADERS-only requests, and that same visible empty-body shape can be preserved by passing `ReadOnlyMemory<byte>.Empty` when no DATA frame was observed.

## Selected Optimization Target

The selected target was delayed request body writer allocation in `Http3Server.ReadRequestAsync` and `ProcessRequestFrameAsync`:

- keep the request body writer `null` until the first DATA frame is processed
- allocate `ArrayBufferWriter<byte>` only when DATA is observed
- preserve empty-body request semantics by passing `ReadOnlyMemory<byte>.Empty` when no DATA was observed
- preserve DATA frame ordering and validation behavior

This was safe and bounded because it only changes allocation timing for the body writer object. It does not alter request frame validation, QPACK decode, header validation, request routing, or response generation.

## Behavior-Preservation Tests

P8 added request lifecycle tests in `tests/Incursa.Quic.Tests/Http3MinimalServerTests.cs`:

| Test | Coverage |
| --- | --- |
| `HeadersOnlyGet_DeliversEmptyBodyToHandler` | HEADERS-only `GET /plaintext` and `GET /json` preserve method, path, headers, and empty body semantics. |
| `PostDataRequest_WithEmptyDataFrame_DeliversEmptyBodyToHandler` | Empty DATA frame still reaches the handler as an empty body. |
| `PostDataRequest_WithMultipleDataFrames_PreservesBodyOrdering` | Multiple DATA frames preserve body ordering. |
| `PostDataRequest_WithFragmentedFrames_PreservesBody` | Fragmented HEADERS+DATA bytes preserve body bytes. |
| `RequestDataBeforeHeaders_Returns400` | DATA-before-HEADERS invalid ordering still returns the existing bad-request behavior. |

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3MinimalServerTests|FullyQualifiedName~Http3HeaderValidationTests"
```

Result: passed, 63 passed, 0 failed.

## Benchmark Additions

P8 added request lifecycle BenchmarkDotNet coverage in `benchmarks/Http3AllocationPathBenchmarks.cs`:

| Benchmark | Purpose |
| --- | --- |
| `RequestLifecycle_HeadersOnlyGetPlaintext` | Approximate HEADERS-only `GET /plaintext` request lifecycle after header decode/validation. |
| `RequestLifecycle_HeadersOnlyGetJson` | Approximate HEADERS-only `GET /json` request lifecycle after header decode/validation. |
| `RequestLifecycle_GetWithEmptyData` | Approximate request lifecycle when an empty DATA frame forces body writer use. |

The benchmark models the selected lifecycle allocation directly; it does not invoke the full async server loop.

## Benchmark Results

Before artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-before\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-before-lifecycle\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

After artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-after\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-after-lifecycle\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

| Benchmark | Before mean | After mean | Mean delta | Before alloc | After alloc | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `RequestHeaders_DecodePlaintextFieldSection` | 226.43 ns | 199.19 ns | -27.24 ns | 1,048 B | 1,048 B | 0 B |
| `RequestHeaders_DecodeJsonFieldSection` | 259.85 ns | 230.72 ns | -29.13 ns | 1,032 B | 1,032 B | 0 B |
| `RequestHeaders_DecodeAndValidatePlaintext` | 423.10 ns | 394.97 ns | -28.13 ns | 1,168 B | 1,168 B | 0 B |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | 638.52 ns | 557.10 ns | -81.42 ns | 1,408 B | 1,408 B | 0 B |
| `RequestLifecycle_HeadersOnlyGetPlaintext` | 660.40 ns | 565.24 ns | -95.16 ns | 1.38 KB | 1,408 B | no material change |
| `RequestLifecycle_HeadersOnlyGetJson` | 627.90 ns | 603.44 ns | -24.46 ns | 1.36 KB | 1,392 B | no material change |
| `RequestLifecycle_GetWithEmptyData` | 861.10 ns | 780.49 ns | -80.61 ns | 1.87 KB | 1,912 B | no material change |

The ShortRun mean-time numbers are noisy and should not be read as a throughput conclusion. The allocation result is the important signal: delaying the body writer object did not produce a material measured allocation reduction in the isolated lifecycle benchmarks.

## ProtocolLab Decision

ProtocolLab was not rerun in P8. The selected microbenchmark did not show a meaningful allocation drop, so an end-to-end h2load counter run was unlikely to produce an interpretable signal over the existing local-run noise.

## Source Review Findings

Measured:

- The no-body lifecycle benchmark remains about 1.4 KB/op after the change.
- Request header decode/validation allocations remain unchanged from P7 levels.
- The selected delayed writer allocation was too small to show a material BenchmarkDotNet allocation delta.

Confirmed but not dominant:

- `Http3Server.ReadRequestAsync` eagerly allocated the body writer object before P8.
- `ArrayBufferWriter<byte>` backing storage was already lazy, so HEADERS-only GET did not allocate a body byte array through that writer.

Likely remaining contributors:

- `Http3RequestMessageValidator.ReceiveHeaders` still copies decoded headers with `fieldSection.ToArray()`.
- `QPackDecoder.DecodeAvailableFieldSection` still returns `fields.WrittenSpan.ToArray()`.
- `Http3HeaderValidator.ValidateRequestHeaders` still scans and may allocate for content-length tracking.
- `Http3Server.ReadRequestAsync` still allocates per request: `Http3FrameReader`, `Http3RequestMessageValidator`, read buffer, request object, and decoded/header arrays.
- `QPackStringLiteral.Read` still creates strings for literal header values.

## Validation

Commands run:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-before --inProcess
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3MinimalServerTests|FullyQualifiedName~Http3HeaderValidationTests"
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*RequestLifecycle*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-before-lifecycle --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*RequestLifecycle*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-after-lifecycle --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p8\bdn-after --inProcess
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
git diff --check
PowerShell parser check for scripts\perf\*.ps1
```

Final validation results:

| Command | Result |
| --- | --- |
| `dotnet build` | Passed, 0 warnings, 0 errors. |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3MinimalServerTests|FullyQualifiedName~Http3HeaderValidationTests"` | Passed, 63 passed, 0 failed. |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj` | Failed with 7 failures: the known 5 trace-link failures and the known 2 DoQ cancellation exact-type failures. |
| `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj` | Passed, 0 warnings, 0 errors. |
| `git diff --check` | Passed. |
| PowerShell parser check for `scripts\perf\*.ps1` | Passed. |

## Keep Decision

The code change is behavior-safe and small, but it is not a material allocation win. It is acceptable to keep because it removes an unnecessary eager object allocation without changing semantics, but P8 should be treated as a negative measurement result for the no-body body-buffer hypothesis.

## Remaining Suspected Allocation Sources

Top remaining suspected source: duplicate request header materialization/copying across QPACK decode, `Http3RequestMessageValidator.ReceiveHeaders`, validation, and `Http3Request` creation.

Other remaining suspects:

- QPACK literal string decoding.
- `Http3HeaderValidator` content-length list allocation.
- Per-request frame reader, validator, read-buffer, and request object lifecycle.
- Async/server-loop allocation outside the isolated microbenchmarks.
- QUIC stream/send queue allocation outside the request lifecycle layer.

## Recommended P9 Prompt

Continue Incursa H3 Performance Phase P9: request header materialization and duplicate-copy reduction.

Use P8 evidence to avoid spending more time on no-body body-buffer allocation. Target exactly one request header lifecycle allocation source, preferably the duplicate decoded header array copy between `QPackDecoder.DecodeFieldSection`, `Http3RequestMessageValidator.ReceiveHeaders`, and `Http3Request` materialization. Add behavior-preservation tests for valid headers, duplicate pseudo-headers, missing pseudo-headers, pseudo-header ordering, unknown regular headers, and malformed QPACK/header behavior. Establish before/after BenchmarkDotNet baselines for `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` and any new validator/header-copy benchmark. Do not change QPACK decode semantics, response generation, QUIC scheduling, packetization, UDP send behavior, request validation semantics, or ProtocolLab benchmark semantics. Rerun ProtocolLab counters only if the selected microbenchmark shows a meaningful allocation drop.
