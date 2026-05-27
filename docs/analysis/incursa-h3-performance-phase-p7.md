# Incursa H3 Performance Phase P7

Phase P7 targeted request header decode and request object allocation attribution. The phase remained bounded to request-side QPACK/header decode behavior, with no changes to response generation, QUIC packetization, scheduling, UDP send behavior, endpoint semantics, or ProtocolLab benchmark semantics.

## P6 Recap

P6 reduced `Http3FrameReader` request frame materialization allocations:

| Benchmark | P5/P6 before allocated | P6 after allocated |
| --- | ---: | ---: |
| `FrameReader_ReadPlaintextHeaders` | 296 B | 224 B |
| `FrameReader_ReadJsonHeaders` | 280 B | 216 B |
| `FrameReader_ReadFragmentedPlaintextHeaders` | unchanged | unchanged |

ProtocolLab counters were mixed after P6, with JSON nearly flat and plaintext noisy. The remaining suspected request-side allocation source was `Http3Server.ReadRequestAsync` after frame materialization, especially QPACK field-section decode, pseudo-header/header materialization, validation, and request object lifecycle.

## Request-Side Benchmark Additions

P7 added focused BenchmarkDotNet coverage in `benchmarks/Http3AllocationPathBenchmarks.cs`:

| Benchmark | Purpose |
| --- | --- |
| `RequestHeaders_DecodePlaintextFieldSection` | Decode a TechEmpower-shaped `GET /plaintext` HTTP/3 request field section through `QPackDecoder`. |
| `RequestHeaders_DecodeJsonFieldSection` | Decode a TechEmpower-shaped `GET /json` HTTP/3 request field section through `QPackDecoder`. |
| `RequestHeaders_DecodeAndValidatePlaintext` | Decode request headers and run HTTP/3 request pseudo-header validation. |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | Approximate the no-body GET request decode, validator, and `Http3Request` materialization shape without invoking the full async server loop. |

The request header fixture is a documented TechEmpower-style h2load shape:

- `:method` = `GET`
- `:scheme` = `https`
- `:authority` = `localhost:5444`
- `:path` = `/plaintext` or `/json`
- `user-agent` = `h2load`
- `accept` = `*/*`

## Selected Optimization Target

The measured target was `QPackDecoder.DecodeAvailableFieldSection`.

Before P7, the decoder used `new ArrayBufferWriter<QPackFieldLine>()` for decoded field lines. On tiny request field sections this incurred the default `ArrayBufferWriter<T>` first-buffer growth shape even though the encoded representation length is already an upper bound on field-line count because each representation consumes at least one byte.

The optimization now initializes the field-line writer with a bounded capacity based on remaining encoded representation bytes, capped at 32 entries:

- no field representations: keep the lazy default writer
- field representations present: use `min(remainingRepresentationBytes, 32)` as the initial field-line capacity

This preserves QPACK decoding semantics. It does not bypass static/dynamic table lookup, string literal decoding, blocked stream handling, invalid representation checks, largest reference validation, or final field-line output shape.

## Behavior-Preservation Tests

P7 added request decode and validation tests in `tests/Incursa.Quic.Tests/Http3HeaderValidationTests.cs`:

| Test | Coverage |
| --- | --- |
| `DecodeAndValidateRequestHeaders_TechEmpowerGet_PreservesFields` | Valid `/plaintext` and `/json` pseudo-headers decode and validate with exact field preservation. |
| `DecodeAndValidateRequestHeaders_UnknownRegularHeader_RemainsAccepted` | Unknown regular headers remain accepted. |
| `DecodeAndValidateRequestHeaders_DuplicatePseudoHeader_ThrowsMessageError` | Duplicate pseudo-header behavior remains a message error. |
| `DecodeAndValidateRequestHeaders_MissingRequiredPseudoHeader_ThrowsMessageError` | Missing required pseudo-header behavior remains a message error. |
| `DecodeAndValidateRequestHeaders_PseudoHeaderAfterRegularHeader_ThrowsMessageError` | Pseudo-header ordering validation remains enforced. |
| `DecodeAndValidateRequestHeaders_MalformedQPackFieldSection_ThrowsDecompressionFailed` | Malformed QPACK field-section behavior remains decompression failure. |

Focused parser/header validation command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests|FullyQualifiedName~Http3FrameLayerTests"
```

Result: passed, 77 passed, 0 failed.

## Benchmark Results

Before artifact:

`C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p7\bdn-before-request\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

After artifact:

`C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p7\bdn-after\results\Incursa.Quic.Benchmarks.Http3AllocationPathBenchmarks-report-github.md`

| Benchmark | Before mean | After mean | Mean delta | Before alloc | After alloc | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `FrameReader_ReadPlaintextHeaders` | 76.82 ns | 84.65 ns | +7.83 ns | 224 B | 224 B | 0 B |
| `FrameReader_ReadJsonHeaders` | 83.39 ns | 82.69 ns | -0.70 ns | 216 B | 216 B | 0 B |
| `FrameReader_ReadFragmentedPlaintextHeaders` | 164.78 ns | 161.33 ns | -3.45 ns | 400 B | 400 B | 0 B |
| `RequestHeaders_DecodePlaintextFieldSection` | 451.80 ns | 311.74 ns | -140.06 ns | 4,632 B | 1,048 B | -3,584 B |
| `RequestHeaders_DecodeJsonFieldSection` | 483.52 ns | 269.57 ns | -213.95 ns | 4,616 B | 1,032 B | -3,584 B |
| `RequestHeaders_DecodeAndValidatePlaintext` | 761.47 ns | 480.21 ns | -281.26 ns | 4,800 B | 1,168 B | -3,632 B |
| `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` | 812.89 ns | 623.88 ns | -189.01 ns | 4,992 B | 1,408 B | -3,584 B |

The selected request-side path dropped by about 3.5 KB/op across the decode and decode-plus-validation shapes. That is large enough to keep the change.

## ProtocolLab Counter Comparison

ProtocolLab artifact:

`C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p7-counters-after-20260527`

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext,http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -CaptureCounters -RunId local-incursa-h3-p7-counters-after-20260527
```

All six validation and benchmark runs passed. Runtime counters were captured for all six runs.

| Scenario | Rep | Requests/s | p50 ms | p95 ms | p99 ms | Allocation rate | Estimated bytes/request |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JSON | 1 | 2,579.7 | 26.60 | 35.55 | 43.71 | 99.12 MB/s | 40,290 B |
| JSON | 2 | 2,504.0 | 27.55 | 34.65 | 40.43 | 99.13 MB/s | 41,512 B |
| JSON | 3 | 2,620.1 | 18.59 | 24.92 | 29.10 | 100.12 MB/s | 40,067 B |
| Plaintext | 1 | 2,692.1 | 21.97 | 27.79 | 33.06 | 103.35 MB/s | 40,255 B |
| Plaintext | 2 | 1,531.9 | 43.42 | 56.11 | 61.76 | 109.04 MB/s | 74,640 B |
| Plaintext | 3 | 2,610.8 | 26.09 | 36.23 | 42.24 | 100.11 MB/s | 40,206 B |

Median paired estimates:

| Scenario | P5/P6 comparison point | P7 paired median | Movement |
| --- | ---: | ---: | ---: |
| JSON | about 41,404 B/request after P6 | about 40,290 B/request | -1,114 B/request |
| Plaintext | about 42,212 B/request after P6 | about 40,255 B/request | -1,957 B/request |

The ProtocolLab run remains local/shared-host evidence only. Plaintext repetition 2 was an outlier and ProtocolLab flagged result instability. Directionally, the runtime allocation signal moved in the expected direction, but this phase should not be interpreted as proof that all remaining request allocation has been explained.

## Source Review Findings

Measured:

- `QPackDecoder.DecodeAvailableFieldSection` allocated about 4.6 KB/op in request field-section decode before P7 because the decoded field collection used the default `ArrayBufferWriter<QPackFieldLine>` allocation shape.
- Reducing the initial field-line capacity dropped request field-section decode to about 1.0 KB/op.

Likely remaining contributors:

- `QPackStringLiteral.Read` still creates strings for literal header values.
- `QPackDecoder.DecodeAvailableFieldSection` still returns `fields.WrittenSpan.ToArray()`.
- `Http3RequestMessageValidator.ReceiveHeaders` still copies decoded fields via `fieldSection.ToArray()`.
- `Http3HeaderValidator.ValidateRequestHeaders` scans and materializes a `List<ulong>` for content-length values.
- `Http3Server.ReadRequestAsync` still allocates per request: `Http3FrameReader`, `Http3RequestMessageValidator`, request read buffer, and an `ArrayBufferWriter<byte>` body buffer before knowing whether a DATA frame exists.

Possible contributors:

- Per-request `Http3Request` object lifecycle and retained header array/list shape.
- Empty-body GET request body representation.
- Repeated pseudo-header lookup scans across validator and request creation.

## Validation

Commands run:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p7\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p7\bdn-before-request --inProcess
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests|FullyQualifiedName~Http3FrameLayerTests"
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p7\bdn-after --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -Scenarios http.core.plaintext,http.core.json -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -CaptureCounters -RunId local-incursa-h3-p7-counters-after-20260527
```

Final repository validation is recorded in the final response for this phase.

Final validation results:

| Command | Result |
| --- | --- |
| `dotnet build` | Passed, 0 warnings, 0 errors. |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3HeaderValidationTests|FullyQualifiedName~Http3FrameLayerTests"` | Passed, 77 passed, 0 failed. |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj` | Failed with 8 failures: the known 5 trace-link failures, the known 2 DoQ cancellation exact-type failures, plus one DoQ fatal-protocol timeout. |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName=Incursa.Quic.Tests.DoqFatalProtocolErrorTests.ServerTreatsInboundUnidirectionalStreamAsFatalProtocolErrorAndClosesConnection"` | Passed, 1 passed, 0 failed. The extra full-suite failure appears intermittent and unrelated to the P7 QPACK/request-header change. |
| `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj` | Passed, 0 warnings, 0 errors. |
| `git diff --check` | Passed. |
| PowerShell parser check for `scripts\perf\*.ps1` | Passed. |

## Keep Decision

Keep the P7 change. It is narrow, measurable, preserves request decode/validation behavior, and reduces a request-side allocation source that appears in the end-to-end path.

## Remaining Suspected Allocation Sources

Top remaining suspected source: `Http3Server.ReadRequestAsync` request object/body lifecycle after QPACK decode, specifically avoidable no-body GET request body allocation and remaining header-copy materialization in `Http3RequestMessageValidator.ReceiveHeaders`.

Other remaining suspects:

- QPACK literal string decoding.
- Duplicate decoded header array copies.
- `Http3HeaderValidator` content-length list allocation.
- Per-request frame reader and validator lifecycle.
- QUIC stream/send queue allocation outside the request header decode layer.

## Recommended P8 Prompt

Continue Incursa H3 Performance Phase P8: no-body GET request lifecycle allocation reduction.

Use P7 evidence to target exactly one request lifecycle allocation source in `Http3Server.ReadRequestAsync` / `Http3RequestMessageValidator`: preferably delayed request body buffer allocation for no-body GET requests if source review confirms `ArrayBufferWriter<byte>` is allocated before any DATA frame. Add behavior-preservation tests for GET with no DATA, GET with DATA where allowed/invalid as current behavior defines, HEADERS-only request completion, HEADERS+DATA body preservation, and invalid sequencing. Establish before/after BenchmarkDotNet baselines for `RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext` and any new no-body request lifecycle benchmark. Do not change QPACK decoding, response generation, QUIC scheduling, packetization, UDP send behavior, or ProtocolLab semantics. Rerun ProtocolLab Incursa-only H3 counters only if the selected microbenchmark drops meaningfully.
