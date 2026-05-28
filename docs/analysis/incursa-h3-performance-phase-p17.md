# Incursa H3 Performance Phase P17

Date: 2026-05-27

## Scope

Phase P17 targeted only the per-request 16 KiB scratch/read buffer allocation in `Http3Server.ReadRequestAsync`.

Guardrails held:

- QUIC scheduling unchanged.
- UDP send behavior unchanged.
- Packet protection unchanged.
- QPACK semantics unchanged.
- HTTP/3 request validation semantics unchanged.
- ProtocolLab benchmark semantics unchanged.
- No benchmark-path or endpoint special-casing was added.

## Visual Studio Allocation Evidence

Manual Visual Studio allocation profiling with source line attribution identified the dominant source:

```text
Http3Server.ReadRequestAsync
  System.Byte[16384]
  23,309 allocations
  382,454,072 bytes
```

At the pre-change source, the exact allocation was:

```csharp
byte[] buffer = new byte[readBufferSize];
```

Location:

- `src\Incursa.Quic.Http3\Http3Server.cs`
- method: `Http3Server.ReadRequestAsync`
- pre-change line: 585

The buffer was temporary scratch for `QuicStream.ReadAsync`. It was passed to `Http3FrameReader.Read(buffer.AsSpan(0, bytesRead))` and was not returned in any request, body, header, or frame object.

## Buffer Lifetime And Safety

`Http3FrameReader` does not retain the caller's read buffer:

- complete frame payloads are materialized into owned storage with `ToArray()`;
- pending fragmented bytes are copied into reader-owned storage;
- later pending slices are also copied into reader-owned storage;
- request DATA payloads are copied from the frame payload into the request body `ArrayBufferWriter<byte>`.

That means the scratch buffer can be returned after `ReadRequestAsync` completes or throws. The production change rents one buffer from `ArrayPool<byte>.Shared` for the duration of the method and returns it in `finally`.

The read count remains `readBufferSize`, not the rented array's physical `Length`, because `ArrayPool<byte>.Shared.Rent(readBufferSize)` may return a larger array. This preserves the old logical 16 KiB maximum read size.

`clearArray: false` is intentional. The buffer contains transient request bytes that are copied into owned HTTP/3 frame/header/body storage before any pooled return. Clearing would add hot-path cost and no object is allowed to retain the scratch span.

## Behavior Coverage

Existing tests already covered:

- HEADERS-only GET `/plaintext` request parsing;
- HEADERS-only GET `/json` request parsing;
- HEADERS plus DATA request parsing;
- multiple DATA frames preserving body ordering;
- partial reads preserving pending bytes for DATA-bearing request frames;
- invalid DATA-before-HEADERS behavior;
- cancellation/abort behavior through existing abrupt stream/reset coverage.

P17 added:

- `HeadersOnlyGet_WithFragmentedHeaders_DeliversRequest`
- `TruncatedRequestFrame_Returns400`

These exercise fragmented HEADERS parsing and malformed/truncated frame behavior on the live minimal HTTP/3 server path after the buffer lifetime change.

No explicit pooled-memory retention test was added because the scratch buffer is not exposed through the public surface. The proof is by code ownership: frame reader pending/complete payloads and request bodies copy into owned storage before the pooled buffer is returned.

## Production Change

`Http3Server.ReadRequestAsync` now uses:

```csharp
byte[] buffer = ArrayPool<byte>.Shared.Rent(readBufferSize);
try
{
    ...
}
finally
{
    ArrayPool<byte>.Shared.Return(buffer, clearArray: false);
}
```

The no-body GET early return remains inside the `try`, so it still returns the pooled buffer. Error, cancellation, malformed-frame, and normal FIN paths also return the buffer through `finally`.

## BenchmarkDotNet

Commands:

```powershell
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj

dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p17\bdn-before `
  --inProcess

dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p17\bdn-after `
  --inProcess
```

Artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p17\bdn-before`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p17\bdn-after`

Selected before/after rows:

| Benchmark | Before mean | Before allocated | After mean | After allocated | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| `RequestReadBuffer_FrameReaderPlaintextHeaders` | 681.22 ns | 16,632 B | 91.94 ns | 224 B | -16,408 B |
| `ReadRequestAsync_HeadersOnlyGetPlaintext` | 1,632.14 ns | 18,104 B | 761.68 ns | 1,696 B | -16,408 B |
| `ReadRequestAsync_HeadersOnlyGetJson` | 1,619.57 ns | 18,080 B | 722.69 ns | 1,672 B | -16,408 B |
| `ReadRequestAsync_FragmentedHeaders` | 1,546.91 ns | 18,256 B | 812.09 ns | 1,848 B | -16,408 B |
| `ReadRequestAsync_HeadersAndSmallData` | 2,048.23 ns | 18,912 B | 1,196.12 ns | 2,504 B | -16,408 B |
| `RequestLifecycle_HeadersOnlyGetPlaintext` | 523.04 ns | 1,288 B | 530.23 ns | 1,288 B | 0 B |
| `RequestLifecycle_HeadersOnlyGetJson` | 512.84 ns | 1,272 B | 533.81 ns | 1,272 B | 0 B |

The request-lifecycle rows intentionally do not include the server scratch read buffer. They stayed allocation-flat, which is expected.

## ProtocolLab Incursa-Only Counter Run

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext,http.core.json `
  -Connections 16 -StreamsPerConnection 10 `
  -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 `
  -RunId local-incursa-h3-p17-buffer-pool-counters-20260527 `
  -CaptureCounters
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p17-buffer-pool-counters-20260527`

All 6 cells passed validation and benchmark execution. Runtime counters were captured for all 6 cells.

| Scenario | Rep | Req/s | p50 ms | p95 ms | p99 ms | Allocation rate B/s | B/request est. | CPU mean | GC gen0/gen1/gen2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `http.core.json` | 1 | 3,745.8 | 20.693 | 29.678 | 35.453 | 80,307,501 | 21,439 | 70.4% | 100 / 32 / 4 |
| `http.core.json` | 2 | 3,573.6 | 24.150 | 34.515 | 44.568 | 78,797,311 | 22,050 | 71.4% | 98 / 31 / 4 |
| `http.core.json` | 3 | 3,752.1 | 15.313 | 22.156 | 29.094 | 81,706,781 | 21,776 | 70.0% | 102 / 32 / 4 |
| `http.core.plaintext` | 1 | 3,686.1 | 18.043 | 26.018 | 32.151 | 80,122,423 | 21,736 | 69.1% | 100 / 32 / 5 |
| `http.core.plaintext` | 2 | 3,391.9 | 25.836 | 35.293 | 43.561 | 78,228,749 | 23,063 | 71.0% | 96 / 30 / 4 |
| `http.core.plaintext` | 3 | 3,820.6 | 15.094 | 21.534 | 28.689 | 82,266,463 | 21,532 | 68.3% | 102 / 33 / 5 |

Compared with the current pre-P17 range of about 33-36 KB/request, this is a clear local counter movement to roughly 21-23 KB/request.

## Kestrel Vs Incursa Refresh

Because the Incursa-only counter run moved clearly, a Kestrel comparison was refreshed.

Command:

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
  --run-id local-h3-kestrel-incursa-p17-buffer-pool-counters-20260527
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-p17-buffer-pool-counters-20260527`

All 12 cells passed validation and benchmark execution. Runtime counters were captured for all 12 cells.

| Implementation | Scenario | Median req/s | B/request range | Allocation rate mean range |
| --- | --- | ---: | ---: | ---: |
| `incursa-http3` | `http.core.json` | 3,744.1 | 21,549-22,135 | 78.2-82.9 MB/s |
| `incursa-http3` | `http.core.plaintext` | 3,583.7 | 21,813-23,399 | 75.9-81.3 MB/s |
| `kestrel-http3` | `http.core.json` | 22,492.8 | 2,919-2,945 | 65.0-66.7 MB/s |
| `kestrel-http3` | `http.core.plaintext` | 21,121.6 | 2,964-3,003 | 62.4-66.1 MB/s |

The local Incursa allocation gap versus Kestrel is still large, but the specific 16 KiB per-request source is no longer part of it.

## Did `System.Byte[16384]` Disappear?

The exact production allocation site was removed from `Http3Server.ReadRequestAsync`. The modeled benchmark row that included the server read buffer dropped from 16,632 B/op to 224 B/op, and every request-read benchmark row dropped by 16,408 B/op.

No post-change Visual Studio allocation profile with source-line attribution was captured in this phase, so this document does not claim a profiler-verified absence of every `System.Byte[16384]` allocation in the whole process. It does prove the targeted `ReadRequestAsync` allocation no longer exists in source and no longer appears in the server-shaped BDN path.

## Validation

Commands and results:

| Command | Result |
| --- | --- |
| `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj` | Passed, 0 warnings, 0 errors |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3MinimalServerTests"` | Passed, 19/19 |
| `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p17\bdn-before --inProcess` | Passed, 35 benchmarks |
| `dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p17\bdn-after --inProcess` | Passed, 35 benchmarks |
| `dotnet build` | Passed, 0 warnings, 0 errors |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj` | Failed only with the known baseline 7 failures: 5 trace-link failures and 2 DoQ cancellation exact-type failures |
| ProtocolLab Incursa-only counters | Passed 6/6 validation and benchmark cells; counters captured 6/6 |
| ProtocolLab Kestrel vs Incursa counters | Passed 12/12 validation and benchmark cells; counters captured 12/12 |

Remaining mechanical checks are tracked in the final response for this phase.

## Conclusion

The change is worth keeping. It removes the measured per-request 16 KiB scratch allocation without changing HTTP/3 parsing behavior, request validation, QPACK semantics, QUIC scheduling, packet protection, UDP send behavior, or ProtocolLab semantics.

Remaining allocation sources still visible from earlier phases:

- HTTP/3 frame payload materialization and fragmented-frame owned storage;
- zero-length arrays;
- ACK payload builders;
- packet build/protection buffers;
- diagnostic/frame emission;
- datagram receive ownership copies.

## Recommended P18 Prompt

Continue Incursa H3 Performance Phase P18: reduce the next measured HTTP/3 request-ingress allocation source after the P17 scratch-buffer pooling.

Work in `C:\src\incursa\quic-dotnet`.

Context:

- P17 removed the per-request `Http3Server.ReadRequestAsync` `System.Byte[16384]` scratch allocation by renting the read buffer from `ArrayPool<byte>.Shared`.
- BDN request-read rows dropped by 16,408 B/op.
- Incursa-only ProtocolLab counters moved from roughly 33-36 KB/request to roughly 21-23 KB/request.
- Kestrel remains around 2.9-3.0 KB/request in the same local h3/h2load shape.
- Do not revisit QUIC scheduling, UDP send, packet protection, QPACK semantics, request validation semantics, ProtocolLab semantics, or endpoint special-casing.

Primary goal:

Attribute and reduce exactly one remaining measured allocation source in the HTTP/3 request ingress path, preferably `Http3FrameReader` payload or fragmented-pending storage if fresh profiling confirms it is still dominant.

Required steps:

1. Capture or inspect allocation evidence after P17 before selecting the source.
2. Add behavior tests first for complete HEADERS, fragmented HEADERS, DATA ordering, DATA-before-HEADERS invalidity, malformed/truncated frames, and no retained references.
3. Add focused BDN rows for the selected frame-ingress source.
4. Optimize only that source.
5. Run before/after BDN, focused HTTP/3 tests, full test project, `dotnet build`, `git diff --check`, and PowerShell parser checks.
6. Rerun ProtocolLab Incursa-only counters only if the selected microbenchmark moves meaningfully.
7. Document whether B/request and throughput moved, and classify all failures against the known baseline.
