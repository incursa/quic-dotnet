# Incursa H3 Performance Phase P15

Date: 2026-05-27

## Scope

Phase P15 refreshed the cumulative Kestrel vs Incursa HTTP/3 comparison and split the remaining `System.Byte[]` allocation signal by suspected subsystem.

This phase did not optimize production code, replace stream waiter infrastructure, change protocol behavior, or change ProtocolLab benchmark semantics. The only code change is two opt-in BenchmarkDotNet baseline methods in the existing HTTP/3 allocation benchmark suite.

## Fresh ProtocolLab Comparison

Command:

```text
dotnet run --project src\Incursa.ProtocolLab.Cli -- run --implementations kestrel-http3,incursa-http3 --scenarios http.core.plaintext,http.core.json --protocol h3 --load-tool h2load --load-tool-mode docker --connections 16 --streams-per-connection 10 --duration 10 --warmup 2 --repetitions 3 --capture-counters --counter-refresh-interval 1 --output C:\src\incursa\protocol-lab\.artifacts\runs --run-id local-h3-kestrel-incursa-p15-counters-20260527
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-p15-counters-20260527`

Totals:

- results: 12
- validation: passed 12, failed 0, unsupported 0, not-run 0
- benchmark attempts: 12
- parsed metrics: 12
- runtime counters: captured 12/12
- errors: 0
- warnings: 19
- comparability: 4/4 aggregate rows are `comparable-with-warnings`

Fresh aggregate comparison:

| implementation | scenario | req/s median | p50 | p95 | p99 | allocation rate median | B/request estimate | GC delta median | CPU mean | CPU max | errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| Incursa | JSON | 3,536.1 | 21.097 ms | 33.371 ms | 46.928 ms | 119,313,314 B/s | 33,742 B | 152 / 48 / 5 | 68.248% | 139.063% | 0 |
| Incursa | Plaintext | 3,605.2 | 18.406 ms | 25.395 ms | 32.223 ms | 122,790,065 B/s | 34,059 B | 157 / 50 / 5 | 69.252% | 154.688% | 0 |
| Kestrel | JSON | 20,783.2 | 7.462 ms | 11.499 ms | 14.790 ms | 61,368,674 B/s | 2,953 B | 39 / 0 / 1 | 125.949% | 300.000% | 0 |
| Kestrel | Plaintext | 20,887.7 | 7.286 ms | 11.738 ms | 15.313 ms | 63,662,660 B/s | 3,048 B | 40 / 0 / 0 | 114.565% | 285.938% | 0 |

Current gap:

| scenario | throughput gap | Incursa B/request | Kestrel B/request | allocation gap | allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| JSON | Kestrel 5.88x faster | 33,742 B | 2,953 B | Incursa 11.43x higher | +30,789 B/request |
| Plaintext | Kestrel 5.79x faster | 34,059 B | 3,048 B | Incursa 11.17x higher | +31,011 B/request |

Evidence and comparability status:

- Evidence class: `external-reference-local`.
- Comparability: `comparable-with-warnings`, not publishable benchmark evidence.
- Main warnings: shared single-machine host, no CPU isolation, no network isolation, load-generator metrics missing, Docker h2load target URL rewrite through `host.docker.internal`, no repeated stable median, local loopback/self-signed certificate mode, and no load-generator saturation check.
- The run is still useful for local regression and profiling direction because both implementations used the same run shape and all H3 protocol proofs passed.

## Cumulative Comparison

Phase 2I/2J external-reference h2load baseline, from the diagnostic review:

| scenario | Kestrel req/s | Incursa req/s | Kestrel/Incursa |
| --- | ---: | ---: | ---: |
| Plaintext | 22,747.5 | 2,579.8 | 8.82x |
| JSON | 22,462.9 | 2,787.4 | 8.06x |

Fresh P15 comparison:

| scenario | Kestrel req/s | Incursa req/s | Kestrel/Incursa |
| --- | ---: | ---: | ---: |
| Plaintext | 20,887.7 | 3,605.2 | 5.79x |
| JSON | 20,783.2 | 3,536.1 | 5.88x |

Incursa has improved versus the Phase 2I/2J baseline in this local run shape:

- Plaintext: 2,579.8 -> 3,605.2 req/s, about +39.7%.
- JSON: 2,787.4 -> 3,536.1 req/s, about +26.9%.
- The Kestrel comparison point is slightly lower than the earlier baseline, so the gap reduction is partly Incursa improvement and partly run/environment drift.

Incursa-only allocation trend:

| phase/run | JSON B/request | Plaintext B/request | note |
| --- | ---: | ---: | --- |
| P10 | ~39,817-41,346 | ~40,462-40,791 | fresh single-repetition attribution runs |
| P11 | ~35,536 | ~34,373 stable reps | noisy 3-rep run, one plaintext outlier |
| P13 | ~34,111 | ~34,529 | memory read fast path retained but end-to-end mostly unchanged |
| P14 | ~34,084 | ~33,800 | wait-path microbenchmark moved; end-to-end mostly unchanged |
| P15 fresh | ~33,742 | ~34,059 | latest like-for-like Kestrel/Incursa comparison |

The cumulative safe phases appear to have moved Incursa down from the P10 40 KB/request range into the 34 KB/request range. P13 and P14 by themselves did not materially move the end-to-end counters.

## Instrumentation Decision

No production diagnostic counters were added in P15.

Reason: a static `byte[]` category split is useful, but it is not precise enough to justify new runtime instrumentation yet. Adding counters at each source would also create design work around disabled overhead, cardinality, and ownership. P15 therefore keeps measurement to existing ProtocolLab counters, source audit, and a narrow BDN baseline. A future instrumentation pass should add opt-in `Meter` counters only behind an explicit enablement switch and should avoid per-request logging or allocation just to measure.

## System.Byte[] Source Split

Audit inputs:

- `pwsh -NoProfile -File scripts\analysis\Find-HotPathPatterns.ps1`
- `rg` searches for `new byte[`, `.ToArray(`, `ArrayBufferWriter<byte>`, packet protection/build/open calls, and stream receive/write surfaces.

Candidate-count snapshot from the helper script:

| pattern | count |
| --- | ---: |
| `new byte[]` | 77 |
| `.ToArray()` | 222 |
| `MemoryStream` | 0 |
| `UTF8.GetBytes` | 4 |
| `WriteAsync` | 9 |

These counts are a candidate inventory, not allocation-stack proof.

Subsystem split:

| category | representative sources | current confidence | notes |
| --- | --- | --- | --- |
| `quic.packet.receive.bytes` | `QuicListenerHost.ReceiveLoopAsync`, `QuicConnectionEndpointHost` | high source confidence, medium allocation confidence | UDP receive buffers are pooled, but received datagrams are copied into owned arrays before routing. This is per datagram and on every H3 request/response path. |
| `quic.packet.decrypt.bytes` | `QuicHandshakeFlowCoordinator.TryOpenProtected...`, `QuicBufferLease`, application-data open paths | high source confidence, medium allocation confidence | Lease paths exist, but open/decrypt still materializes plaintext packet buffers and sometimes slices payloads to arrays. |
| `quic.packet.build.bytes` | `QuicHandshakeFlowCoordinator.TryBuildProtected...`, `QuicConnectionRuntime.Streams.TryProtectAndAccount...`, coalesced datagram builders | high source confidence, medium-high allocation confidence | Outbound protected packets allocate or rent packet buffers; tiny responses still pay packet build/protection per response. |
| `quic.stream.frame.payload.bytes` | `QuicConnectionRuntime.Streams` outbound STREAM payload builders and combine buffers | high source confidence, medium-high allocation confidence | Existing H3 benchmark shapes show response-frame bytes copied again into a STREAM-frame payload buffer. |
| `quic.stream.read.consumer.bytes` | `QuicStream.ReadAsync(byte[],...)` consumers, `Http3Server.ReadRequestAsync` local buffers | medium source confidence, low current priority | P13 moved request reads to the `Memory<byte>` path and P14 reduced wait-path allocation. No evidence justifies replacing the waiter in P15. |
| `h3.frame.payload.bytes` | `Http3FrameReader.Read`: payload `.ToArray()`, pending append/slice | high source confidence, medium-high allocation confidence | Every request HEADERS frame payload becomes an owned `byte[]`; fragmentation also appends and slices pending bytes. |
| `h3.request.body.buffer.bytes` | `Http3Server.ProcessRequestFrameAsync`, `Http3Request` body copy | medium source confidence, low for current h2load GETs | `/plaintext` and `/json` are no-body GETs, so this is not likely the dominant current signal. |
| `h3.response.buffer.bytes` | `Http3Server.WriteBufferedResponseFramesAsync`, `Http3FrameWriter.WriteFrame`, `EncodeResponseFieldSection` | high source confidence, high benchmark adjacency | Tiny responses allocate QPACK field-section bytes, H3 response frame bytes, then STREAM payload/packet bytes. |
| `qpack.bytes` | `QPackEncoder.EncodeFieldSection`, `QPackDecoder.DecodeFieldSection`, pending encoder-stream append/slice | high source confidence, medium allocation confidence | P7/P9 reduced QPACK/header arrays, but field-section encode/decode still returns arrays. |
| `diagnostics.qlog.bytes` | `QuicDiagnostics` packet byte snapshots, qlog mapper/capture | high source confidence, low for default benchmark path | Qlog and diagnostics are not the first target unless enabled; packet snapshots allocate when diagnostic emission captures bytes. |

The largest likely current `System.Byte[]` family is not one isolated call. It is the response-to-QUIC-send byte-array chain plus per-datagram/packet ownership:

1. response headers encoded to QPACK bytes;
2. HTTP/3 HEADERS/DATA frames buffered to bytes;
3. H3 frame bytes wrapped in a QUIC STREAM payload;
4. STREAM payload protected into packet/datagram bytes;
5. receive side repeats datagram ownership, open/decrypt, frame payload, and stream receive-buffer ownership.

## P15 Benchmark Baseline

Added two narrow BenchmarkDotNet baselines to `Http3AllocationPathBenchmarks`:

- `ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload`
- `ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload`

Command:

```text
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponsePipeline_EncodeBufferAndBuild*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p15\bdn-response-pipeline --inProcess
```

Results:

| benchmark | mean | Gen0 | allocated |
| --- | ---: | ---: | ---: |
| `ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload` | 846.0 ns | 0.0925 | 776 B |
| `ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload` | 890.6 ns | 0.0954 | 800 B |

This baseline covers only the response field-section -> H3 frame buffer -> QUIC STREAM payload byte-array chain. It does not include protected packet construction, UDP send, receive-side datagram ownership, packet open/decrypt, or stream receive buffering. That means it is a good P16 starting slice, not a full explanation for the roughly 31 KB/request allocation gap to Kestrel.

## Is Another Optimization Justified?

Yes, but not in `SemaphoreSlim` or read-wait internals.

The current Incursa vs Kestrel allocation gap is about 31 KB/request. P14 proved that the read wait path can be improved locally, but end-to-end counters barely moved. The remaining evidence points to byte-array ownership and copy boundaries across H3 response assembly, STREAM payload construction, packet build/open, and UDP datagram ownership.

The next optimization should be a bounded byte-array chain where behavior can be proven with byte-exact tests and an isolated benchmark. The best next target is the response-buffer-to-STREAM-payload path, because it is per request, benchmarkable, easy to behavior-test, and adjacent to the current BDN baseline. Packet build/open may be larger, but it has a broader correctness blast radius.

Confidence:

- High that Incursa still has a large allocation gap versus Kestrel in this run shape.
- Medium-high that `System.Byte[]` remains the dominant allocation family based on P10 type evidence plus source audit.
- Medium that the response-to-STREAM payload chain is the right first P16 target.
- Low that source audit alone identifies the largest exact call stack; PerfView or a working allocation-stack analyzer would still improve precision.

## Recommended P16 Prompt

```text
Continue Incursa H3 Performance Phase P16: response frame to STREAM payload byte-array chain reduction.

Work in C:\src\incursa\quic-dotnet.

Context:
P15 refreshed the Kestrel vs Incursa H3 comparison. Incursa now runs around 3.5-3.6k req/s and 33.7-34.1 KB/request, while Kestrel runs around 20.8k req/s and 3.0 KB/request in the same local h2load/docker shape. P15 source audit split the remaining System.Byte[] signal and added BDN baselines:
- ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload: 776 B/op
- ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload: 800 B/op

Primary goal:
Reduce one measured byte-array allocation in the response field-section -> HTTP/3 frame buffer -> QUIC STREAM payload path without changing HTTP/3, QPACK, QUIC scheduling, ACK/loss recovery, UDP send behavior, ProtocolLab semantics, or sample endpoint behavior.

Do not optimize SemaphoreSlim/read-wait internals.
Do not change ProtocolLab benchmark semantics.
Do not special-case /plaintext, /json, or h2load.

Before editing production code:
- add focused byte-exact tests for response HEADERS/DATA frame bytes, final FIN write behavior, chunking behavior, and STREAM payload formatting;
- run the existing P15 response-pipeline benchmarks as the before baseline;
- identify exactly one allocation source to remove, preferably avoiding an intermediate byte[] between H3 frame buffering and QUIC STREAM payload construction.

After the change:
- rerun focused tests;
- rerun the response-pipeline BDN baselines;
- run dotnet build, full test project, benchmark project build, git diff --check, and the scripts\perf PowerShell parser check;
- rerun ProtocolLab only if the microbenchmark allocation drop is large enough to be visible over local noise.
```

## Validation

Commands run:

```text
dotnet run --project src\Incursa.ProtocolLab.Cli -- run --implementations kestrel-http3,incursa-http3 --scenarios http.core.plaintext,http.core.json --protocol h3 --load-tool h2load --load-tool-mode docker --connections 16 --streams-per-connection 10 --duration 10 --warmup 2 --repetitions 3 --capture-counters --counter-refresh-interval 1 --output C:\src\incursa\protocol-lab\.artifacts\runs --run-id local-h3-kestrel-incursa-p15-counters-20260527
pwsh -NoProfile -File scripts\analysis\Find-HotPathPatterns.ps1
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponsePipeline_EncodeBufferAndBuild*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p15\bdn-response-pipeline --inProcess
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
git diff --check
$failed=$false; Get-ChildItem scripts\perf\*.ps1 | ForEach-Object { $tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $failed=$true } }; if ($failed) { exit 1 }
```

Results:

- `dotnet build`: passed with 0 warnings and 0 errors.
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed with 0 warnings and 0 errors.
- P15 response-pipeline BenchmarkDotNet run: completed.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 7 failures.

Full test failure classification:

- 5 trace-link failures matched the known pre-existing trace-link family.
- 2 DoQ cancellation exact-type failures matched the known pre-existing family.
- No intermittent DoQ timeout appeared in the final full test run.
- No new persistent failure family was introduced by P15.
