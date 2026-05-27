# Incursa H3 Performance Phase P1

Runtime profiling and hot-path evidence for the Incursa QUIC + HTTP/3 request/response path.

This phase is diagnostic only. No protocol behavior, benchmark semantics, correctness checks, or response semantics were changed.

## Evidence Reviewed

- `docs/analysis/incursa-h3-performance-diagnostic-review.md`
- `docs/analysis/incursa-h3-request-response-path.md`
- `scripts/analysis/Find-HotPathPatterns.ps1`
- `C:\src\incursa\protocol-lab\docs\analysis\incursa-h3-phase2j-performance-review.md`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-h2load-phase2i`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-counters-phase2k`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-h3-kestrel-incursa-counters-runtime-diagnostics`

`local-h3-kestrel-incursa-h2load-phase2k-fixed` was requested as optional evidence but was not present.

The Phase 2I/2J h2load evidence still shows the key shape:

| scenario | Kestrel req/s | Incursa req/s | ratio |
| --- | ---: | ---: | ---: |
| `http.core.plaintext` | 22,747.5 | 2,579.8 | 8.82x |
| `http.core.json` | 22,462.9 | 2,787.4 | 8.06x |

Plaintext and JSON remain close, so the leading target is shared QUIC/H3 request-response overhead, not JSON serialization.

## Baseline Verification

Before this phase changed files:

- `dotnet build` passed with 0 warnings and 0 errors.
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj` failed with 7 failed, 5889 passed, 0 skipped, 5896 total.

The current failures are the same known families as the prior report:

- 5 trace-link assertions expecting canonical entries in `REQUIREMENT-GAPS.md` or related trace artifacts.
- 2 DoQ lifecycle cancellation tests expecting exact `OperationCanceledException` but receiving `TaskCanceledException`.

The previously reported DoQ timeout failure did not reproduce in this baseline run.

## Benchmark Target

The ProtocolLab Incursa target is `implementations/incursa-http3.yaml` in the sibling ProtocolLab repo. It points at:

`C:\src\incursa\quic-dotnet\samples\Incursa.Http3.Samples.TechEmpower\Incursa.Http3.Samples.TechEmpower.csproj`

Current ProtocolLab startup prefers direct process identity:

```text
dotnet exec C:\src\incursa\quic-dotnet\samples\Incursa.Http3.Samples.TechEmpower\bin\Debug\net10.0\Incursa.Http3.Samples.TechEmpower.dll --port 5444
```

This fixes the earlier `dotnet run` wrapper attribution problem for counter capture.

The sample confirms:

- `/plaintext` and `/json` share the same `TechEmpowerHandler.HandleAsync` and `Payload` response construction path.
- Both response bodies are precomputed static byte arrays.
- The per-request sample-layer work is mostly route dispatch, `StripQuery`, `DateTimeOffset.UtcNow.ToString("R")`, `content-length` formatting, and construction of response header field lines.
- qlog and SSL key log export are disabled in the ProtocolLab manifest; the sample does not pass a diagnostics sink by default.
- There is no per-request application logging in the benchmark path unless `INCURSA_QUIC_DEBUG_APP_RX=1` is set, which ProtocolLab does not set.

Sample-layer overhead is real but not currently the leading explanation for an 8x-9x gap because plaintext and JSON converge and the bulk of work is below the handler.

## Commands Run

Baseline and tool checks:

```powershell
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet-counters --version
dotnet-trace --version
dotnet tool list --local
dotnet tool list --global
dotnet run --project C:\src\incursa\protocol-lab\src\Incursa.ProtocolLab.Cli -- check --root C:\src\incursa\protocol-lab
```

Counter capture:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -Scenarios http.core.plaintext `
  -DurationSeconds 5 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -CaptureCounters `
  -RunId local-incursa-h3-p1-counters-20260527-pt

pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -Scenarios http.core.json `
  -DurationSeconds 5 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -CaptureCounters `
  -RunId local-incursa-h3-p1-counters-20260527-json
```

Trace/tool blocker:

```powershell
pwsh -NoProfile -File scripts\perf\Collect-IncursaH3Trace.ps1 `
  -ProcessId $PID `
  -DurationSeconds 5 `
  -ArtifactRoot .artifacts\perf\incursa-h3-p1\trace-tool-check-20260527
```

Hot-path candidate search:

```powershell
pwsh -NoProfile -File scripts\analysis\Find-HotPathPatterns.ps1 |
  Set-Content .artifacts\perf\incursa-h3-p1\hotpath-patterns-20260527.txt
```

## Tools

| tool | status | notes |
| --- | --- | --- |
| Docker h2load H3 | available | ProtocolLab `check` reports `h2load-docker-h3` available and H3-supported. |
| process h2load | unavailable | Not found on PATH. |
| global `dotnet-counters` | unavailable | Not found on PATH from the quic-dotnet repo. |
| ProtocolLab local `dotnet-counters` | available | `dotnet tool run dotnet-counters -- ...`, version `9.0.661903`. |
| `dotnet-trace` | unavailable | Not found on PATH; no trace was captured. |

## Runtime Counter Evidence

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p1-counters-20260527-pt`
- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p1-counters-20260527-json`

Both runs:

- used Incursa only
- used ProtocolLab h2load Docker mode
- used direct `dotnet exec` target startup
- resolved the diagnostic target with high confidence
- captured `System.Runtime` counters from the target process
- are single-run local samples, not stable benchmark claims

| scenario | req/s | CPU mean | CPU max | allocation rate mean | Gen0/Gen1/Gen2 delta | GC pause delta | thread-pool queue max | exception rate mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| plaintext | 2,278.8 | 58.0 | 156.3 | 90.1 MB/s | 68 / 19 / 3 | 0.268 s | 0 | 62.2/s |
| JSON | 2,352.8 | 55.2 | 148.4 | 92.3 MB/s | 69 / 20 / 3 | 0.268 s | 1 | 46.2/s |

Interpretation:

- The strongest measured signal is allocation/GC pressure in the shared path.
- CPU is non-trivial but not obviously saturated in these short samples.
- Thread-pool queue length is not currently a leading signal.
- Exception rate is unexpectedly nonzero and needs follow-up with exception-type attribution before it is treated as a bottleneck.
- Plaintext and JSON counters are close, reinforcing that shared QUIC/H3 overhead dominates the next investigation.

## Trace Result

No CPU trace was captured in this phase because `dotnet-trace` is not installed on PATH.

Blocker artifact:

`C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p1\trace-tool-check-20260527\trace-summary.json`

Provisioning instruction recorded by the script:

```powershell
dotnet tool install --global dotnet-trace
```

After provisioning, rerun trace capture against the Incursa server PID during the same ProtocolLab h2load cell shape.

## Hot-Path Source Review

### Measured

Allocation and GC pressure are measured in the Incursa target process during both plaintext and JSON h2load cells. The source-level allocation sites below are likely contributors, but they are not yet individually measured.

### Likely

`QuicListenerHost.ReceiveLoopAsync`

- Copies every received datagram with `buffer.AsSpan(0, receiveResult.ReceivedBytes).ToArray()` before endpoint routing.
- Sends each `QuicConnectionSendDatagramEffect` through a synchronous `socket.SendTo` call.

`Http3FrameReader.Read`

- Appends incoming bytes into a new `byte[]`.
- Copies every frame payload with `ToArray`.
- Allocates `List<Http3Frame>` and returns a new frame array.
- Slices pending bytes through `ToArray`.

`Http3Server.ReadRequestAsync` and response write path

- Allocates a frame reader, request validator, body writer, and read buffer per request stream.
- Decodes HEADERS through QPACK into materialized header fields.
- Builds response headers and encoded field sections per request.
- `WriteBufferedResponseFramesAsync` builds an aggregate buffer and then calls `writer.WrittenSpan.ToArray()`.
- `WriteFinalFrameBytesAsync` drives the final response write into the QUIC stream path; small responses likely traverse a full async/write/protect/send cycle per response.

`QuicConnectionRuntime.Streams.cs`

- `HandleWriteStreamAction` builds a new STREAM payload for writes, often immediately protects and emits a datagram.
- `TryBuildOutboundStreamPayload` allocates a padded buffer at least `ApplicationMinimumProtectedPayloadLength`.
- `streamIds: new[] { streamId }` allocates on the direct write path.
- `FlushPendingApplicationSends` allocates sorted queued writes, combined payloads, and distinct stream-id arrays when the delayed path is used.

`Http3Server.EncodeResponseFieldSection`

- Rebuilds response field sections each request.
- Scans the QPACK static table for field and name lookup.
- `WriteRawString` uses `HeaderTextEncoding.GetBytes(value)`, allocating byte arrays for header names/values.

### Possible

`QuicConnectionRuntimeEndpoint` and `QuicConnectionRuntimeShard`

- Endpoint route lookup uses multiple `ConcurrentDictionary` layers by handle, route length, and stateless reset state.
- Shard handoff uses an unbounded `Channel` and async consumer loop.
- Current counters do not show thread-pool queue pressure, so scheduling overhead remains possible but not leading from P1 evidence.

`QPackDecoder`

- Encoder-stream append and blocked-field-section paths allocate arrays.
- Regular static request decode still materializes `QPackFieldLine[]`; not yet isolated as a dominant cost.

### Low Confidence

Logging/qlog overhead is low confidence as a bottleneck in the benchmark target. ProtocolLab marks qlog support disabled for the Incursa target, the sample does not configure a diagnostics sink, and hot-path diagnostic emission gates on `diagnosticsSink?.IsEnabled`.

## Top Suspected Bottleneck Category

Allocation-heavy shared QUIC/H3 request-response processing, especially packet/frame/response write buffer materialization and per-request header/QPACK work.

Confidence: medium.

The counter evidence now supports allocation/GC pressure as a real symptom. The exact dominant allocation sites still require CPU/allocation trace evidence or lower-level benchmarks.

## Top 5 Follow-Up Targets

1. `QuicConnectionRuntime.Streams.cs`: `HandleWriteStreamAction`, `TryBuildOutboundStreamPayload`, `TryProtectAndAccountStreamApplicationPayload`, `FlushPendingApplicationSends`
2. `Http3Server.cs`: `ReadRequestAsync`, `WriteResponseAsync`, `WriteBufferedResponseFramesAsync`, `EncodeResponseFieldSection`, `WriteRawString`
3. `QuicListenerHost.cs`: `ReceiveLoopAsync`, `SendDatagram`
4. `Http3FrameReader.cs`: `Read`, `Append`, `SlicePending`
5. `QuicConnectionRuntimeEndpoint.cs` / `QuicConnectionRuntimeShard.cs`: route lookup, `TryPost`, `ConsumeInboxAsync`

`QPackDecoder.cs` remains a close secondary target for request header decode materialization.

## Lower-Level Benchmark Plan

The existing diagnostic review already proposes a BenchmarkDotNet plan. P1 narrows the first benchmark slice to allocation-heavy paths:

1. HTTP/3 frame read of one complete HEADERS frame from one buffer.
2. HTTP/3 response write assembly for plaintext-sized body: headers + one DATA frame.
3. QPACK response header encode for the TechEmpower header set.
4. QUIC STREAM frame payload build for small H3 response payloads.
5. Protected packet builder for one small application STREAM payload.
6. UDP receive classification with route lookup using a representative active connection-id table.
7. End-to-end in-memory plaintext response generation through `TechEmpowerHandler` plus `Http3Server` response assembly, excluding socket I/O.
8. JSON response generation with the same path, to keep the shared-path comparison honest.

Do not implement the full suite until the trace confirms which slice is hottest.

## Recommended Next Measurement Phase

Phase P2 should collect allocation and CPU attribution, not optimize yet:

- Install or restore `dotnet-trace`.
- Run one Incursa plaintext and one Incursa JSON h2load cell with:
  - `dotnet-counters` enabled through ProtocolLab.
  - `dotnet-trace collect --profile cpu-sampling` against the resolved target PID.
  - optional GC allocation profile if collection overhead is acceptable.
- Attribute exception types during the same run.
- Compare top stacks against:
  - `Http3FrameReader`
  - `Http3Server` response header/frame write
  - `QuicConnectionRuntime.Streams` write/protect/send
  - `QuicListenerHost` receive/send
  - `ConcurrentDictionary` / `Channel` scheduling surfaces

Recommended next prompt:

```text
Incursa H3 Performance Phase P2: collect dotnet-trace CPU/allocation evidence for the Incursa HTTP/3 TechEmpower target during ProtocolLab h2load plaintext and JSON runs. Do not optimize. Use the P1 scripts and artifacts, attach to the resolved dotnet exec server process, preserve raw traces and counters, attribute exception types, and update docs/analysis/incursa-h3-performance-phase-p2.md with measured top stacks and allocation sources.
```

## Final Validation

After adding the P1 scripts and this document:

- `dotnet build` passed with 0 warnings and 0 errors.
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj` failed with the same 7 baseline failures: 5 trace-link assertions and 2 DoQ cancellation exception-type assertions.
- `git diff --check` passed.
- PowerShell parser validation for `scripts\perf\*.ps1` passed.

The final test failure set matches the pre-edit baseline in this phase. No new test failures were introduced.
