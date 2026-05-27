# Incursa H3 Performance Phase P16

Date: 2026-05-27

## Scope

Phase P16 reduced one measured byte-array allocation in the response field-section -> HTTP/3 frame buffer -> QUIC STREAM payload chain.

The selected optimization was deliberately narrow: keep the existing HTTP/3 response frame buffer as `ReadOnlyMemory<byte>` through the final `QuicStream` write instead of materializing a second response-frame `byte[]` with `ArrayBufferWriter<byte>.WrittenSpan.ToArray()`.

This phase did not change HTTP/3 semantics, QPACK behavior, ACK/loss recovery, QUIC scheduling, UDP send behavior, packet protection behavior, ProtocolLab benchmark semantics, or endpoint behavior.

## P15 Recap

P15 refreshed the local Kestrel vs Incursa H3 comparison:

| implementation | scenario | req/s median | B/request estimate |
| --- | --- | ---: | ---: |
| Incursa | JSON | 3,536.1 | 33,742 B |
| Incursa | Plaintext | 3,605.2 | 34,059 B |
| Kestrel | JSON | 20,783.2 | 2,953 B |
| Kestrel | Plaintext | 20,887.7 | 3,048 B |

P15 also added the response-pipeline baselines:

| benchmark | mean | allocated |
| --- | ---: | ---: |
| `ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload` | 846.0 ns | 776 B |
| `ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload` | 890.6 ns | 800 B |

## Response-To-Stream Findings

The response path allocated and copied through this chain:

1. `Http3Server.EncodeResponseFieldSection` encoded response headers to a QPACK field-section `byte[]`.
2. `Http3Server.WriteBufferedResponseFramesAsync` wrote HEADERS and DATA frames into an `ArrayBufferWriter<byte>`.
3. The buffered response path called `writer.WrittenSpan.ToArray()`, allocating a second H3 response-frame byte array.
4. `QuicConnectionRuntime.TryBuildOutboundStreamPayload` copied those H3 bytes into a QUIC STREAM frame payload byte array.
5. Packet protection then built protected packet/datagram bytes.

The selected P16 target was step 3 only.

The writer backing array is owned by the local response-write async state and is not exposed for mutation after it is passed as `ReadOnlyMemory<byte>`. `QuicStream.WriteFinalAsync(ReadOnlyMemory<byte>)` awaits the runtime write completion, so the memory remains alive until the runtime has built the STREAM payload.

## Behavior Tests

Added focused byte-exact coverage in `Http3FrameLayerTests`:

- response HEADERS frame bytes are preserved;
- response DATA frame bytes are preserved;
- combined HEADERS + DATA bytes are preserved;
- STREAM frame payload bytes equal the combined H3 frames;
- FIN is set on the STREAM frame;
- stream ID and offset are unchanged;
- body bytes are unchanged;
- `:status`, `server`, `date`, `content-type`, and `content-length` decode unchanged;
- no extra non-zero bytes appear after the parsed STREAM frame payload.

Focused command:

```text
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3FrameLayerTests"
```

Result: passed, 33/33.

## Code Change

Production changes:

- Added `QuicStream.WriteAsync(ReadOnlyMemory<byte>, CancellationToken)` override to keep memory writes on the existing runtime write path.
- Added internal `QuicStream.WriteFinalAsync(ReadOnlyMemory<byte>, CancellationToken)`.
- Changed `Http3Server.WriteBufferedResponseFramesAsync` to pass `writer.WrittenMemory` to the final frame write instead of `writer.WrittenSpan.ToArray()`.
- Kept the existing `byte[]` final-write path as a compatibility wrapper.

Benchmark changes:

- Updated the existing `ResponsePipeline_EncodeBufferAndBuild*` benchmark shape to mirror the optimized handoff: write H3 frames into an `ArrayBufferWriter<byte>` and pass `WrittenSpan` directly into STREAM payload construction.

## BenchmarkDotNet

Before command:

```text
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponsePipeline_EncodeBufferAndBuild*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p16\bdn-before --inProcess
```

After command:

```text
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponsePipeline_EncodeBufferAndBuild*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p16\bdn-after --inProcess
```

| benchmark | before mean | after mean | mean delta | before allocated | after allocated | allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `ResponseFrames_BufferPlaintext` | 51.33 ns | 48.91 ns | -2.42 ns | 224 B | 224 B | 0 B |
| `ResponseFrames_EncodeAndBufferPlaintext` | 747.41 ns | 808.54 ns | +61.13 ns | 648 B | 648 B | 0 B |
| `QuicStreamPayload_BuildPlaintextResponsePayload` | 33.86 ns | 32.07 ns | -1.79 ns | 128 B | 128 B | 0 B |
| `QuicStreamPayload_BuildJsonResponsePayload` | 32.08 ns | 33.23 ns | +1.15 ns | 136 B | 136 B | 0 B |
| `ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload` | 785.08 ns | 843.87 ns | +58.79 ns | 776 B | 680 B | -96 B |
| `ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload` | 809.61 ns | 822.51 ns | +12.90 ns | 800 B | 696 B | -104 B |

Gen0 also moved on the selected pipeline benchmarks:

| benchmark | before Gen0 | after Gen0 |
| --- | ---: | ---: |
| `ResponsePipeline_EncodeBufferAndBuildPlaintextStreamPayload` | 0.0925 | 0.0811 |
| `ResponsePipeline_EncodeBufferAndBuildJsonStreamPayload` | 0.0954 | 0.0830 |

The selected wait-free response handoff allocation moved by one small array per operation. Runtime did not clearly improve in ShortRun noise, but the allocation reduction is direct and mechanically explained by removing the response-frame `ToArray()`.

## ProtocolLab Counter Rerun

The first P16 ProtocolLab attempt partially ran, then failed because UDP port 5444 was held by a generated Docker target after the first repetition. Subsequent process-mode target starts failed with `SocketException (10048)`. Generated ProtocolLab containers for the failed run were removed, and the Incursa-only counter run was rerun.

Clean rerun command:

```text
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p16-counters-rerun-20260527 -CaptureCounters
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p16-counters-rerun-20260527`

Clean rerun totals:

- results: 6
- validation: passed 6, failed 0
- benchmark attempts: 6
- parsed metrics: 6
- runtime counters: captured 6/6
- errors: 0
- comparability: `comparable-with-warnings`

| scenario | P15 req/s | P16 req/s | P15 alloc rate | P16 alloc rate | P15 B/request | P16 B/request | P16 GC delta | P16 CPU mean/max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| JSON | 3,536.1 | 2,443.5 | 119,313,314 B/s | 88,291,153 B/s | 33,742 B | 36,133 B | 113 / 35 / 4 | 67.801% / 156.250% |
| Plaintext | 3,605.2 | 2,430.5 | 122,790,065 B/s | 86,737,645 B/s | 34,059 B | 35,687 B | 112 / 34 / 4 | 67.801% / 154.688% |

The ProtocolLab rerun does not show an end-to-end allocation win. Allocation rate dropped, but request throughput dropped more, so B/request increased. Given the shared-host local run warnings and the small per-response microbenchmark delta, this should be treated as no material end-to-end movement.

## Validation

Commands run:

```text
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponsePipeline_EncodeBufferAndBuild*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p16\bdn-before --inProcess
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3FrameLayerTests"
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ResponsePipeline_EncodeBufferAndBuild*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p16\bdn-after --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p16-counters-20260527 -CaptureCounters
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p16-counters-rerun-20260527 -CaptureCounters
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
git diff --check
$failed=$false; Get-ChildItem scripts\perf\*.ps1 | ForEach-Object { $tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $failed=$true } }; if ($failed) { exit 1 }
```

Results:

- `dotnet build`: passed with 0 warnings and 0 errors.
- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed with 0 warnings and 0 errors.
- Focused `Http3FrameLayerTests`: passed, 33/33.
- BenchmarkDotNet before and after runs completed.
- Clean ProtocolLab rerun passed all six validations and h2load repetitions.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.
- Full `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with 7 known failures.

Full test failure classification:

- 5 trace-link failures: known pre-existing family.
- 2 DoQ cancellation exact-type failures: known pre-existing family.
- No intermittent DoQ timeout appeared.
- No new persistent failure family appeared.

## Keep Decision

The change is worth keeping as a safe, byte-exact, measured micro-allocation reduction:

- selected response-pipeline allocation dropped by 96-104 B/op;
- behavior tests preserve exact HEADERS, DATA, STREAM payload, FIN, stream ID, body, and headers;
- full-suite failures match the known baseline families;
- no protocol semantics changed.

It is not enough to explain or materially move the remaining end-to-end H3 allocation gap.

## Remaining Suspected Allocation Sources

The top remaining suspected sources are still byte-array ownership and copy boundaries outside this small response handoff:

- QUIC STREAM payload buffer allocation still remains;
- packet protection/build still allocates protected packet/datagram bytes;
- receive-side datagram ownership and packet open/decrypt likely remain per-packet sources;
- HTTP/3 request frame payload arrays and QPACK field-section arrays still remain;
- the response path still allocates the QPACK field-section and the `ArrayBufferWriter<byte>` backing array.

## Recommended P17 Prompt

```text
Continue Incursa H3 Performance Phase P17: allocation-stack attribution for packet build/open byte arrays.

Work in C:\src\incursa\quic-dotnet and use ProtocolLab from C:\src\incursa\protocol-lab.

Context:
P16 removed one response-frame handoff byte[] allocation. The selected BDN response-pipeline benchmarks dropped:
- plaintext: 776 B/op -> 680 B/op
- JSON: 800 B/op -> 696 B/op

The Incursa-only ProtocolLab rerun did not show a material end-to-end B/request improvement. Do not continue optimizing the response frame handoff unless allocation-stack evidence says it is still a top source.

Primary goal:
Capture and analyze allocation stacks for Incursa H3 under the local h2load/docker shape, then identify the largest remaining System.Byte[] subsystem with call-stack evidence.

Do not optimize first.
Do not change HTTP/3 semantics, QPACK behavior, QUIC scheduling, ACK/loss recovery, packet protection semantics, UDP send behavior, ProtocolLab benchmark semantics, or endpoint behavior.

Tasks:
1. Run Incursa-only ProtocolLab h3 h2load for http.core.plaintext and http.core.json with counters enabled.
2. Capture allocation-stack evidence for one scenario at a time using the repo-local trace mode or dotnet-trace allocation collection. Prefer plaintext first, then JSON if time allows.
3. Split System.Byte[] allocation stacks by subsystem:
   - packet receive/datagram ownership
   - packet open/decrypt plaintext buffers
   - packet build/protection buffers
   - STREAM payload buffers
   - HTTP/3 frame reader payload buffers
   - QPACK encode/decode field-section buffers
   - diagnostics/qlog byte snapshots
4. Add or update one narrow BenchmarkDotNet baseline only for the largest proven source.
5. Do not optimize unless one source is clearly large, behavior-testable, and bounded.
6. Produce docs\analysis\incursa-h3-performance-phase-p17.md with trace commands, artifacts, stack summary, selected next target, risk, and recommended P18 prompt.

Validation:
- dotnet build
- dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
- benchmark project build if changed
- git diff --check
- PowerShell parser check for scripts\perf\*.ps1
```
