# Incursa H3 Performance Phase P21

Date: 2026-05-28

## Scope

Phase P21 is attribution-first. No protocol or runtime optimization was performed.

Guardrails held:

- HTTP/3 semantics were not changed.
- QPACK wire semantics and public QPACK API behavior were not changed.
- QUIC scheduling, UDP send, packet protection, and ACK/loss recovery were not changed.
- ProtocolLab benchmark semantics were not changed.
- No `/plaintext`, `/json`, h2load, or TechEmpower special casing was added.

## P20 Recap

P20 replaced the response header builder's default `ArrayBufferWriter<QPackFieldLine>` with an exact-sized `QPackFieldLine[]`.

Selected BDN result:

| Benchmark | Before | After | Delta |
| --- | ---: | ---: | ---: |
| `ResponseHeaders_BuildPlaintextHeaders` | 4,288 B | 104 B | -4,184 B |
| `ResponseHeaders_BuildJsonHeaders` | 4,288 B | 104 B | -4,184 B |

P20 Incursa-only ProtocolLab counters moved:

| Scenario | P19 B/request | P20 B/request | Delta |
| --- | ---: | ---: | ---: |
| `http.core.json` | 21,722 B | 20,354 B | -1,368 B |
| `http.core.plaintext` | 21,344 B | 19,693 B | -1,651 B |

The P20 change is worth keeping. It removed a measured response-side source without changing wire bytes, public QPACK APIs, or request decoding.

## Fresh ProtocolLab Counters

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
  -RunId local-incursa-h3-p21-counters-20260528 `
  -CaptureCounters
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p21-counters-20260528`

All 6 validation and benchmark cells passed. Runtime counters were captured for all 6 cells.

| Scenario | Req/s median | p50 ms | p95 ms | p99 ms | Allocation rate median | B/request est. | CPU mean/max | GC gen0/gen1/gen2 | Exceptions/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `http.core.json` | 3,278.1 | 32.50 | 42.99 | 49.20 | 65,594,406 B/s | 20,010 B | 66.5% / 148.4% | 81 / 24 / 4 | 47.7 | 0 |
| `http.core.plaintext` | 3,649.6 | 20.70 | 32.84 | 43.29 | 63,013,152 B/s | 17,266 B | 67.7% / 142.2% | 79 / 24 / 4 | 58.6 | 0 |

Fresh no-trace counter range: about 17.3-20.0 KB/request.

Run noise/stability notes:

- All cells passed and no failed/timeout requests were reported.
- The aggregate still carries local-run warnings: shared host, no CPU isolation, no network isolation, host-docker-internal rewrite, missing load-generator metrics, no repeated stable median, and single-machine measurement.
- Trace-captured runs are not used as the primary B/request baseline because `dotnet-trace` increased observed allocation/GC pressure.

## Fresh Allocation Traces

Plaintext command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 30 `
  -WarmupSeconds 2 `
  -Repetitions 1 `
  -RunId local-incursa-h3-p21-plaintext-gc-20260528 `
  -CaptureCounters `
  -TraceMode gc-allocation `
  -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p21\plaintext-gc-allocation `
  -TraceDurationSeconds 40
```

JSON command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.json `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 30 `
  -WarmupSeconds 2 `
  -Repetitions 1 `
  -RunId local-incursa-h3-p21-json-gc-20260528 `
  -CaptureCounters `
  -TraceMode gc-allocation `
  -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p21\json-gc-allocation `
  -TraceDurationSeconds 40
```

Artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p21\plaintext-gc-allocation\trace.nettrace`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p21\json-gc-allocation\trace.nettrace`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p21\plaintext-byte-stack-analysis\byte-stack-summary.md`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p21\json-byte-stack-analysis\byte-stack-summary.md`

Analysis command:

```powershell
dotnet run --project .artifacts\perf\incursa-h3-p17\trace-byte-stack-analyzer\trace-byte-stack-analyzer.csproj -- `
  .artifacts\perf\incursa-h3-p21\plaintext-gc-allocation\trace.nettrace `
  .artifacts\perf\incursa-h3-p21\plaintext-byte-stack-analysis

dotnet run --project .artifacts\perf\incursa-h3-p17\trace-byte-stack-analyzer\trace-byte-stack-analyzer.csproj -- `
  .artifacts\perf\incursa-h3-p21\json-gc-allocation\trace.nettrace `
  .artifacts\perf\incursa-h3-p21\json-byte-stack-analysis
```

`dotnet-trace report topN` failed on these GC allocation traces with `System.FormatException: Read past end of stream`. The TraceEvent analyzer still extracted allocation tick type summaries, but call stacks were empty. PerfView, Visual Studio, or dotMemory is still required for source-line allocation attribution of the top `System.Byte[]` bucket.

## Top Allocated Types

Plaintext trace:

| Type | Count | Sampled bytes | Share |
| --- | ---: | ---: | ---: |
| `System.Byte[]` | 4,659 | 496,500,520 | 17.9% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 1,321 | 140,755,936 | 5.1% |
| `Entry<System.UInt64>[]` | 1,028 | 109,540,744 | 4.0% |
| `System.Object` | 867 | 92,374,752 | 3.3% |
| `Enumerator<System.UInt64, Incursa.Quic.QuicRecoverySentPacketState>` | 806 | 85,889,896 | 3.1% |
| `Incursa.Quic.QuicConnectionSendDatagramEffect` | 726 | 77,360,488 | 2.8% |
| `Incursa.Quic.QuicAckFrame` | 678 | 72,255,312 | 2.6% |
| `Incursa.Quic.QuicConnectionEffect[]` | 651 | 69,361,656 | 2.5% |
| ACK receipt node arrays | 629 | 67,015,888 | 2.4% |
| `Incursa.Qpack.QPackFieldLine[]` | 550 | 58,607,424 | 2.1% |

JSON trace:

| Type | Count | Sampled bytes | Share |
| --- | ---: | ---: | ---: |
| `System.Byte[]` | 4,396 | 468,462,896 | 18.1% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 1,343 | 143,098,072 | 5.5% |
| `Entry<System.UInt64>[]` | 974 | 103,802,696 | 4.0% |
| `System.Object` | 763 | 81,300,304 | 3.1% |
| timer priority tuple arrays | 10 | 75,571,512 | 2.9% |
| `Enumerator<System.UInt64, Incursa.Quic.QuicRecoverySentPacketState>` | 674 | 71,811,968 | 2.8% |
| ACK receipt node arrays | 638 | 67,980,528 | 2.6% |
| `Incursa.Quic.QuicAckFrame` | 622 | 66,266,128 | 2.6% |
| `Incursa.Quic.QuicConnectionSendDatagramEffect` | 593 | 63,195,072 | 2.4% |
| `Incursa.Qpack.QPackFieldLine[]` | 488 | 52,009,056 | 2.0% |

## P20 Movement Check

`QPackFieldLine[]` moved materially:

- P19 plaintext trace: 16.6% sampled share after request-side P19 work.
- P21 plaintext trace: 2.1% sampled share after response-side P20 work.
- P21 JSON trace: 2.0% sampled share.

The previous response `BuildResponseHeaders` `Array.Resize<T>` source is no longer visible as a dominant type-level signal. The targeted P20 BDN benchmark remains the strongest proof that the builder `Array.Resize<T>` path disappeared; this P21 EventPipe pass cannot prove source-line absence because allocation stacks were empty.

## Subsystem Split

| Subsystem | Evidence | Approx. share | Top method/call site | Confidence | Optimization risk |
| --- | --- | ---: | --- | --- | --- |
| QPACK request decode/materialization | `QPackFieldLine[]` type in both traces | 2.0-2.1% | no stack; remaining request/response exact arrays likely mixed | Medium for type, low for call site | Medium; public defensive-copy behavior must remain |
| QPACK response encode/materialization | P20 BDN plus low `QPackFieldLine[]` share | included in 2.0-2.1% | `BuildResponseHeaders` no longer dominant | Medium | Low if only measured later; not selected now |
| HTTP/3 frame reader payload buffers | `System.Byte[]` top type, no stack | part of 17.9-18.1% unknown byte[] | unknown | Low | Medium; parser behavior and ownership rules are sensitive |
| HTTP/3 response frame buffers | `System.Byte[]` top type, no stack | part of 17.9-18.1% unknown byte[] | unknown | Low | Medium; wire bytes must remain identical |
| STREAM payload construction | `System.Byte[]`, `QuicConnectionSendDatagramEffect`, `QuicConnectionEffect[]` | byte[] unknown; effects 2.4-2.8%; effect arrays 2.4-2.5% | no stack | Medium for type, low for call site | Medium-high; transport send path is out of scope without stronger attribution |
| Packet build/protection buffers | `System.Byte[]` top type plus crypto cipher allocations | part of 17.9-18.1% unknown byte[]; cipher about 1.0-1.1% | no stack | Low | High; packet protection is explicitly guarded |
| Packet open/decrypt buffers | `System.Byte[]` top type | part of 17.9-18.1% unknown byte[] | no stack | Low | High; packet opening is security-sensitive |
| UDP receive/datagram ownership | `System.Byte[]`, `IPAddress`, `IPEndPoint`, packet received event types | byte[] unknown; `IPAddress` 1.9-2.1%; packet received event JSON 0.9% | no stack | Low | Medium-high; receive ownership and lifetime are sensitive |
| Diagnostics/event/qlog allocations | `Http3DiagnosticEvent` type in both traces; code review shows construction before disabled sink check | 5.1-5.5% | `Http3Server` `Emit(new Http3DiagnosticEvent(...))` sites before `Emit` checks `diagnosticsSink?.IsEnabled` | High | Low-medium; behavior is testable for enabled/disabled sinks |
| ACK/frame model allocation | `QuicAckFrame`, ACK receipt node arrays, `Entry<ulong>[]`, recovery enumerators | individual types 2.4-4.0% | no stack | Medium for subsystem, low for call site | High; ACK/loss recovery is guarded |
| Lifecycle/timer/effect arrays | timer tuple arrays, `QuicConnectionEffect[]`, slot arrays, task/state-machine types | individual types 1.0-2.9% | no stack | Medium for subsystem, low for call site | Medium-high; needs dedicated attribution |
| Async/task/read lifecycle allocation | state machines and tasks | about 1.0-1.6% per visible type | no stack | Medium for type | Medium; broad async changes are risky |
| Unknown/unclassified | `System.Byte[]` with empty stacks | 17.9-18.1% | no stack | High for type, low for source | Unknown; needs stronger profiler |

## Selected P22 Target

Selected target: avoid `Http3DiagnosticEvent` allocation when HTTP/3 diagnostics are disabled.

Confidence: high for bounded source, medium for end-to-end impact.

Rationale:

- `Http3DiagnosticEvent` is the clearest post-P20 Incursa-owned allocation source with source code attribution.
- The TechEmpower sample used by ProtocolLab does not configure `Http3ServerOptions.DiagnosticsSink`, so these events are currently allocated and immediately dropped by `Emit`.
- The source is behavior-testable: disabled sinks should allocate no event objects and emit nothing; enabled sinks must continue receiving the same events with the same payloads and ordering.
- It does not require changing HTTP/3 semantics, QPACK semantics, packet protection, UDP send, scheduling, or ProtocolLab semantics.

Not selected for P22:

- `System.Byte[]` is the top sampled type, but the P21 EventPipe trace had empty call stacks. This needs Visual Studio, dotMemory, PerfView, or a more targeted benchmark/probe before a safe byte-buffer optimization can be selected.
- ACK/loss recovery and packet/protection-related types are visible, but those subsystems are explicitly guarded and need stronger call-site attribution before any optimization.
- Remaining `QPackFieldLine[]` is no longer dominant after P20.

## Optimization Status

No optimization was performed in P21.

Behavior changed: no.

## Validation

Commands run:

```powershell
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
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
- full test project: failed with 7 known failures, 5 trace-link failures and 2 DoQ cancellation exact-type failures.
- no loopback socket bind failure reproduced in the P21 full-suite run.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

## Recommended P22 Prompt

Continue Incursa H3 Performance Phase P22: eliminate disabled HTTP/3 diagnostic event allocations.

Work in `C:\src\incursa\quic-dotnet`.

Context: P21 fresh post-P20 allocation traces show `Incursa.Quic.Http3.Http3DiagnosticEvent` is now the clearest bounded Incursa-owned allocation source:

- plaintext: 140,755,936 sampled bytes, 5.1%
- JSON: 143,098,072 sampled bytes, 5.5%

The TechEmpower ProtocolLab sample does not configure `Http3ServerOptions.DiagnosticsSink`, but `Http3Server` constructs `new Http3DiagnosticEvent(...)` at each call site before `Emit` checks `diagnosticsSink?.IsEnabled`. The event is then dropped. `System.Byte[]` remains the top sampled type at about 18%, but EventPipe stack extraction was empty, so byte-array call-site optimization should wait for stronger attribution.

Primary goal: avoid allocating `Http3DiagnosticEvent` when HTTP/3 diagnostics are disabled while preserving enabled diagnostics behavior exactly.

Add tests first for disabled diagnostics emitting no events and enabled diagnostics preserving event kind, payload, and ordering. Add/extend BDN benchmarks for disabled and enabled server diagnostic emission paths. Then implement a narrow guard/helper design in `Http3Server` that checks diagnostics availability before constructing event objects. Do not change HTTP/3 semantics, QPACK behavior, public QPACK APIs, QUIC scheduling, UDP send, packet protection, ACK/loss recovery, or ProtocolLab semantics. Rerun focused tests, BDN before/after, and ProtocolLab counters.
