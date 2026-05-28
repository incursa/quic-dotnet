# Incursa H3 Performance Phase P22

Date: 2026-05-28

## Scope

Phase P22 targeted only disabled HTTP/3 diagnostic event allocation. No HTTP/3 semantics, QPACK behavior, QUIC scheduling, packet protection, UDP send behavior, ACK/loss recovery, ProtocolLab benchmark semantics, or TechEmpower route behavior were intentionally changed.

## P21 Recap

P21 was attribution-only. It found fresh Incursa-only counters around:

| Scenario | P21 B/request |
| --- | ---: |
| `http.core.json` | 20,010 B |
| `http.core.plaintext` | 17,266 B |

The fresh P21 sampled traces showed:

| Type | Plaintext share | JSON share |
| --- | ---: | ---: |
| `System.Byte[]` | 17.9% | 18.1% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 5.1% | 5.5% |
| `Incursa.Qpack.QPackFieldLine[]` | 2.1% | 2.0% |

`QPackFieldLine[]` was no longer dominant after P19/P20. `Http3DiagnosticEvent` was selected because source review showed event objects were constructed before `Emit` checked `diagnosticsSink?.IsEnabled`, and the ProtocolLab TechEmpower sample does not configure `Http3ServerOptions.DiagnosticsSink`.

## Allocation Sites

`Http3Server` constructed `Http3DiagnosticEvent` objects on disabled paths for connection start/close, stream open/close, settings sent/received, QPACK instruction sent/received, frame sent/received, request started/completed, response started/completed, and error events.

`Http3DiagnosticEvent` is a sealed record with payload properties only; construction has no side effects. The diagnostics sink receives the event only through `IHttp3DiagnosticsSink.Emit`. Therefore the disabled path can safely check `IsEnabled` before constructing the record.

## Selected Guard Strategy

The selected design keeps the diagnostics API unchanged and adds cheap internal helpers:

- `IsDiagnosticEnabled(IHttp3DiagnosticsSink?)`
- `EmitStreamOpenedDiagnostic(...)`
- `EmitFrameDiagnostic(...)`
- `EmitRequestStartedDiagnostic(...)`
- `EmitResponseStartedDiagnostic(...)`
- `EmitResponseCompletedDiagnostic(...)`
- `EmitRequestCompletedDiagnostic(...)`
- `EmitStreamClosedDiagnostic(...)`

Each helper returns before constructing `Http3DiagnosticEvent` when the sink is null or disabled. Less common direct event sites now guard with `IsDiagnosticEnabled` before constructing the event.

Enabled behavior is intended to remain identical: same event kind, role, stream id, stream kind, frame type, raw frame type, payload length, method, path, status code, error code, message, and ordering at the existing emission points.

## Behavior Tests

Added focused diagnostics tests in `Http3MinimalServerTests`:

- disabled diagnostics preserve request/response behavior and emit no sink calls;
- disabled helper paths suppress stream, frame, request, response, and close events;
- enabled helper paths preserve payloads and ordering;
- enabled simple request lifecycle still emits request-stream events in the expected order.

Focused test result:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3MinimalServerTests"
```

Result: passed, 23/23.

## BenchmarkDotNet

Before command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3DiagnosticAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\bdn-before `
  --inProcess
```

After command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- `
  --job Short `
  --filter "*Http3DiagnosticAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" `
  --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\bdn-after `
  --inProcess
```

Diagnostic allocation benchmarks:

| Benchmark | Before allocated | After allocated | Before mean | After mean |
| --- | ---: | ---: | ---: | ---: |
| `DiagnosticsDisabled_StreamOpened` | 144 B | 0 B | 11.41 ns | 0.747 ns |
| `DiagnosticsEnabled_StreamOpened` | 144 B | 144 B | 14.85 ns | 12.20 ns |
| `DiagnosticsDisabled_FrameEmitted` | 144 B | 0 B | 15.09 ns | 0.764 ns |
| `DiagnosticsEnabled_FrameEmitted` | 144 B | 144 B | 17.08 ns | 14.10 ns |
| `DiagnosticsDisabled_RequestLifecycleShape` | 1,296 B | 0 B | 134.74 ns | 4.918 ns |
| `DiagnosticsEnabled_RequestLifecycleShape` | 1,296 B | 1,296 B | 166.54 ns | 111.83 ns |

Selected allocation-path benchmarks stayed allocation-neutral:

| Benchmark | Before allocated | After allocated |
| --- | ---: | ---: |
| `ReadRequestAsync_HeadersOnlyGetPlaintext` | 1,112 B | 1,112 B |
| `ReadRequestAsync_HeadersOnlyGetJson` | 1,088 B | 1,088 B |
| `RequestLifecycle_HeadersOnlyGetPlaintext` | 752 B | 752 B |
| `RequestLifecycle_HeadersOnlyGetJson` | 736 B | 736 B |

Artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\bdn-before`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\bdn-after`

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
  -RunId local-incursa-h3-p22-counters-20260528 `
  -CaptureCounters
```

Artifact:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p22-counters-20260528`

All six validation and benchmark cells passed. Runtime counters were captured for all six cells.

| Scenario | Req/s median | p50 ms | p95 ms | p99 ms | Allocation rate median | B/request est. | CPU mean/max | GC gen0/gen1/gen2 | Exceptions/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `http.core.json` | 3,584.4 | 22.76 | 33.94 | 40.63 | 61,274,774 B/s | 17,095 B | 68.2% / 145.3% | 76 / 24 / 4 | 52.8 | 0 |
| `http.core.plaintext` | 3,462.4 | 25.03 | 35.05 | 41.92 | 61,955,721 B/s | 17,894 B | 68.4% / 146.9% | 76 / 24 / 4 | 45.3 | 0 |

Comparison against P21:

| Scenario | P21 B/request | P22 B/request | Delta |
| --- | ---: | ---: | ---: |
| `http.core.json` | 20,010 B | 17,095 B | -2,915 B |
| `http.core.plaintext` | 17,266 B | 17,894 B | +628 B |

The counter result is directionally useful but mixed. JSON moved clearly downward; plaintext landed in the local shared-host noise band and slightly above P21. Because the signal was not consistently lower across both scenarios, no Kestrel-vs-Incursa refresh was run in P22.

## Allocation Trace Check

Optional post-P22 plaintext GC allocation trace command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 30 `
  -WarmupSeconds 2 `
  -Repetitions 1 `
  -RunId local-incursa-h3-p22-plaintext-gc-20260528 `
  -CaptureCounters `
  -TraceMode gc-allocation `
  -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\plaintext-gc-allocation `
  -TraceDurationSeconds 40
```

Trace artifacts:

- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\plaintext-gc-allocation\trace.nettrace`
- `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\plaintext-byte-stack-analysis\byte-stack-summary.md`

The generated type summary no longer contains `Http3DiagnosticEvent`. Top sampled types after P22:

| Type | Count | Sampled bytes | Share |
| --- | ---: | ---: | ---: |
| `System.Byte[]` | 3,760 | 400,623,672 | 19.8% |
| `Entry<System.UInt64>[]` | 730 | 77,772,216 | 3.8% |
| `System.Object` | 669 | 71,280,448 | 3.5% |
| recovery enumerator | 559 | 59,556,320 | 2.9% |
| `Incursa.Quic.QuicAckFrame` | 543 | 57,864,112 | 2.9% |
| `Incursa.Quic.QuicConnectionEffect[]` | 522 | 55,621,344 | 2.7% |
| ACK receipt node arrays | 503 | 53,600,384 | 2.6% |
| `Incursa.Quic.QuicConnectionSendDatagramEffect` | 478 | 50,930,528 | 2.5% |
| `Incursa.Qpack.QPackFieldLine[]` | 444 | 47,303,776 | 2.3% |

`System.Byte[]` remains the top sampled type. Call stacks are still empty in the TraceEvent analyzer output, so source-line attribution for byte arrays still requires Visual Studio, dotMemory, or PerfView.

## Validation

Commands run:

```powershell
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~Http3MinimalServerTests"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3DiagnosticAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*Http3DiagnosticAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p22\bdn-after --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p22-counters-20260528 -CaptureCounters
git diff --check
```

PowerShell parser check:

```powershell
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
- focused `Http3MinimalServerTests`: passed, 23/23.
- full test project: failed with the known 7 failures, 5 trace-link failures and 2 DoQ cancellation exact-type failures.
- benchmark project build: passed, 0 warnings, 0 errors.
- BDN before/after: completed.
- ProtocolLab Incursa-only counters: completed, 6/6 validation passed, 6/6 benchmark succeeded, counters captured 6/6.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

## Behavior Impact

Disabled diagnostics are allocation-free for the helper-covered stream/frame/request lifecycle shapes measured by BDN.

Enabled diagnostics behavior is unchanged by design and covered by payload/order tests. The event construction guard changes whether disabled sinks pay the allocation cost; it does not change HTTP/3 wire behavior, request parsing, response generation, QPACK wire semantics, QUIC scheduling, packet protection, UDP send behavior, or ProtocolLab benchmark semantics.

## Remaining Allocation Source

Post-P22 sampled attribution points back to `System.Byte[]` as the largest visible type at 19.8% sampled bytes, but the EventPipe analyzer still has empty call stacks. The visible non-byte-array sources are ACK/recovery/effect related and require stronger call-site attribution before they are safe targets.

## Recommended P23 Prompt

Continue Incursa H3 Performance Phase P23: post-P22 `System.Byte[]` source attribution.

Use fresh post-P22 evidence. Do not optimize from the old P10/P15/P16 byte-array split. Collect Visual Studio, dotMemory, PerfView, or equivalent allocation attribution with source-line/call-stack evidence for the top `System.Byte[]` allocations during Incursa H3 ProtocolLab h2load plaintext and JSON. Keep ProtocolLab semantics unchanged. Classify byte arrays into HTTP/3 frame payload buffers, response frame buffers, STREAM payload construction, packet build/protection buffers, packet open/decrypt buffers, UDP receive/datagram ownership, qlog/diagnostic snapshots, and unknown. Select exactly one bounded, behavior-testable P24 target only if the new source is clear. Do not change QUIC scheduling, UDP send, packet protection, ACK/loss recovery, QPACK semantics, or HTTP/3 semantics without focused tests and BDN baselines.
