# Incursa H3 Performance Phase P14

Date: 2026-05-27

## Scope

Phase P14 continued the stream-read work from P13 by measuring and reducing one bounded allocation source in the `QuicStream` read wait path. The phase did not change HTTP/3 semantics, QPACK behavior, ACK/loss recovery, QUIC scheduling, UDP send behavior, ProtocolLab benchmark semantics, endpoint/sample behavior, or h2load-specific handling.

## P13 Recap

P13 added the `Memory<byte>` `ReadAsync` overload, added an already-buffered synchronous completion helper, and moved `Http3Server.ReadRequestAsync` to the memory read path.

The selected P13 microbenchmark, `ReadAsyncMemory_AlreadyBufferedRequestSizedPayload`, dropped from 72 B/op to 0 B/op. End-to-end ProtocolLab counters stayed in the same noisy range:

| Scenario | P13 B/request |
| --- | ---: |
| `http.core.json` | ~34,111 |
| `http.core.plaintext` | ~34,529 |

P13 therefore proved that the selected already-buffered read path could be allocation-free without materially moving the end-to-end H3 allocation signal.

## Wait-Path Findings

The P14 inspection focused on `QuicStream.ReadAsync`, `QuicStream.ReadCoreAsync`, receive-buffer notification, cancellation, abort, FIN/end-of-stream, and flow-control credit update behavior.

Findings:

- A read that cannot complete synchronously waits through `SemaphoreSlim.WaitAsync(cancellationToken)`.
- The actual wait allocates the semaphore async waiter/task path, plus the async state-machine work needed to suspend and resume.
- Cancellation registration is already delayed until the read truly waits because `TryCompleteReadSynchronously` runs before `WaitAsync`.
- A non-cancelable waiting read does not need a cancellation registration, but still goes through the semaphore waiter/task path.
- The implementation has one semaphore waiter per waiting read, not a dedicated explicit stream-level waiter.
- Concurrent pending reads are not rejected today. A single notification releases one waiter, and each resumed waiter rechecks buffered data, abort, cancellation, and FIN state.
- Flow-control credit is updated only when `TryCompleteReadSynchronously` copies bytes to the caller. The optimization does not bypass that path.
- A reusable stream-level waiter may be possible later, but it is not safe to introduce without first deciding and proving the intended behavior for multiple pending reads.

## Selected Optimization

The selected target was the outer async state machine in `QuicStream.ReadAsync(Memory<byte>, CancellationToken)` on the wait path.

Before P14, the `Memory<byte>` overload synchronously checked the already-buffered path, then awaited `ReadCoreAsync`. That meant a true wait paid for both the outer overload's async state machine and the inner `ReadCoreAsync` wait path.

P14 changed the overload to:

- return `ValueTask.FromResult(bytesRead)` when the synchronous read helper completes;
- return `ReadCoreAsync(buffer, cancellationToken)` directly when the read must wait.

This preserves the existing `ReadCoreAsync` loop, `SemaphoreSlim` wait behavior, cancellation behavior, abort handling, FIN handling, byte ordering, and flow-control accounting. It also preserves the P13 already-buffered fast path.

## Behavior Tests Added

Focused stream read wait-path tests were added to `QuicStreamReadLifecycleTests`:

- read waits when no data is available;
- waiting read completes with exact bytes when data arrives;
- waiting partial read preserves the unread tail;
- multiple reads preserve byte order across waits;
- cancellation before data arrives preserves cancellation behavior;
- cancellation after data arrives but before read wake preserves cancellation and leaves bytes readable;
- abort while read is waiting preserves the original `QuicException`;
- FIN while read is waiting completes with zero and closes reads;
- read after FIN preserves end-of-stream behavior;
- one data notification releases only one pending read, matching current concurrent-read behavior;
- waiting read preserves flow-control credit accounting.

Focused result:

```text
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~QuicStreamReadLifecycleTests
Passed: 18, Failed: 0
```

## Benchmarks Added

`benchmarks\QuicStreamReadLifecycleBenchmarks.cs` now includes controlled in-memory wait-path shapes:

- `ReadAsync_WaitsThenCompletesSmallPayload`
- `ReadAsync_WaitsThenCompletesRequestSizedPayload`
- `ReadAsync_WaitsThenCompletesPartialRead`
- `ReadAsync_WaitsThenFin`
- `ReadAsync_CanceledBeforeData`
- `ReadAsync_AbortBeforeData`

The wait-path benchmarks start a read, keep it pending, inject stream data/FIN/abort/cancellation through the same stream bookkeeping path, then complete the read. Absolute allocation values include the controlled receive-frame injection and stream bookkeeping work, but before/after deltas isolate the selected read-path optimization.

## BenchmarkDotNet Results

Before artifacts:

- `.artifacts\perf\incursa-h3-p14\bdn-before`
- `.artifacts\perf\incursa-h3-p14\bdn-before-wait`

After artifacts:

- `.artifacts\perf\incursa-h3-p14\bdn-after`
- `.artifacts\perf\incursa-h3-p14\bdn-after-fastpath-check`

Primary stream-read comparison:

| Benchmark | Before Mean | After Mean | Mean Delta | Before Alloc | After Alloc | Alloc Delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `ReadAsyncMemory_AlreadyBufferedRequestSizedPayload` | 272.4 ns | 232.8 ns | -39.6 ns | 0 B | 0 B | 0 B |
| `ReadAsync_AlreadyBufferedRequestSizedPayload` | 340.0 ns | 200.8 ns | -139.2 ns | 79 B | 98 B | +19 B |
| `ReadAsync_AlreadyBufferedPartialRead` | 420.7 ns | 273.2 ns | -147.5 ns | 50 B | 58 B | +8 B |
| `ReadAsync_EndOfStreamAfterBufferedData` | 442.6 ns | 125.3 ns | -317.3 ns | 17 B | 27 B | +10 B |
| `ReadAsync_WaitsThenCompletesSmallPayload` | 4,642.8 ns | 2,525.5 ns | -2,117.3 ns | 686 B | 554 B | -132 B |
| `ReadAsync_WaitsThenCompletesRequestSizedPayload` | 3,554.0 ns | 3,131.0 ns | -423.0 ns | 746 B | 610 B | -136 B |
| `ReadAsync_WaitsThenCompletesPartialRead` | 4,577.6 ns | 2,842.0 ns | -1,735.6 ns | 722 B | 588 B | -134 B |
| `ReadAsync_WaitsThenFin` | 5,356.4 ns | 3,050.8 ns | -2,305.6 ns | 394 B | 260 B | -134 B |
| `ReadAsync_CanceledBeforeData` | 47,798.2 ns | 38,544.4 ns | -9,253.8 ns | 3,890 B | 2,995 B | -895 B |
| `ReadAsync_AbortBeforeData` | 43,986.8 ns | 22,977.7 ns | -21,009.1 ns | 2,866 B | 1,534 B | -1,332 B |

The already-buffered memory fast path remained allocation-free in the focused after check. A broad after run reported a noisy 26 B allocation for that row, so the focused single-benchmark rerun is the better comparison point for the P13 fast-path invariant.

The selected wait-path optimization reduced measured allocations for all new waiting-read shapes. The steady data/FIN waits dropped by about 132-136 B/op. Cancellation and abort shapes dropped more because they also avoid outer suspension work around paths that already allocate exception/cancellation machinery.

## ProtocolLab Counters

ProtocolLab was rerun because the selected wait-path benchmark moved meaningfully.

Command:

```text
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p14-counters-20260527 -CaptureCounters
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p14-counters-20260527`

Summary:

| Scenario | P13 B/request | P14 B/request | P14 req/s median | p50 | p95 | p99 | Alloc rate median | GC delta median | CPU mean median | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `http.core.json` | ~34,111 | ~34,084 | 3,630.0 | 21.650 ms | 32.761 ms | 42.544 ms | 123,725,578 B/s | 159 / 50 / 5 | 68.917% | 0 |
| `http.core.plaintext` | ~34,529 | ~33,800 | 3,526.3 | 24.316 ms | 37.456 ms | 43.015 ms | 119,187,531 B/s | 153 / 47 / 5 | 69.196% | 0 |

Validation/benchmark cells passed 6/6. Runtime counters were captured for 6/6 runs. The run still carried the expected local comparability warnings, including no CPU/network isolation, host-docker-internal URL rewrite, missing load-generator metrics, and noisy repeated medians.

The ProtocolLab allocation estimate did not move enough to claim an end-to-end allocation improvement. JSON was effectively unchanged from P13. Plaintext was lower than P13, but the difference is within the noisy range already observed for these local runs.

## Validation

Commands run:

```text
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" "*QuicByteBufferAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p14\bdn-before --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicStreamReadLifecycleBenchmarks*Wait*" "*QuicStreamReadLifecycleBenchmarks*CanceledBeforeData" "*QuicStreamReadLifecycleBenchmarks*AbortBeforeData" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p14\bdn-before-wait-dry --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p14\bdn-before-wait --inProcess
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~QuicStreamReadLifecycleTests
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" "*QuicByteBufferAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p14\bdn-after --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*ReadAsyncMemory_AlreadyBufferedRequestSizedPayload" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p14\bdn-after-fastpath-check --inProcess
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p14-counters-20260527 -CaptureCounters
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~InteropHarnessProcessObservabilityTests.ChildProcessKeyUpdateEmitsTheClientKeyUpdateMarkerEarlyAndKeepsStderrEmptyOnTheGreenPath
```

Results:

- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed.
- Focused stream lifecycle tests: passed, 18/18.
- After BenchmarkDotNet run: completed.
- ProtocolLab Incursa h3 h2load run: completed with 6/6 passed cells and 0 errors.
- `dotnet build`: passed.
- Full test project: failed with 8 failures.
- Five failures were the known trace-link family.
- Two failures were the known DoQ cancellation exact-type family.
- One keyupdate interop timeout appeared in the full run, then passed when rerun individually. This was treated as intermittent timing behavior, not a new persistent failure family.
- PowerShell parser validation for `scripts\perf\*.ps1`: passed.

## Keep Or Revert

The change is worth keeping.

Reasons:

- It reduces a measured wait-path allocation source without changing read semantics.
- It keeps the P13 already-buffered memory fast path allocation-free in the focused check.
- It preserves cancellation, abort, FIN, byte ordering, one-notification/one-waiter behavior, and flow-control accounting in focused tests.
- It leaves the riskier semaphore/waiter lifecycle untouched for this phase.

The change is not enough by itself to materially move ProtocolLab end-to-end allocation counters.

## Remaining Suspected Allocation Sources

The top remaining stream read wait-path source is still the inner `ReadCoreAsync` plus `SemaphoreSlim.WaitAsync` waiter/task lifecycle. That path is riskier because the current implementation permits multiple pending reads and relies on semaphore release counts to avoid lost wake-ups.

Broader H3 allocation suspects remain more likely to explain the roughly 34 KB/request ProtocolLab signal:

- request/response packet and stream payload byte arrays;
- STREAM frame receive buffering and bookkeeping;
- packet protection/open/build buffers;
- HTTP/3 request lifecycle buffers;
- QPACK/header decode and encode allocation surfaces;
- byte-array `Stream.ReadAsync` consumers outside the P13 memory fast path;
- diagnostics/runtime exception counter noise during local ProtocolLab runs.

## Recommended P15 Prompt

Continue Incursa H3 Performance Phase P15 as an attribution-first allocation pass. Start from the P14 artifacts and ProtocolLab counter result, but do not assume the remaining end-to-end allocation is in the stream wait path. Capture or derive the largest live per-request allocation source in the Incursa HTTP/3 request lifecycle, then optimize exactly one measured source only after behavior tests.

Required constraints:

- Do not change HTTP/3 semantics, QPACK behavior, ACK/loss recovery, QUIC scheduling, UDP send behavior, ProtocolLab semantics, endpoint/sample behavior, or cancellation/abort/FIN behavior.
- Preserve the P13 already-buffered memory fast path and the P14 wait-path behavior tests.
- If targeting stream wait again, first decide and test the intended multiple-pending-read contract before replacing `SemaphoreSlim.WaitAsync` with a reusable waiter.
- If attribution points outside stream wait, prefer the largest measured request-lifecycle or packet/STREAM buffer source over speculative waiter refactoring.
- Finish with before/after BenchmarkDotNet tables, ProtocolLab Incursa h3 h2load counters when the selected microbenchmark moves, and an updated analysis document.
