# Incursa H3 Performance Phase P13

Date: 2026-05-27

Phase: Incursa H3 Performance Phase P13: QuicStream.ReadAsync and stream read lifecycle allocation attribution/reduction

Scope: one bounded stream-read lifecycle optimization. No HTTP/3 semantics, QPACK behavior, ACK/loss recovery behavior, QUIC scheduling, UDP send behavior, ProtocolLab benchmark semantics, or sample endpoint behavior were intentionally changed.

## P12 Recap

P12 attributed a bounded `System.Byte[]` source in `QuicConnectionStreamState.TryReceiveStreamFrame` / `InsertReadableBytes` and optimized full-segment inserts to retain the already-owned `byte[]` rather than copying the same payload again.

The isolated reduction was real but small:

| benchmark | P12 before | P12 after |
| --- | ---: | ---: |
| `StreamReceive_SinglePayloadFrame` | about 1.25 KB | about 1.22 KB |
| `StreamReceive_TwoContiguousPayloadFrames` | about 1.41 KB | about 1.35 KB |

P12 did not rerun ProtocolLab because the microbenchmark reduction was too small relative to the noisy P11 counter run.

## Stream Read Lifecycle Findings

Source review focused on `QuicStream.ReadAsync`, `ReadCoreAsync`, stream receive-buffer handling, cancellation/abort checks, FIN completion, and flow-control credit updates.

Findings:

- `QuicStream` had a byte-array `ReadAsync(byte[], int, int, CancellationToken)` override returning `Task<int>`.
- `QuicStream` did not override `ReadAsync(Memory<byte>, CancellationToken)`, so callers using the modern `Stream` memory API could fall back through the base implementation.
- `Http3Server.ReadRequestAsync` was using the byte-array overload even though it reads into a fixed local buffer and can safely pass `Memory<byte>`.
- `ReadCoreAsync` already had an immediate-read branch before waiting on `readGate`, but entering the async method still left room for state-machine/task allocation depending on call shape.
- Flow-control updates are queued when bytes are consumed. P13 preserved that behavior by moving the same immediate-read logic into a shared synchronous helper rather than removing it.
- Waiting reads, cancellation registration, abort, and end-of-stream paths were not optimized in this phase.

## Benchmark Additions

Added `benchmarks/QuicStreamReadLifecycleBenchmarks.cs` with memory diagnostics for already-buffered read shapes:

- `ReadAsyncMemory_AlreadyBufferedRequestSizedPayload`
- `ReadAsync_AlreadyBufferedRequestSizedPayload`
- `ReadAsync_AlreadyBufferedSmallPayload`
- `ReadAsync_AlreadyBufferedPartialRead`
- `ReadAsync_EndOfStreamAfterBufferedData`

The primary benchmark is the synchronous fast path: data is already buffered, the read completes immediately, and there is no cancellation, abort, or wait.

Artifacts:

- Before targeted run: `.artifacts\perf\incursa-h3-p13\bdn-before-readlifecycle-v5`
- After targeted run: `.artifacts\perf\incursa-h3-p13\bdn-after-readlifecycle`
- Broad after run: `.artifacts\perf\incursa-h3-p13\bdn-after`

The broad after run executed the wider H3/byte-buffer/stream-read suite. The targeted lifecycle runs are the primary before/after evidence because the broad run's stream-read rows were noisier.

## Behavior-Preservation Tests

Added `tests/Incursa.Quic.Tests/QuicStreamReadLifecycleTests.cs`:

- already-buffered byte-array read returns exact bytes;
- already-buffered memory read returns exact bytes;
- partial reads preserve unread tail and byte ordering;
- exact read through FIN followed by read after FIN returns zero;
- zero-length read returns zero and leaves buffered bytes unread;
- cancellation before waiting is preserved for byte-array read;
- cancellation before waiting is preserved for memory read.

Focused command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~QuicStreamReadLifecycleTests
```

Result: passed, 7/7.

## Selected Optimization Target

Selected target: avoid allocation on the already-buffered `ReadAsync(Memory<byte>, CancellationToken)` synchronous completion path.

Change:

- added `QuicStream.ReadAsync(Memory<byte>, CancellationToken)`;
- extracted the immediate read/check path into `TryCompleteReadSynchronously`;
- kept `ReadCoreAsync` as the wait/cancellation/abort path when data is not immediately available;
- changed `Http3Server.ReadRequestAsync` to call the memory overload for its request-stream read buffer.

The byte-array overload remains behavior-compatible and still returns `Task<int>`, so its allocation shape is expected to remain.

## Benchmark Results

Before command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p13\bdn-before-readlifecycle-v5 --inProcess
```

After command:

```powershell
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p13\bdn-after-readlifecycle --inProcess
```

| benchmark | before mean | before alloc | after mean | after alloc | allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ReadAsyncMemory_AlreadyBufferedRequestSizedPayload` | 377.9 ns | 72 B | 266.0 ns | 0 B | -72 B |
| `ReadAsync_AlreadyBufferedRequestSizedPayload` | 329.4 ns | 85 B | 336.3 ns | 85 B | 0 B |
| `ReadAsync_AlreadyBufferedSmallPayload` | 437.1 ns | 13 B | 479.2 ns | 14 B | +1 B |
| `ReadAsync_AlreadyBufferedPartialRead` | 386.6 ns | 48 B | 440.2 ns | 41 B | -7 B |
| `ReadAsync_EndOfStreamAfterBufferedData` | 616.1 ns | 9 B | 628.1 ns | 12 B | +3 B |

The selected memory-read path moved from 72 B/op to 0 B/op and improved mean time in the targeted short run. Other byte-array read shapes are effectively unchanged, as expected.

The broad after benchmark run also passed, but the stream-read rows showed high short-run noise and are not used for the primary P13 allocation claim.

## ProtocolLab Counter Rerun

ProtocolLab was rerun because the selected memory-read benchmark dropped to zero allocation and `Http3Server.ReadRequestAsync` now uses that path.

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 -ProtocolLabRoot C:\src\incursa\protocol-lab -Scenarios http.core.plaintext,http.core.json -Connections 16 -StreamsPerConnection 10 -DurationSeconds 10 -WarmupSeconds 2 -Repetitions 3 -RunId local-incursa-h3-p13-counters-20260527 -CaptureCounters
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p13-counters-20260527`

Counter summary:

| scenario | median req/s | median allocation rate | median B/request estimate | CPU mean median | Gen0/Gen1/Gen2 total |
| --- | ---: | ---: | ---: | ---: | ---: |
| JSON | 3,751.5 | 121.3 MB/s | 34,111 B | 69.2% | 485 / 155 / 15 |
| Plaintext | 3,657.8 | 120.9 MB/s | 34,529 B | 69.4% | 486 / 154 / 15 |

The P13 end-to-end counter result is compatible with the P11/P12 noisy range: JSON moved lower than the P11 reference of about 35.5 KB/request, while plaintext remained around the prior stable plaintext range of about 33.4-34.4 KB/request. This does not prove a meaningful end-to-end allocation-rate reduction from P13 alone.

## Validation

Commands run:

```powershell
dotnet build
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter FullyQualifiedName~QuicStreamReadLifecycleTests
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p13\bdn-after-readlifecycle --inProcess
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicStreamReadLifecycleBenchmarks*" "*QuicByteBufferAllocationBenchmarks*" "*Http3AllocationPathBenchmarks*" --artifacts C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p13\bdn-after --inProcess
git diff --check
$failed=$false; Get-ChildItem scripts\perf\*.ps1 | ForEach-Object { $tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $failed=$true } }; if ($failed) { exit 1 }
```

Results:

- `dotnet build`: passed.
- focused `QuicStreamReadLifecycleTests`: passed, 7/7.
- benchmark project build: passed.
- selected and broad BenchmarkDotNet runs: completed.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.
- full test project: failed with the known pre-existing family, 7 failed / 5,932 passed / 5,939 total.

Known full-test failures observed:

- 5 trace-link assertions expecting entries in `REQUIREMENT-GAPS.md`.
- 2 DoQ cancellation exact-type assertions expecting `OperationCanceledException` and receiving `TaskCanceledException`.

No new persistent failure family was observed.

## Worth Keeping

The P13 change is worth keeping. It removes allocation from the already-buffered memory-read path, gives `Http3Server.ReadRequestAsync` a lower-allocation read call shape, and preserves stream read behavior under focused tests.

The change is too small to explain the remaining end-to-end allocation signal by itself. The remaining ProtocolLab allocation estimate is still roughly 34 KB/request.

## Remaining Suspected Allocation Sources

Top remaining suspects after P13:

- stream read wait/suspend path, including `SemaphoreSlim.WaitAsync`, async state, cancellation, and read waiter lifecycle when data is not already buffered;
- broader `System.Byte[]` packet/stream/request buffers outside the single P12 receive-buffer slice;
- packet/frame parse and payload materialization that still copies byte arrays;
- byte-array `Stream.ReadAsync` consumers that cannot benefit from `ValueTask<int>`;
- per-request HTTP/3 object lifecycle and residual QPACK/header arrays, now likely secondary to transport/read lifecycle.

## Recommended P14

Recommended next phase:

```text
Continue Incursa H3 Performance Phase P14: stream read wait-path and read waiter allocation attribution.

Context:
P13 added a QuicStream Memory<byte> ReadAsync synchronous fast path and moved Http3Server.ReadRequestAsync to it. The selected already-buffered Memory<byte> read benchmark dropped from 72 B/op to 0 B/op, but ProtocolLab counters remain around 34 KB/request. The remaining P10 <ReadAsync>d__54 signal is therefore more likely from reads that suspend or wait, not from the already-buffered synchronous path.

Goal:
Attribute and reduce one measured read wait-path allocation source, such as SemaphoreSlim.WaitAsync/task allocation, cancellation registration, read waiter lifecycle, or async state-machine churn, while preserving cancellation, abort, FIN/end-of-stream, flow-control, and byte ordering semantics.

Do not change HTTP/3/QPACK behavior, ACK/loss recovery, QUIC scheduling, UDP send behavior, ProtocolLab semantics, or endpoint behavior.
```
