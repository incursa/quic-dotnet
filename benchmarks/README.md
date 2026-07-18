# Benchmarks

Permanent BenchmarkDotNet suites for `Incursa.Quic`.

## Baseline Path

The reusable baseline surface for current product-viability checks is the
set of hot paths that most directly affect congestion control, RTT estimation,
sender-adjacent stream state, and send-priority ordering:

- `QuicCongestionControlBenchmarks`
- `QuicRttEstimatorBenchmarks`
- `QuicConnectionStreamStateBenchmarks`
- `QuicStreamWritePreparationBenchmarks`
- `QuicApplicationSendPriorityBenchmarks`

Run them through the launcher:

```powershell
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short
```

`Dry` validates the harness quickly. `Short` is the recommended repeatable
baseline measurement for the current Incursa-only internal suites. It is not a
public `System.Net.Quic` or direct MSQUIC comparison.

## Performance Lane Surface Mapping

`scripts/perf/Invoke-QuicPerformanceLane.ps1` uses the permanent BenchmarkDotNet
suites as local developer-feedback companions to ProtocolLab source-reference
runs:

- `RawQuicMultiplex` runs `QuicApplicationSendPriorityBenchmarks`,
  `QuicApplicationSendQueueSortingBenchmarks`,
  `QuicApplicationSendBatchPayloadBenchmarks`, and
  `QuicStreamParsingBenchmarks`.
- `RawQuicStreamThroughput` runs the same send/parsing suites with
  ProtocolLab `quic.transport.stream-throughput.1mb` for transport-only
  throughput isolation.
- `RawQuicDuplex` runs the same send/parsing suites plus
  `QuicConnectionStreamStateBenchmarks`.
- `RawQuicSendCore` runs send-priority, queue-sorting, batch-payload,
  distinct-stream-id, outstanding-sent-stream-packet lookup/bookkeeping/
  lifecycle, deadline-scheduler, congestion-control, and congestion-discard
  suites without a ProtocolLab run unless the caller supplies a raw QUIC
  scenario.
- `CryptoCore` runs packet-protection, key-phase, crypto-buffer, and managed
  X25519 suites without a ProtocolLab run. It is a local microbenchmark surface
  for cryptographic hot paths, not an end-to-end transport benchmark.
- `PublicApiStream` runs `QuicPublicApiStreamTransferBenchmarks` and
  `QuicPublicApiSteadyStateStreamBenchmarks` through the public comparison
  launcher and does not claim equivalence with ProtocolLab raw QUIC or HTTP/3
  scenarios.

The `Smoke` lane uses BDN `Dry`. The `Confidence` lane uses BDN `Short` and is
report-only until stable baselines and thresholds are established.

## Public Comparison

The benchmark project also carries a bounded public-facade comparison suite:

- `QuicPublicApiLoopbackBenchmarks`
- `QuicPublicApiStreamTransferBenchmarks`
- `QuicPublicApiSteadyStateStreamBenchmarks`
- `QuicPublicApiLifecyclePhaseBenchmarks`

Run it through the launcher when the goal is a like-for-like local comparison
between the Incursa public facade and `System.Net.Quic`:

```powershell
.\scripts\benchmarks\Invoke-QuicPublicComparison.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicPublicComparison.ps1 -Job Short
```

These suites are intentionally narrow. The current proven floor for
`QuicPublicApiLoopbackBenchmarks` compares only public-facade loopback
connection establishment plus disposal. `QuicPublicApiStreamTransferBenchmarks`
compares bounded public-facade loopback upload-only, download-only,
request/response, and sequential and concurrent many-stream request/response
workloads.
`QuicPublicApiSteadyStateStreamBenchmarks` keeps a connection established across
iterations so per-stream request/response and queued-write costs can be separated
from connection setup and handshake cost.
`QuicPublicApiLifecyclePhaseBenchmarks` keeps the public-facade phase split honest
by attributing listener setup, connect/accept/handshake, stream open/accept,
request write/read, FIN, connection close, and disposal separately. The rows are
still matched across Incursa.Quic and System.Net.Quic only when both public APIs
report support.
`System.Net.Quic` omits the standalone `StreamOpenAccept` row and the later
stream-lifecycle rows because inbound accept does not complete in isolation in
this benchmark surface and would otherwise hang the smoke run.
Unsupported implementations are omitted when either public support marker
(`QuicConnection.IsSupported` or `QuicListener.IsSupported`) is false, and the
results must not be treated as equivalent to the repo's internal helper
benchmarks or as full internet, HTTP/3, or interop-runner performance claims.
The public stream-transfer comparison is traced under `REQ-QUIC-API-0016` and
now has its own bounded benchmark suite.

For a faster non-BDN allocation probe of the established-connection
request/response path, run:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-stream 200 --json .artifacts/perf/public-stream-profile/local-profile-stream.json
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-stream 200 --target incursa --json .artifacts/perf/public-stream-profile/local-profile-stream-incursa.json
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --profile-stream-phases 200 --json .artifacts/perf/public-stream-profile/local-profile-stream-phases.json
```

`--profile-stream` reuses one connected pair per implementation and reports two
passes of managed bytes, working set, private bytes, and elapsed time per
request/response stream operation. Use `--target incursa`, `--target systemnet`,
or `--target all` when tracing one implementation is more useful than the
default comparison run.

`--profile-stream-phases` reuses one Incursa connected pair and breaks the same
established request/response stream operation into public API phases such as
open, write, complete-writes, read, EOF, and dispose. Open, write, and
complete-writes are split into API-start and await-completion buckets so setup
cost can be separated from runtime completion cost. Treat the phase output as
diagnostic attribution for choosing the next code-review target, not as a
standalone performance claim.

## Local HTTP/3 Loopback

Use the local HTTP/3 harness for repeated end-to-end development measurements
before escalating a candidate to ProtocolLab:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- `
  --http3-loopback `
  --payload-sizes 65536,1048576 `
  --concurrency 1,4,16 `
  --samples 5 `
  --duration-seconds 3 `
  --warmup-seconds 1 `
  --label candidate `
  --json .artifacts/perf/http3-local/candidate.json
```

Certificate generation, listener startup, and connection warmup are outside
measured samples. Every response must use exact HTTP/3, declare the expected
content length, and match every expected payload byte. The JSON report includes
per-sample throughput, request rate, p50/p95/p99 latency, process-wide managed
allocation, collection counts, median/range, and coefficient of variation.
The client and server share one process and host, so use the harness for rapid
A/B development evidence rather than isolated-hardware or peer claims. When
separate source roots are required, build each benchmark binary and run them in
an interleaved A/B/B/A order before comparing results.

## Black-Box External Lane

For public cross-implementation work, use an external client-driven benchmark
such as [`h2load`](https://nghttp2.org/documentation/h2load.1.html) against an
HTTP/3 endpoint. `h2load` has an `--h3` mode and reports connection, request,
throughput, and allocation-adjacent transport statistics from the outside.

There is no active QUIC-specific standard benchmark to anchor this lane on.
The closest public protocolization attempt is the IETF QUIC Performance
Internet-Draft, but it is expired and no longer active. Treat that draft as a
historical reference only. Keep this lane separate from the repo-native BDN
suites above.

## Other Suites

The benchmark project also contains the following permanent suites:

- `QuicByteBufferAllocationBenchmarks`, including terminal STREAM receive
  rows that guard exact retained capacity when final size is known.
- `QuicPublicApiLoopbackBenchmarks`
- `QuicPublicApiStreamTransferBenchmarks`
- `QuicPublicApiSteadyStateStreamBenchmarks`
- `QuicFrameCodecBenchmarks`
- `Http3AllocationPathBenchmarks`
- `QuicPathValidationBenchmarks`
- `QuicEcnValidationBenchmarks`
- `QuicCryptoBufferBenchmarks`
- `QuicDplpmtudStateBenchmarks`
- `QuicAeadUsageLimitCalculatorBenchmarks`
- `QuicAeadKeyLifecycleBenchmarks`
- `QuicTransportParametersBenchmarks`
- `QuicHeaderParsingBenchmarks`
- `QuicStreamParsingBenchmarks`
- `QuicVariableLengthIntegerBenchmarks`
- `QuicInitialPacketProtectionBenchmarks`
- `QuicInitialPacketOpenBenchmarks`
- `QuicHandshakePacketProtectionBenchmarks`
- `QuicRetryIntegrityBenchmarks`
- `QuicAddressValidationTokenBenchmarks`
- `DoqPaddingBenchmarks`
- `DnsServiceBindingWireRecordBenchmarks`
- `QuicTlsServerHelloRetryRequestBenchmarks`
- `QuicTlsX25519Benchmarks`
- `QuicTlsServerFinishedPublicationBenchmarks`
- `QuicTlsClientFinishedPublicationBenchmarks`
- `QuicApplicationPacketKeyPhaseBenchmarks`
- `QuicRepeatedKeyUpdateControlBenchmarks`
- `QuicTlsClientZeroRttEmissionBenchmarks`
- `QuicTlsClientZeroRttRejectionCleanupBenchmarks`
- `QuicStatelessResetBenchmarks`
- `QuicAckPiggybackPolicyBenchmarks`
- `QuicAckPiggybackPayloadBenchmarks`
- `QuicLongHeaderAckPiggybackPayloadBenchmarks`
- `QuicAckFrameSentRangeStorageBenchmarks`
- `QuicAckGenerationStateRangeEnumerationBenchmarks`
- `QuicDiagnosticsBenchmarks`
- `QuicDatagramFrameBenchmarks`
- `QuicApplicationSendDistinctStreamIdBenchmarks`
- `QuicApplicationSendQueueSortingBenchmarks`
- `QuicDeadlineSchedulerBenchmarks`
- `QuicRuntimeCollectionBenchmarks`
- `QuicConnectionSnapshotBenchmarks`
- `QuicRetransmissionQueueRemovalBenchmarks`
- `QuicOutstandingSentStreamPacketLookupBenchmarks`
- `QuicOutstandingSentStreamPacketBookkeepingBenchmarks`
- `QuicOutstandingSentStreamPacketLifecycleBenchmarks`
- `QuicCongestionControlDiscardBenchmarks`

Target a specific suite with `--filter` when iterating locally:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*Http3AllocationPathBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckPiggybackPolicyBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckPiggybackPayloadBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicLongHeaderAckPiggybackPayloadBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicPublicApiLifecyclePhaseBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckFrameSentRangeStorageBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckGenerationStateRangeEnumerationBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDiagnosticsBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationSendPriorityBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationSendDistinctStreamIdBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationSendQueueSortingBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDeadlineSchedulerBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRuntimeCollectionBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicConnectionSnapshotBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRetransmissionQueueRemovalBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicOutstandingSentStreamPacket*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicCongestionControlDiscardBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAddressValidationTokenBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*DoqPaddingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*DnsServiceBindingWireRecordBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicInitialPacketOpenBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDatagramFrameBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTlsX25519Benchmarks*"
```

BenchmarkDotNet writes reports under `.artifacts/bdn/results` by default.
The baseline launcher writes each filtered suite under
`.artifacts/bdn/baseline/<Job>/<Suite>/` unless `-ArtifactsRoot` is supplied.
