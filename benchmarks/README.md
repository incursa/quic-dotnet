# Benchmarks

Permanent BenchmarkDotNet suites for `Incursa.Quic`.

## Baseline Path

The reusable baseline surface for current product-viability checks is the
set of hot paths that most directly affect congestion control, RTT estimation,
sender-adjacent stream state, and send-priority ordering:

- `QuicCongestionControlBenchmarks`
- `QuicRttEstimatorBenchmarks`
- `QuicConnectionStreamStateBenchmarks`
- `QuicApplicationSendPriorityBenchmarks`

Run them through the launcher:

```powershell
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short
```

`Dry` validates the harness quickly. `Short` is the recommended repeatable
baseline measurement for the current Incursa-only internal suites. It is not a
public `System.Net.Quic` or direct MSQUIC comparison.

## Public Comparison

The benchmark project also carries a bounded public-facade comparison suite:

- `QuicPublicApiLoopbackBenchmarks`
- `QuicPublicApiStreamTransferBenchmarks`

Run it through the launcher when the goal is a like-for-like local comparison
between the Incursa public facade and `System.Net.Quic`:

```powershell
.\scripts\benchmarks\Invoke-QuicPublicComparison.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicPublicComparison.ps1 -Job Short
```

These suites are intentionally narrow. The current proven floor for
`QuicPublicApiLoopbackBenchmarks` compares only public-facade loopback
connection establishment plus disposal. `QuicPublicApiStreamTransferBenchmarks`
compares one bounded public-facade loopback request/response stream workload.
Unsupported implementations are omitted when either public support marker
(`QuicConnection.IsSupported` or `QuicListener.IsSupported`) is false, and the
results must not be treated as equivalent to the repo's internal helper
benchmarks or as full internet, HTTP/3, or interop-runner performance claims.
The public stream-transfer comparison is traced under `REQ-QUIC-API-0016` and
now has its own bounded benchmark suite.

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

- `QuicPublicApiLoopbackBenchmarks`
- `QuicPublicApiStreamTransferBenchmarks`
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
- `QuicTlsServerHelloRetryRequestBenchmarks`
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
- `QuicRuntimeCollectionBenchmarks`
- `QuicConnectionSnapshotBenchmarks`
- `QuicRetransmissionQueueRemovalBenchmarks`
- `QuicCongestionControlDiscardBenchmarks`

Target a specific suite with `--filter` when iterating locally:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*Http3AllocationPathBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckPiggybackPolicyBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckPiggybackPayloadBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicLongHeaderAckPiggybackPayloadBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckFrameSentRangeStorageBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAckGenerationStateRangeEnumerationBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDiagnosticsBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationSendPriorityBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationSendDistinctStreamIdBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationSendQueueSortingBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRuntimeCollectionBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicConnectionSnapshotBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRetransmissionQueueRemovalBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicCongestionControlDiscardBenchmarks*" --inProcess
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAddressValidationTokenBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicInitialPacketOpenBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDatagramFrameBenchmarks*" --inProcess
```

BenchmarkDotNet writes reports under `.artifacts/bdn/results` by default.
The baseline launcher writes each filtered suite under
`.artifacts/bdn/baseline/<Job>/<Suite>/` unless `-ArtifactsRoot` is supplied.
