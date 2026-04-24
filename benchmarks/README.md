# Benchmarks

Permanent BenchmarkDotNet suites for `Incursa.Quic`.

## Baseline Path

The reusable baseline surface for current product-viability checks is the
trio of hot paths that most directly affect congestion control, RTT
estimation, and sender-adjacent stream state:

- `QuicCongestionControlBenchmarks`
- `QuicRttEstimatorBenchmarks`
- `QuicConnectionStreamStateBenchmarks`

Run them through the launcher:

```powershell
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short
```

`Dry` validates the harness quickly. `Short` is the recommended repeatable
baseline measurement for the current Incursa-only internal suites. It is not a
public `System.Net.Quic` or MSQUIC comparison.

## Public Comparison

The benchmark project also carries a bounded public-facade comparison suite:

- `QuicPublicApiLoopbackBenchmarks`
- `QuicPublicApiStreamTransferBenchmarks`

Run it directly when the goal is a like-for-like local comparison between the
Incursa public facade and `System.Net.Quic`:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicPublicApiLoopbackBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicPublicApiLoopbackBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicPublicApiStreamTransferBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Short --filter "*QuicPublicApiStreamTransferBenchmarks*"
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

## Other Suites

The benchmark project also contains the following permanent suites:

- `QuicPublicApiLoopbackBenchmarks`
- `QuicPublicApiStreamTransferBenchmarks`
- `QuicFrameCodecBenchmarks`
- `QuicCryptoBufferBenchmarks`
- `QuicDplpmtudStateBenchmarks`
- `QuicAeadUsageLimitCalculatorBenchmarks`
- `QuicAeadKeyLifecycleBenchmarks`
- `QuicTransportParametersBenchmarks`
- `QuicHeaderParsingBenchmarks`
- `QuicStreamParsingBenchmarks`
- `QuicVariableLengthIntegerBenchmarks`
- `QuicInitialPacketProtectionBenchmarks`
- `QuicHandshakePacketProtectionBenchmarks`
- `QuicRetryIntegrityBenchmarks`
- `QuicTlsServerHelloRetryRequestBenchmarks`
- `QuicTlsServerFinishedPublicationBenchmarks`
- `QuicTlsClientFinishedPublicationBenchmarks`
- `QuicApplicationPacketKeyPhaseBenchmarks`
- `QuicRepeatedKeyUpdateControlBenchmarks`
- `QuicTlsClientZeroRttEmissionBenchmarks`
- `QuicTlsClientZeroRttRejectionCleanupBenchmarks`
- `QuicStatelessResetBenchmarks`

Target a specific suite with `--filter` when iterating locally:

```powershell
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
```

BenchmarkDotNet writes reports under `BenchmarkDotNet.Artifacts/results`
relative to the current working directory. When you run the launcher from the
repo root, reports land under the repo-root `BenchmarkDotNet.Artifacts/results`
directory.
