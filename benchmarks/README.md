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

## Other Suites

The benchmark project also contains the following permanent suites:

- `QuicFrameCodecBenchmarks`
- `QuicCryptoBufferBenchmarks`
- `QuicDplpmtudStateBenchmarks`
- `QuicAeadUsageLimitCalculatorBenchmarks`
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
