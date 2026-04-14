# Benchmarks

This directory contains permanent BenchmarkDotNet suites for the QUIC parser hot paths.

## Current Suite

- `Incursa.Quic.Benchmarks`
- `QuicFrameCodecBenchmarks`: CRYPTO frame parsing and formatting, plus STREAM frame formatting
- `QuicCongestionControlBenchmarks`: congestion-window updates, ECN/loss recovery, and persistent-congestion detection
- `QuicTransportParametersBenchmarks`: transport-parameter parsing and formatting
- `QuicRttEstimatorBenchmarks`: RTT sample processing, ACK-delay clamping, and explicit min-RTT refresh
- `QuicInitialPacketProtectionBenchmarks`: Initial secret derivation, protect, and open
- `QuicHandshakePacketProtectionBenchmarks`: Handshake packet protection protect and open with TLS-derived material
- `QuicRetryIntegrityBenchmarks`: Retry integrity tag generation and validation
- `QuicTlsServerFinishedPublicationBenchmarks`: server Finished publication and 1-RTT packet-protection material derivation
- `QuicTlsClientFinishedPublicationBenchmarks`: client Finished publication and 1-RTT readiness derivation
- `QuicApplicationPacketKeyPhaseBenchmarks`: 1-RTT short-header packet formatting and opening with preserved Key Phase bits
- `QuicTlsClientZeroRttEmissionBenchmarks`: client resumption material publication and protected 0-RTT packet formatting
- `QuicTlsClientZeroRttRejectionCleanupBenchmarks`: rejected-vs-accepted cleanup for dormant ZeroRtt packet-protection material

## Run

```bash
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHeaderParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --filter "*QuicHeaderParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicVariableLengthIntegerBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicStreamParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicCongestionControlBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTransportParametersBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRttEstimatorBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicInitialPacketProtectionBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHandshakePacketProtectionBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRetryIntegrityBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTlsServerFinishedPublicationBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTlsClientFinishedPublicationBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicApplicationPacketKeyPhaseBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTlsClientZeroRttEmissionBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTlsClientZeroRttRejectionCleanupBenchmarks*"
```

Use `--filter` to narrow to a subset of benchmarks when iterating locally.
