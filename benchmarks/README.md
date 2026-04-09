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
```

Use `--filter` to narrow to a subset of benchmarks when iterating locally.
