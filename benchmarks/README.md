# Benchmarks

This directory contains permanent BenchmarkDotNet suites for the QUIC parser hot paths.

## Current Suite

- `Incursa.Quic.Benchmarks`
- `QuicFrameCodecBenchmarks`: CRYPTO frame parsing and formatting

## Run

```bash
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHeaderParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --filter "*QuicHeaderParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicVariableLengthIntegerBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicStreamParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
```

Use `--filter` to narrow to a subset of benchmarks when iterating locally.
