# Benchmarks

This directory contains permanent BenchmarkDotNet suites for the QUIC parser hot paths.

## Current Suite

- `Incursa.Quic.Benchmarks`

## Run

```bash
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHeaderParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --filter "*QuicHeaderParsingBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicVariableLengthIntegerBenchmarks*"
dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicStreamParsingBenchmarks*"
```

Use `--filter` to narrow to a subset of benchmarks when iterating locally.
