---
title: QUIC Benchmark Evidence Summary
status: passing
kind: benchmarks
---

# QUIC Benchmark Evidence Summary

This evidence captures the dry BenchmarkDotNet run used to validate the QUIC
hot-path benchmark suites and to provide benchmark evidence for attestation.

## Suites Executed

- `benchmarks/QuicHeaderParsingBenchmarks.cs`
- `benchmarks/QuicStreamParsingBenchmarks.cs`
- `benchmarks/QuicVariableLengthIntegerBenchmarks.cs`
- `benchmarks/QuicFrameCodecBenchmarks.cs`

## Command

- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*Quic*Benchmarks*"`

## Outcome

- The dry run completed successfully for all 19 benchmark methods.
- BenchmarkDotNet exported suite reports beneath
  `benchmarks/BenchmarkDotNet.Artifacts/results`.
- This directory can now be consumed as benchmark evidence by Workbench
  attestation.

## Related Verification Artifacts

- `specs/verification/quic/VER-QUIC-RFC8999-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9000-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9001-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9002-0001.json`
