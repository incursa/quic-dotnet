---
title: QUIC Benchmark Evidence Summary
status: passing
kind: benchmarks
---

# QUIC Benchmark Evidence Summary

This evidence captures the dry BenchmarkDotNet run used to validate the QUIC
hot-path benchmark suites and to provide benchmark evidence for attestation.

## Suites Executed

- `benchmarks/QuicInitialPacketProtectionBenchmarks.cs`
- `benchmarks/QuicHeaderParsingBenchmarks.cs`
- `benchmarks/QuicStreamParsingBenchmarks.cs`
- `benchmarks/QuicVariableLengthIntegerBenchmarks.cs`
- `benchmarks/QuicFrameCodecBenchmarks.cs`

## Command

- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicInitialPacketProtectionBenchmarks*"`

## Outcome

- The dry run completed successfully for all 3 benchmark methods in the Initial packet protection suite.
- BenchmarkDotNet exported suite reports beneath
  `BenchmarkDotNet.Artifacts/results` relative to the working directory. When
  you run the command from the repo root, the reports land under the repo-root
  `BenchmarkDotNet.Artifacts/results` directory.
- This directory can now be consumed as benchmark evidence by Workbench
  attestation.
- Earlier benchmark evidence for the existing hot-path suites remains in the
  repository history and is not replaced by this additive Initial-slice run.

## Related Verification Artifacts

- `specs/verification/quic/VER-QUIC-RFC8999-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9000-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9001-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9002-0001.json`
