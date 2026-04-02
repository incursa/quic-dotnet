# 9002-04-congestion-control implementation summary

## Requirements completed

Implemented and tested the following RFC 9002 section 7 requirements in the helper-state slice:

- `REQ-QUIC-RFC9002-S7-0002`, `REQ-QUIC-RFC9002-S7-0003`, `REQ-QUIC-RFC9002-S7-0004`, `REQ-QUIC-RFC9002-S7-0006`
- `REQ-QUIC-RFC9002-S7P1-0001`
- `REQ-QUIC-RFC9002-S7P2-0001`, `REQ-QUIC-RFC9002-S7P2-0002`, `REQ-QUIC-RFC9002-S7P2-0003`, `REQ-QUIC-RFC9002-S7P2-0004`, `REQ-QUIC-RFC9002-S7P2-0005`
- `REQ-QUIC-RFC9002-S7P3P1-0001`, `REQ-QUIC-RFC9002-S7P3P1-0002`, `REQ-QUIC-RFC9002-S7P3P1-0003`
- `REQ-QUIC-RFC9002-S7P3P2-0001`, `REQ-QUIC-RFC9002-S7P3P2-0002`, `REQ-QUIC-RFC9002-S7P3P2-0003`, `REQ-QUIC-RFC9002-S7P3P2-0004`, `REQ-QUIC-RFC9002-S7P3P2-0005`, `REQ-QUIC-RFC9002-S7P3P2-0006`, `REQ-QUIC-RFC9002-S7P3P2-0007`
- `REQ-QUIC-RFC9002-S7P3P3-0001`, `REQ-QUIC-RFC9002-S7P3P3-0002`
- `REQ-QUIC-RFC9002-S7P4-0001`, `REQ-QUIC-RFC9002-S7P4-0002`
- `REQ-QUIC-RFC9002-S7P5-0001`, `REQ-QUIC-RFC9002-S7P5-0002`
- `REQ-QUIC-RFC9002-S7P6-0001`
- `REQ-QUIC-RFC9002-S7P6P1-0001`, `REQ-QUIC-RFC9002-S7P6P1-0002`, `REQ-QUIC-RFC9002-S7P6P1-0003`
- `REQ-QUIC-RFC9002-S7P6P2-0001`, `REQ-QUIC-RFC9002-S7P6P2-0002`, `REQ-QUIC-RFC9002-S7P6P2-0003`, `REQ-QUIC-RFC9002-S7P6P2-0004`, `REQ-QUIC-RFC9002-S7P6P2-0005`, `REQ-QUIC-RFC9002-S7P6P2-0006`
- `REQ-QUIC-RFC9002-S7P8-0001`, `REQ-QUIC-RFC9002-S7P8-0003`

## Files changed

- `src/Incursa.Quic/QuicCongestionControlState.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`
- `benchmarks/QuicCongestionControlBenchmarks.cs`
- `benchmarks/README.md`
- `specs/generated/quic/chunks/9002-04-congestion-control.implementation-summary.md`
- `specs/generated/quic/chunks/9002-04-congestion-control.implementation-summary.json`

## Tests added or updated

- Added `QuicCongestionControlStateTests` to cover:
  - initial window and minimum window formulas
  - per-path state independence
  - ACK-only exclusion from bytes in flight and congestion control
  - probe packet flight accounting
  - loss entry, ECN entry, and recovery behavior
  - pacing interval and burst-limit helpers
  - persistent congestion duration and collapse behavior
  - gentler recovery-window reduction helper
- Added `QuicCongestionControlBenchmarks` to keep the hot-path helper methods in the permanent benchmark suite.

## Tests run

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter FullyQualifiedName~QuicCongestionControlStateTests`
- `dotnet build benchmarks/Incursa.Quic.Benchmarks.csproj`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`

Results:

- Targeted congestion-control tests: passed, 6/6
- Benchmark project build: passed, 0 warnings, 0 errors
- Full test project: passed, 326/326

## Remaining open requirements in scope

Deferred because the repo slice still lacks a full sender/pacer/application-limited classification surface:

- `REQ-QUIC-RFC9002-S7-0001`
- `REQ-QUIC-RFC9002-S7P7-0001`
- `REQ-QUIC-RFC9002-S7P7-0002`
- `REQ-QUIC-RFC9002-S7P7-0003`
- `REQ-QUIC-RFC9002-S7P7-0004`
- `REQ-QUIC-RFC9002-S7P7-0005`
- `REQ-QUIC-RFC9002-S7P8-0002`

## Risks and follow-up notes

- The helper now models RFC 9002 congestion-control math and state transitions, but it does not yet own packet scheduling or send-loop pacing decisions.
- `TryComputePacingIntervalMicros` and `TryGetBurstLimitBytes` are intentionally helper-level calculations; a sender integration slice is still needed to make the pacing requirements end-to-end.
- `PublicAPI.Unshipped.txt` was updated to keep the new public surface analyzer-clean without exposing record-generated members.
