# 9001-01-tls-core Closeout

## Scope

- RFC: `9001`
- Section tokens: `S2`, `S3`, `S4`, `S5`
- Canonical spec: [`SPEC-QUIC-RFC9001.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9001.json)
- Implementation summary: [`9001-01-tls-core.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json) (authoritative)
- Reconciliation artifact: [`9001-01-tls-core.reconciliation.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.reconciliation.json) (stale no-evidence snapshot)

## Summary

- Requirements in scope: `34`
- Implemented and tested: `3`
- Deferred: `1`
- Blocked by concrete dependency: `30`
- Stale IDs found in scope: `0`
- Silent gaps found in scope: `0`

## Requirements Completed

- `REQ-QUIC-RFC9001-S4-0001` Carry handshake data in CRYPTO frames.
- `REQ-QUIC-RFC9001-S4-0002` Define CRYPTO frame boundaries.
- `REQ-QUIC-RFC9001-S5-0003` Leave Version Negotiation packets unprotected.

## Remaining Open Requirements

### Deferred

- `REQ-QUIC-RFC9001-S2-0001` Interpret uppercase BCP 14 keywords.

### Blocked by Concrete Technical Dependency

- `REQ-QUIC-RFC9001-S3-0001` through `REQ-QUIC-RFC9001-S3-0012`
- `REQ-QUIC-RFC9001-S4-0003` through `REQ-QUIC-RFC9001-S4-0011`
- `REQ-QUIC-RFC9001-S5-0001`, `REQ-QUIC-RFC9001-S5-0002`, `REQ-QUIC-RFC9001-S5-0004` through `REQ-QUIC-RFC9001-S5-0010`

## Consistency Check

- The selected tests now carry canonical RFC 9001 requirement traits only:
  - [`QuicFrameCodecPart3Tests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs)
  - [`QuicVersionNegotiationTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs)
- No RFC 9001 requirement refs were found in `src` or `benchmarks`.
- The requirement refs present in tests are the expected ones:
  - `REQ-QUIC-RFC9001-S4-0001`
  - `REQ-QUIC-RFC9001-S4-0002`
  - `REQ-QUIC-RFC9001-S5-0003`
- No stale or wrong requirement IDs were found in scope.

## Files Changed

- [`tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs)
- [`tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs)
- [`benchmarks/QuicBenchmarkData.cs`](C:/src/incursa/quic-dotnet/benchmarks/QuicBenchmarkData.cs)
- [`benchmarks/QuicFrameCodecBenchmarks.cs`](C:/src/incursa/quic-dotnet/benchmarks/QuicFrameCodecBenchmarks.cs)
- [`benchmarks/README.md`](C:/src/incursa/quic-dotnet/benchmarks/README.md)
- [`specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.md`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.md)
- [`specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json)
- [`specs/generated/quic/chunks/9001-01-tls-core.closeout.md`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.closeout.md)
- [`specs/generated/quic/chunks/9001-01-tls-core.closeout.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.closeout.json)

## Tests Run and Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
- Result: Passed
- Summary: `198 passed, 0 failed, 0 skipped`
- `dotnet build benchmarks/Incursa.Quic.Benchmarks.csproj -c Release`
- Result: Passed
- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"`
- Result: Passed
- Summary: `2 benchmarks executed successfully in Dry mode`

## Risks / Follow-up Notes

- The remaining RFC 9001 clauses still depend on TLS handshake, packet protection, and key-update plumbing that is not present in this repository.
- The benchmark lane for CRYPTO frames was validated in Dry mode only.
- The reconciliation artifact remains useful as provenance, but the implementation summary is the authoritative audit input for this chunk.

## Conclusion

- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is trace-consistent and ready for repo-wide trace/audit tooling, but it is not fully closed because 31 requirements remain intentionally deferred or blocked.
