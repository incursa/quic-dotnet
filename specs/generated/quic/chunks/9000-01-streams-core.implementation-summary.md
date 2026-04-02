# RFC 9000 Chunk Implementation Summary: `9000-01-streams-core`

## Audit Result
- `partial_with_explicit_defer`
- In-scope requirements: 44 total, 8 implemented and tested, 1 partially implemented, 10 tested but implementation mapping unclear, 25 not implemented.
- Reconciliation artifact was present and used as the starting point.
- This pass did not change transport behavior; it tightened direct requirement refs on the existing stream parser and frame codec tests.

## Requirements Completed
- `S2P1`: `REQ-QUIC-RFC9000-S2P1-0003`, `REQ-QUIC-RFC9000-S2P1-0004`, `REQ-QUIC-RFC9000-S2P1-0006`, `REQ-QUIC-RFC9000-S2P1-0008`, `REQ-QUIC-RFC9000-S2P1-0009`, `REQ-QUIC-RFC9000-S2P1-0010`, `REQ-QUIC-RFC9000-S2P1-0011`
- `S2P2`: `REQ-QUIC-RFC9000-S2P2-0001`

## Direct Trace Updates This Pass
- `REQ-QUIC-RFC9000-S2P2-0002`, `REQ-QUIC-RFC9000-S2P2-0009`, `REQ-QUIC-RFC9000-S2P4-0004`, `REQ-QUIC-RFC9000-S2P4-0005`, `REQ-QUIC-RFC9000-S2P4-0006`, and `REQ-QUIC-RFC9000-S2P4-0007` now have direct requirement refs on the existing parser/codec tests.
- These refs improve traceability only; they do not add the missing stateful stream machinery called for by the open clauses.

## Files Changed
- `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`
- `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`
- `specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.md`
- `specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.json`

## Tests Added or Updated
- `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`: added canonical RFC 9000 section tags for the stream-frame parser tests that cover ordered stream payload bytes, offset handling, and FIN-bearing frames.
- `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`: added the same stream payload and FIN trace refs to the fuzz coverage.
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`: added canonical S2P4 refs to the RESET_STREAM and STOP_SENDING codec tests.
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`: added the same S2P4 refs to the fuzz coverage.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicStream"` - `30 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` - `295 passed, 0 failed, 0 skipped`

## Remaining Open Requirements in Scope
- `S2`: `REQ-QUIC-RFC9000-S2-0001` through `REQ-QUIC-RFC9000-S2-0005`, and `REQ-QUIC-RFC9000-S2-0007` remain not implemented.
- `S2`: `REQ-QUIC-RFC9000-S2-0006`, `REQ-QUIC-RFC9000-S2-0008`, and `REQ-QUIC-RFC9000-S2-0009` remain wire-level only and still need a stateful stream implementation to become fully proven.
- `S2P1`: `REQ-QUIC-RFC9000-S2P1-0001`, `REQ-QUIC-RFC9000-S2P1-0002`, `REQ-QUIC-RFC9000-S2P1-0005`, `REQ-QUIC-RFC9000-S2P1-0007`, and `REQ-QUIC-RFC9000-S2P1-0012` through `REQ-QUIC-RFC9000-S2P1-0014` remain not implemented.
- `S2P2`: `REQ-QUIC-RFC9000-S2P2-0002` remains partially implemented; `REQ-QUIC-RFC9000-S2P2-0003` through `REQ-QUIC-RFC9000-S2P2-0008` and `REQ-QUIC-RFC9000-S2P2-0010` remain not implemented; `REQ-QUIC-RFC9000-S2P2-0009` remains wire-level only.
- `S2P3`: all three requirements remain not implemented.
- `S2P4`: `REQ-QUIC-RFC9000-S2P4-0001` through `REQ-QUIC-RFC9000-S2P4-0003` and `REQ-QUIC-RFC9000-S2P4-0008` remain not implemented; `REQ-QUIC-RFC9000-S2P4-0004` through `REQ-QUIC-RFC9000-S2P4-0007` remain wire-level only and still depend on a stateful stream surface.

## Risks or Follow-up Notes
- The stream chunk is still blocked on missing connection-scoped stream state, allocation, and reassembly machinery.
- The current pass improves auditability but does not close any of the stateful transport gaps.
