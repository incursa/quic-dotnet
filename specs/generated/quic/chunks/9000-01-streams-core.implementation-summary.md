# RFC 9000 Chunk Implementation Summary: `9000-01-streams-core`

## Audit Result
- `partial_with_explicit_defer`
- In-scope requirements: 44 total, 8 implemented and tested, 1 partially implemented, 10 tested but implementation mapping unclear, 25 not implemented.
- Reconciliation artifact was present and used as the starting point.
- This pass closed the ordered stream reassembly slice for `REQ-QUIC-RFC9000-0047` and kept the remaining stream parser / frame codec refs aligned with the open clauses.

## Requirements Completed
- `S2P1`: `REQ-QUIC-RFC9000-S2P1-0003`, `REQ-QUIC-RFC9000-0032`, `REQ-QUIC-RFC9000-0033`, `REQ-QUIC-RFC9000-S2P1-0008`, `REQ-QUIC-RFC9000-S2P1-0009`, `REQ-QUIC-RFC9000-S2P1-0010`, `REQ-QUIC-RFC9000-S2P1-0011`
- `S2P2`: `REQ-QUIC-RFC9000-S2P2-0001`, `REQ-QUIC-RFC9000-0047`

## Direct Trace Updates This Pass
- `REQ-QUIC-RFC9000-0047` now has direct requirement-home proof in `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-0047.cs`, and `REQ-QUIC-RFC9000-S2P2-0009`, `REQ-QUIC-RFC9000-S2P4-0004`, `REQ-QUIC-RFC9000-S2P4-0005`, `REQ-QUIC-RFC9000-S2P4-0006`, and `REQ-QUIC-RFC9000-S2P4-0007` keep their direct refs on the existing parser/codec tests.
- The new S2P2-0002 home closes the ordered reassembly slice; the remaining refs keep the parser/codec-only clauses traced while the larger stream surface stays deferred.

## Files Changed
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-0047.cs`
- `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`
- `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`
- `specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.md`
- `specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.json`

## Tests Added or Updated
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-0047.cs`: added direct positive, negative, and edge proof for ordered stream reassembly.
- `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`: added canonical RFC 9000 section tags for the stream-frame parser tests that cover ordered stream payload bytes, offset handling, and FIN-bearing frames.
- `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`: added the same stream payload and FIN trace refs to the fuzz coverage.
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`: added canonical S2P4 refs to the RESET_STREAM and STOP_SENDING codec tests.
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`: added the same S2P4 refs to the fuzz coverage.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicStream"` - `30 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` - `295 passed, 0 failed, 0 skipped`

## Remaining Open Requirements in Scope
- `S2`: `REQ-QUIC-RFC9000-0019` through `REQ-QUIC-RFC9000-0022`, and `REQ-QUIC-RFC9000-0025` remain not implemented.
- `S2`: `REQ-QUIC-RFC9000-0024`, `REQ-QUIC-RFC9000-0027`, and `REQ-QUIC-RFC9000-0026` remain wire-level only and still need a stateful stream implementation to become fully proven.
- `S2P1`: `REQ-QUIC-RFC9000-S2P1-0001`, `REQ-QUIC-RFC9000-S2P1-0002`, `REQ-QUIC-RFC9000-0031`, `REQ-QUIC-RFC9000-0034`, and `REQ-QUIC-RFC9000-S2P1-0012` through `REQ-QUIC-RFC9000-S2P1-0014` remain not implemented.
- `S2P2`: `REQ-QUIC-RFC9000-0048` through `REQ-QUIC-RFC9000-0052` and `RFC9000-S2-2-P6-R01` remain not implemented; `REQ-QUIC-RFC9000-S2P2-0009` remains wire-level only.
- `S2P3`: all three requirements remain not implemented.
- `S2P4`: `REQ-QUIC-RFC9000-S2P4-0001` through `REQ-QUIC-RFC9000-S2P4-0003` and `REQ-QUIC-RFC9000-S2P4-0008` remain not implemented; `REQ-QUIC-RFC9000-S2P4-0004` through `REQ-QUIC-RFC9000-S2P4-0007` remain wire-level only and still depend on a stateful stream surface.

## Risks or Follow-up Notes
- Ordered receive buffering, final-size accounting, and MAX_* application now exist at the helper layer, and the new S2P2-0002 requirement-home proof exercises the ordered reassembly slice directly.
- The chunk is still blocked on an application-facing stream API, sender/recovery integration, and end-to-end STOP_SENDING/RESET orchestration.
- Retransmission-driven send states remain deferred.
