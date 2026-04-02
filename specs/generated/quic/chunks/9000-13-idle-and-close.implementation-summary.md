# 9000-13-idle-and-close Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9000-S10P1-0001`
- `REQ-QUIC-RFC9000-S10P1-0003`
- `REQ-QUIC-RFC9000-S10P1-0005`
- `REQ-QUIC-RFC9000-S10P1-0006`
- `REQ-QUIC-RFC9000-S10P1-0007`
- `REQ-QUIC-RFC9000-S10P1P1-0001`

## Files Changed
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `src/Incursa.Quic/QuicIdleTimeoutState.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicIdleTimeoutStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
- `specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.md`
- `specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.json`

## Tests Added or Updated
- Added `QuicIdleTimeoutStateTests` to cover idle-timeout floor calculation, absent-timeout handling, and idle restart bookkeeping.
- Updated `QuicFrameCodecTests` to carry `REQ-QUIC-RFC9000-S10P1P1-0001` on the existing PING and ack-eliciting coverage.
- Updated `QuicTransportParametersTests` to carry `REQ-QUIC-RFC9000-S10P1-0003` on the existing `max_idle_timeout` round-trip coverage.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicIdleTimeoutStateTests|FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicTransportParametersTests"`
- Result: `51 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
- Result: `304 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
- `REQ-QUIC-RFC9000-S10-0001`, `REQ-QUIC-RFC9000-S10-0002`, `REQ-QUIC-RFC9000-S10P1-0002`, `REQ-QUIC-RFC9000-S10P1-0004`, `REQ-QUIC-RFC9000-S10P1P2-0001`, `REQ-QUIC-RFC9000-S10P1P2-0002`, `REQ-QUIC-RFC9000-S10P2-0001`, `REQ-QUIC-RFC9000-S10P2-0002`, `REQ-QUIC-RFC9000-S10P2-0003`, `REQ-QUIC-RFC9000-S10P2-0004`, `REQ-QUIC-RFC9000-S10P2-0005`, `REQ-QUIC-RFC9000-S10P2-0006`, `REQ-QUIC-RFC9000-S10P2-0007`, `REQ-QUIC-RFC9000-S10P2-0008`, `REQ-QUIC-RFC9000-S10P2-0009`, `REQ-QUIC-RFC9000-S10P2-0010`, `REQ-QUIC-RFC9000-S10P2-0011`, `REQ-QUIC-RFC9000-S10P2-0012`, `REQ-QUIC-RFC9000-S10P2P1-0001`, `REQ-QUIC-RFC9000-S10P2P1-0002`, `REQ-QUIC-RFC9000-S10P2P1-0003`, `REQ-QUIC-RFC9000-S10P2P1-0004`, `REQ-QUIC-RFC9000-S10P2P1-0005`, `REQ-QUIC-RFC9000-S10P2P1-0006`, `REQ-QUIC-RFC9000-S10P2P1-0007`, `REQ-QUIC-RFC9000-S10P2P1-0008`, `REQ-QUIC-RFC9000-S10P2P1-0009`, `REQ-QUIC-RFC9000-S10P2P1-0010`, `REQ-QUIC-RFC9000-S10P2P2-0001`, `REQ-QUIC-RFC9000-S10P2P2-0002`, `REQ-QUIC-RFC9000-S10P2P2-0003`, `REQ-QUIC-RFC9000-S10P2P2-0004`, `REQ-QUIC-RFC9000-S10P2P2-0005`, `REQ-QUIC-RFC9000-S10P2P3-0001`, `REQ-QUIC-RFC9000-S10P2P3-0002`, `REQ-QUIC-RFC9000-S10P2P3-0003`, `REQ-QUIC-RFC9000-S10P2P3-0004`, `REQ-QUIC-RFC9000-S10P2P3-0005`, `REQ-QUIC-RFC9000-S10P2P3-0006`, `REQ-QUIC-RFC9000-S10P2P3-0007`, `REQ-QUIC-RFC9000-S10P2P3-0008`, `REQ-QUIC-RFC9000-S10P2P3-0009`, `REQ-QUIC-RFC9000-S10P2P3-0010`, `REQ-QUIC-RFC9000-S10P2P3-0011`, `REQ-QUIC-RFC9000-S10P2P3-0012`, `REQ-QUIC-RFC9000-S10P2P3-0013`
- The helper slice closes the idle-timeout arithmetic requirements, but the connection-close and draining behaviors still need a connection-state machine and CONNECTION_CLOSE wire support.
- `REQ-QUIC-RFC9000-S10P1P2-0001` is intentionally left as policy guidance rather than transport behavior.

## Risks or Follow-up Notes
- The repo still has no connection-level close/drain lifecycle, so all Section 10.2 requirements remain blocked.
- Idle timeout expiration is now detectable, but silent close and immediate close still require a connection controller to act on that state.
- No reconciliation artifact existed for this chunk, so it was treated as greenfield.
