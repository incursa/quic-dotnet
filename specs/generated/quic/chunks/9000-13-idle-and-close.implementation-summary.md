# 9000-13-idle-and-close Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9000-S10P1-0001`
- `REQ-QUIC-RFC9000-S10P1-0003`
- `REQ-QUIC-RFC9000-S10P1-0005`
- `REQ-QUIC-RFC9000-S10P1-0006`
- `REQ-QUIC-RFC9000-S10P1-0007`
- `REQ-QUIC-RFC9000-S10P1P1-0001`
- `REQ-QUIC-RFC9000-S10P2P2-0001`
- `REQ-QUIC-RFC9000-S10P2P2-0003`

## Files Changed
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `src/Incursa.Quic/QuicIdleTimeoutState.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicIdleTimeoutStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S10P2P1-0008.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S10P2P2-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S10P2P2-0003.cs`
- `specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.md`
- `specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.json`

## Tests Added or Updated
- Added `QuicIdleTimeoutStateTests` to cover idle-timeout floor calculation, absent-timeout handling, and idle restart bookkeeping.
- Updated `QuicFrameCodecTests` to carry `REQ-QUIC-RFC9000-S10P1P1-0001` on the existing PING and ack-eliciting coverage.
- Updated `QuicTransportParametersTests` to carry `REQ-QUIC-RFC9000-S10P1-0003` on the existing `max_idle_timeout` round-trip coverage.
- Added requirement-home tests for the close-path helper slice so the lifecycle helper now proves closing-state entry plus draining-state no-send behavior without inventing a packet sender.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S10P2P1_0008|FullyQualifiedName~REQ_QUIC_RFC9000_S10P2P2_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S10P2P2_0003|FullyQualifiedName~REQ_QUIC_RFC9000_S10P2P2_0004"`
- Result: `7 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore`
- Result: `1349 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
- `REQ-QUIC-RFC9000-S10-0001`, `REQ-QUIC-RFC9000-S10-0002`, `REQ-QUIC-RFC9000-S10P1-0002`, `REQ-QUIC-RFC9000-S10P1-0004`, `REQ-QUIC-RFC9000-S10P1P2-0001`, `REQ-QUIC-RFC9000-S10P1P2-0002`, `REQ-QUIC-RFC9000-S10P2-0002`, `REQ-QUIC-RFC9000-S10P2-0004` through `REQ-QUIC-RFC9000-S10P2-0012`, `REQ-QUIC-RFC9000-S10P2P1-0001` through `REQ-QUIC-RFC9000-S10P2P1-0010`, `REQ-QUIC-RFC9000-S10P2P2-0002`, `REQ-QUIC-RFC9000-S10P2P2-0004`, `REQ-QUIC-RFC9000-S10P2P2-0005`, `REQ-QUIC-RFC9000-S10P2P3-0001` through `REQ-QUIC-RFC9000-S10P2P3-0013`
- The helper slice now closes the idle-timeout arithmetic requirements plus the closing/draining no-send helper clauses, but silent close/state discard, receive-triggered draining, and CONNECTION_CLOSE wire emission still need the endpoint runtime.
- `REQ-QUIC-RFC9000-S10P1P2-0001` is intentionally left as policy guidance rather than transport behavior.

## Risks or Follow-up Notes
- The repo now has helper-level closing/draining state transitions, but no endpoint runtime to turn those flags into packet emission or discard behavior.
- Idle timeout expiration is now detectable, but silent close and immediate close still require a connection controller to act on that state.
- No reconciliation artifact existed for this chunk, so it was treated as greenfield.
