# Closeout

- Chunk: `9000-28-errors-registry-and-security`
- RFC: `9000`
- In-scope requirements: `70`
- Status counts: `34 implemented and tested`, `30 intentionally deferred`, `6 blocked by technical dependency`
- Reconciliation input: missing on disk at `./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.json`

## Audit Result

The chunk is internally consistent.

- Every in-scope requirement in `specs/requirements/quic/SPEC-QUIC-RFC9000.json` was matched to the requested section tokens.
- Every in-scope requirement has one of:
  - implementation evidence
  - test evidence
  - an explicit deferred or blocker note
- No stale or wrong requirement IDs were found in the in-scope test refs.
- No direct requirement refs were found in `src/` for this chunk, which matches the repo pattern for these helper slices.

## Evidence

Implemented-and-tested coverage is anchored in these test files:

- `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportErrorCodeTests.cs`
- `tests/Incursa.Quic.Tests/QuicHandshakeDoneFrameTests.cs`
- `tests/Incursa.Quic.Tests/QuicHandshakeDoneFrameFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs`
- `tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs`
- `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`
- `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P19-*.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/QuicConnectionCloseFrameProofSupport.cs`

## Notes

- Live addendum: `S19P19-0012`, `S19P19-0017`, `S19P19-0018`, and `S19P19-0019` are now covered by focused CONNECTION_CLOSE requirement-home proof under `ARC-QUIC-RFC9000-0043`, `WI-QUIC-RFC9000-0043`, and `VER-QUIC-RFC9000-0043`.
- `S19P20-0004`, `S19P20-0005`, `S19P20-0006`, `S21P2-0001`, `S21P2-0002`, and `S21P5P3-0001` remain deferred or blocked with explicit reasons.
- There are no silent gaps in scope.
- The chunk is ready to be merged or queued for repo-wide trace/audit tooling.
