# Closeout

- Chunk: `9000-29-iana-and-late-sections`
- RFC: `9000`
- In-scope requirements: `52`
- Status counts: `26 implemented and tested`, `26 intentionally deferred`
- Reconciliation input: missing on disk at `./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.json`

## Audit Result

The chunk is internally consistent.

- Every in-scope requirement in `specs/requirements/quic/SPEC-QUIC-RFC9000.json` matched one of the requested section tokens.
- Every in-scope requirement has one of:
  - implementation evidence
  - test evidence
  - an explicit deferred note
- No stale or wrong requirement IDs were found in the in-scope test refs.
- No direct requirement refs were found in `src/`, which matches the repo pattern for this helper slice.

## Section Coverage

- `S22P1P1`: `0001`-`0014` implemented and tested
- `S22P1P2`: `0001`-`0007` deferred
- `S22P1P3`: `0001`-`0004` deferred
- `S22P1P4`: `0001`-`0008` deferred
- `S22P2`: `0001`-`0004` implemented and tested
- `S22P3`: `0001`-`0002` deferred; `0003`-`0004` implemented and tested
- `S22P4`: `0001`-`0002`, `0005` deferred; `0003`, `0004`, `0006` implemented and tested
- `S22P5`: `0001`-`0002` deferred; `0003`-`0005` implemented and tested

## Evidence

Implemented-and-tested coverage is anchored in these test files:

- `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportErrorCodeTests.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S22P1P1-0001.cs` through `REQ-QUIC-RFC9000-S22P1P1-0014.cs`

The implementation-side evidence is anchored in:

- `src/Incursa.Quic/QuicTransportErrorCode.cs`
- `src/Incursa.Quic/QuicIanaRegistrationPolicy.cs`

## Notes

- `S22P1P2-0001` through `S22P1P2-0007`, `S22P1P3-0001` through `S22P1P3-0004`, and `S22P1P4-0001` through `S22P1P4-0008` remain deferred with explicit reasons.
- `S22P1P1-0001` through `S22P1P1-0014` are now proved by a bounded policy model rather than transport-runtime behavior.
- The S22P3, S22P4, and S22P5 policy clauses that remain deferred are registry-governance requirements, not runtime codec behavior.
- There are no silent gaps in scope.
- The chunk is ready to be merged or queued for repo-wide trace/audit tooling.
