# RFC 9000 Chunk Reconciliation: `9000-02-stream-state`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S3, S3P1, S3P2, S3P3, S3P4, S3P5`

## Status Summary

- implemented and tested: 16
- partially implemented: 10
- blocked: 40

## Requirements in Scope

### S3

- implemented and tested: `REQ-QUIC-RFC9000-S3-0001`, `REQ-QUIC-RFC9000-S3-0002`
- partially implemented: `REQ-QUIC-RFC9000-S3-0003`

### S3P1

- implemented and tested: `REQ-QUIC-RFC9000-S3P1-0001`, `REQ-QUIC-RFC9000-S3P1-0002`, `REQ-QUIC-RFC9000-S3P1-0007`, `REQ-QUIC-RFC9000-S3P1-0008`
- partially implemented: `REQ-QUIC-RFC9000-S3P1-0003`, `REQ-QUIC-RFC9000-S3P1-0009`
- blocked: `REQ-QUIC-RFC9000-S3P1-0004`, `REQ-QUIC-RFC9000-S3P1-0005`, `REQ-QUIC-RFC9000-S3P1-0006`, `REQ-QUIC-RFC9000-S3P1-0010`, `REQ-QUIC-RFC9000-S3P1-0011`, `REQ-QUIC-RFC9000-S3P1-0012`, `REQ-QUIC-RFC9000-S3P1-0013`, `REQ-QUIC-RFC9000-S3P1-0014`, `REQ-QUIC-RFC9000-S3P1-0015`, `REQ-QUIC-RFC9000-S3P1-0016`, `REQ-QUIC-RFC9000-S3P1-0017`

### S3P2

- implemented and tested: `REQ-QUIC-RFC9000-S3P2-0005`, `REQ-QUIC-RFC9000-S3P2-0006`, `REQ-QUIC-RFC9000-S3P2-0008`, `REQ-QUIC-RFC9000-S3P2-0011`, `REQ-QUIC-RFC9000-S3P2-0014`, `REQ-QUIC-RFC9000-S3P2-0016`, `REQ-QUIC-RFC9000-S3P2-0017`, `REQ-QUIC-RFC9000-S3P2-0019`, `REQ-QUIC-RFC9000-S3P2-0020`, `REQ-QUIC-RFC9000-S3P2-0024`
- partially implemented: `REQ-QUIC-RFC9000-S3P2-0001`, `REQ-QUIC-RFC9000-S3P2-0002`, `REQ-QUIC-RFC9000-S3P2-0003`, `REQ-QUIC-RFC9000-S3P2-0007`, `REQ-QUIC-RFC9000-S3P2-0013`, `REQ-QUIC-RFC9000-S3P2-0015`, `REQ-QUIC-RFC9000-S3P2-0021`
- blocked: `REQ-QUIC-RFC9000-S3P2-0004`, `REQ-QUIC-RFC9000-S3P2-0009`, `REQ-QUIC-RFC9000-S3P2-0010`, `REQ-QUIC-RFC9000-S3P2-0012`, `REQ-QUIC-RFC9000-S3P2-0018`, `REQ-QUIC-RFC9000-S3P2-0022`, `REQ-QUIC-RFC9000-S3P2-0023`

### S3P3

- blocked: `REQ-QUIC-RFC9000-S3P3-0001`, `REQ-QUIC-RFC9000-S3P3-0002`, `REQ-QUIC-RFC9000-S3P3-0003`, `REQ-QUIC-RFC9000-S3P3-0004`, `REQ-QUIC-RFC9000-S3P3-0005`, `REQ-QUIC-RFC9000-S3P3-0006`

### S3P4

- blocked: `REQ-QUIC-RFC9000-S3P4-0001`, `REQ-QUIC-RFC9000-S3P4-0002`, `REQ-QUIC-RFC9000-S3P4-0003`

### S3P5

- blocked: `REQ-QUIC-RFC9000-S3P5-0001`, `REQ-QUIC-RFC9000-S3P5-0002`, `REQ-QUIC-RFC9000-S3P5-0003`, `REQ-QUIC-RFC9000-S3P5-0004`, `REQ-QUIC-RFC9000-S3P5-0005`, `REQ-QUIC-RFC9000-S3P5-0006`, `REQ-QUIC-RFC9000-S3P5-0007`, `REQ-QUIC-RFC9000-S3P5-0008`, `REQ-QUIC-RFC9000-S3P5-0009`, `REQ-QUIC-RFC9000-S3P5-0010`, `REQ-QUIC-RFC9000-S3P5-0011`, `REQ-QUIC-RFC9000-S3P5-0012`, `REQ-QUIC-RFC9000-S3P5-0013`

## Existing Implementation Evidence

- `src/Incursa.Quic/QuicConnectionStreamState.cs` owns the helper-layer stream state transitions.
- `src/Incursa.Quic/QuicConnectionStreamSnapshot.cs` records the stream snapshot exposed to tests.
- `src/Incursa.Quic/QuicStreamSendState.cs` and `src/Incursa.Quic/QuicStreamReceiveState.cs` define the send/receive state enums.
- `src/Incursa.Quic/QuicStreamId.cs` provides the parsed stream-id helper that the tests use.

## Existing Test Evidence

- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0006.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0007.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0008.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0009.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0010.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0011.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0012.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0013.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0014.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0015.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0016.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P1-0017.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0006.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0007.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0008.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0009.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0010.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0011.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0012.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0013.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0014.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0015.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0016.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0017.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0018.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0019.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0020.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0021.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0022.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0023.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P2-0024.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P3-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P3-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P3-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P3-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P3-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P3-0006.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P4-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P4-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P4-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0006.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0007.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0008.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0009.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0010.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0011.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0012.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S3P5-0013.cs`

## Generated Inputs Consulted

- `docs/requirements-workflow.md`
- `specs/generated/quic/quic-existing-work-inventory.md`
- `specs/generated/quic/chunks/9000-02-stream-state.implementation-summary.md`
- `specs/generated/quic/chunks/9000-02-stream-state.closeout.md`
- `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`

## Tests Run and Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore`
- Passed: 1325
- Failed: 0
- Skipped: 0
- Duration: 874 ms

## Remaining Gaps

- The helper layer closes 16 clauses, but 10 remain partially implemented and 40 remain blocked.
- The remaining blocked work needs the application-facing stream abstraction, sender/recovery orchestration, and STOP_SENDING/RESET coordination.
- The partially implemented work still needs stronger edge or negative proof.
