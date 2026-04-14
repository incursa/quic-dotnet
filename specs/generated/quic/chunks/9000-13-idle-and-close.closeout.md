# 9000-13-idle-and-close Closeout

## Scope

- RFC: `9000`
- Section tokens: `S10`, `S10P1`, `S10P1P1`, `S10P1P2`, `S10P2`, `S10P2P1`, `S10P2P2`, `S10P2P3`
- Canonical spec: [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)
- Implementation summary: [`9000-13-idle-and-close.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.json)
- Reconciliation artifact: not present at `./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.json`

## Summary

- Requirements in scope: 52
- Implemented and tested: 9
- Blocked: 43
- Partial: 0
- Needs review: 0
- Stale IDs found in scope: 0
- Silent gaps found in scope: 0

## Scope Inventory

- `S10`: `REQ-QUIC-RFC9000-S10-0001`, `REQ-QUIC-RFC9000-S10-0002`
- `S10P1`: `REQ-QUIC-RFC9000-S10P1-0001`, `REQ-QUIC-RFC9000-S10P1-0002`, `REQ-QUIC-RFC9000-S10P1-0003`, `REQ-QUIC-RFC9000-S10P1-0004`, `REQ-QUIC-RFC9000-S10P1-0005`, `REQ-QUIC-RFC9000-S10P1-0006`, `REQ-QUIC-RFC9000-S10P1-0007`
- `S10P1P1`: `REQ-QUIC-RFC9000-S10P1P1-0001`
- `S10P1P2`: `REQ-QUIC-RFC9000-S10P1P2-0001`, `REQ-QUIC-RFC9000-S10P1P2-0002`
- `S10P2`: `REQ-QUIC-RFC9000-S10P2-0001` through `REQ-QUIC-RFC9000-S10P2-0012`
- `S10P2P1`: `REQ-QUIC-RFC9000-S10P2P1-0001` through `REQ-QUIC-RFC9000-S10P2P1-0010`
- `S10P2P2`: `REQ-QUIC-RFC9000-S10P2P2-0001` through `REQ-QUIC-RFC9000-S10P2P2-0005`
- `S10P2P3`: `REQ-QUIC-RFC9000-S10P2P3-0001` through `REQ-QUIC-RFC9000-S10P2P3-0013`

## Evidence

- The idle-timeout helper implementation is in [`QuicIdleTimeoutState.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicIdleTimeoutState.cs#L1).
- `REQ-QUIC-RFC9000-S10P1-0001`, `REQ-QUIC-RFC9000-S10P1-0003`, `REQ-QUIC-RFC9000-S10P1-0005`, `REQ-QUIC-RFC9000-S10P1-0006`, and `REQ-QUIC-RFC9000-S10P1-0007` are traced in [`QuicIdleTimeoutStateTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicIdleTimeoutStateTests.cs#L10).
- `REQ-QUIC-RFC9000-S10P1P1-0001` is traced in [`QuicFrameCodecTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs#L41).
- The connection close/drain lifecycle helper is in [`QuicConnectionLifecycleState.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionLifecycleState.cs#L1).
- `REQ-QUIC-RFC9000-S10P2P2-0001`, `REQ-QUIC-RFC9000-S10P2P2-0003`, and `REQ-QUIC-RFC9000-S10P2P2-0005` are traced in [`REQ-QUIC-RFC9000-S10P2P2-0001.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S10P2P2-0001.cs#L1), [`REQ-QUIC-RFC9000-S10P2P2-0003.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S10P2P2-0003.cs#L1), and [`REQ-QUIC-RFC9000-S10P2P2-0005.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S10P2P2-0005.cs#L1).
- `REQ-QUIC-RFC9000-S10P2P1-0008` and `REQ-QUIC-RFC9000-S10P2P2-0004` remain helper-backed but blocked because the repo still lacks the endpoint runtime and CONNECTION_CLOSE receive/send pipeline needed to bind those transitions to real packets.
- `REQ-QUIC-RFC9000-S10P1-0003` is also traced in [`QuicTransportParametersTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs#L6).
- The implementation summary records explicit blockers for the remaining `S10`, `S10P1P2`, `S10P2P1`, `S10P2P2`, and `S10P2P3` requirements.
- The scoped test runs reported `7 passed, 0 failed, 0 skipped` on the existing close-path helper slice and `2 passed, 0 failed, 0 skipped` on the peer-close draining tests, and the full test suite reported `1349 passed, 0 failed, 0 skipped`.

## Reference Audit

- In-scope source requirement refs found: none.
- In-scope test requirement refs found: `REQ-QUIC-RFC9000-S10P1-0001`, `REQ-QUIC-RFC9000-S10P1-0003`, `REQ-QUIC-RFC9000-S10P1-0005`, `REQ-QUIC-RFC9000-S10P1-0006`, `REQ-QUIC-RFC9000-S10P1-0007`, `REQ-QUIC-RFC9000-S10P1P1-0001`, `REQ-QUIC-RFC9000-S10P2P2-0001`, `REQ-QUIC-RFC9000-S10P2P2-0003`, `REQ-QUIC-RFC9000-S10P2P2-0005`.
- Stale or wrong in-scope requirement refs found: none.
- The audited test files also contain unrelated RFC tags outside this chunk scope; those were ignored.

## Blocked Scope

- `S10`: 2 blocked
- `S10P1`: 5 implemented, 2 blocked
- `S10P1P1`: 1 implemented
- `S10P1P2`: 2 blocked
- `S10P2`: 2 implemented, 10 blocked
- `S10P2P1`: 10 blocked
- `S10P2P2`: 3 implemented, 2 blocked
- `S10P2P3`: 13 blocked

## Conclusion

The chunk is clean for trace purposes: there are no stale requirement IDs in scope and no silent gaps in scope. The helper-backed close/drain slice now proves the closing-state entry, the draining/no-send clauses, and the peer-close draining transition, while the remaining immediate-close and CONNECTION_CLOSE wire-emission behaviors are explicitly deferred behind missing endpoint-runtime support.
