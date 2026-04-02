# 9000-13-idle-and-close Closeout

## Scope

- RFC: `9000`
- Section tokens: `S10`, `S10P1`, `S10P1P1`, `S10P1P2`, `S10P2`, `S10P2P1`, `S10P2P2`, `S10P2P3`
- Canonical spec: [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)
- Implementation summary: [`9000-13-idle-and-close.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.json)
- Reconciliation artifact: not present at `./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.json`

## Summary

- Requirements in scope: 52
- Implemented and tested: 6
- Blocked: 46
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
- `REQ-QUIC-RFC9000-S10P1-0003` is also traced in [`QuicTransportParametersTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs#L6).
- The implementation summary records explicit blockers for all `S10`, `S10P1P2`, `S10P2`, `S10P2P1`, `S10P2P2`, and `S10P2P3` requirements.
- The scoped test run reported `51 passed, 0 failed, 0 skipped`, and the full test suite reported `304 passed, 0 failed, 0 skipped`.

## Reference Audit

- In-scope source requirement refs found: none.
- In-scope test requirement refs found: `REQ-QUIC-RFC9000-S10P1-0001`, `REQ-QUIC-RFC9000-S10P1-0003`, `REQ-QUIC-RFC9000-S10P1-0005`, `REQ-QUIC-RFC9000-S10P1-0006`, `REQ-QUIC-RFC9000-S10P1-0007`, `REQ-QUIC-RFC9000-S10P1P1-0001`.
- Stale or wrong in-scope requirement refs found: none.
- The audited test files also contain unrelated RFC tags outside this chunk scope; those were ignored.

## Blocked Scope

- `S10`: 2 blocked
- `S10P1`: 5 implemented, 2 blocked
- `S10P1P1`: 1 implemented
- `S10P1P2`: 2 blocked
- `S10P2`: 12 blocked
- `S10P2P1`: 10 blocked
- `S10P2P2`: 5 blocked
- `S10P2P3`: 13 blocked

## Conclusion

The chunk is clean for trace purposes: there are no stale requirement IDs in scope and no silent gaps in scope. The remaining close/draining behavior is explicitly deferred behind missing connection-state and CONNECTION_CLOSE support, so this chunk is ready for merge or for final repo-wide trace/audit tooling.
