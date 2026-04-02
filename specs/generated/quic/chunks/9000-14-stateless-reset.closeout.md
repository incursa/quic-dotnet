# 9000-14-stateless-reset Closeout

## Scope

- RFC: `9000`
- Section tokens: `S10P3`, `S10P3P1`, `S10P3P2`, `S10P3P3`
- Canonical spec: [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)
- Implementation summary: [`9000-14-stateless-reset.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-14-stateless-reset.implementation-summary.json)
- Reconciliation artifact: not present at `C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.json`

## Summary

- Requirements in scope: 55
- Covered by implementation or test evidence: 33
- Explicitly deferred or blocked: 19
- Uncovered / silent gaps: 3
- Stale IDs in scope: 0
- Wrong IDs in tests or source refs: 0
- Reconciliation artifact present: no

## Scope Inventory

- `S10P3`: `REQ-QUIC-RFC9000-S10P3-0001`, `REQ-QUIC-RFC9000-S10P3-0002`, `REQ-QUIC-RFC9000-S10P3-0003`, `REQ-QUIC-RFC9000-S10P3-0004`, `REQ-QUIC-RFC9000-S10P3-0005`, `REQ-QUIC-RFC9000-S10P3-0006`, `REQ-QUIC-RFC9000-S10P3-0007`, `REQ-QUIC-RFC9000-S10P3-0008`, `REQ-QUIC-RFC9000-S10P3-0009`, `REQ-QUIC-RFC9000-S10P3-0010`, `REQ-QUIC-RFC9000-S10P3-0011`, `REQ-QUIC-RFC9000-S10P3-0012`, `REQ-QUIC-RFC9000-S10P3-0013`, `REQ-QUIC-RFC9000-S10P3-0014`, `REQ-QUIC-RFC9000-S10P3-0015`, `REQ-QUIC-RFC9000-S10P3-0016`, `REQ-QUIC-RFC9000-S10P3-0017`, `REQ-QUIC-RFC9000-S10P3-0018`, `REQ-QUIC-RFC9000-S10P3-0019`, `REQ-QUIC-RFC9000-S10P3-0020`, `REQ-QUIC-RFC9000-S10P3-0021`, `REQ-QUIC-RFC9000-S10P3-0022`, `REQ-QUIC-RFC9000-S10P3-0023`, `REQ-QUIC-RFC9000-S10P3-0024`, `REQ-QUIC-RFC9000-S10P3-0025`, `REQ-QUIC-RFC9000-S10P3-0026`, `REQ-QUIC-RFC9000-S10P3-0027`, `REQ-QUIC-RFC9000-S10P3-0028`, `REQ-QUIC-RFC9000-S10P3-0029`
- `S10P3P1`: `REQ-QUIC-RFC9000-S10P3P1-0001`, `REQ-QUIC-RFC9000-S10P3P1-0002`, `REQ-QUIC-RFC9000-S10P3P1-0003`, `REQ-QUIC-RFC9000-S10P3P1-0004`, `REQ-QUIC-RFC9000-S10P3P1-0005`, `REQ-QUIC-RFC9000-S10P3P1-0006`, `REQ-QUIC-RFC9000-S10P3P1-0007`, `REQ-QUIC-RFC9000-S10P3P1-0008`, `REQ-QUIC-RFC9000-S10P3P1-0009`, `REQ-QUIC-RFC9000-S10P3P1-0010`, `REQ-QUIC-RFC9000-S10P3P1-0011`, `REQ-QUIC-RFC9000-S10P3P1-0012`
- `S10P3P2`: `REQ-QUIC-RFC9000-S10P3P2-0001`, `REQ-QUIC-RFC9000-S10P3P2-0002`, `REQ-QUIC-RFC9000-S10P3P2-0003`, `REQ-QUIC-RFC9000-S10P3P2-0004`, `REQ-QUIC-RFC9000-S10P3P2-0005`, `REQ-QUIC-RFC9000-S10P3P2-0006`, `REQ-QUIC-RFC9000-S10P3P2-0007`, `REQ-QUIC-RFC9000-S10P3P2-0008`, `REQ-QUIC-RFC9000-S10P3P2-0009`, `REQ-QUIC-RFC9000-S10P3P2-0010`, `REQ-QUIC-RFC9000-S10P3P2-0011`, `REQ-QUIC-RFC9000-S10P3P2-0012`
- `S10P3P3`: `REQ-QUIC-RFC9000-S10P3P3-0001`, `REQ-QUIC-RFC9000-S10P3P3-0002`

## Evidence

- The helper implementation in [`src/Incursa.Quic/QuicStatelessReset.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicStatelessReset.cs#L16) covers token length, the 38-bit unpredictable-prefix floor, datagram sizing, token generation, reset formatting, trailing-token extraction, and token-set comparison.
- `REQ-QUIC-RFC9000-S10P3-0003`, `REQ-QUIC-RFC9000-S10P3-0004`, `REQ-QUIC-RFC9000-S10P3-0016`, `REQ-QUIC-RFC9000-S10P3P2-0002`, `REQ-QUIC-RFC9000-S10P3P2-0009`, `REQ-QUIC-RFC9000-S10P3P2-0010`, `REQ-QUIC-RFC9000-S10P3P2-0011`, and `REQ-QUIC-RFC9000-S10P3P2-0012` are traced in [`tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs#L16).
- `REQ-QUIC-RFC9000-S10P3-0005`, `REQ-QUIC-RFC9000-S10P3-0006`, `REQ-QUIC-RFC9000-S10P3-0007`, `REQ-QUIC-RFC9000-S10P3-0008`, `REQ-QUIC-RFC9000-S10P3-0013`, `REQ-QUIC-RFC9000-S10P3-0021`, `REQ-QUIC-RFC9000-S10P3-0022`, `REQ-QUIC-RFC9000-S10P3-0023`, `REQ-QUIC-RFC9000-S10P3-0024`, and `REQ-QUIC-RFC9000-S10P3-0026` are traced in [`tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs#L65).
- `REQ-QUIC-RFC9000-S10P3-0009`, `REQ-QUIC-RFC9000-S10P3-0010`, `REQ-QUIC-RFC9000-S10P3-0011`, `REQ-QUIC-RFC9000-S10P3-0027`, `REQ-QUIC-RFC9000-S10P3-0028`, and `REQ-QUIC-RFC9000-S10P3P3-0001` are traced in [`tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs#L95).
- `REQ-QUIC-RFC9000-S10P3P1-0001`, `REQ-QUIC-RFC9000-S10P3P1-0003`, `REQ-QUIC-RFC9000-S10P3P1-0007`, and `REQ-QUIC-RFC9000-S10P3P1-0009` are traced in [`tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs#L144).
- `REQ-QUIC-RFC9000-S10P3-0017` is traced in [`tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs#L168).
- `REQ-QUIC-RFC9000-S10P3-0018` is traced in [`tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs#L29).
- `REQ-QUIC-RFC9000-S10P3-0012` is traced in [`tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs#L65) and [`tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs#L222).
- `REQ-QUIC-RFC9000-S10P3-0025` has helper-level code evidence in [`src/Incursa.Quic/QuicStatelessReset.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicStatelessReset.cs#L16) and public-API exposure in [`src/Incursa.Quic/PublicAPI.Unshipped.txt`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt#L381), but it is not called out directly by the chunk summary or a direct requirement annotation, so I kept it in the uncovered bucket for this audit.

## Deferred Requirements

- `REQ-QUIC-RFC9000-S10P3-0002`: Connection-close preference is blocked by the missing connection error routing and close-path surface.
- `REQ-QUIC-RFC9000-S10P3-0014`: Packet-ending token recognition is helper-covered, but endpoint draining and connection shutdown are still missing.
- `REQ-QUIC-RFC9000-S10P3-0019`: Immediate connection teardown on Stateless Reset requires a connection-state machine.
- `REQ-QUIC-RFC9000-S10P3-0020`: Token invalidation on `RETIRE_CONNECTION_ID` needs endpoint state and retirement bookkeeping.
- `REQ-QUIC-RFC9000-S10P3-0029`: Version-aware Stateless Reset generation still needs negotiated-version policy and endpoint history.
- `REQ-QUIC-RFC9000-S10P3P1-0002`: Recent-token memory by connection ID and remote address needs a receive-side token store.
- `REQ-QUIC-RFC9000-S10P3P1-0004`: Skipping the token check after another packet succeeds requires a datagram-processing pipeline.
- `REQ-QUIC-RFC9000-S10P3P1-0005`: Always checking the first unprocessable packet is blocked by the missing datagram-processing pipeline.
- `REQ-QUIC-RFC9000-S10P3P1-0006`: Unused and retired-token filtering needs connection-scoped token bookkeeping.
- `REQ-QUIC-RFC9000-S10P3P1-0008`: Entering draining and ceasing sends on a match requires connection lifecycle state.
- `REQ-QUIC-RFC9000-S10P3P1-0010`: Remember-and-scope behavior spans `NEW_CONNECTION_ID`, transport-parameter, and retirement state that is not yet modeled.
- `REQ-QUIC-RFC9000-S10P3P1-0011`: Draining on match is blocked by the missing connection-state machine.
- `REQ-QUIC-RFC9000-S10P3P1-0012`: Stopping sends on match is blocked by the missing connection-state machine.
- `REQ-QUIC-RFC9000-S10P3P2-0003`: Recoverable connection-ID length handling for static-key tokens is not modeled.
- `REQ-QUIC-RFC9000-S10P3P2-0005`: Preventing reuse of the CID/static-key pair needs endpoint state and allocation policy.
- `REQ-QUIC-RFC9000-S10P3P2-0006`: Preventing reuse of reset CIDs across shared static keys needs cross-endpoint policy state.
- `REQ-QUIC-RFC9000-S10P3P2-0007`: Enforcing one token per CID needs a token registry.
- `REQ-QUIC-RFC9000-S10P3P2-0008`: Treating duplicates as protocol violations needs connection-level token issuance state.
- `REQ-QUIC-RFC9000-S10P3P3-0002`: Reset-send limiting requires stateful accounting of emitted Stateless Resets.

## Uncovered Requirements

- `REQ-QUIC-RFC9000-S10P3-0001`: No direct implementation, test, or deferred note in the chunk summary; the receive-path trigger still is not wired to a connection-state machine.
- `REQ-QUIC-RFC9000-S10P3-0015`: No direct implementation, test, or deferred note in the chunk summary; long-header-triggered Stateless Reset behavior is not directly traced.
- `REQ-QUIC-RFC9000-S10P3-0025`: Helper constants show the 38-bit floor, but the chunk summary and direct trace surface do not record the requirement explicitly, so it remains an audit gap.

## Reference Audit

- In-scope source requirement refs found: none.
- In-scope test requirement refs found:
  - [`tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs) - `REQ-QUIC-RFC9000-S10P3-0003`, `REQ-QUIC-RFC9000-S10P3-0004`, `REQ-QUIC-RFC9000-S10P3-0005`, `REQ-QUIC-RFC9000-S10P3-0006`, `REQ-QUIC-RFC9000-S10P3-0007`, `REQ-QUIC-RFC9000-S10P3-0008`, `REQ-QUIC-RFC9000-S10P3-0009`, `REQ-QUIC-RFC9000-S10P3-0010`, `REQ-QUIC-RFC9000-S10P3-0011`, `REQ-QUIC-RFC9000-S10P3-0013`, `REQ-QUIC-RFC9000-S10P3-0016`, `REQ-QUIC-RFC9000-S10P3-0021`, `REQ-QUIC-RFC9000-S10P3-0022`, `REQ-QUIC-RFC9000-S10P3-0023`, `REQ-QUIC-RFC9000-S10P3-0024`, `REQ-QUIC-RFC9000-S10P3-0026`, `REQ-QUIC-RFC9000-S10P3-0027`, `REQ-QUIC-RFC9000-S10P3-0028`, `REQ-QUIC-RFC9000-S10P3P1-0001`, `REQ-QUIC-RFC9000-S10P3P1-0003`, `REQ-QUIC-RFC9000-S10P3P1-0005`, `REQ-QUIC-RFC9000-S10P3P1-0007`, `REQ-QUIC-RFC9000-S10P3P1-0008`, `REQ-QUIC-RFC9000-S10P3P1-0009`, `REQ-QUIC-RFC9000-S10P3P1-0011`, `REQ-QUIC-RFC9000-S10P3P1-0012`, `REQ-QUIC-RFC9000-S10P3P2-0002`, `REQ-QUIC-RFC9000-S10P3P2-0009`, `REQ-QUIC-RFC9000-S10P3P2-0010`, `REQ-QUIC-RFC9000-S10P3P2-0011`, `REQ-QUIC-RFC9000-S10P3P2-0012`, `REQ-QUIC-RFC9000-S10P3P3-0001`
  - [`tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs) - `REQ-QUIC-RFC9000-S10P3-0003`, `REQ-QUIC-RFC9000-S10P3-0017`
  - [`tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs) - `REQ-QUIC-RFC9000-S10P3-0018`
  - [`tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs) - `REQ-QUIC-RFC9000-S10P3-0012`
  - [`tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs) - `REQ-QUIC-RFC9000-S10P3-0012`
- Stale or wrong in-scope requirement refs found: none.
- Some test methods carry deferred IDs because they exercise adjacent helper behavior; those IDs remain deferred in this closeout and are not counted as completed.

## Conclusion

This chunk is not trace-clean yet. The implementation and test surface cover most of the stateless-reset helper slice, and the deferred requirements are explicitly blocked, but three scoped requirements still lack enough direct trace to close:

- `REQ-QUIC-RFC9000-S10P3-0001`
- `REQ-QUIC-RFC9000-S10P3-0015`
- `REQ-QUIC-RFC9000-S10P3-0025`

`REQ-QUIC-RFC9000-S10P3-0025` is the only one with helper-level code evidence that looks close to complete; it still needs explicit trace alignment before this chunk can be treated as merge-ready for final repo-wide audit tooling.
