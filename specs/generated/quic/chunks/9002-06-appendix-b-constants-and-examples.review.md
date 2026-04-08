# 9002-06-appendix-b-constants-and-examples Review

## Verdict
`split_this_appendix_chunk`

## Scope
- RFC: `9002`
- Section tokens: `SBP1`, `SBP2`, `SBP3`, `SBP4`, `SBP5`, `SBP6`, `SBP7`, `SBP8`, `SBP9`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`

## Summary
- Total in scope: 28
- Move now: 23
- Defer: 5
- Retained overlap: 1

The smallest executable subset of this appendix is the 23 helper-backed restatements already represented by `QuicCongestionControlState` and `QuicEcnValidationState`. The remaining 5 clauses stay deferred until the repo has sender/runtime PMTU accounting and connection-owned key-discard cleanup.

## In Scope
- `SBP1`: `REQ-QUIC-RFC9002-SBP1-0001`, `REQ-QUIC-RFC9002-SBP1-0002`
- `SBP2`: `REQ-QUIC-RFC9002-SBP2-0001`, `REQ-QUIC-RFC9002-SBP2-0002`, `REQ-QUIC-RFC9002-SBP2-0003`, `REQ-QUIC-RFC9002-SBP2-0004`, `REQ-QUIC-RFC9002-SBP2-0005`
- `SBP3`: `REQ-QUIC-RFC9002-SBP3-0001`
- `SBP4`: `REQ-QUIC-RFC9002-SBP4-0001`
- `SBP5`: `REQ-QUIC-RFC9002-SBP5-0001`, `REQ-QUIC-RFC9002-SBP5-0002`, `REQ-QUIC-RFC9002-SBP5-0003`, `REQ-QUIC-RFC9002-SBP5-0004`, `REQ-QUIC-RFC9002-SBP5-0005`, `REQ-QUIC-RFC9002-SBP5-0006`
- `SBP6`: `REQ-QUIC-RFC9002-SBP6-0001`, `REQ-QUIC-RFC9002-SBP6-0002`, `REQ-QUIC-RFC9002-SBP6-0003`
- `SBP7`: `REQ-QUIC-RFC9002-SBP7-0001`, `REQ-QUIC-RFC9002-SBP7-0002`
- `SBP8`: `REQ-QUIC-RFC9002-SBP8-0001`, `REQ-QUIC-RFC9002-SBP8-0002`, `REQ-QUIC-RFC9002-SBP8-0003`, `REQ-QUIC-RFC9002-SBP8-0004`, `REQ-QUIC-RFC9002-SBP8-0005`
- `SBP9`: `REQ-QUIC-RFC9002-SBP9-0001`, `REQ-QUIC-RFC9002-SBP9-0002`, `REQ-QUIC-RFC9002-SBP9-0003`

## Duplicate / Near-Duplicate Analysis
- `SBP2-0002` and `SBP4-0001` are the same bytes-in-flight accounting theme from opposite directions: one describes what counts, the other describes the increment when sending.
- `SBP5-0001` through `SBP5-0006` are one acknowledgment-processing cluster, not six independent implementation slices.
- `SBP6-0001` through `SBP6-0003` are one recovery-entry cluster.
- `SBP8-0001` through `SBP8-0005` are one persistent-congestion cluster.
- `SBP2-0005` overlaps with the ECN per-space accounting already modeled by `QuicEcnValidationState` and the `TryProcessEcn` helper.
- `SBP9-0003` repeats the same key-discard timer cleanup that already appeared as appendix overlap in the Appendix A recovery-state chunk.

## Move Now
- `REQ-QUIC-RFC9002-SBP1-0001` and `REQ-QUIC-RFC9002-SBP1-0002`
- `REQ-QUIC-RFC9002-SBP2-0002`, `REQ-QUIC-RFC9002-SBP2-0004`, and `REQ-QUIC-RFC9002-SBP2-0005`
- `REQ-QUIC-RFC9002-SBP3-0001`
- `REQ-QUIC-RFC9002-SBP4-0001`
- `REQ-QUIC-RFC9002-SBP5-0001` through `REQ-QUIC-RFC9002-SBP5-0006`
- `REQ-QUIC-RFC9002-SBP6-0001` through `REQ-QUIC-RFC9002-SBP6-0003`
- `REQ-QUIC-RFC9002-SBP7-0001` and `REQ-QUIC-RFC9002-SBP7-0002`
- `REQ-QUIC-RFC9002-SBP8-0001` through `REQ-QUIC-RFC9002-SBP8-0005`

These are already surfaced by `QuicCongestionControlState` and `QuicEcnValidationState`, with direct unit coverage for the core formulas and state transitions.

## Defer
- `REQ-QUIC-RFC9002-SBP2-0001`
- `REQ-QUIC-RFC9002-SBP2-0003`
- `REQ-QUIC-RFC9002-SBP9-0001` through `REQ-QUIC-RFC9002-SBP9-0003`

`SBP2-0001` and `SBP2-0003` need sender-side PMTU and wire-overhead accounting that is not present in the current helper layer. `SBP9` needs connection-owned packet bookkeeping and key-discard cleanup that this repository does not currently expose, so this remainder stays deferred.

## Existing Evidence
- `src/Incursa.Quic/QuicCongestionControlState.cs`
- `src/Incursa.Quic/QuicEcnValidationState.cs`
- `src/Incursa.Quic/QuicVersionNegotiation.cs`
- `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs`

## Recommendation
Split this appendix chunk into a smaller executable subset.
