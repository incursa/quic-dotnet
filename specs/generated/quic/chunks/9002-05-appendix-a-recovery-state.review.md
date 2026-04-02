# 9002-05-appendix-a-recovery-state Review

## Verdict
`split_this_appendix_chunk`

## Scope
- RFC: `9002`
- Section tokens: `SAP1`, `SAP1P1`, `SAP2`, `SAP4`, `SAP5`, `SAP6`, `SAP7`, `SAP8`, `SAP9`, `SAP10`, `SAP11`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`

## Summary
- Total in scope: 49
- Move now: 23
- Defer: 26
- Retained overlap: 1

The appendix is not safe to queue as one implementation unit. The helper-backed restatements already have code and tests in the repo, but the packet-tracking, timer-ownership, probe-sending, and key-discard clauses still need a fuller runtime layer.

## Move Now
- `SAP2-0001` through `SAP2-0005`
- `SAP7-0001` through `SAP7-0009`
- `SAP8-0001` through `SAP8-0004`
- `SAP8-0006`
- `SAP10-0001` through `SAP10-0004`

These are the appendix clauses that already map cleanly to the current helper surfaces:
- `QuicRttEstimator`
- `QuicRecoveryTiming`
- `QuicAckGenerationState`
- `QuicCongestionControlState`

## Defer
- `SAP1-0001` through `SAP1-0006`
- `SAP1P1-0001` through `SAP1P1-0005`
- `SAP4-0001`
- `SAP5-0001` through `SAP5-0003`
- `SAP6-0001` through `SAP6-0002`
- `SAP8-0005`
- `SAP9-0001` through `SAP9-0005`
- `SAP11-0001` through `SAP11-0003`

The deferred items need a sender/recovery runtime layer that can own packet records, arm and cancel timers, emit PTO probes, and discard recovery state with key lifecycle changes.

## Retained Overlap
- `SAP11-0003` is the retained appendix overlap with `SBP9-0003`.

## Existing Evidence
- `src/Incursa.Quic/QuicAckGenerationState.cs`
- `src/Incursa.Quic/QuicCongestionControlState.cs`
- `src/Incursa.Quic/QuicRttEstimator.cs`
- `src/Incursa.Quic/QuicRecoveryTiming.cs`
- `src/Incursa.Quic/QuicIdleTimeoutState.cs`
- `src/Incursa.Quic/QuicAddressValidation.cs`
- `src/Incursa.Quic/QuicAntiAmplificationBudget.cs`
- `src/Incursa.Quic/QuicPathValidation.cs`
- `tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs`
- `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs`
- `tests/Incursa.Quic.Tests/QuicIdleTimeoutStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs`
- `tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs`
- `tests/Incursa.Quic.Tests/QuicPathValidationTests.cs`

## Recommendation
Split this appendix chunk into a smaller executable subset. Move the helper-backed appendix restatements now and keep the sender/timer/key-discard clauses deferred until the loss-recovery runtime layer is available.
