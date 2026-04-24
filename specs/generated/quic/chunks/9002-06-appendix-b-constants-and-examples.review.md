# 9002-06-appendix-b-constants-and-examples Review

## Verdict
`closed_after_split_slices`

## Scope
- RFC: `9002`
- Section tokens: `SBP1`, `SBP2`, `SBP3`, `SBP4`, `SBP5`, `SBP6`, `SBP7`, `SBP8`, `SBP9`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`

## Summary
- Total in scope: 28
- Helper-backed executable subset: 23
- Follow-up closures: 5
- Defer: 0
- Retained overlap: 1

The appendix was intentionally split because the original helper-only review could not claim PMTU accounting or connection-owned key-discard cleanup. The current repository now has traced closures for all three pieces: the helper-backed constants/examples subset, the PMTU/recovery accounting topoff, and the key-discard remainder including the retained `SBP9-0003` / `SAP11-0003` overlap. No scoped Appendix B requirement remains deferred by this generated review.

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
- `SBP2-0005` overlaps with the ECN per-space accounting modeled by `QuicEcnValidationState` and the `TryProcessEcn` helper.
- `SBP9-0003` repeats the key-discard timer cleanup that also appears as the retained Appendix A overlap `REQ-QUIC-RFC9002-SAP11-0003`.

## Helper-Backed Subset Closed
- `REQ-QUIC-RFC9002-SBP1-0001` and `REQ-QUIC-RFC9002-SBP1-0002`
- `REQ-QUIC-RFC9002-SBP2-0002`, `REQ-QUIC-RFC9002-SBP2-0004`, and `REQ-QUIC-RFC9002-SBP2-0005`
- `REQ-QUIC-RFC9002-SBP3-0001`
- `REQ-QUIC-RFC9002-SBP4-0001`
- `REQ-QUIC-RFC9002-SBP5-0001` through `REQ-QUIC-RFC9002-SBP5-0006`
- `REQ-QUIC-RFC9002-SBP6-0001` through `REQ-QUIC-RFC9002-SBP6-0003`
- `REQ-QUIC-RFC9002-SBP7-0001` and `REQ-QUIC-RFC9002-SBP7-0002`
- `REQ-QUIC-RFC9002-SBP8-0001` through `REQ-QUIC-RFC9002-SBP8-0005`

These are surfaced by `QuicCongestionControlState` and `QuicEcnValidationState`, with direct requirement-home coverage for the core formulas and state transitions.

## Follow-Up Closures
- `REQ-QUIC-RFC9002-SBP2-0001` and `REQ-QUIC-RFC9002-SBP2-0003` are closed by the recovery accounting subset that clamps RFC 9002 recovery formulas to the 1200-byte floor while preserving the RFC 9000 path value used for close-only gating.
- `REQ-QUIC-RFC9002-SBP9-0001` through `REQ-QUIC-RFC9002-SBP9-0003` are closed by the connection-owned sender ledger and TLS key-discard transition path under `ARC-QUIC-RFC9002-0002`, `WI-QUIC-RFC9002-0002`, and `VER-QUIC-RFC9002-0002`.
- `REQ-QUIC-RFC9002-SBP9-0003` remains the retained overlap with `REQ-QUIC-RFC9002-SAP11-0003`; the runtime key-discard proof is the closing evidence, and the older helper-only persistent-congestion examples remain supporting evidence.

## Deferred
- None.

## Tests Run
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9002_SBP1|FullyQualifiedName~REQ_QUIC_RFC9002_SBP2_0002|FullyQualifiedName~REQ_QUIC_RFC9002_SBP2_0004|FullyQualifiedName~REQ_QUIC_RFC9002_SBP2_0005|FullyQualifiedName~REQ_QUIC_RFC9002_SBP3|FullyQualifiedName~REQ_QUIC_RFC9002_SBP4|FullyQualifiedName~REQ_QUIC_RFC9002_SBP5|FullyQualifiedName~REQ_QUIC_RFC9002_SBP6|FullyQualifiedName~REQ_QUIC_RFC9002_SBP7|FullyQualifiedName~REQ_QUIC_RFC9002_SBP8"`
- Result: `47 passed, 0 failed, 0 skipped`
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9002_SBP2_0001|FullyQualifiedName~REQ_QUIC_RFC9002_SBP2_0003"`
- Result: `8 passed, 0 failed, 0 skipped`
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9002_SBP9|FullyQualifiedName~REQ_QUIC_RFC9002_SAP11_0003"`
- Result: `19 passed, 0 failed, 0 skipped`

## Preserved Evidence
- `artifacts/benchmark-baseline/20260422-230344-dry/`
- `artifacts/benchmark-baseline/20260422-230945-short/`
- `artifacts/benchmark-baseline/20260422-2350-rfc9002-pmtu-accounting-dry/`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- `specs/architecture/quic/ARC-QUIC-RFC9002-0002.json`
- `specs/work-items/quic/WI-QUIC-RFC9002-0002.json`
- `specs/verification/quic/VER-QUIC-RFC9002-0002.json`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/`

## Recommendation
Keep the split boundaries as the Appendix B closeout record. The chunk is no longer blocked by the old helper-only review, but this does not broaden pacing, PMTU discovery, or key-discard lifecycle behavior beyond the traced requirements and existing evidence.
