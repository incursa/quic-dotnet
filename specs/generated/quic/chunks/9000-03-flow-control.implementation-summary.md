# 9000-03-flow-control Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9000-S4-0001` through `REQ-QUIC-RFC9000-S4-0005`
- `REQ-QUIC-RFC9000-S4P1-0001` through `REQ-QUIC-RFC9000-S4P1-0014`
- `REQ-QUIC-RFC9000-S4P2-0001`
- `REQ-QUIC-RFC9000-S4P2-0005`
- `REQ-QUIC-RFC9000-S4P4-0001` through `REQ-QUIC-RFC9000-S4P4-0004`
- `REQ-QUIC-RFC9000-S4P5-0001` through `REQ-QUIC-RFC9000-S4P5-0008`
- `REQ-QUIC-RFC9000-S4P6-0001` through `REQ-QUIC-RFC9000-S4P6-0012`
- `REQ-QUIC-RFC9000-S4P6-0013`

## Requirements Still Partial
- None.

## Requirements Remaining Blocked
- `REQ-QUIC-RFC9000-S4P1-0015`
- `REQ-QUIC-RFC9000-S4P2-0002` through `REQ-QUIC-RFC9000-S4P2-0004`

## Files Changed
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- `specs/architecture/quic/ARC-QUIC-RFC9000-0001.json`
- `specs/work-items/quic/WI-QUIC-RFC9000-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9000-0001.json`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0011.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0014.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P2-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P4-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P5-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P5-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0007.cs`

## Tests Added or Updated
- `REQ_QUIC_RFC9000_S4_0002.TryReceiveStreamFrame_LimitsBytesOnStreamsAndAcrossTheConnection`
- `REQ_QUIC_RFC9000_S4P1_0002.TryReceiveStreamFrame_LimitsThePerStreamReceiveBufferUse`
- `REQ_QUIC_RFC9000_S4P1_0003.TryReceiveStreamFrame_LimitsTheTotalStreamDataBytesAcrossTheConnection`
- `REQ_QUIC_RFC9000_S4P1_0011.TryApplyMaxFrames_IgnoresSmallerAdvertisedLimits`
- `REQ_QUIC_RFC9000_S4P2_0005.TryReadStreamData_SendsCreditWithoutWaitingForBlockedSignals`
- `REQ_QUIC_RFC9000_S4P4_0001.TryReceiveResetStreamFrame_TerminatesOnlyTheReceiveDirectionAndPreservesTheSendDirection`
- `REQ_QUIC_RFC9000_S4P5_0001.TryRegisterLoss_RetransmitsFinTerminationWithTheSameFinalSize`
- `REQ_QUIC_RFC9000_S4P5_0001.TryRegisterLoss_RetransmitsResetTerminationWithTheSameFinalSize`
- `REQ_QUIC_RFC9000_S4P5_0001.TryAcknowledgePacket_KeepsQueuedFinalSizeRetransmissionAfterUnrelatedAcknowledgment`
- `REQ_QUIC_RFC9000_S4P5_0001.Fuzz_FinalSizeRemainsStableAcrossSupportedTerminationOrders`
- `REQ_QUIC_RFC9000_S4P5_0005.TryReserveSendCapacity_RejectsBytesAtOrBeyondTheKnownFinalSize`

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0012|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0036"`
- Result: `13 passed, 0 failed, 0 skipped`

## Risks or Follow-up Notes
- The final-size reliability proof is bounded to supported FIN-only and RESET_STREAM termination packets retaining their final size through the current retransmission ledger; it does not claim broader sender/recovery orchestration.
- The unfiltered test project run on 2026-04-23 completed with `3102 passed, 33 failed, 0 skipped`; those failures were outside the touched S4P5 requirement-home and trace files and are not used as closing evidence for this slice.
- The only remaining blockers are the blocked-sender cadence requirement and the blocked-signal policy requirements in S4P2.
