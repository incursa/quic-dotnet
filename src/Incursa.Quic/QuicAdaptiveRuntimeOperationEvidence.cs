// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicAdaptiveRuntimeOperationEligibilityResult : byte
{
    Eligible = 0,
    Ineligible = 1,
    Clamped = 2,
}

internal enum QuicAdaptiveRuntimeOperationEligibilityReason : byte
{
    Eligible = 0,
    StructurallyInactive = 1,
    MissingInput = 2,
    InvalidInput = 3,
    LifecycleGuard = 4,
    ResourceGuard = 5,
    SafetyOverride = 6,
    NotAxisMechanism = 7,
    UnclassifiableEvidence = 8,
}

internal enum QuicApplicationSendBatchMechanismEvent : byte
{
    LegalEligiblePrefixUsed = 0,
    SingleEligiblePrefixUsed = 1,
    NoPacketPlan = 2,
    Unclassifiable = 3,
}

internal enum QuicBufferCopyCoalescingMechanismEvent : byte
{
    ExactCombinedPrefixRetained = 0,
    LowerTwoSourceSegmentCapApplied = 1,
    NoCombinedOwnerRented = 2,
    NotAxisMechanism = 3,
    Unclassifiable = 4,
}

internal readonly record struct QuicApplicationSendBatchOperationEvidence(
    ulong EpochSequence,
    ulong DecisionInstanceSequence,
    ulong OperationSequence,
    QuicAdaptiveRuntimeStage1PolicyValue CandidateValue,
    QuicAdaptiveRuntimeOperationEligibilityResult EligibilityResult,
    QuicAdaptiveRuntimeOperationEligibilityReason EligibilityReason,
    QuicApplicationSendBatchMechanismEvent MechanismEvent,
    uint LegalWriteCount,
    uint AppliedWriteCount,
    ulong LegalWriteBytes,
    ulong AppliedWriteBytes);

internal readonly record struct QuicBufferCopyCoalescingOperationEvidence(
    ulong EpochSequence,
    ulong DecisionInstanceSequence,
    ulong OperationSequence,
    QuicBufferCopyPolicyValue CandidateValue,
    QuicAdaptiveRuntimeOperationEligibilityResult EligibilityResult,
    QuicAdaptiveRuntimeOperationEligibilityReason EligibilityReason,
    QuicBufferCopyCoalescingMechanismEvent MechanismEvent,
    uint LegalSourceSegmentCount,
    uint AppliedSourceSegmentCount,
    ulong LegalBytes,
    ulong AppliedBytes,
    bool OwnerRented);

internal readonly record struct QuicApplicationSendBatchBehaviorEpochCounts(
    ulong LegalEligiblePrefixOperationCount,
    ulong LegalEligiblePrefixAppliedBytes,
    ulong SingleEligiblePrefixOperationCount,
    ulong SingleEligiblePrefixAppliedBytes,
    ulong StructurallyInactiveOperationCount,
    ulong ClampedOperationCount,
    ulong UnclassifiableOperationCount,
    ulong TotalLegalWriteBytes,
    ulong TotalAppliedWriteBytes);
