// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0206")]
public sealed class REQ_QUIC_CRT_0206
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BatchCandidatePrecedesEligibilityAndMechanismEvidence()
    {
        QuicApplicationSendPlan plan = CreateBatchPlan(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            eligibleWriteCount: 3,
            selectedWriteCount: 1,
            eligibleWriteBytes: 300,
            selectedWriteBytes: 100);
        QuicApplicationSendBatchObservation observation =
            CreateBatchObservation(planSequence: 11, in plan);
        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);

        QuicApplicationSendBatchOperationEvidence evidence =
            QuicApplicationSendBatchPolicy.CreateOperationEvidence(
                epochSequence: 7,
                in observation,
                in decision,
                in plan);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            evidence.CandidateValue);
        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityResult.Eligible,
            evidence.EligibilityResult);
        Assert.Equal(
            QuicApplicationSendBatchMechanismEvent.SingleEligiblePrefixUsed,
            evidence.MechanismEvent);
        Assert.Equal((ulong)7, evidence.EpochSequence);
        Assert.Equal((ulong)11, evidence.DecisionInstanceSequence);
        Assert.Equal(evidence.DecisionInstanceSequence, evidence.OperationSequence);
        Assert.Equal((uint)3, evidence.LegalWriteCount);
        Assert.Equal((uint)1, evidence.AppliedWriteCount);
        Assert.Equal((ulong)300, evidence.LegalWriteBytes);
        Assert.Equal((ulong)100, evidence.AppliedWriteBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForcedBatchCandidateCannotBypassResourceEligibility()
    {
        QuicApplicationSendPlan plan = QuicApplicationSendPlan.None(
            QuicSendPolicyBlockedReason.CongestionLimited);
        QuicApplicationSendBatchObservation observation =
            CreateBatchObservation(planSequence: 12, in plan);
        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);

        QuicApplicationSendBatchOperationEvidence evidence =
            QuicApplicationSendBatchPolicy.CreateOperationEvidence(
                epochSequence: 8,
                in observation,
                in decision,
                in plan);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            evidence.CandidateValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityResult.Clamped,
            evidence.EligibilityResult);
        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityReason.ResourceGuard,
            evidence.EligibilityReason);
        Assert.Equal(
            QuicApplicationSendBatchMechanismEvent.NoPacketPlan,
            evidence.MechanismEvent);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowBatchRecommendationNeverChangesAppliedMechanism()
    {
        QuicApplicationSendPlan plan = CreateBatchPlan(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            eligibleWriteCount: 3,
            selectedWriteCount: 3,
            eligibleWriteBytes: 300,
            selectedWriteBytes: 300);
        QuicApplicationSendBatchObservation observation =
            CreateBatchObservation(planSequence: 13, in plan);
        observation = observation with
        {
            MissingSignalMask =
                QuicApplicationSendBatchSignalMask.MaximumPayloadBytes,
        };
        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.Shadow,
                hasForcedValue: false,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                in plan);
        QuicApplicationSendBatchOperationEvidence evidence =
            QuicApplicationSendBatchPolicy.CreateOperationEvidence(
                epochSequence: 9,
                in observation,
                in decision,
                in plan);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            evidence.CandidateValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicApplicationSendBatchMechanismEvent.LegalEligiblePrefixUsed,
            evidence.MechanismEvent);
        Assert.Equal((uint)3, evidence.AppliedWriteCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BufferCoalescingDerivesOnlyFromCombinedSendMechanism()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegmentCount: 4,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        QuicBufferCopyCoalescingOperationEvidence evidence =
            QuicBufferCopyPolicy.CreateOperationEvidence(
                epochSequence: 10,
                decisionInstanceSequence: 21,
                operationSequence: 21,
                QuicBufferCopyPath.CombinedApplicationSend,
                in decision,
                legalSourceSegmentCount: 4,
                appliedSourceSegmentCount: 2,
                legalBytes: 400,
                appliedBytes: 200,
                ownerRented: true);

        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            evidence.CandidateValue);
        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityResult.Eligible,
            evidence.EligibilityResult);
        Assert.Equal(
            QuicBufferCopyCoalescingMechanismEvent
                .LowerTwoSourceSegmentCapApplied,
            evidence.MechanismEvent);
        Assert.Equal((uint)4, evidence.LegalSourceSegmentCount);
        Assert.Equal((uint)2, evidence.AppliedSourceSegmentCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BroadBufferCopyPathCannotBecomeCoalescingBehavior()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.ObserveOnly,
                forcedValue: null,
                legalSourceSegmentCount: 2,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        QuicBufferCopyCoalescingOperationEvidence evidence =
            QuicBufferCopyPolicy.CreateOperationEvidence(
                epochSequence: 10,
                decisionInstanceSequence: 22,
                operationSequence: 22,
                QuicBufferCopyPath.OutboundPacketProtection,
                in decision,
                legalSourceSegmentCount: 2,
                appliedSourceSegmentCount: 2,
                legalBytes: 200,
                appliedBytes: 200,
                ownerRented: true);

        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityResult.Ineligible,
            evidence.EligibilityResult);
        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityReason.NotAxisMechanism,
            evidence.EligibilityReason);
        Assert.Equal(
            QuicBufferCopyCoalescingMechanismEvent.NotAxisMechanism,
            evidence.MechanismEvent);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CombinedSendWithoutOwnerRentRemainsIneligible()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegmentCount: 4,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        QuicBufferCopyCoalescingOperationEvidence evidence =
            QuicBufferCopyPolicy.CreateOperationEvidence(
                epochSequence: 10,
                decisionInstanceSequence: 24,
                operationSequence: 24,
                QuicBufferCopyPath.CombinedApplicationSend,
                in decision,
                legalSourceSegmentCount: 4,
                appliedSourceSegmentCount: 0,
                legalBytes: 400,
                appliedBytes: 0,
                ownerRented: false);

        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityResult.Ineligible,
            evidence.EligibilityResult);
        Assert.Equal(
            QuicAdaptiveRuntimeOperationEligibilityReason.ResourceGuard,
            evidence.EligibilityReason);
        Assert.Equal(
            QuicBufferCopyCoalescingMechanismEvent.NoCombinedOwnerRented,
            evidence.MechanismEvent);
        Assert.False(evidence.OwnerRented);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowBufferRecommendationLeavesExactPrefixApplied()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.Shadow,
                forcedValue: null,
                legalSourceSegmentCount: 4,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);
        QuicBufferCopyCoalescingOperationEvidence evidence =
            QuicBufferCopyPolicy.CreateOperationEvidence(
                epochSequence: 11,
                decisionInstanceSequence: 23,
                operationSequence: 23,
                QuicBufferCopyPath.CombinedApplicationSend,
                in decision,
                legalSourceSegmentCount: 4,
                appliedSourceSegmentCount: 4,
                legalBytes: 400,
                appliedBytes: 400,
                ownerRented: true);

        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            evidence.CandidateValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicBufferCopyCoalescingMechanismEvent
                .ExactCombinedPrefixRetained,
            evidence.MechanismEvent);
    }

    private static QuicApplicationSendPlan CreateBatchPlan(
        QuicApplicationSendBatchPolicyMode mode,
        int eligibleWriteCount,
        int selectedWriteCount,
        int eligibleWriteBytes,
        int selectedWriteBytes)
        => new(
            selectedWriteCount == 1
                ? QuicApplicationSendPlanKind.SingleWrite
                : QuicApplicationSendPlanKind.Batch,
            selectedWriteCount,
            FragmentDataLength: 0,
            HasMoreQueuedData: selectedWriteCount < eligibleWriteCount,
            QuicSendPolicyBlockedReason.None,
            FirstStreamId: 0,
            mode,
            eligibleWriteCount,
            eligibleWriteBytes,
            selectedWriteBytes);

    private static QuicApplicationSendBatchObservation CreateBatchObservation(
        ulong planSequence,
        in QuicApplicationSendPlan plan)
        => new(
            planSequence,
            CapturedAtTicks: 1,
            QuicApplicationSendBatchObservation.CurrentObservationContractVersion,
            QuicApplicationSendBatchObservation.CurrentRuleVersion,
            QuicApplicationSendBatchSignalMask.None,
            QuicApplicationSendBatchSignalMask.None,
            QuicApplicationSendBatchObservationCondition.None,
            QuicAdaptiveRuntimeLifecycle.None,
            MaximumPayloadBytes: 1200,
            plan.EligibleWriteCount,
            plan.EligibleWriteBytes,
            QueuedApplicationWrites: (uint)plan.EligibleWriteCount,
            OutboundBacklogBytes: (ulong)plan.EligibleWriteBytes,
            DistinctQueuedStreams: 1,
            OldestQueuedSendAgeMicros: 0,
            QueueDelayEwmaMicros: 0,
            ActorServiceTimeEwmaMicros: 0,
            BytesInFlight: 0,
            CongestionWindowBytes: 1200,
            RetainedSendBuffers: 0,
            RetainedSendBytes: 0);
}
