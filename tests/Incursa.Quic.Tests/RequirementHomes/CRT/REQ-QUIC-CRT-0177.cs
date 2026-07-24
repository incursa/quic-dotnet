// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

public sealed class REQ_QUIC_CRT_0177
{
    [Fact]
    public void UnifiedSnapshotAcceptsFourLegacyAxesInCanonicalOrder()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = new(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum));

        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.ApplicationSendTurnPlanning.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.ApplicationSendBatchFormation.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.QueuedSendBurstBudget.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.OversizedWriteAdmissionQuantum.AppliedValue);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 2)]
    [InlineData(2, 3)]
    [InlineData(3, 4)]
    [InlineData(3, 5)]
    public void UnifiedSnapshotAcceptsExactlyOneForcedAxis(
        int forcedAxisValue,
        int forcedPolicyValue)
    {
        QuicAdaptiveRuntimeStage1Axis forcedAxis =
            (QuicAdaptiveRuntimeStage1Axis)forcedAxisValue;
        QuicAdaptiveRuntimeStage1PolicyValue forcedValue =
            (QuicAdaptiveRuntimeStage1PolicyValue)forcedPolicyValue;
        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = CreateSnapshot(
            forcedAxis,
            forcedValue);

        QuicAdaptiveRuntimeStage1AxisDecision forced = forcedAxis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                snapshot.ApplicationSendTurnPlanning,
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                snapshot.ApplicationSendBatchFormation,
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                snapshot.QueuedSendBurstBudget,
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                snapshot.OversizedWriteAdmissionQuantum,
            _ => throw new ArgumentOutOfRangeException(nameof(forcedAxis)),
        };

        Assert.True(forced.HasForcedValue);
        Assert.Equal(forcedValue, forced.AppliedValue);
    }

    [Fact]
    public void UnifiedSnapshotRejectsDuplicateOrOutOfOrderAxis()
    {
        QuicAdaptiveRuntimeStage1AxisDecision sendTurn =
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning);

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            sendTurn,
            sendTurn,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotRejectsMultipleForcedAxes()
    {
        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning,
                QuicAdaptiveRuntimeStage1PolicyValue.Conservative),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotRejectsNonLegacyAdjacentAxis()
    {
        QuicAdaptiveRuntimeStage1AxisDecision invalidAdjacent = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget) with
        {
            SelectedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            AppliedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
        };

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            invalidAdjacent,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotRequiresForcedAndAppliedIdentityToMatch()
    {
        QuicAdaptiveRuntimeStage1AxisDecision invalidForced = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible) with
        {
            AppliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
        };

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            invalidForced,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotAllowsNamedSafetyOverrideOfForcedValue()
    {
        QuicAdaptiveRuntimeStage1AxisDecision guarded = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram) with
        {
            AppliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            SelectionSource = QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
            SafetyOverrideReason = QuicAdaptiveRuntimeStage1SafetyOverrideReason.Recovery,
        };

        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = new(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            guarded,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum));

        Assert.True(snapshot.QueuedSendBurstBudget.SafetyOverrideApplied);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.QueuedSendBurstBudget.AppliedValue);
    }

    [Fact]
    public void UnifiedSnapshotRejectsPolicyValueFromAnotherAxis()
    {
        QuicAdaptiveRuntimeStage1AxisDecision invalid = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation) with
        {
            SelectedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
        };

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            invalid,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    private static QuicAdaptiveRuntimeStage1PolicySnapshot CreateSnapshot(
        QuicAdaptiveRuntimeStage1Axis forcedAxis,
        QuicAdaptiveRuntimeStage1PolicyValue forcedValue)
        => new(
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning
                    ? forcedValue
                    : null),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation
                    ? forcedValue
                    : null),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget
                    ? forcedValue
                    : null),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum
                    ? forcedValue
                    : null));

    private static QuicAdaptiveRuntimeStage1AxisDecision CreateDecision(
        QuicAdaptiveRuntimeStage1Axis axis,
        QuicAdaptiveRuntimeStage1PolicyValue? forcedValue = null)
    {
        (QuicAdaptiveRuntimeStage1DecisionBoundary boundary,
            QuicAdaptiveRuntimeStage1LatchLifetime lifetime) = axis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
                    QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn),
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.PacketPlan,
                    QuicAdaptiveRuntimeStage1LatchLifetime.PacketPlan),
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
                    QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn),
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.LogicalWriteAdmission,
                    QuicAdaptiveRuntimeStage1LatchLifetime.LogicalWrite),
            _ => throw new ArgumentOutOfRangeException(nameof(axis)),
        };

        return new QuicAdaptiveRuntimeStage1AxisDecision(
            axis,
            ObservationContractVersion: $"{axis}-observation-v1",
            RuleVersion: $"{axis}-rule-v1",
            SnapshotVersion: $"{axis}-snapshot-v1",
            ReasonVersion: $"{axis}-reasons-v1",
            ProvenanceVersion: $"{axis}-provenance-v1",
            QuicAdaptiveRuntimeStage1Validity.None,
            HasForcedValue: forcedValue.HasValue,
            ForcedValue: forcedValue.GetValueOrDefault(),
            HasShadowRecommendation: false,
            ShadowRecommendation: QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            SelectedValue: forcedValue ?? QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            AppliedValue: forcedValue ?? QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            SelectionSource: forcedValue.HasValue
                ? QuicAdaptiveRuntimeStage1SelectionSource.Forced
                : QuicAdaptiveRuntimeStage1SelectionSource.LegacySelector,
            ReasonCode: 0,
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.None,
            boundary,
            lifetime,
            QuicAdaptiveRuntimeStage1LatchState.Latched,
            QuicAdaptiveRuntimeStage1FallbackState.NotRequired,
            DecisionSequence: 1,
            LatchSequence: 1);
    }
}
