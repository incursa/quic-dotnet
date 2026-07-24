// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0175")]
public sealed class REQ_QUIC_CRT_0175
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidObservationRecommendsLegacyWithoutCreatingAPlannerConsumer()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1);

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, snapshot.AppliedPolicy);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, snapshot.RecommendedPolicy);
        Assert.Equal(QuicApplicationSendTurnShadowReason.LegacyCurrent, snapshot.Reason);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, runtime.ApplicationSendTurnPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void GuardFallbackRemainsBehaviorNeutral()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                Conditions = QuicApplicationSendTurnObservationCondition.RecoveryUnstable,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, snapshot.AppliedPolicy);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, snapshot.RecommendedPolicy);
        Assert.Equal(QuicApplicationSendTurnShadowReason.RecoveryGuard, snapshot.Reason);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EachSnapshotIsImmutableAndBoundToOneTurn()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation firstObservation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1);
        Assert.True(controller.TryEvaluate(
            in firstObservation,
            out QuicApplicationSendTurnPolicySnapshot firstSnapshot));

        QuicApplicationSendTurnObservation secondObservation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2) with
            {
                Conditions = QuicApplicationSendTurnObservationCondition.ResourceConstrained,
            };
        Assert.True(controller.TryEvaluate(
            in secondObservation,
            out QuicApplicationSendTurnPolicySnapshot secondSnapshot));

        Assert.Equal(1UL, firstSnapshot.TurnSequence);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, firstSnapshot.RecommendedPolicy);
        Assert.Equal(2UL, secondSnapshot.TurnSequence);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, secondSnapshot.RecommendedPolicy);
        Assert.True(secondSnapshot.Transitioned);
    }
}
