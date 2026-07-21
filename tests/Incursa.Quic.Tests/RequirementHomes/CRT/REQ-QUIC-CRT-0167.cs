// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0167")]
public sealed class REQ_QUIC_CRT_0167
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IdenticalOrderedObservationsReplayIdentically()
    {
        QuicReceiveCreditShadowController first = default;
        QuicReceiveCreditShadowController second = default;
        QuicReceiveCreditPolicySnapshot lastSnapshot = default;
        QuicAdaptiveRuntimeConnectionObservation[] observations =
        [
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 15),
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(2, liveObserverStreams: 16),
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(3, liveObserverStreams: 16, hasIssuedApplicationData: true),
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(4, liveObserverStreams: 24),
        ];

        foreach (QuicAdaptiveRuntimeConnectionObservation observation in observations)
        {
            Assert.True(first.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot firstSnapshot));
            Assert.True(second.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot secondSnapshot));
            Assert.Equal(firstSnapshot, secondSnapshot);
            lastSnapshot = firstSnapshot;
        }

        Assert.True(lastSnapshot.HasIssuedApplicationData);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, lastSnapshot.ProposedPolicy);
    }

    [Theory]
    [InlineData((uint)QuicAdaptiveRuntimeSignalMask.HasIssuedApplicationData)]
    [InlineData((uint)QuicAdaptiveRuntimeSignalMask.LiveObserverStreams)]
    [InlineData((uint)QuicAdaptiveRuntimeSignalMask.Lifecycle)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingRequiredSignalSelectsConservativeFallback(uint missingSignalMask)
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                MissingSignalMask = (QuicAdaptiveRuntimeSignalMask)missingSignalMask,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicAdaptiveRuntimePolicyReason.MissingSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleRequiredSignalSelectsConservativeFallback()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                StaleSignalMask = QuicAdaptiveRuntimeSignalMask.LiveObserverStreams,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicAdaptiveRuntimePolicyReason.StaleSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void FallbackReasonPrecedenceIsDeterministic()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                MissingSignalMask = QuicAdaptiveRuntimeSignalMask.LiveObserverStreams,
                StaleSignalMask = QuicAdaptiveRuntimeSignalMask.HasIssuedApplicationData,
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Active | QuicAdaptiveRuntimeLifecycle.Closing,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicAdaptiveRuntimePolicyReason.MissingSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContradictoryLifecycleSelectsConservativeFallback()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Active | QuicAdaptiveRuntimeLifecycle.Closing,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicAdaptiveRuntimePolicyReason.ContradictorySignals);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SaturatedRuleInputSelectsConservativeFallback()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, ushort.MaxValue);

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicAdaptiveRuntimePolicyReason.ArithmeticSaturated);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContractOrRuleVersionMismatchSelectsConservativeFallback()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                PolicyRuleVersion = "unreviewed-rule",
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicAdaptiveRuntimePolicyReason.RuleVersionMismatch);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DuplicateAndOutOfOrderEpochsAreRejectedWithoutAdvancingSnapshotVersion()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation first =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16);
        Assert.True(controller.TryEvaluate(in first, out QuicReceiveCreditPolicySnapshot firstSnapshot));

        Assert.False(controller.TryEvaluate(in first, out _));
        QuicAdaptiveRuntimeConnectionObservation zero =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(0, liveObserverStreams: 16);
        Assert.False(controller.TryEvaluate(in zero, out _));

        QuicAdaptiveRuntimeConnectionObservation second =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(2, liveObserverStreams: 15);
        Assert.True(controller.TryEvaluate(in second, out QuicReceiveCreditPolicySnapshot secondSnapshot));
        Assert.Equal(firstSnapshot.SnapshotVersion + 1, secondSnapshot.SnapshotVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TerminalStateNeverReturnsToANonterminalState()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation terminal =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Closing | QuicAdaptiveRuntimeLifecycle.Terminal,
            };
        Assert.True(controller.TryEvaluate(in terminal, out QuicReceiveCreditPolicySnapshot terminalSnapshot));
        Assert.Equal(QuicAdaptiveRuntimePolicyState.Terminal, terminalSnapshot.State);

        QuicAdaptiveRuntimeConnectionObservation active =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(2, liveObserverStreams: 16);
        Assert.True(controller.TryEvaluate(in active, out QuicReceiveCreditPolicySnapshot laterSnapshot));
        Assert.Equal(QuicAdaptiveRuntimePolicyState.Terminal, laterSnapshot.State);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, laterSnapshot.ProposedPolicy);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DisposalPublishesTheBoundedCancellationOrDisposalReason()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation disposed =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16) with
            {
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Discarded | QuicAdaptiveRuntimeLifecycle.Disposed,
            };

        Assert.True(controller.TryEvaluate(in disposed, out QuicReceiveCreditPolicySnapshot snapshot));

        Assert.Equal(QuicAdaptiveRuntimePolicyState.Terminal, snapshot.State);
        Assert.Equal(QuicAdaptiveRuntimePolicyReason.CancellationOrDisposal, snapshot.Reason);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, snapshot.ProposedPolicy);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PublishedSnapshotsRemainImmutableAcrossLaterEvaluations()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation first =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16);
        Assert.True(controller.TryEvaluate(in first, out QuicReceiveCreditPolicySnapshot latchedSnapshot));

        QuicAdaptiveRuntimeConnectionObservation second =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(2, liveObserverStreams: 16, hasIssuedApplicationData: true);
        Assert.True(controller.TryEvaluate(in second, out QuicReceiveCreditPolicySnapshot laterSnapshot));

        Assert.Equal(QuicReceiveCreditPolicyMode.ReadDominantBatch, latchedSnapshot.ProposedPolicy);
        Assert.False(latchedSnapshot.HasIssuedApplicationData);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, laterSnapshot.ProposedPolicy);
        Assert.True(laterSnapshot.HasIssuedApplicationData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SteadyStateShadowEvaluationDoesNotAllocate()
    {
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation warmup =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(1, liveObserverStreams: 16);
        Assert.True(controller.TryEvaluate(in warmup, out _));

        bool allEvaluated = true;
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (ulong epochSequence = 2; epochSequence < 1026; epochSequence++)
        {
            QuicAdaptiveRuntimeConnectionObservation observation =
                QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(epochSequence, liveObserverStreams: 16);
            allEvaluated &= controller.TryEvaluate(in observation, out _);
        }

        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.True(allEvaluated);
        Assert.Equal(allocatedBefore, allocatedAfter);
    }

    private static void AssertFallback(
        QuicReceiveCreditPolicySnapshot snapshot,
        QuicAdaptiveRuntimePolicyReason expectedReason)
    {
        Assert.Equal(QuicAdaptiveRuntimePolicyState.Fallback, snapshot.State);
        Assert.Equal(QuicReceiveCreditPolicyMode.LegacyCurrent, snapshot.AppliedPolicy);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, snapshot.ProposedPolicy);
        Assert.Equal(expectedReason, snapshot.Reason);
    }
}

internal static class QuicAdaptiveRuntimeShadowTestSupport
{
    internal static QuicAdaptiveRuntimeConnectionObservation CreateObservation(
        ulong epochSequence,
        ushort liveObserverStreams,
        bool hasIssuedApplicationData = false)
        => new(
            epochSequence,
            EpochStartTicks: (long)epochSequence * 10,
            EpochEndTicks: ((long)epochSequence * 10) + 10,
            ActiveDurationMicros: 1,
            QuicAdaptiveRuntimeConnectionObservation.CurrentObservationContractVersion,
            QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
            AdvisorAgeMicros: null,
            MissingSignalMask: QuicAdaptiveRuntimeSignalMask.QueueDelayEwma,
            StaleSignalMask: QuicAdaptiveRuntimeSignalMask.None,
            LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
            hasIssuedApplicationData,
            OpenStreams: liveObserverStreams,
            liveObserverStreams,
            QueuedApplicationWrites: 0,
            QueueDelayEwmaMicros: 0);
}
