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

    [Theory]
    [InlineData((int)QuicApplicationSendTurnObservationMode.ObserveOnly, false)]
    [InlineData((int)QuicApplicationSendTurnObservationMode.Shadow, true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimePublishesAtTheExistingSendTurnBoundaryWithoutInstallingAPlanner(
        int modeValue,
        bool expectedRecommendation)
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
                connectionSendLimit: 4_096,
                localBidirectionalSendLimit: 4_096);
        Queue<PostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher((requestId, actionKind, streamId, streamData, streamDataSuffix) =>
        {
            postedWrites.Enqueue(new PostedStreamWrite(
                requestId,
                actionKind,
                streamId,
                streamData,
                streamDataSuffix));
            return true;
        });
        RecordingApplicationSendTurnEvidenceSink sink = new();
        QuicApplicationSendTurnObservationMode mode =
            (QuicApplicationSendTurnObservationMode)modeValue;
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode = QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            ApplicationSendTurnObservationMode = mode,
            ApplicationSendTurnEvidenceSink = sink,
        });
        runtime.ObserveApplicationSendWorkItemQueueDelay(queueDelayMilliseconds: 0.25);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[16],
            CancellationToken.None).AsTask();
        PostedStreamWrite postedWrite = Assert.Single(postedWrites);
        _ = runtime.TransitionStreamWrite(
            postedWrite.RequestId,
            postedWrite.ActionKind,
            postedWrite.StreamId,
            postedWrite.StreamData,
            postedWrite.StreamDataSuffix,
            nowTicks: 20);
        Assert.Empty(sink.Evidence);
        long dueTicks = Assert.IsType<long>(
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
        ulong timerGeneration =
            runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);
        _ = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks,
                QuicConnectionTimerKind.ApplicationSendDelay,
                timerGeneration),
            dueTicks);

        QuicApplicationSendTurnEvidence evidence = Assert.Single(sink.Evidence);
        Assert.Equal(mode, evidence.Mode);
        Assert.Equal(expectedRecommendation, evidence.HasRecommendation);
        Assert.Equal(1UL, evidence.Observation.TurnSequence);
        Assert.Equal(1U, evidence.Observation.QueuedApplicationWrites);
        Assert.Equal(1U, evidence.Observation.RetainedSendBuffers);
        Assert.Equal(QuicAdaptiveRuntimeLifecycle.Active, evidence.Observation.LifecycleFlags);
        if (expectedRecommendation)
        {
            Assert.Equal(
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
                evidence.Snapshot.AppliedPolicy);
            Assert.Equal(
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
                evidence.Snapshot.RecommendedPolicy);
            Assert.Equal(
                QuicApplicationSendTurnShadowReason.LegacyCurrent,
                evidence.Snapshot.Reason);
        }
        else
        {
            Assert.Equal(default, evidence.Snapshot);
        }

        Assert.Null(runtime.ApplicationSendTurnPlanner);
        Assert.Equal(mode, runtime.ApplicationSendTurnObservationMode);
        await write.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OnlyOneAxisCanOwnShadowSelection()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            AdaptiveRuntimeShadowEnabled = true,
            ApplicationSendTurnObservationMode = QuicApplicationSendTurnObservationMode.Shadow,
            ApplicationSendTurnEvidenceSink = new RecordingApplicationSendTurnEvidenceSink(),
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));

        Assert.Equal(
            "Only one adaptive-runtime shadow axis can be enabled on a connection.",
            exception.Message);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeShadowCannotReplaceAnInjectedPlanner()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            applicationSendTurnPlanner: QuicCurrentApplicationSendTurnPlanner.Instance);
        QuicClientConnectionOptions options = new()
        {
            ApplicationSendTurnObservationMode = QuicApplicationSendTurnObservationMode.Shadow,
            ApplicationSendTurnEvidenceSink = new RecordingApplicationSendTurnEvidenceSink(),
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Same(
            QuicCurrentApplicationSendTurnPlanner.Instance,
            runtime.ApplicationSendTurnPlanner);
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
    }

    [Theory]
    [InlineData((int)QuicReceiveCreditPolicyMode.Immediate, (int)QuicApplicationSendTurnPolicyMode.LegacyCurrent)]
    [InlineData((int)QuicReceiveCreditPolicyMode.LegacyCurrent, (int)QuicApplicationSendTurnPolicyMode.Conservative)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AdjacentOrAppliedCandidateModesAreRejected(
        int receiveCreditModeValue,
        int applicationSendTurnModeValue)
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ForcedReceiveCreditPolicyMode = (QuicReceiveCreditPolicyMode)receiveCreditModeValue,
            ForcedApplicationSendTurnPolicyMode =
                (QuicApplicationSendTurnPolicyMode)applicationSendTurnModeValue,
            ApplicationSendTurnObservationMode = QuicApplicationSendTurnObservationMode.Shadow,
            ApplicationSendTurnEvidenceSink = new RecordingApplicationSendTurnEvidenceSink(),
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Null(runtime.ApplicationSendTurnPlanner);
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EvidenceSinkFailureCannotEscapeTheSendTurn()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
                connectionSendLimit: 4_096,
                localBidirectionalSendLimit: 4_096);
        Queue<PostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher((requestId, actionKind, streamId, streamData, streamDataSuffix) =>
        {
            postedWrites.Enqueue(new PostedStreamWrite(
                requestId,
                actionKind,
                streamId,
                streamData,
                streamDataSuffix));
            return true;
        });
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ApplicationSendTurnObservationMode = QuicApplicationSendTurnObservationMode.Shadow,
            ApplicationSendTurnEvidenceSink = new ThrowingApplicationSendTurnEvidenceSink(),
        });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[16],
            CancellationToken.None).AsTask();
        PostedStreamWrite postedWrite = Assert.Single(postedWrites);
        _ = runtime.TransitionStreamWrite(
            postedWrite.RequestId,
            postedWrite.ActionKind,
            postedWrite.StreamId,
            postedWrite.StreamData,
            postedWrite.StreamDataSuffix,
            nowTicks: 20);
        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong timerGeneration =
            runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                timerGeneration),
            dueTicks.Value);

        Assert.True(result.StateChanged);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
        await write.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingApplicationSendTurnEvidenceSink :
        IQuicApplicationSendTurnEvidenceSink
    {
        internal List<QuicApplicationSendTurnEvidence> Evidence { get; } = [];

        public bool TryPublish(in QuicApplicationSendTurnEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }

    private sealed class ThrowingApplicationSendTurnEvidenceSink :
        IQuicApplicationSendTurnEvidenceSink
    {
        public bool TryPublish(in QuicApplicationSendTurnEvidence evidence)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}
