// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0178")]
public sealed class REQ_QUIC_CRT_0178
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LegacyCurrentPreservesTheExistingPayloadBoundedBatch()
    {
        PendingApplicationSendRequest[] queuedWrites = CreateQueuedWrites();
        int maximumPayloadBytes =
            queuedWrites[0].StreamPayloadLength + queuedWrites[1].StreamPayloadLength;

        QuicApplicationSendPlan plan =
            QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                queuedWrites,
                QuicQueuedApplicationSendBudget.AllowSingleDatagram(maximumPayloadBytes),
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Batch, plan.Kind);
        Assert.Equal(2, plan.SelectedWriteCount);
        Assert.Equal(2, plan.EligibleWriteCount);
        Assert.Equal(maximumPayloadBytes, plan.EligibleWriteBytes);
        Assert.Equal(QuicApplicationSendBatchPolicyMode.LegacyCurrent, plan.BatchPolicyMode);
        Assert.Equal([4UL, 8UL], queuedWrites[..plan.SelectedWriteCount].Select(static write => write.StreamId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SingleEligibleSelectsOnlyTheFirstAlreadyLegalWrite()
    {
        PendingApplicationSendRequest[] queuedWrites = CreateQueuedWrites();
        int maximumPayloadBytes =
            queuedWrites[0].StreamPayloadLength + queuedWrites[1].StreamPayloadLength;

        QuicApplicationSendPlan plan =
            QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                queuedWrites,
                QuicQueuedApplicationSendBudget.AllowSingleDatagram(maximumPayloadBytes),
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.SingleWrite, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.Equal(2, plan.EligibleWriteCount);
        Assert.Equal(maximumPayloadBytes, plan.EligibleWriteBytes);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal(4UL, plan.FirstStreamId);
        Assert.Equal(QuicApplicationSendBatchPolicyMode.SingleEligible, plan.BatchPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SingleEligibleCannotBypassRuntimeFragmentation()
    {
        PendingApplicationSendRequest oversized =
            CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 96);

        QuicApplicationSendPlan plan =
            QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                [oversized],
                QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 40),
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Fragment, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.InRange(plan.FragmentDataLength, 1, 95);
        Assert.Equal(1, plan.EligibleWriteCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SingleEligibleCannotBypassAResourceBlockedBudget()
    {
        PendingApplicationSendRequest[] queuedWrites = CreateQueuedWrites();
        QuicApplicationSendPlan plan =
            QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                queuedWrites,
                QuicQueuedApplicationSendBudget.Blocked(
                    QuicSendPolicyBlockedReason.CongestionLimited),
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                out Exception? exception);
        QuicApplicationSendBatchObservation observation =
            CreateObservation(planSequence: 1, in plan);

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.None, plan.Kind);
        Assert.Equal(QuicSendPolicyBlockedReason.CongestionLimited, plan.BlockedReason);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.Resource,
            decision.SafetyOverrideReason);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedSingleEligibleProducesOnePacketPlanLatch()
    {
        QuicApplicationSendPlan plan = CreatePlan(
            QuicApplicationSendBatchPolicyMode.SingleEligible);
        QuicApplicationSendBatchObservation observation =
            CreateObservation(planSequence: 7, in plan);

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
            decision.Axis);
        Assert.True(decision.HasForcedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            decision.ForcedValue);
        Assert.Equal(decision.ForcedValue, decision.SelectedValue);
        Assert.Equal(decision.ForcedValue, decision.AppliedValue);
        Assert.Equal(QuicAdaptiveRuntimeStage1SelectionSource.Forced, decision.SelectionSource);
        Assert.Equal(QuicAdaptiveRuntimeStage1DecisionBoundary.PacketPlan, decision.DecisionBoundary);
        Assert.Equal(QuicAdaptiveRuntimeStage1LatchLifetime.PacketPlan, decision.LatchLifetime);
        Assert.Equal(QuicAdaptiveRuntimeStage1LatchState.Completed, decision.LatchState);
        Assert.Equal(7UL, decision.DecisionSequence);
        Assert.Equal(7UL, decision.LatchSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendationDoesNotChangeAppliedBatchPolicy()
    {
        QuicApplicationSendPlan plan = CreatePlan(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent);
        QuicApplicationSendBatchObservation observation =
            CreateObservation(planSequence: 1, in plan);

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.Shadow,
                hasForcedValue: false,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                in plan);

        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule, decision.SelectionSource);
    }

    [Theory]
    [InlineData(
        (int)QuicApplicationSendBatchSignalMask.EligibleWriteCount,
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchObservationCondition.None,
        (int)QuicAdaptiveRuntimeStage1Validity.Missing)]
    [InlineData(
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchSignalMask.MaximumPayloadBytes,
        (int)QuicApplicationSendBatchObservationCondition.None,
        (int)QuicAdaptiveRuntimeStage1Validity.Stale)]
    [InlineData(
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchObservationCondition.ArithmeticSaturated,
        (int)QuicAdaptiveRuntimeStage1Validity.Saturated)]
    [InlineData(
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchObservationCondition.Contradictory,
        (int)QuicAdaptiveRuntimeStage1Validity.Contradictory)]
    [InlineData(
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchSignalMask.None,
        (int)QuicApplicationSendBatchObservationCondition.OutOfDomain,
        (int)QuicAdaptiveRuntimeStage1Validity.OutOfDomain)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void InvalidShadowInputsRecommendConservativeSingleEligible(
        int missingMaskValue,
        int staleMaskValue,
        int conditionValue,
        int expectedValidityValue)
    {
        QuicApplicationSendPlan plan = CreatePlan(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent);
        QuicApplicationSendBatchObservation observation =
            CreateObservation(planSequence: 1, in plan) with
            {
                MissingSignalMask = (QuicApplicationSendBatchSignalMask)missingMaskValue,
                StaleSignalMask = (QuicApplicationSendBatchSignalMask)staleMaskValue,
                Conditions = (QuicApplicationSendBatchObservationCondition)conditionValue,
            };

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.Shadow,
                hasForcedValue: false,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                in plan);

        Assert.Equal(
            (QuicAdaptiveRuntimeStage1Validity)expectedValidityValue,
            decision.Validity);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(QuicAdaptiveRuntimeStage1LatchState.Fallback, decision.LatchState);
        Assert.Equal(QuicAdaptiveRuntimeStage1FallbackState.Applied, decision.FallbackState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TerminalLifecycleOverridesAForcedBatch()
    {
        QuicApplicationSendPlan plan = CreatePlan(
            QuicApplicationSendBatchPolicyMode.SingleEligible);
        QuicApplicationSendBatchObservation observation =
            CreateObservation(planSequence: 1, in plan) with
            {
                LifecycleFlags =
                    QuicAdaptiveRuntimeLifecycle.Closing
                    | QuicAdaptiveRuntimeLifecycle.Terminal,
            };

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.Terminal,
            decision.SafetyOverrideReason);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(QuicAdaptiveRuntimeStage1LatchState.Terminal, decision.LatchState);
        Assert.Equal(QuicAdaptiveRuntimeStage1FallbackState.Terminal, decision.FallbackState);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 1)]
    [InlineData(16, 1)]
    [InlineData(64, 1)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SingleEligibleIsAlwaysALowerOnlyLegalPrefix(
        int legalEligibleCount,
        int expectedSelectedCount)
    {
        int selectedCount = QuicApplicationSendBatchPolicy.SelectWriteCount(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            legalEligibleCount);

        Assert.Equal(expectedSelectedCount, selectedCount);
        Assert.InRange(selectedCount, 0, legalEligibleCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimePublishesTheForcedBatchAtThePacketPlanBoundary()
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
        RecordingApplicationSendTurnEvidenceSink turnSink = new();
        RecordingApplicationSendBatchEvidenceSink batchSink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.LegacyCurrent,
            AdaptiveRuntimeShadowEnabled = true,
            ForcedApplicationSendTurnPolicyMode =
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            ApplicationSendTurnObservationMode =
                QuicApplicationSendTurnObservationMode.ObserveOnly,
            ApplicationSendTurnEvidenceSink = turnSink,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.SingleEligible,
            ApplicationSendBatchObservationMode =
                QuicApplicationSendBatchObservationMode.Shadow,
            ApplicationSendBatchEvidenceSink = batchSink,
        });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId firstStreamId,
            out _));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId secondStreamId,
            out _));

        Task firstWrite = runtime.WriteStreamAsync(
            firstStreamId.Value,
            new byte[16],
            CancellationToken.None).AsTask();
        Task secondWrite = runtime.WriteStreamAsync(
            secondStreamId.Value,
            new byte[16],
            CancellationToken.None).AsTask();
        Assert.Equal(2, postedWrites.Count);
        while (postedWrites.TryDequeue(out PostedStreamWrite postedWrite))
        {
            _ = runtime.TransitionStreamWrite(
                postedWrite.RequestId,
                postedWrite.ActionKind,
                postedWrite.StreamId,
                postedWrite.StreamData,
                postedWrite.StreamDataSuffix,
                nowTicks: 20);
        }

        Assert.Empty(batchSink.Evidence);
        long dueTicks = Assert.IsType<long>(
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
        ulong timerGeneration =
            runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks,
                QuicConnectionTimerKind.ApplicationSendDelay,
                timerGeneration),
            dueTicks);

        Assert.True(result.StateChanged);
        QuicApplicationSendBatchEvidence firstEvidence = batchSink.Evidence[0];
        Assert.Equal(
            QuicApplicationSendBatchObservationMode.Shadow,
            firstEvidence.Mode);
        Assert.True(firstEvidence.Observation.EligibleWriteCount >= 2);
        Assert.Equal(2U, firstEvidence.Observation.QueuedApplicationWrites);
        Assert.Equal(32UL, firstEvidence.Observation.OutboundBacklogBytes);
        Assert.Equal(2, firstEvidence.Observation.DistinctQueuedStreams);
        Assert.Equal(2U, firstEvidence.Observation.RetainedSendBuffers);
        Assert.True(firstEvidence.Observation.RetainedSendBytes >= 32);
        Assert.True(
            firstEvidence.Observation.MissingSignalMask.HasFlag(
                QuicApplicationSendBatchSignalMask.QueueDelayEwma));
        bool actorServiceTimeMissing =
            firstEvidence.Observation.MissingSignalMask.HasFlag(
                QuicApplicationSendBatchSignalMask.ActorServiceTimeEwma);
        if (actorServiceTimeMissing)
        {
            Assert.Equal(0U, firstEvidence.Observation.ActorServiceTimeEwmaMicros);
        }
        Assert.Equal(1, firstEvidence.AppliedWriteCount);
        Assert.True(firstEvidence.Decision.HasForcedValue);
        Assert.True(firstEvidence.Decision.HasShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            firstEvidence.Decision.ForcedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            firstEvidence.Decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.Forced,
            firstEvidence.Decision.SelectionSource);
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.ObserveOnly,
            runtime.ApplicationSendTurnObservationMode);
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            runtime.ApplicationSendBatchPolicyMode);
        Assert.Equal(
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            runtime.GetAppliedReceiveCreditPolicyMode());
        Assert.NotEmpty(turnSink.Evidence);
        await Task.WhenAll(firstWrite, secondWrite).WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData((int)QuicApplicationSendBatchObservationMode.Disabled, true)]
    [InlineData((int)QuicApplicationSendBatchObservationMode.Shadow, false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EvidenceSinkConfigurationMustMatchTheObservationMode(
        int modeValue,
        bool includeSink)
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ApplicationSendBatchObservationMode =
                (QuicApplicationSendBatchObservationMode)modeValue,
            ApplicationSendBatchEvidenceSink = includeSink
                ? new RecordingApplicationSendBatchEvidenceSink()
                : null,
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendBatchObservationMode.Disabled,
            runtime.ApplicationSendBatchObservationMode);
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            runtime.ApplicationSendBatchPolicyMode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UndefinedConfigurationIsRejectedWithoutPartialState(
        bool invalidObservationMode)
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = invalidObservationMode
            ? new QuicClientConnectionOptions
            {
                ApplicationSendBatchObservationMode =
                    (QuicApplicationSendBatchObservationMode)byte.MaxValue,
                ApplicationSendBatchEvidenceSink =
                    new RecordingApplicationSendBatchEvidenceSink(),
            }
            : new QuicClientConnectionOptions
            {
                ForcedApplicationSendBatchPolicyMode =
                    (QuicApplicationSendBatchPolicyMode)byte.MaxValue,
            };

        Assert.Throws<ArgumentOutOfRangeException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendBatchObservationMode.Disabled,
            runtime.ApplicationSendBatchObservationMode);
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            runtime.ApplicationSendBatchPolicyMode);
    }

    [Theory]
    [InlineData((int)QuicReceiveCreditPolicyMode.Immediate, (int)QuicApplicationSendTurnPolicyMode.LegacyCurrent)]
    [InlineData((int)QuicReceiveCreditPolicyMode.LegacyCurrent, (int)QuicApplicationSendTurnPolicyMode.Conservative)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForcedBatchRejectsANonLegacyAdjacentAxis(
        int receiveCreditModeValue,
        int applicationSendTurnModeValue)
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ForcedReceiveCreditPolicyMode =
                (QuicReceiveCreditPolicyMode)receiveCreditModeValue,
            ForcedApplicationSendTurnPolicyMode =
                (QuicApplicationSendTurnPolicyMode)applicationSendTurnModeValue,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.SingleEligible,
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            runtime.ApplicationSendBatchPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackPreservesTheExistingBatchPath()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode =
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
        });

        Assert.Equal(
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            runtime.GetAppliedReceiveCreditPolicyMode());
        Assert.Equal(
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            runtime.ApplicationSendTurnPolicyMode);
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            runtime.ApplicationSendBatchPolicyMode);
        Assert.Equal(
            QuicApplicationSendBatchObservationMode.Disabled,
            runtime.ApplicationSendBatchObservationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesBatchModeAndSink()
    {
        RecordingApplicationSendBatchEvidenceSink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.SingleEligible,
            ApplicationSendBatchObservationMode =
                QuicApplicationSendBatchObservationMode.ObserveOnly,
            ApplicationSendBatchEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(selectedOptions, returnedOptions);

        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            selectedOptions.ForcedApplicationSendBatchPolicyMode);
        Assert.Equal(
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            selectedOptions.ApplicationSendBatchObservationMode);
        Assert.Same(sink, selectedOptions.ApplicationSendBatchEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BatchPolicyCannotBeConfiguredTwice()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureApplicationSendBatchPolicyMode(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent);

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureApplicationSendBatchPolicyMode(
                QuicApplicationSendBatchPolicyMode.SingleEligible));
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            runtime.ApplicationSendBatchPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EvidenceSinkFailureCannotEscapeThePacketPlan()
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
            ApplicationSendBatchObservationMode =
                QuicApplicationSendBatchObservationMode.Shadow,
            ApplicationSendBatchEvidenceSink =
                new ThrowingApplicationSendBatchEvidenceSink(),
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
        long dueTicks = Assert.IsType<long>(
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
        ulong timerGeneration =
            runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks,
                QuicConnectionTimerKind.ApplicationSendDelay,
                timerGeneration),
            dueTicks);

        Assert.True(result.StateChanged);
        await write.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplayProducesTheSameDecision()
    {
        QuicApplicationSendPlan plan = CreatePlan(
            QuicApplicationSendBatchPolicyMode.SingleEligible);
        QuicApplicationSendBatchObservation observation =
            CreateObservation(planSequence: 11, in plan);

        QuicAdaptiveRuntimeStage1AxisDecision first =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.Shadow,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);
        QuicAdaptiveRuntimeStage1AxisDecision replay =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                QuicApplicationSendBatchObservationMode.Shadow,
                hasForcedValue: true,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                in plan);

        Assert.Equal(first, replay);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UndefinedPolicyModeIsRejectedEvenWithoutEligibleWork(bool emptyQueue)
    {
        PendingApplicationSendRequest[] queuedWrites = emptyQueue
            ? []
            : CreateQueuedWrites();
        QuicQueuedApplicationSendBudget budget = emptyQueue
            ? QuicQueuedApplicationSendBudget.AllowSingleDatagram(1_024)
            : QuicQueuedApplicationSendBudget.Blocked(
                QuicSendPolicyBlockedReason.CongestionLimited);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                queuedWrites,
                budget,
                (QuicApplicationSendBatchPolicyMode)byte.MaxValue,
                out _));
    }

    private static QuicApplicationSendPlan CreatePlan(
        QuicApplicationSendBatchPolicyMode mode)
    {
        PendingApplicationSendRequest[] queuedWrites = CreateQueuedWrites();
        return QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(
                queuedWrites[0].StreamPayloadLength + queuedWrites[1].StreamPayloadLength),
            mode,
            out _);
    }

    private static QuicApplicationSendBatchObservation CreateObservation(
        ulong planSequence,
        in QuicApplicationSendPlan plan)
        => new(
            planSequence,
            CapturedAtTicks: 10,
            QuicApplicationSendBatchObservation.CurrentObservationContractVersion,
            QuicApplicationSendBatchObservation.CurrentRuleVersion,
            QuicApplicationSendBatchSignalMask.None,
            QuicApplicationSendBatchSignalMask.None,
            QuicApplicationSendBatchObservationCondition.None,
            QuicAdaptiveRuntimeLifecycle.Active,
            MaximumPayloadBytes: Math.Max(plan.EligibleWriteBytes, 1),
            plan.EligibleWriteCount,
            plan.EligibleWriteBytes,
            QueuedApplicationWrites: 3,
            OutboundBacklogBytes: 24,
            DistinctQueuedStreams: 3,
            OldestQueuedSendAgeMicros: 100,
            QueueDelayEwmaMicros: 10,
            ActorServiceTimeEwmaMicros: 5,
            BytesInFlight: 32,
            CongestionWindowBytes: 1_024,
            RetainedSendBuffers: 3,
            RetainedSendBytes: 96);

    private static PendingApplicationSendRequest[] CreateQueuedWrites()
        =>
        [
            CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8),
            CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8),
            CreateQueuedWrite(sequence: 2, streamId: 12, dataLength: 8),
        ];

    private static PendingApplicationSendRequest CreateQueuedWrite(
        long sequence,
        ulong streamId,
        int dataLength)
    {
        byte[] streamData =
            Enumerable.Range(0, dataLength).Select(static value => (byte)value).ToArray();
        byte[] streamPayload = new byte[dataLength + 32];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask,
            streamId,
            offset: 0,
            streamData,
            streamPayload,
            out int streamPayloadLength));

        return new PendingApplicationSendRequest(
            sequence,
            streamId,
            Priority: 0,
            streamPayload[..streamPayloadLength],
            streamPayloadLength);
    }

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingApplicationSendBatchEvidenceSink :
        IQuicApplicationSendBatchEvidenceSink
    {
        internal List<QuicApplicationSendBatchEvidence> Evidence { get; } = [];

        public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }

    private sealed class ThrowingApplicationSendBatchEvidenceSink :
        IQuicApplicationSendBatchEvidenceSink
    {
        public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
            => throw new InvalidOperationException("diagnostic sink failure");
    }

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
}
