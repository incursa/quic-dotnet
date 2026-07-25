// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0190")]
public sealed class REQ_QUIC_CRT_0190
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LegacyCurrentPreservesTheAlreadyLegalCombinedPrefix()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.Disabled,
                QuicBufferCopyPolicyValue.LegacyCurrent,
                legalSourceSegmentCount: 5,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        Assert.True(decision.HasForcedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicBufferCopySelectionSource.Forced,
            decision.SelectionSource);
        Assert.Equal(5, decision.LegalSourceSegmentCount);
        Assert.Equal(5, decision.AppliedSourceSegmentCount);
        Assert.False(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MemoryConservativeCapsOnlyTheLegalCombinedPrefix()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegmentCount: 5,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            decision.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            decision.AppliedValue);
        Assert.Equal(5, decision.LegalSourceSegmentCount);
        Assert.Equal(
            QuicBufferCopyPolicy.MemoryConservativeMaximumSourceSegments,
            decision.AppliedSourceSegmentCount);
        Assert.False(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendsWithoutChangingTheAppliedPrefix()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.Shadow,
                forcedValue: null,
                legalSourceSegmentCount: 5,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        Assert.False(decision.HasForcedValue);
        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            decision.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicBufferCopySelectionSource.ShadowRule,
            decision.SelectionSource);
        Assert.Equal(5, decision.AppliedSourceSegmentCount);
    }

    [Theory]
    [InlineData((int)QuicBufferCopyValidity.ArithmeticSaturated)]
    [InlineData((int)QuicBufferCopyValidity.Contradictory)]
    [InlineData((int)QuicBufferCopyValidity.OutOfDomain)]
    [InlineData((int)QuicBufferCopyValidity.StaleRequiredInput)]
    [InlineData((int)QuicBufferCopyValidity.InvalidInput)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidEvidenceOverridesForcedMemoryConservative(
        int validityValue)
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.Shadow,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegmentCount: 5,
                (QuicBufferCopyValidity)validityValue,
                lifecycleGuard: false);

        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            decision.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicBufferCopySelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(
            QuicBufferCopySafetyOverride.InvalidObservation,
            decision.SafetyOverride);
        Assert.Equal(5, decision.AppliedSourceSegmentCount);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleGuardOverridesForcedMemoryConservative()
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.Shadow,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegmentCount: 5,
                QuicBufferCopyValidity.None,
                lifecycleGuard: true);

        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicBufferCopySafetyOverride.Lifecycle,
            decision.SafetyOverride);
        Assert.Equal(
            QuicBufferCopyReasonCode.LifecycleGuard,
            decision.ReasonCode);
        Assert.Equal(5, decision.AppliedSourceSegmentCount);
        Assert.True(decision.FallbackApplied);
    }

    [Theory]
    [InlineData(0, (int)QuicBufferCopyReasonCode.MissingInput, 0)]
    [InlineData(1, (int)QuicBufferCopyReasonCode.Contradictory, 1)]
    [InlineData(-1, (int)QuicBufferCopyReasonCode.OutOfDomain, 0)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidBoundaryInputsFallBackWithoutExecutingAPlan(
        int legalSourceSegmentCount,
        int expectedReason,
        int expectedAppliedSourceSegmentCount)
    {
        QuicBufferCopyPolicyDecision decision =
            QuicBufferCopyPolicy.Evaluate(
                QuicBufferCopyObservationMode.Shadow,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegmentCount,
                QuicBufferCopyValidity.None,
                lifecycleGuard: false);

        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            decision.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicBufferCopySafetyOverride.InvalidObservation,
            decision.SafetyOverride);
        Assert.Equal(
            (QuicBufferCopyReasonCode)expectedReason,
            decision.ReasonCode);
        Assert.Equal(
            expectedAppliedSourceSegmentCount,
            decision.AppliedSourceSegmentCount);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidClosedValuesAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                (QuicBufferCopyObservationMode)byte.MaxValue,
                forcedValue: null));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.ObserveOnly,
                (QuicBufferCopyPolicyValue)byte.MaxValue));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BehaviorDistinctAdjacentAxisForcingIsRejected()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedReceiveCreditPolicyMode =
                        QuicReceiveCreditPolicyMode.LegacyCurrent,
                    ForcedApplicationSendBatchPolicyMode =
                        QuicApplicationSendBatchPolicyMode.SingleEligible,
                    ForcedBufferCopyPolicyValue =
                        QuicBufferCopyPolicyValue.MemoryConservative,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BehaviorDistinctReceiveCreditForcingIsRejected()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedReceiveCreditPolicyMode =
                        QuicReceiveCreditPolicyMode.ReadDominantBatch,
                    ForcedBufferCopyPolicyValue =
                        QuicBufferCopyPolicyValue.MemoryConservative,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackRestoresTheExactLegalPrefix()
    {
        using QuicConnectionRuntime conservative =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        conservative.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedBufferCopyPolicyValue =
                    QuicBufferCopyPolicyValue.MemoryConservative,
            });
        using QuicConnectionRuntime rollback =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        rollback.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedBufferCopyPolicyValue =
                    QuicBufferCopyPolicyValue.LegacyCurrent,
            });

        Assert.Equal(
            2,
            conservative.ResolveBufferCopyPolicyDecision(5)
                .AppliedSourceSegmentCount);
        QuicBufferCopyPolicyDecision rollbackDecision =
            rollback.ResolveBufferCopyPolicyDecision(5);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            rollbackDecision.AppliedValue);
        Assert.Equal(5, rollbackDecision.AppliedSourceSegmentCount);
        Assert.False(rollbackDecision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnifiedEpochRetainsConfiguredPolicyWithoutAnOperation()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot stage1 =
            QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
                sendTurnForced: null,
                QuicApplicationSendTurnObservationMode.Disabled,
                sendBatchForced: null,
                QuicApplicationSendBatchObservationMode.Disabled,
                burstForced: null,
                QuicQueuedSendBurstObservationMode.Disabled,
                oversizedForced: null,
                QuicOversizedWriteAdmissionObservationMode.Disabled);
        QuicBufferCopyConfiguredPolicySnapshot buffer =
            QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.Shadow,
                forcedValue: null);
        RecordingUnifiedEpochSink sink = new();
        QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator accumulator =
            new(in stage1, in buffer, sink);
        QuicAdaptiveRuntimeConnectionObservation connection =
            new(
                1,
                EpochStartTicks: 10,
                EpochEndTicks: 20,
                ActiveDurationMicros: 1,
                QuicAdaptiveRuntimeConnectionObservation
                    .CurrentObservationContractVersion,
                QuicAdaptiveRuntimeConnectionObservation
                    .CurrentPolicyRuleVersion,
                AdvisorAgeMicros: null,
                MissingSignalMask: QuicAdaptiveRuntimeSignalMask.None,
                StaleSignalMask: QuicAdaptiveRuntimeSignalMask.None,
                LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
                HasIssuedApplicationData: false,
                OpenStreams: 0,
                LiveObserverStreams: 0,
                QueuedApplicationWrites: 0,
                QueueDelayEwmaMicros: 0);
        QuicReceiveCreditPolicySnapshot receive =
            new(
                SnapshotVersion: 1,
                QuicAdaptiveRuntimeConnectionObservation
                    .CurrentPolicyRuleVersion,
                QuicAdaptiveRuntimePolicyState.Conservative,
                QuicAdaptiveRuntimePolicyState.Conservative,
                Transitioned: false,
                StateEpochCount: 1,
                StateDurationMicros: 1,
                CandidateEvidenceCount: 0,
                ReliefEvidenceCount: 0,
                EpochSequence: 1,
                QuicReceiveCreditPolicyMode.LegacyCurrent,
                QuicReceiveCreditPolicyMode.Immediate,
                QuicAdaptiveRuntimePolicyReason.LegacyImmediate,
                HasIssuedApplicationData: false);
        QuicAdaptiveRuntimePostServiceBoundary boundary =
            new(
                1,
                EpochEndTicks: 20,
                QuicAdaptiveRuntimePostServiceBoundarySource.HostedShard,
                QuicActorServiceDisposition.Completed,
                ActorServiceSequence: null,
                ActorObservationPublished: false,
                ResourceReleaseCompleted: true,
                QuicAdaptiveRuntimePostServiceBoundaryValidity.None);

        Assert.True(accumulator.TryPublish(
            in connection,
            in receive,
            in boundary));

        QuicAdaptiveRuntimeUnifiedEpochEvidence evidence =
            Assert.Single(sink.Evidence);
        Assert.False(evidence.BufferCopy.HasObservation);
        Assert.Equal(
            QuicBufferCopyObservationMode.Shadow,
            evidence.BufferCopy.PolicySnapshot.Mode);
        Assert.True(
            evidence.BufferCopy.PolicySnapshot.HasShadowRecommendation);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            evidence.BufferCopy.PolicySnapshot.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.LegacyCurrent,
            evidence.BufferCopy.PolicySnapshot.AppliedValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeAppliesTheBufferCapAfterTheStage1Plan()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 8_192,
                    localBidirectionalSendLimit: 8_192);
        Queue<PostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                postedWrites.Enqueue(new(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        RecordingBufferEvidenceSink bufferSink = new();
        RecordingBatchEvidenceSink batchSink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedReceiveCreditPolicyMode =
                    QuicReceiveCreditPolicyMode.LegacyCurrent,
                ApplicationSendBatchObservationMode =
                    QuicApplicationSendBatchObservationMode.ObserveOnly,
                ApplicationSendBatchEvidenceSink = batchSink,
                ForcedBufferCopyPolicyValue =
                    QuicBufferCopyPolicyValue.MemoryConservative,
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.Shadow,
                BufferCopyEvidenceSink = bufferSink,
            });

        List<Task> writes = [];
        for (int index = 0; index < 4; index++)
        {
            Assert.True(
                runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                    bidirectional: true,
                    out QuicStreamId streamId,
                    out _));
            writes.Add(
                runtime.WriteStreamAsync(
                    streamId.Value,
                    new byte[16],
                    CancellationToken.None).AsTask());
        }

        Assert.Equal(4, postedWrites.Count);
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

        long dueTicks = Assert.IsType<long>(
            runtime.TimerState.GetDueTicks(
                QuicConnectionTimerKind.ApplicationSendDelay));
        ulong timerGeneration =
            runtime.TimerState.GetGeneration(
                QuicConnectionTimerKind.ApplicationSendDelay);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks,
                QuicConnectionTimerKind.ApplicationSendDelay,
                timerGeneration),
            dueTicks);

        Assert.True(result.StateChanged);
        QuicApplicationSendBatchEvidence batch =
            Assert.Single(batchSink.Evidence);
        Assert.True(batch.AppliedWriteCount >= 4);
        QuicBufferCopyObservation combined = Assert.Single(
            bufferSink.Copies,
            static copy =>
                copy.Path
                    == QuicBufferCopyPath.CombinedApplicationSend);
        Assert.Equal(
            (uint)batch.AppliedWriteCount,
            combined.LegalSourceSegmentCount);
        Assert.Equal(
            (uint)QuicBufferCopyPolicy
                .MemoryConservativeMaximumSourceSegments,
            combined.SourceSegmentCount);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            combined.ForcedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            combined.ShadowRecommendation);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            combined.SelectedValue);
        Assert.Equal(
            QuicBufferCopyPolicyValue.MemoryConservative,
            combined.AppliedValue);
        Assert.Equal(
            QuicBufferCopySelectionSource.Forced,
            combined.SelectionSource);
        Assert.False(combined.FallbackApplied);

        await runtime.DisposeAsync();
        foreach (Task write in writes)
        {
            _ = await Record.ExceptionAsync(async () => await write);
        }
    }

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingBufferEvidenceSink :
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink
    {
        internal List<QuicBufferCopyObservation> Copies { get; } = [];

        internal List<QuicBufferReleaseObservation> Releases { get; } = [];

        public bool TryPublish(in QuicBufferCopyObservation observation)
        {
            Copies.Add(observation);
            return true;
        }

        public bool TryPublish(in QuicBufferReleaseObservation observation)
        {
            Releases.Add(observation);
            return true;
        }
    }

    private sealed class RecordingBatchEvidenceSink :
        IQuicApplicationSendBatchEvidenceSink
    {
        internal List<QuicApplicationSendBatchEvidence> Evidence { get; } = [];

        public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }

    private sealed class RecordingUnifiedEpochSink :
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink
    {
        internal List<QuicAdaptiveRuntimeUnifiedEpochEvidence> Evidence
        {
            get;
        } = [];

        public bool TryPublish(
            in QuicAdaptiveRuntimeUnifiedEpochEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }
}
