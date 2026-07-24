// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0180")]
public sealed class REQ_QUIC_CRT_0180
{
    [Theory]
    [InlineData((int)QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent, 2)]
    [InlineData((int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment, 1)]
    [InlineData((int)QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment, 2)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EveryForcedValueResolvesAtLogicalWriteAdmission(
        int modeValue,
        int expectedChunkQuantum)
    {
        QuicOversizedWriteAdmissionPolicyMode mode =
            (QuicOversizedWriteAdmissionPolicyMode)modeValue;
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 7, legacyChunkQuantum: 2);

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                hasForcedValue: true,
                mode);

        Assert.Equal(expectedChunkQuantum, resolution.AppliedChunkQuantum);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.Forced,
            resolution.Decision.SelectionSource);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1DecisionBoundary.LogicalWriteAdmission,
            resolution.Decision.DecisionBoundary);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1LatchLifetime.LogicalWrite,
            resolution.Decision.LatchLifetime);
        Assert.Equal(7UL, resolution.Decision.DecisionSequence);
        Assert.Equal(7UL, resolution.Decision.LatchSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendationNeverChangesLegacyApplication()
    {
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 1, legacyChunkQuantum: 2);

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.Shadow,
                hasForcedValue: false,
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent);

        Assert.True(resolution.Decision.HasShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            resolution.Decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            resolution.Decision.AppliedValue);
        Assert.Equal(2, resolution.AppliedChunkQuantum);
    }

    [Theory]
    [InlineData(
        (int)QuicOversizedWriteAdmissionSignalMask.LogicalWrite,
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionCondition.None,
        (int)QuicAdaptiveRuntimeStage1Validity.Missing)]
    [InlineData(
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionSignalMask.QueueDelayEwma,
        (int)QuicOversizedWriteAdmissionCondition.None,
        (int)QuicAdaptiveRuntimeStage1Validity.Stale)]
    [InlineData(
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionCondition.ArithmeticSaturated,
        (int)QuicAdaptiveRuntimeStage1Validity.Saturated)]
    [InlineData(
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionCondition.Contradictory,
        (int)QuicAdaptiveRuntimeStage1Validity.Contradictory)]
    [InlineData(
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionSignalMask.None,
        (int)QuicOversizedWriteAdmissionCondition.OutOfDomain,
        (int)QuicAdaptiveRuntimeStage1Validity.OutOfDomain)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidShadowInputsRemainExplicitAndRecommendConservative(
        int missingMaskValue,
        int staleMaskValue,
        int conditionValue,
        int expectedValidityValue)
    {
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 1) with
            {
                MissingSignalMask =
                    (QuicOversizedWriteAdmissionSignalMask)missingMaskValue,
                StaleSignalMask =
                    (QuicOversizedWriteAdmissionSignalMask)staleMaskValue,
                Conditions =
                    (QuicOversizedWriteAdmissionCondition)conditionValue,
            };

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.Shadow,
                hasForcedValue: false,
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent);

        Assert.True(
            (resolution.Decision.Validity
                & (QuicAdaptiveRuntimeStage1Validity)expectedValidityValue) != 0);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment,
            resolution.Decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            resolution.Decision.AppliedValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DispatcherGuardOverridesForcedBoundedMultiFragment()
    {
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 1) with
            {
                ContinuationDispatcherAvailable = false,
                LegalMaximumChunkQuantum = 1,
                Conditions =
                    QuicOversizedWriteAdmissionCondition.ResourceConstrained,
            };

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment);

        Assert.Equal(1, resolution.AppliedChunkQuantum);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.BoundedMultiFragment,
            resolution.Decision.SelectedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment,
            resolution.Decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
            resolution.Decision.SelectionSource);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.Resource,
            resolution.Decision.SafetyOverrideReason);
    }

    [Theory]
    [InlineData(
        (int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
        (int)QuicAdaptiveRuntimeLifecycle.Terminal,
        (int)QuicAdaptiveRuntimeStage1SafetyOverrideReason.Terminal)]
    [InlineData(
        (int)QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment,
        (int)QuicAdaptiveRuntimeLifecycle.Disposed,
        (int)QuicAdaptiveRuntimeStage1SafetyOverrideReason.Disposal)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleGuardRemainsAuthoritativeForEveryForcedMechanism(
        int modeValue,
        int lifecycleValue,
        int expectedOverrideValue)
    {
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 1) with
            {
                LifecycleFlags =
                    (QuicAdaptiveRuntimeLifecycle)lifecycleValue,
            };

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                hasForcedValue: true,
                (QuicOversizedWriteAdmissionPolicyMode)modeValue);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
            resolution.Decision.SelectionSource);
        Assert.Equal(
            (QuicAdaptiveRuntimeStage1SafetyOverrideReason)expectedOverrideValue,
            resolution.Decision.SafetyOverrideReason);
        Assert.Equal(1, resolution.AppliedChunkQuantum);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiagnosticValidityAndRecoveryDoNotDefeatAForceableLegalMechanism()
    {
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 1) with
            {
                MissingSignalMask =
                    QuicOversizedWriteAdmissionSignalMask.QueueDelayEwma
                    | QuicOversizedWriteAdmissionSignalMask.ActorServiceTimeEwma,
                Conditions =
                    QuicOversizedWriteAdmissionCondition.RecoveryUnstable,
            };

        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment);

        Assert.Equal(2, resolution.AppliedChunkQuantum);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.BoundedMultiFragment,
            resolution.Decision.AppliedValue);
        Assert.True(
            (resolution.Decision.Validity
                & QuicAdaptiveRuntimeStage1Validity.Missing) != 0);
    }

    [Theory]
    [InlineData((int)QuicOversizedWriteOutcome.Completed, false)]
    [InlineData((int)QuicOversizedWriteOutcome.Canceled, false)]
    [InlineData((int)QuicOversizedWriteOutcome.Terminal, true)]
    [InlineData((int)QuicOversizedWriteOutcome.Disposed, true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LogicalWriteLatchCompletesOnlyAtOperationTermination(
        int outcomeValue,
        bool terminal)
    {
        QuicOversizedWriteAdmissionObservation observation =
            CreateObservation(sequence: 9);
        QuicOversizedWriteAdmissionResolution resolution =
            QuicOversizedWriteAdmissionPolicy.Resolve(
                in observation,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment);

        QuicAdaptiveRuntimeStage1AxisDecision latchedDecision =
            resolution.Decision;
        QuicAdaptiveRuntimeStage1AxisDecision completed =
            QuicOversizedWriteAdmissionPolicy.Complete(
                in latchedDecision,
                (QuicOversizedWriteOutcome)outcomeValue);

        Assert.Equal(
            terminal
                ? QuicAdaptiveRuntimeStage1LatchState.Terminal
                : QuicAdaptiveRuntimeStage1LatchState.Completed,
            completed.LatchState);
        Assert.Equal(9UL, completed.LatchSequence);
    }

    [Theory]
    [InlineData((int)QuicOversizedWriteAdmissionPolicyMode.SingleFragment, 1, 0)]
    [InlineData((int)QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment, 2, 2)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeForcesAndCompletesEachMechanism(
        int modeValue,
        int expectedQuantum,
        int expectedContinuationPosts)
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 2 * 1024 * 1024,
                    localBidirectionalSendLimit: 2 * 1024 * 1024);
        ConcurrentQueue<PostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                postedWrites.Enqueue(new PostedStreamWrite(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        RegisterDistinctStreamObservers(runtime, count: 16);
        RecordingEvidenceSink sink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode =
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            ForcedQueuedSendBurstPolicyMode =
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            ForcedOversizedWriteAdmissionPolicyMode =
                (QuicOversizedWriteAdmissionPolicyMode)modeValue,
            OversizedWriteAdmissionObservationMode =
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
            OversizedWriteAdmissionEvidenceSink = sink,
        });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        const int chunkLength = 32 * 1024;
        byte[] payload = new byte[5 * chunkLength];

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            payload,
            CancellationToken.None).AsTask();
        long nowTicks = 20;
        while (!write.IsCompleted)
        {
            if (postedWrites.TryDequeue(out PostedStreamWrite postedWrite))
            {
                _ = TransitionStreamWrite(runtime, postedWrite, nowTicks++);
                continue;
            }

            await Task.Yield();
        }

        await write.WaitAsync(TimeSpan.FromSeconds(5));
        QuicOversizedWriteAdmissionEvidence evidence =
            Assert.Single(sink.Evidence);
        Assert.Equal(expectedQuantum, evidence.AppliedChunkQuantum);
        Assert.Equal(5, evidence.CommittedFragments);
        Assert.Equal(expectedContinuationPosts, evidence.ContinuationPosts);
        Assert.Equal((ulong)payload.Length, evidence.CommittedBytes);
        Assert.Equal(QuicOversizedWriteOutcome.Completed, evidence.Outcome);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1LatchState.Completed,
            evidence.Decision.LatchState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task CancellationPublishesOneAttributableTerminalOutcome()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 2 * 1024 * 1024,
                    localBidirectionalSendLimit: 2 * 1024 * 1024);
        ConcurrentQueue<PostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                postedWrites.Enqueue(new PostedStreamWrite(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        RegisterDistinctStreamObservers(runtime, count: 16);
        RecordingEvidenceSink sink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedOversizedWriteAdmissionPolicyMode =
                QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment,
            OversizedWriteAdmissionObservationMode =
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
            OversizedWriteAdmissionEvidenceSink = sink,
        });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        using CancellationTokenSource cancellation = new();

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[5 * 32 * 1024],
            cancellation.Token).AsTask();
        Assert.True(postedWrites.TryDequeue(out PostedStreamWrite firstWrite));
        _ = TransitionStreamWrite(runtime, firstWrite, nowTicks: 30);
        await cancellation.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => write.WaitAsync(TimeSpan.FromSeconds(5)));
        QuicOversizedWriteAdmissionEvidence evidence =
            Assert.Single(sink.Evidence);
        Assert.Equal(QuicOversizedWriteOutcome.Canceled, evidence.Outcome);
        Assert.Equal(2, evidence.CommittedFragments);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForcedOversizedWriteRejectsANonLegacyAdjacentAxis()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedApplicationSendBatchPolicyMode =
                        QuicApplicationSendBatchPolicyMode.SingleEligible,
                    ForcedOversizedWriteAdmissionPolicyMode =
                        QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
                }));
        Assert.Equal(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            runtime.OversizedWriteAdmissionPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackPreservesTheRetainedSelector()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode =
                QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            ForcedQueuedSendBurstPolicyMode =
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            ForcedOversizedWriteAdmissionPolicyMode =
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
        });

        Assert.Equal(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            runtime.OversizedWriteAdmissionPolicyMode);
        Assert.Equal(
            QuicOversizedWriteAdmissionObservationMode.Disabled,
            runtime.OversizedWriteAdmissionObservationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ForceLegacyRollbackRunsTheExactRetainedMultiplexedSelector()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 2 * 1024 * 1024,
                    localBidirectionalSendLimit: 2 * 1024 * 1024);
        ConcurrentQueue<PostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                postedWrites.Enqueue(new PostedStreamWrite(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        RegisterDistinctStreamObservers(runtime, count: 16);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedOversizedWriteAdmissionPolicyMode =
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
        });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        using CancellationTokenSource cancellation = new();
        byte[] payload = new byte[5 * 32 * 1024];

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            payload,
            cancellation.Token).AsTask();
        Assert.True(postedWrites.TryDequeue(out PostedStreamWrite firstWrite));
        Assert.Equal(payload.Length, firstWrite.StreamData.Length);

        await cancellation.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(
            () => write.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesOversizedWriteModeAndSink()
    {
        RecordingEvidenceSink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ForcedOversizedWriteAdmissionPolicyMode =
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            OversizedWriteAdmissionObservationMode =
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
            OversizedWriteAdmissionEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(selectedOptions, returnedOptions);

        Assert.Equal(
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            selectedOptions.ForcedOversizedWriteAdmissionPolicyMode);
        Assert.Equal(
            QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
            selectedOptions.OversizedWriteAdmissionObservationMode);
        Assert.Same(sink, selectedOptions.OversizedWriteAdmissionEvidenceSink);
    }

    [Theory]
    [InlineData((int)QuicOversizedWriteAdmissionObservationMode.Disabled, true)]
    [InlineData((int)QuicOversizedWriteAdmissionObservationMode.Shadow, false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EvidenceSinkConfigurationMustMatchObservationMode(
        int modeValue,
        bool includeSink)
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    OversizedWriteAdmissionObservationMode =
                        (QuicOversizedWriteAdmissionObservationMode)modeValue,
                    OversizedWriteAdmissionEvidenceSink = includeSink
                        ? new RecordingEvidenceSink()
                        : null,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OversizedWritePolicyCannotBeConfiguredTwice()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureOversizedWriteAdmissionPolicyMode(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent);

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureOversizedWriteAdmissionPolicyMode(
                QuicOversizedWriteAdmissionPolicyMode.SingleFragment));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BoundedStateSequenceReplayIsDeterministic()
    {
        Random random = new(180);
        for (ulong sequence = 1; sequence <= 256; sequence++)
        {
            QuicOversizedWriteAdmissionObservation observation =
                CreateObservation(
                    sequence,
                    legacyChunkQuantum: random.Next(1, 3)) with
                {
                    MissingSignalMask = random.Next(0, 5) == 0
                        ? QuicOversizedWriteAdmissionSignalMask.QueueDelayEwma
                        : QuicOversizedWriteAdmissionSignalMask.None,
                    Conditions = random.Next(0, 7) == 0
                        ? QuicOversizedWriteAdmissionCondition.ArithmeticSaturated
                        : QuicOversizedWriteAdmissionCondition.None,
                };

            QuicOversizedWriteAdmissionResolution first =
                QuicOversizedWriteAdmissionPolicy.Resolve(
                    in observation,
                    QuicOversizedWriteAdmissionObservationMode.Shadow,
                    hasForcedValue: false,
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent);
            QuicOversizedWriteAdmissionResolution replay =
                QuicOversizedWriteAdmissionPolicy.Resolve(
                    in observation,
                    QuicOversizedWriteAdmissionObservationMode.Shadow,
                    hasForcedValue: false,
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent);

            Assert.Equal(first, replay);
        }
    }

    private static QuicOversizedWriteAdmissionObservation CreateObservation(
        ulong sequence,
        int legacyChunkQuantum = 1)
        => new(
            sequence,
            CapturedAtTicks: 10,
            QuicOversizedWriteAdmissionObservation.CurrentObservationContractVersion,
            QuicOversizedWriteAdmissionObservation.CurrentRuleVersion,
            QuicOversizedWriteAdmissionSignalMask.None,
            QuicOversizedWriteAdmissionSignalMask.None,
            QuicOversizedWriteAdmissionCondition.None,
            QuicAdaptiveRuntimeLifecycle.Active,
            LogicalWriteBytes: 5 * 32 * 1024,
            LogicalRemainingBytes: 5 * 32 * 1024,
            MaximumApplicationPayloadBytes: 1_200,
            MaximumFragmentBytes: 32 * 1024,
            DistinctObservedStreams: 16,
            QueuedApplicationWrites: 4,
            QueueDelayEwmaMicros: 10,
            ActorServiceTimeEwmaMicros: 5,
            BytesInFlight: 2_400,
            CongestionWindowBytes: 12_000,
            RetainedSendBuffers: 4,
            RetainedSendBytes: 8_192,
            ContinuationDispatcherAvailable: true,
            LegacySelectedChunkQuantum: legacyChunkQuantum,
            LegalMaximumChunkQuantum: 2);

    private static void RegisterDistinctStreamObservers(
        QuicConnectionRuntime runtime,
        int count)
    {
        for (int index = 0; index < count; index++)
        {
            _ = runtime.RegisterStreamObserver(
                (ulong)(index * 4),
                static _ => { });
        }
    }

    private static QuicConnectionTransitionResult TransitionStreamWrite(
        QuicConnectionRuntime runtime,
        PostedStreamWrite write,
        long nowTicks)
        => runtime.TransitionStreamWrite(
            write.RequestId,
            write.ActionKind,
            write.StreamId,
            write.StreamData,
            write.StreamDataSuffix,
            nowTicks);

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingEvidenceSink :
        IQuicOversizedWriteAdmissionEvidenceSink
    {
        internal List<QuicOversizedWriteAdmissionEvidence> Evidence { get; } = [];

        public bool TryPublish(in QuicOversizedWriteAdmissionEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }
}
