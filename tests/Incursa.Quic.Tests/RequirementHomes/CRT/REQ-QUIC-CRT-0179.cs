// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0179")]
public sealed class REQ_QUIC_CRT_0179
{
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(12)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LegacyCurrentPreservesTheLegalDatagramCap(int legalMaximumDatagrams)
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                legalMaximumDatagrams,
                maxPayloadBytes: 1_200);

        QuicQueuedApplicationSendBudget applied =
            QuicQueuedSendBurstPolicy.Apply(
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                legalBudget);

        Assert.Equal(legalBudget, applied);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(12)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SingleDatagramIsALowerOnlyCap(int legalMaximumDatagrams)
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                legalMaximumDatagrams,
                maxPayloadBytes: 1_200);

        QuicQueuedApplicationSendBudget applied =
            QuicQueuedSendBurstPolicy.Apply(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                legalBudget);

        Assert.True(applied.CanSendQueuedApplicationData);
        Assert.Equal(1, applied.MaxDatagrams);
        Assert.Equal(legalBudget.MaxPayloadBytes, applied.MaxPayloadBytes);
        Assert.InRange(applied.MaxDatagrams, 1, legalBudget.MaxDatagrams);
    }

    [Theory]
    [InlineData((int)QuicSendPolicyBlockedReason.NoActivePath)]
    [InlineData((int)QuicSendPolicyBlockedReason.OrdinaryPacketsUnavailable)]
    [InlineData((int)QuicSendPolicyBlockedReason.OneRttProtectionUnavailable)]
    [InlineData((int)QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending)]
    [InlineData((int)QuicSendPolicyBlockedReason.InvalidPayloadBudget)]
    [InlineData((int)QuicSendPolicyBlockedReason.CongestionLimited)]
    [InlineData((int)QuicSendPolicyBlockedReason.AntiAmplificationLimited)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SingleDatagramCannotBypassABlockedTransportBudget(int reasonValue)
    {
        QuicSendPolicyBlockedReason reason = (QuicSendPolicyBlockedReason)reasonValue;
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Blocked(
                reason,
                shouldPrioritizeRetransmission:
                    reason == QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending);

        QuicQueuedApplicationSendBudget applied =
            QuicQueuedSendBurstPolicy.Apply(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                legalBudget);
        QuicQueuedSendBurstObservation observation =
            CreateObservation(turnSequence: 1, legalBudget);
        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                in legalBudget);

        Assert.Equal(legalBudget, applied);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.NotEqual(
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.None,
            decision.SafetyOverrideReason);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedSingleDatagramProducesOneActorTurnLatch()
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                maxDatagrams: 12,
                maxPayloadBytes: 1_200);
        QuicQueuedSendBurstObservation observation =
            CreateObservation(turnSequence: 7, legalBudget);

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                in legalBudget);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
            decision.Axis);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            decision.ForcedValue);
        Assert.Equal(decision.ForcedValue, decision.SelectedValue);
        Assert.Equal(decision.ForcedValue, decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.Forced,
            decision.SelectionSource);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
            decision.DecisionBoundary);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn,
            decision.LatchLifetime);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1LatchState.Completed,
            decision.LatchState);
        Assert.Equal(7UL, decision.DecisionSequence);
        Assert.Equal(7UL, decision.LatchSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendationDoesNotChangeTheAppliedCap()
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                maxDatagrams: 12,
                maxPayloadBytes: 1_200);
        QuicQueuedSendBurstObservation observation =
            CreateObservation(turnSequence: 1, legalBudget);

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.Shadow,
                hasForcedValue: false,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                in legalBudget);

        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule,
            decision.SelectionSource);
    }

    [Theory]
    [InlineData(
        (int)QuicQueuedSendBurstSignalMask.QueuedApplicationWrites,
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstObservationCondition.None,
        (int)QuicAdaptiveRuntimeStage1Validity.Missing)]
    [InlineData(
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstSignalMask.Congestion,
        (int)QuicQueuedSendBurstObservationCondition.None,
        (int)QuicAdaptiveRuntimeStage1Validity.Stale)]
    [InlineData(
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstObservationCondition.ArithmeticSaturated,
        (int)QuicAdaptiveRuntimeStage1Validity.Saturated)]
    [InlineData(
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstObservationCondition.Contradictory,
        (int)QuicAdaptiveRuntimeStage1Validity.Contradictory)]
    [InlineData(
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstSignalMask.None,
        (int)QuicQueuedSendBurstObservationCondition.OutOfDomain,
        (int)QuicAdaptiveRuntimeStage1Validity.OutOfDomain)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void InvalidShadowInputsRecommendSingleDatagramButApplyLegacy(
        int missingMaskValue,
        int staleMaskValue,
        int conditionValue,
        int expectedValidityValue)
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                maxDatagrams: 12,
                maxPayloadBytes: 1_200);
        QuicQueuedSendBurstObservation observation =
            CreateObservation(turnSequence: 1, legalBudget) with
            {
                MissingSignalMask =
                    (QuicQueuedSendBurstSignalMask)missingMaskValue,
                StaleSignalMask =
                    (QuicQueuedSendBurstSignalMask)staleMaskValue,
                Conditions =
                    (QuicQueuedSendBurstObservationCondition)conditionValue,
            };

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.Shadow,
                hasForcedValue: false,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                in legalBudget);

        Assert.Equal(
            (QuicAdaptiveRuntimeStage1Validity)expectedValidityValue,
            decision.Validity);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1FallbackState.Applied,
            decision.FallbackState);
    }

    [Theory]
    [InlineData((int)QuicAdaptiveRuntimeLifecycle.Terminal)]
    [InlineData((int)QuicAdaptiveRuntimeLifecycle.Disposed)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TerminalLifecycleOverridesAForcedCap(int lifecycleValue)
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                maxDatagrams: 12,
                maxPayloadBytes: 1_200);
        QuicQueuedSendBurstObservation observation =
            CreateObservation(turnSequence: 1, legalBudget) with
            {
                LifecycleFlags =
                    QuicAdaptiveRuntimeLifecycle.Closing
                    | (QuicAdaptiveRuntimeLifecycle)lifecycleValue,
            };

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.ObserveOnly,
                hasForcedValue: true,
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                in legalBudget);

        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1LatchState.Terminal,
            decision.LatchState);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1FallbackState.Terminal,
            decision.FallbackState);
        Assert.Equal(
            lifecycleValue == (int)QuicAdaptiveRuntimeLifecycle.Disposed
                ? (ushort)QuicQueuedSendBurstReason.DisposalGuard
                : (ushort)QuicQueuedSendBurstReason.TerminalGuard,
            decision.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplayProducesTheSameDecision()
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                maxDatagrams: 4,
                maxPayloadBytes: 1_200);
        QuicQueuedSendBurstObservation observation =
            CreateObservation(turnSequence: 11, legalBudget);

        QuicAdaptiveRuntimeStage1AxisDecision first =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.Shadow,
                hasForcedValue: true,
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                in legalBudget);
        QuicAdaptiveRuntimeStage1AxisDecision replay =
            QuicQueuedSendBurstPolicy.Evaluate(
                in observation,
                QuicQueuedSendBurstObservationMode.Shadow,
                hasForcedValue: true,
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                in legalBudget);

        Assert.Equal(first, replay);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Fuzz")]
    public void BoundedActorTurnSequenceNeverRaisesTransportAuthority()
    {
        for (int sequence = 1; sequence <= 256; sequence++)
        {
            bool blocked = sequence % 7 == 0;
            QuicQueuedApplicationSendBudget legalBudget = blocked
                ? QuicQueuedApplicationSendBudget.Blocked(
                    sequence % 2 == 0
                        ? QuicSendPolicyBlockedReason.CongestionLimited
                        : QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending)
                : QuicQueuedApplicationSendBudget.Allowed(
                    maxDatagrams: 1 + (sequence % 12),
                    maxPayloadBytes: 1_000 + (sequence % 200));
            QuicQueuedSendBurstPolicyMode forcedMode =
                sequence % 2 == 0
                    ? QuicQueuedSendBurstPolicyMode.LegacyCurrent
                    : QuicQueuedSendBurstPolicyMode.SingleDatagram;
            QuicQueuedSendBurstObservation observation =
                CreateObservation((ulong)sequence, legalBudget) with
                {
                    MissingSignalMask = sequence % 11 == 0
                        ? QuicQueuedSendBurstSignalMask.QueueDelayEwma
                        : QuicQueuedSendBurstSignalMask.None,
                    StaleSignalMask = sequence % 13 == 0
                        ? QuicQueuedSendBurstSignalMask.Congestion
                        : QuicQueuedSendBurstSignalMask.None,
                    Conditions = sequence % 17 == 0
                        ? QuicQueuedSendBurstObservationCondition.OutOfDomain
                        : QuicQueuedSendBurstObservationCondition.None,
                };

            QuicQueuedApplicationSendBudget appliedBudget =
                QuicQueuedSendBurstPolicy.Apply(forcedMode, legalBudget);
            QuicAdaptiveRuntimeStage1AxisDecision first =
                QuicQueuedSendBurstPolicy.Evaluate(
                    in observation,
                    QuicQueuedSendBurstObservationMode.Shadow,
                    hasForcedValue: true,
                    forcedMode,
                    in legalBudget);
            QuicAdaptiveRuntimeStage1AxisDecision replay =
                QuicQueuedSendBurstPolicy.Evaluate(
                    in observation,
                    QuicQueuedSendBurstObservationMode.Shadow,
                    hasForcedValue: true,
                    forcedMode,
                    in legalBudget);

            Assert.Equal(first, replay);
            Assert.Equal((ulong)sequence, first.DecisionSequence);
            Assert.Equal((ulong)sequence, first.LatchSequence);
            if (blocked)
            {
                Assert.Equal(legalBudget, appliedBudget);
                Assert.Equal(
                    QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
                    first.SelectionSource);
                Assert.Equal(
                    QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
                    first.AppliedValue);
            }
            else
            {
                Assert.True(appliedBudget.CanSendQueuedApplicationData);
                Assert.InRange(
                    appliedBudget.MaxDatagrams,
                    1,
                    legalBudget.MaxDatagrams);
                Assert.Equal(
                    legalBudget.MaxPayloadBytes,
                    appliedBudget.MaxPayloadBytes);
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UndefinedPolicyModeIsRejected()
    {
        QuicQueuedApplicationSendBudget legalBudget =
            QuicQueuedApplicationSendBudget.Allowed(
                maxDatagrams: 4,
                maxPayloadBytes: 1_200);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicQueuedSendBurstPolicy.Apply(
                (QuicQueuedSendBurstPolicyMode)byte.MaxValue,
                legalBudget));
    }

    [Theory]
    [InlineData((int)QuicQueuedSendBurstObservationMode.Disabled, true)]
    [InlineData((int)QuicQueuedSendBurstObservationMode.Shadow, false)]
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
            QueuedSendBurstObservationMode =
                (QuicQueuedSendBurstObservationMode)modeValue,
            QueuedSendBurstEvidenceSink = includeSink
                ? new RecordingQueuedSendBurstEvidenceSink()
                : null,
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicQueuedSendBurstObservationMode.Disabled,
            runtime.QueuedSendBurstObservationMode);
        Assert.Equal(
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            runtime.QueuedSendBurstPolicyMode);
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
                QueuedSendBurstObservationMode =
                    (QuicQueuedSendBurstObservationMode)byte.MaxValue,
                QueuedSendBurstEvidenceSink =
                    new RecordingQueuedSendBurstEvidenceSink(),
            }
            : new QuicClientConnectionOptions
            {
                ForcedQueuedSendBurstPolicyMode =
                    (QuicQueuedSendBurstPolicyMode)byte.MaxValue,
            };

        Assert.Throws<ArgumentOutOfRangeException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicQueuedSendBurstObservationMode.Disabled,
            runtime.QueuedSendBurstObservationMode);
        Assert.Equal(
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            runtime.QueuedSendBurstPolicyMode);
    }

    [Theory]
    [InlineData(
        (int)QuicReceiveCreditPolicyMode.Immediate,
        (int)QuicApplicationSendTurnPolicyMode.LegacyCurrent,
        (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent)]
    [InlineData(
        (int)QuicReceiveCreditPolicyMode.LegacyCurrent,
        (int)QuicApplicationSendTurnPolicyMode.Conservative,
        (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent)]
    [InlineData(
        (int)QuicReceiveCreditPolicyMode.LegacyCurrent,
        (int)QuicApplicationSendTurnPolicyMode.LegacyCurrent,
        (int)QuicApplicationSendBatchPolicyMode.SingleEligible)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForcedBurstRejectsANonLegacyAdjacentAxis(
        int receiveCreditModeValue,
        int applicationSendTurnModeValue,
        int applicationSendBatchModeValue)
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
                (QuicApplicationSendBatchPolicyMode)applicationSendBatchModeValue,
            ForcedQueuedSendBurstPolicyMode =
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            runtime.QueuedSendBurstPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackPreservesTheExistingBurstBudget()
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
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            runtime.QueuedSendBurstPolicyMode);
        Assert.Equal(
            QuicQueuedSendBurstObservationMode.Disabled,
            runtime.QueuedSendBurstObservationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesBurstModeAndSink()
    {
        RecordingQueuedSendBurstEvidenceSink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ForcedQueuedSendBurstPolicyMode =
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
            QueuedSendBurstObservationMode =
                QuicQueuedSendBurstObservationMode.ObserveOnly,
            QueuedSendBurstEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(selectedOptions, returnedOptions);

        Assert.Equal(
            QuicQueuedSendBurstPolicyMode.SingleDatagram,
            selectedOptions.ForcedQueuedSendBurstPolicyMode);
        Assert.Equal(
            QuicQueuedSendBurstObservationMode.ObserveOnly,
            selectedOptions.QueuedSendBurstObservationMode);
        Assert.Same(sink, selectedOptions.QueuedSendBurstEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BurstPolicyCannotBeConfiguredTwice()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureQueuedSendBurstPolicyMode(
            QuicQueuedSendBurstPolicyMode.LegacyCurrent);

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureQueuedSendBurstPolicyMode(
                QuicQueuedSendBurstPolicyMode.SingleDatagram));
        Assert.Equal(
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            runtime.QueuedSendBurstPolicyMode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeLatchesBurstAndObservesLegacyAdjacentAxes(
        bool forceSingleDatagram)
    {
        QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
                connectionSendLimit: 16_384,
                localBidirectionalSendLimit: 16_384);
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
        RecordingQueuedSendBurstEvidenceSink burstSink = new();

        try
        {
            runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
            {
                AdaptiveRuntimeShadowEnabled = true,
                ApplicationSendTurnObservationMode =
                    QuicApplicationSendTurnObservationMode.ObserveOnly,
                ApplicationSendTurnEvidenceSink = turnSink,
                ApplicationSendBatchObservationMode =
                    QuicApplicationSendBatchObservationMode.ObserveOnly,
                ApplicationSendBatchEvidenceSink = batchSink,
                ForcedQueuedSendBurstPolicyMode = forceSingleDatagram
                    ? QuicQueuedSendBurstPolicyMode.SingleDatagram
                    : null,
                QueuedSendBurstObservationMode =
                    QuicQueuedSendBurstObservationMode.Shadow,
                QueuedSendBurstEvidenceSink = burstSink,
            });

            QuicStreamId[] streamIds = new QuicStreamId[4];
            for (int index = 0; index < streamIds.Length; index++)
            {
                Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                    bidirectional: true,
                    out streamIds[index],
                    out _));
            }

            Task directWrite = runtime.WriteStreamAsync(
                streamIds[0].Value,
                new byte[800],
                CancellationToken.None).AsTask();
            PostedStreamWrite directPostedWrite = Assert.Single(postedWrites);
            _ = postedWrites.Dequeue();
            _ = runtime.TransitionStreamWrite(
                directPostedWrite.RequestId,
                directPostedWrite.ActionKind,
                directPostedWrite.StreamId,
                directPostedWrite.StreamData,
                directPostedWrite.StreamDataSuffix,
                nowTicks: 10);
            await directWrite.WaitAsync(TimeSpan.FromSeconds(5));

            ulong largestAcknowledged = runtime.SendRuntime.SentPackets.Keys
                .Where(static key =>
                    key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
                .Max(static key => key.PacketNumber);

            for (int index = 0; index < 48; index++)
            {
                Task write = runtime.WriteStreamAsync(
                    streamIds[index % streamIds.Length].Value,
                    new byte[31],
                    CancellationToken.None).AsTask();
                PostedStreamWrite postedWrite = Assert.Single(postedWrites);
                _ = postedWrites.Dequeue();
                _ = runtime.TransitionStreamWrite(
                    postedWrite.RequestId,
                    postedWrite.ActionKind,
                    postedWrite.StreamId,
                    postedWrite.StreamData,
                    postedWrite.StreamDataSuffix,
                    nowTicks: 20);
                await write.WaitAsync(TimeSpan.FromSeconds(5));
            }

            Assert.Empty(burstSink.Evidence);
            QuicConnectionTransitionResult result =
                QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
                    runtime,
                    observedAtTicks: 100,
                    packetNumber: 1,
                    largestAcknowledged);

            Assert.True(result.StateChanged);
            QuicQueuedSendBurstEvidence evidence =
                Assert.Single(burstSink.Evidence);
            Assert.Equal(
                QuicQueuedSendBurstObservationMode.Shadow,
                evidence.Mode);
            Assert.Equal(48U, evidence.Observation.QueuedApplicationWrites);
            Assert.Equal(1_488UL, evidence.Observation.OutboundBacklogBytes);
            Assert.Equal(4, evidence.Observation.DistinctQueuedStreams);
            Assert.Equal(48U, evidence.Observation.RetainedSendBuffers);
            Assert.True(evidence.Observation.RetainedSendBytes >= 1_488);
            Assert.Equal(
                forceSingleDatagram,
                evidence.Decision.HasForcedValue);
            Assert.True(evidence.Decision.HasShadowRecommendation);
            Assert.Equal(
                QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
                evidence.Decision.ShadowRecommendation);
            QuicAdaptiveRuntimeStage1PolicyValue expectedAppliedValue =
                forceSingleDatagram
                    ? QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram
                    : QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            Assert.Equal(expectedAppliedValue, evidence.Decision.AppliedValue);
            Assert.Equal(
                forceSingleDatagram ? 1 : evidence.LegalMaximumDatagrams,
                evidence.AppliedMaximumDatagrams);
            Assert.Equal(48, evidence.QueuedWritesBefore);
            Assert.Equal(
                forceSingleDatagram
                    ? QuicApplicationSendRecoveryFlushOutcome.BurstLimitReached
                    : QuicApplicationSendRecoveryFlushOutcome.QueueDrained,
                evidence.Outcome);
            if (forceSingleDatagram)
            {
                Assert.Equal(1, evidence.EmittedDatagrams);
                Assert.Equal(
                    QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
                    evidence.Decision.ForcedValue);
                Assert.InRange(evidence.QueuedWritesAfter, 1, 47);
                Assert.True(evidence.FollowOnWakeRequired);
                Assert.True(evidence.FollowOnWakeDueTicks.HasValue);
                Assert.True(evidence.FollowOnWakeGeneration > 0);
            }
            else
            {
                Assert.InRange(
                    evidence.EmittedDatagrams,
                    2,
                    evidence.LegalMaximumDatagrams);
                Assert.Equal(0, evidence.QueuedWritesAfter);
                Assert.False(evidence.FollowOnWakeRequired);
            }

            Assert.NotEmpty(turnSink.Evidence);
            Assert.NotEmpty(batchSink.Evidence);
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
                forceSingleDatagram
                    ? QuicQueuedSendBurstPolicyMode.SingleDatagram
                    : QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                runtime.QueuedSendBurstPolicyMode);
        }
        finally
        {
            await runtime.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EvidenceSinkFailureCannotEscapeTheActorTurn()
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
            QueuedSendBurstObservationMode =
                QuicQueuedSendBurstObservationMode.Shadow,
            QueuedSendBurstEvidenceSink =
                new ThrowingQueuedSendBurstEvidenceSink(),
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

        QuicConnectionTransitionResult result =
            ExpireApplicationSendDelay(runtime);

        Assert.True(result.StateChanged);
        await write.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static QuicConnectionTransitionResult ExpireApplicationSendDelay(
        QuicConnectionRuntime runtime)
    {
        long dueTicks = Assert.IsType<long>(
            runtime.TimerState.GetDueTicks(
                QuicConnectionTimerKind.ApplicationSendDelay));
        ulong timerGeneration =
            runtime.TimerState.GetGeneration(
                QuicConnectionTimerKind.ApplicationSendDelay);
        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks,
                QuicConnectionTimerKind.ApplicationSendDelay,
                timerGeneration),
            dueTicks);
    }

    private static QuicQueuedSendBurstObservation CreateObservation(
        ulong turnSequence,
        QuicQueuedApplicationSendBudget legalBudget)
        => new(
            turnSequence,
            CapturedAtTicks: 10,
            QuicQueuedSendBurstObservation.CurrentObservationContractVersion,
            QuicQueuedSendBurstObservation.CurrentRuleVersion,
            QuicQueuedSendBurstSignalMask.None,
            QuicQueuedSendBurstSignalMask.None,
            QuicQueuedSendBurstObservationCondition.None,
            QuicAdaptiveRuntimeLifecycle.Active,
            QueuedApplicationWrites: 12,
            OutboundBacklogBytes: 12_000,
            DistinctQueuedStreams: 4,
            OldestQueuedSendAgeMicros: 100,
            QueueDelayEwmaMicros: 10,
            ActorServiceTimeEwmaMicros: 5,
            BurstLimitHits: 1,
            BytesInFlight: 2_400,
            CongestionWindowBytes: 12_000,
            RetainedSendBuffers: 12,
            RetainedSendBytes: 24_000,
            HandshakeConfirmed: true,
            LegalMaximumDatagrams: legalBudget.MaxDatagrams,
            ConfiguredMaximumDatagrams:
                QuicSendPolicy.EstablishedQueuedApplicationSendBurstDatagrams);

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingQueuedSendBurstEvidenceSink :
        IQuicQueuedSendBurstEvidenceSink
    {
        internal List<QuicQueuedSendBurstEvidence> Evidence { get; } = [];

        public bool TryPublish(in QuicQueuedSendBurstEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }

    private sealed class ThrowingQueuedSendBurstEvidenceSink :
        IQuicQueuedSendBurstEvidenceSink
    {
        public bool TryPublish(in QuicQueuedSendBurstEvidence evidence)
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
}
