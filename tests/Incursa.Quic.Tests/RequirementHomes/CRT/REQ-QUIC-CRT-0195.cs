// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0195")]
public sealed class REQ_QUIC_CRT_0195
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedSegmentedBatchBuildsWhenCapabilityIsAvailable()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .SegmentedBatch);

        Assert.True(policy.ShouldBuildBatch(64));

        QuicApplicationDatagramBatchTransportDecision decision =
            policy.EvaluateForTest(
                queuedStreamCount: 64,
                QuicApplicationDatagramBatchTransportValidity.None,
                lifecycleGuard: false);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportPolicyValue.SegmentedBatch,
            decision.SelectedValue);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportPolicyValue.SegmentedBatch,
            decision.AppliedValue);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportSelectionSource.Forced,
            decision.SelectionSource);
        Assert.True(decision.BuildSegmentedBatch);
        Assert.False(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedOrdinaryDatagramsNeverBuildsABatch()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams);

        Assert.False(policy.ShouldBuildBatch(0));
        Assert.False(policy.ShouldBuildBatch(64));
        Assert.False(policy.IsPromoted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Regression")]
    public void ForceLegacyRollbackMatchesTheUnforcedOneWayRule()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy unforced = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            forcedValue: null,
            pressureStreamCount: 4);
        QuicAdaptiveApplicationDatagramBatchPolicy forcedLegacy =
            CreatePolicy(
                QuicApplicationDatagramBatchTransportObservationMode.Disabled,
                QuicApplicationDatagramBatchTransportPolicyValue
                    .LegacyCurrent,
                pressureStreamCount: 4);

        int[] sequence = [1, 4, 1, 4, 4, 1];
        Assert.Equal(
            sequence.Select(unforced.ShouldBuildBatch),
            sequence.Select(forcedLegacy.ShouldBuildBatch));
        Assert.True(unforced.IsPromoted);
        Assert.True(forcedLegacy.IsPromoted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendsOrdinaryWithoutChangingLegacyApplication()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Shadow,
            forcedValue: null,
            pressureStreamCount: 4);
        RecordingSink sink = new();
        policy.ConfigureEvidenceSink(sink);

        Assert.True(policy.ShouldBuildBatch(1));

        QuicApplicationDatagramBatchTransportDecision decision =
            Assert.Single(sink.Decisions);
        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams,
            decision.SelectedValue);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportPolicyValue.SegmentedBatch,
            decision.AppliedValue);
        Assert.True(decision.BuildSegmentedBatch);
    }

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)2)]
    [InlineData((byte)3)]
    [InlineData((byte)4)]
    [InlineData((byte)5)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapabilityFailureOverridesForcedSegmentedBatch(
        byte statusValue)
    {
        QuicApplicationDatagramBatchTransportCapabilityStatus status =
            (QuicApplicationDatagramBatchTransportCapabilityStatus)
                statusValue;
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .SegmentedBatch);
        ObserveCapability(policy, status);

        Assert.False(policy.ShouldBuildBatch(1));
        QuicApplicationDatagramBatchTransportDecision decision =
            policy.EvaluateForTest(
                queuedStreamCount: 1,
                QuicApplicationDatagramBatchTransportValidity.None,
                lifecycleGuard: false);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams,
            decision.AppliedValue);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportSafetyOverride
                .CapabilityUnavailable,
            decision.SafetyOverride);
        Assert.True(decision.FallbackApplied);
    }

    [Theory]
    [InlineData((byte)1, (byte)10)]
    [InlineData((byte)2, (byte)11)]
    [InlineData((byte)4, (byte)12)]
    [InlineData((byte)8, (byte)13)]
    [InlineData((byte)16, (byte)14)]
    [InlineData((byte)32, (byte)15)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidObservationsFallBackToOrdinaryDatagrams(
        byte validityValue,
        byte expectedReasonValue)
    {
        QuicApplicationDatagramBatchTransportValidity validity =
            (QuicApplicationDatagramBatchTransportValidity)validityValue;
        QuicApplicationDatagramBatchTransportReasonCode expectedReason =
            (QuicApplicationDatagramBatchTransportReasonCode)
                expectedReasonValue;
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .SegmentedBatch);

        QuicApplicationDatagramBatchTransportDecision decision =
            policy.EvaluateForTest(
                queuedStreamCount: 1,
                validity,
                lifecycleGuard: false);

        Assert.Equal(expectedReason, decision.ReasonCode);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportSafetyOverride
                .InvalidObservation,
            decision.SafetyOverride);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams,
            decision.AppliedValue);
        Assert.False(decision.BuildSegmentedBatch);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleGuardOverridesForcedSegmentedBatch()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .SegmentedBatch);

        QuicApplicationDatagramBatchTransportDecision decision =
            policy.EvaluateForTest(
                queuedStreamCount: 1,
                QuicApplicationDatagramBatchTransportValidity.None,
                lifecycleGuard: true);

        Assert.Equal(
            QuicApplicationDatagramBatchTransportSafetyOverride.Lifecycle,
            decision.SafetyOverride);
        Assert.Equal(
            QuicApplicationDatagramBatchTransportReasonCode.LifecycleGuard,
            decision.ReasonCode);
        Assert.False(decision.BuildSegmentedBatch);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Regression")]
    public void ServerLegacyModePreservesUnconditionalCapableBatching()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            forcedValue: null,
            pressureStreamCount: 4,
            requiredConsecutivePressureTurns: 2,
            legacyPressurePromotionEnabled: false);
        ObserveCapability(
            policy,
            QuicApplicationDatagramBatchTransportCapabilityStatus
                .WindowsUdpSendMessageSize);

        for (int index = 0; index < 16; index++)
        {
            Assert.True(policy.ShouldBuildBatch(64));
        }

        Assert.False(policy.IsPromoted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void LaterCapabilityEpochCanRestoreAForcedBatchSeam()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .SegmentedBatch);
        ObserveCapability(
            policy,
            QuicApplicationDatagramBatchTransportCapabilityStatus
                .ProbeFailed,
            capabilityEpoch: 1);
        Assert.False(policy.ShouldBuildBatch(1));

        ObserveCapability(
            policy,
            QuicApplicationDatagramBatchTransportCapabilityStatus
                .WindowsUdpSendMessageSize,
            capabilityEpoch: 2);
        Assert.True(policy.ShouldBuildBatch(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingEvidenceSinkCannotChangeSelection()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.ObserveOnly,
            forcedValue: null);
        policy.ConfigureEvidenceSink(new ThrowingSink());

        Assert.True(policy.ShouldBuildBatch(1));
        policy.RecordOutcome(
            new QuicApplicationDatagramBatchTransportOutcome(
                QuicApplicationDatagramBatchTransportOutcomeKind
                    .SegmentedBatch,
                CapabilityEpoch: 1,
                SocketCallCount: 1,
                DatagramCount: 2,
                SegmentCount: 2,
                SubmittedBytes: 2944,
                AcceptedBytes: 2944,
                Succeeded: true,
                PartialSend: false,
                LifecycleGuard: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EvidenceKeepsSnapshotCapabilityDecisionAndOutcomeDistinct()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.ObserveOnly,
            QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams);
        RecordingSink sink = new();
        policy.ConfigureEvidenceSink(sink);

        Assert.False(policy.ShouldBuildBatch(1));
        QuicApplicationDatagramBatchTransportOutcome outcome = new(
            QuicApplicationDatagramBatchTransportOutcomeKind
                .OrdinaryDatagram,
            CapabilityEpoch: 1,
            SocketCallCount: 1,
            DatagramCount: 1,
            SegmentCount: 0,
            SubmittedBytes: 1200,
            AcceptedBytes: 1200,
            Succeeded: true,
            PartialSend: false,
            LifecycleGuard: false);
        policy.RecordOutcome(in outcome);

        Assert.Single(sink.Snapshots);
        Assert.Single(sink.Capabilities);
        Assert.Single(sink.Decisions);
        Assert.Equal(outcome, Assert.Single(sink.Outcomes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidClosedValuesAndCapabilityEpochAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicApplicationDatagramBatchTransportPolicy.ValidateValue(
                (QuicApplicationDatagramBatchTransportPolicyValue)
                    byte.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicApplicationDatagramBatchTransportPolicy
                .ValidateObservationMode(
                    (QuicApplicationDatagramBatchTransportObservationMode)
                        byte.MaxValue));
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new();
        Assert.Throws<ArgumentOutOfRangeException>(
            () => policy.ObserveCapability(
                new QuicApplicationDatagramBatchTransportCapability(
                    CapabilityEpoch: 0,
                    QuicApplicationDatagramBatchTransportCapabilityStatus
                        .UnsupportedPlatform)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRequiresAConnectionLocalTransportPolicy()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ApplicationDatagramBatchTransportObservationMode =
                        QuicApplicationDatagramBatchTransportObservationMode
                            .ObserveOnly,
                    ApplicationDatagramBatchTransportEvidenceSink =
                        new RecordingSink(),
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsOptionsThatDoNotMatchTheLocalPolicy()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Shadow,
            forcedValue: null);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            applicationDatagramBatchPolicy: policy);

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ApplicationDatagramBatchTransportObservationMode =
                        QuicApplicationDatagramBatchTransportObservationMode
                            .ObserveOnly,
                    ApplicationDatagramBatchTransportEvidenceSink =
                        new RecordingSink(),
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsASecondBehaviorDistinctTreatment()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            applicationDatagramBatchPolicy: policy);

        InvalidOperationException exception =
            Assert.Throws<InvalidOperationException>(
                () => runtime.ConfigureAdaptiveRuntimePolicy(
                    new QuicClientConnectionOptions
                    {
                        ForcedApplicationDatagramBatchTransportPolicyValue =
                            QuicApplicationDatagramBatchTransportPolicyValue
                                .OrdinaryDatagrams,
                        ForcedQueuedSendBurstPolicyMode =
                            QuicQueuedSendBurstPolicyMode.SingleDatagram,
                    }));
        Assert.Contains(
            "Only one behavior-distinct adaptive runtime policy axis",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimePublishesOnlyAfterMatchingConfigurationIsAccepted()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = CreatePolicy(
            QuicApplicationDatagramBatchTransportObservationMode.ObserveOnly,
            forcedValue: null);
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            applicationDatagramBatchPolicy: policy);

        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ApplicationDatagramBatchTransportObservationMode =
                    QuicApplicationDatagramBatchTransportObservationMode
                        .ObserveOnly,
                ApplicationDatagramBatchTransportEvidenceSink = sink,
            });

        Assert.Single(sink.Snapshots);
        Assert.Single(sink.Capabilities);
        Assert.Empty(sink.Decisions);
        Assert.Empty(sink.Outcomes);
        Assert.Same(policy, runtime.ApplicationDatagramBatchPolicy);
    }

    private static QuicAdaptiveApplicationDatagramBatchPolicy CreatePolicy(
        QuicApplicationDatagramBatchTransportObservationMode mode,
        QuicApplicationDatagramBatchTransportPolicyValue? forcedValue,
        int pressureStreamCount = 4)
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            mode,
            forcedValue,
            pressureStreamCount,
            requiredConsecutivePressureTurns: 2);
        ObserveCapability(
            policy,
            QuicApplicationDatagramBatchTransportCapabilityStatus
                .WindowsUdpSendMessageSize);
        return policy;
    }

    private static void ObserveCapability(
        QuicAdaptiveApplicationDatagramBatchPolicy policy,
        QuicApplicationDatagramBatchTransportCapabilityStatus status,
        ulong capabilityEpoch = 1)
    {
        QuicApplicationDatagramBatchTransportCapability capability = new(
            capabilityEpoch,
            status);
        policy.ObserveCapability(in capability);
    }

    private sealed class RecordingSink :
        IQuicApplicationDatagramBatchTransportEvidenceSink
    {
        internal List<
            QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot>
            Snapshots { get; } = [];

        internal List<QuicApplicationDatagramBatchTransportCapability>
            Capabilities { get; } = [];

        internal List<QuicApplicationDatagramBatchTransportDecision>
            Decisions { get; } = [];

        internal List<QuicApplicationDatagramBatchTransportOutcome>
            Outcomes { get; } = [];

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
                snapshot)
        {
            Snapshots.Add(snapshot);
            return true;
        }

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportCapability capability)
        {
            Capabilities.Add(capability);
            return true;
        }

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportDecision decision)
        {
            Decisions.Add(decision);
            return true;
        }

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportOutcome outcome)
        {
            Outcomes.Add(outcome);
            return true;
        }
    }

    private sealed class ThrowingSink :
        IQuicApplicationDatagramBatchTransportEvidenceSink
    {
        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
                snapshot) => throw new InvalidOperationException();

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportCapability capability) =>
            throw new InvalidOperationException();

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportDecision decision) =>
            throw new InvalidOperationException();

        public bool TryPublish(
            in QuicApplicationDatagramBatchTransportOutcome outcome) =>
            throw new InvalidOperationException();
    }
}
