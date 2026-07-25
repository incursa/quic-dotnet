// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0196")]
public sealed class REQ_QUIC_CRT_0196
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosedContractIsVersionedAndConnectionLifetimeLatched()
    {
        QuicCongestionPacingProfileDecision decision =
            QuicCongestionPacingProfilePolicy.Evaluate(
                QuicCongestionPacingProfileObservationMode.ObserveOnly,
                forcedValue: null,
                connectionStartSequence: 7,
                captureTicks: 11);

        Assert.Equal("congestion_pacing_profile", decision.AxisId);
        Assert.Equal(
            "quic-congestion-pacing-profile-observation-v1",
            decision.ObservationContractVersion);
        Assert.Equal(
            "quic-congestion-pacing-profile-policy-snapshot-v1",
            decision.SnapshotVersion);
        Assert.Equal(
            "quic-congestion-pacing-profile-research-only-rule-v1",
            decision.RuleVersion);
        Assert.Equal(
            QuicCongestionPacingProfileDecisionBoundary
                .ConnectionConstruction,
            decision.DecisionBoundary);
        Assert.Equal(
            QuicCongestionPacingProfileLatchLifetime.ConnectionLifetime,
            decision.LatchLifetime);
        Assert.Equal(7UL, decision.ConnectionStartSequence);
        Assert.Equal(11, decision.CaptureTicks);
        Assert.Equal(12_000UL, decision.InitialCongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, decision.InitialSlowStartThresholdBytes);
        Assert.Equal(0UL, decision.InitialBytesInFlight);
    }

    [Theory]
    [InlineData((byte)0, (byte)0)]
    [InlineData((byte)1, (byte)1)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EveryImplementedValueIsIndependentlyForceable(
        byte forcedValueValue,
        byte expectedAlgorithmValue)
    {
        QuicCongestionPacingProfilePolicyValue forcedValue =
            (QuicCongestionPacingProfilePolicyValue)forcedValueValue;
        QuicCongestionControlAlgorithm expectedAlgorithm =
            (QuicCongestionControlAlgorithm)expectedAlgorithmValue;
        QuicCongestionPacingProfileDecision decision =
            QuicCongestionPacingProfilePolicy.Evaluate(
                QuicCongestionPacingProfileObservationMode.Disabled,
                forcedValue,
                connectionStartSequence: 1,
                captureTicks: 2);

        Assert.True(decision.HasForcedValue);
        Assert.Equal(forcedValue, decision.ForcedValue);
        Assert.Equal(forcedValue, decision.SelectedValue);
        Assert.Equal(forcedValue, decision.AppliedValue);
        Assert.Equal(
            QuicCongestionPacingProfileSelectionSource.Forced,
            decision.SelectionSource);
        Assert.Equal(expectedAlgorithm, decision.AppliedAlgorithm);
        Assert.False(decision.FallbackApplied);
    }

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    [InlineData((byte)2)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnforcedModesAlwaysApplyLegacy(
        byte modeValue)
    {
        QuicCongestionPacingProfileObservationMode mode =
            (QuicCongestionPacingProfileObservationMode)modeValue;
        QuicCongestionPacingProfileDecision decision =
            QuicCongestionPacingProfilePolicy.Evaluate(
                mode,
                forcedValue: null,
                connectionStartSequence: 1,
                captureTicks: 2);

        Assert.False(decision.HasForcedValue);
        Assert.Equal(
            QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            decision.SelectedValue);
        Assert.Equal(
            QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            decision.AppliedAlgorithm);
        Assert.Equal(
            mode == QuicCongestionPacingProfileObservationMode.Shadow,
            decision.HasShadowRecommendation);
        if (mode == QuicCongestionPacingProfileObservationMode.Shadow)
        {
            Assert.Equal(
                QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
                decision.ShadowRecommendation);
            Assert.Equal(
                QuicCongestionPacingProfileReasonCode.ShadowResearchOnly,
                decision.ReasonCode);
        }
    }

    [Theory]
    [InlineData((byte)1, (byte)5)]
    [InlineData((byte)2, (byte)6)]
    [InlineData((byte)4, (byte)7)]
    [InlineData((byte)8, (byte)8)]
    [InlineData((byte)16, (byte)9)]
    [InlineData((byte)32, (byte)10)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidObservationOverridesForcedCubic(
        byte validityValue,
        byte expectedReasonValue)
    {
        QuicCongestionPacingProfileDecision decision =
            QuicCongestionPacingProfilePolicy.Evaluate(
                QuicCongestionPacingProfileObservationMode.Disabled,
                QuicCongestionPacingProfilePolicyValue.Cubic,
                connectionStartSequence: 1,
                captureTicks: 2,
                validity:
                    (QuicCongestionPacingProfileValidity)validityValue);

        Assert.Equal(
            (QuicCongestionPacingProfileReasonCode)expectedReasonValue,
            decision.ReasonCode);
        Assert.Equal(
            QuicCongestionPacingProfileSafetyOverride.InvalidObservation,
            decision.SafetyOverride);
        Assert.Equal(
            QuicCongestionPacingProfilePolicyValue.Cubic,
            decision.SelectedValue);
        Assert.Equal(
            QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            decision.AppliedAlgorithm);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingAndOutOfDomainInputsAreNormalizedAndGuarded()
    {
        QuicCongestionPacingProfileDecision decision =
            QuicCongestionPacingProfilePolicy.Evaluate(
                QuicCongestionPacingProfileObservationMode.Disabled,
                QuicCongestionPacingProfilePolicyValue.Cubic,
                connectionStartSequence: 0,
                captureTicks: 2,
                maximumDatagramSizeBytes: 1);

        Assert.Equal(
            QuicCongestionPacingProfileReasonCode.MissingInput,
            decision.ReasonCode);
        Assert.True(
            decision.Validity.HasFlag(
                QuicCongestionPacingProfileValidity.MissingRequiredInput));
        Assert.True(
            decision.Validity.HasFlag(
                QuicCongestionPacingProfileValidity.OutOfDomain));
        Assert.Equal(1200UL, decision.MaximumDatagramSizeBytes);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            decision.AppliedAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleGuardOverridesForcedCubic()
    {
        QuicCongestionPacingProfileDecision decision =
            QuicCongestionPacingProfilePolicy.Evaluate(
                QuicCongestionPacingProfileObservationMode.Disabled,
                QuicCongestionPacingProfilePolicyValue.Cubic,
                connectionStartSequence: 1,
                captureTicks: 2,
                lifecycleGuard: true);

        Assert.Equal(
            QuicCongestionPacingProfileSafetyOverride.Lifecycle,
            decision.SafetyOverride);
        Assert.Equal(
            QuicCongestionPacingProfileReasonCode.LifecycleGuard,
            decision.ReasonCode);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            decision.AppliedAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidClosedValuesAndModesAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicCongestionPacingProfilePolicy.ValidateValue(
                (QuicCongestionPacingProfilePolicyValue)byte.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicCongestionPacingProfilePolicy
                .ValidateObservationMode(
                    (QuicCongestionPacingProfileObservationMode)
                        byte.MaxValue));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Regression")]
    public void ForceLegacyRollbackMatchesTheDefaultRuntime()
    {
        using QuicConnectionRuntime baseline = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime forcedLegacy = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionPacingProfileObservationMode:
                QuicCongestionPacingProfileObservationMode.Disabled,
            forcedCongestionPacingProfilePolicyValue:
                QuicCongestionPacingProfilePolicyValue.LegacyCurrent);

        Assert.Equal(
            baseline.CongestionPacingProfileDecision.AppliedAlgorithm,
            forcedLegacy.CongestionPacingProfileDecision.AppliedAlgorithm);
        Assert.Equal(
            baseline.SendRuntime.FlowController.CongestionControlState
                .CongestionWindowBytes,
            forcedLegacy.SendRuntime.FlowController.CongestionControlState
                .CongestionWindowBytes);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            forcedLegacy.SendRuntime.FlowController.CongestionControlState
                .CongestionControlAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Regression")]
    public void RetainedDirectCubicConstructionAcceptsDefaultConfiguration()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionControlAlgorithm:
                QuicCongestionControlAlgorithm.Cubic);

        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions());

        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            runtime.SendRuntime.FlowController.CongestionControlState
                .CongestionControlAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Regression")]
    public void ForcedCubicSurvivesPathStateResetWithoutReselection()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionPacingProfileObservationMode:
                QuicCongestionPacingProfileObservationMode.Disabled,
            forcedCongestionPacingProfilePolicyValue:
                QuicCongestionPacingProfilePolicyValue.Cubic);
        QuicCongestionPacingProfileDecision before =
            runtime.CongestionPacingProfileDecision;

        runtime.SendRuntime.FlowController.CongestionControlState
            .RegisterPacketSent(1_200);
        runtime.SendRuntime.ResetPathRecoveryState();

        Assert.Equal(before, runtime.CongestionPacingProfileDecision);
        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            runtime.SendRuntime.FlowController.CongestionControlState
                .CongestionControlAlgorithm);
        Assert.Equal(
            0UL,
            runtime.SendRuntime.FlowController.CongestionControlState
                .BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimePublishesOnlyTheImmutableConstructionDecision()
    {
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionPacingProfileObservationMode:
                QuicCongestionPacingProfileObservationMode.Shadow);

        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                CongestionPacingProfileObservationMode =
                    QuicCongestionPacingProfileObservationMode.Shadow,
                CongestionPacingProfileEvidenceSink = sink,
            });

        Assert.Equal(
            runtime.CongestionPacingProfileDecision,
            Assert.Single(sink.Decisions));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsMismatchedConfigurationAndMissingSink()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionPacingProfileObservationMode:
                QuicCongestionPacingProfileObservationMode.Shadow);

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    CongestionPacingProfileObservationMode =
                        QuicCongestionPacingProfileObservationMode
                            .ObserveOnly,
                    CongestionPacingProfileEvidenceSink =
                        new RecordingSink(),
                }));
        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    CongestionPacingProfileObservationMode =
                        QuicCongestionPacingProfileObservationMode.Shadow,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsASecondBehaviorDistinctTreatment()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            forcedCongestionPacingProfilePolicyValue:
                QuicCongestionPacingProfilePolicyValue.Cubic);

        InvalidOperationException exception =
            Assert.Throws<InvalidOperationException>(
                () => runtime.ConfigureAdaptiveRuntimePolicy(
                    new QuicClientConnectionOptions
                    {
                        ForcedCongestionPacingProfilePolicyValue =
                            QuicCongestionPacingProfilePolicyValue.Cubic,
                        ForcedQueuedSendBurstPolicyMode =
                            QuicQueuedSendBurstPolicyMode.SingleDatagram,
                    }));
        Assert.Contains(
            "Only one behavior-distinct adaptive runtime policy axis",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingEvidenceSinkCannotChangeTheAppliedController()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionPacingProfileObservationMode:
                QuicCongestionPacingProfileObservationMode.ObserveOnly);

        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                CongestionPacingProfileObservationMode =
                    QuicCongestionPacingProfileObservationMode.ObserveOnly,
                CongestionPacingProfileEvidenceSink = new ThrowingSink(),
            });

        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            runtime.SendRuntime.FlowController.CongestionControlState
                .CongestionControlAlgorithm);
    }

    private sealed class RecordingSink :
        IQuicCongestionPacingProfileEvidenceSink
    {
        internal List<QuicCongestionPacingProfileDecision> Decisions
        {
            get;
        } = [];

        public bool TryPublish(
            in QuicCongestionPacingProfileDecision decision)
        {
            Decisions.Add(decision);
            return true;
        }
    }

    private sealed class ThrowingSink :
        IQuicCongestionPacingProfileEvidenceSink
    {
        public bool TryPublish(
            in QuicCongestionPacingProfileDecision decision)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}
