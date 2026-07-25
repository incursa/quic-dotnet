// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicCongestionPacingProfileObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

internal enum QuicCongestionPacingProfilePolicyValue : byte
{
    LegacyCurrent = 0,
    Cubic = 1,
}

internal enum QuicCongestionPacingProfileSelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowResearch = 2,
    SafetyOverride = 3,
}

internal enum QuicCongestionPacingProfileReasonCode : byte
{
    LegacyCurrent = 0,
    ObserveOnly = 1,
    ShadowResearchOnly = 2,
    ForcedLegacyCurrent = 3,
    ForcedCubic = 4,
    MissingInput = 5,
    StaleInput = 6,
    ArithmeticSaturated = 7,
    Contradictory = 8,
    InvalidInput = 9,
    OutOfDomain = 10,
    LifecycleGuard = 11,
}

internal enum QuicCongestionPacingProfileSafetyOverride : byte
{
    None = 0,
    InvalidObservation = 1,
    Lifecycle = 2,
}

internal enum QuicCongestionPacingProfileDecisionBoundary : byte
{
    ConnectionConstruction = 0,
}

internal enum QuicCongestionPacingProfileLatchLifetime : byte
{
    ConnectionLifetime = 0,
}

[Flags]
internal enum QuicCongestionPacingProfileValidity : byte
{
    None = 0,
    MissingRequiredInput = 1 << 0,
    StaleRequiredInput = 1 << 1,
    ArithmeticSaturated = 1 << 2,
    Contradictory = 1 << 3,
    InvalidInput = 1 << 4,
    OutOfDomain = 1 << 5,
}

internal readonly record struct
    QuicCongestionPacingProfileConfiguredPolicySnapshot(
        QuicCongestionPacingProfileObservationMode Mode,
        bool HasForcedValue,
        QuicCongestionPacingProfilePolicyValue ForcedValue,
        bool HasShadowRecommendation,
        QuicCongestionPacingProfilePolicyValue ShadowRecommendation,
        QuicCongestionPacingProfilePolicyValue SelectedValue,
        QuicCongestionPacingProfilePolicyValue AppliedValue,
        QuicCongestionPacingProfileSelectionSource SelectionSource,
        QuicCongestionPacingProfileReasonCode ReasonCode,
        QuicCongestionPacingProfileSafetyOverride SafetyOverride,
        QuicCongestionPacingProfileDecisionBoundary DecisionBoundary,
        QuicCongestionPacingProfileLatchLifetime LatchLifetime,
        bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-congestion-pacing-profile-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct QuicCongestionPacingProfileDecision(
    QuicCongestionPacingProfileObservationMode Mode,
    bool HasForcedValue,
    QuicCongestionPacingProfilePolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicCongestionPacingProfilePolicyValue ShadowRecommendation,
    QuicCongestionPacingProfilePolicyValue SelectedValue,
    QuicCongestionPacingProfilePolicyValue AppliedValue,
    QuicCongestionPacingProfileSelectionSource SelectionSource,
    QuicCongestionPacingProfileReasonCode ReasonCode,
    QuicCongestionPacingProfileSafetyOverride SafetyOverride,
    QuicCongestionPacingProfileDecisionBoundary DecisionBoundary,
    QuicCongestionPacingProfileLatchLifetime LatchLifetime,
    bool FallbackApplied,
    ulong ConnectionStartSequence,
    long CaptureTicks,
    ulong MaximumDatagramSizeBytes,
    ulong InitialCongestionWindowBytes,
    ulong InitialSlowStartThresholdBytes,
    ulong InitialBytesInFlight,
    QuicCongestionControlAlgorithm AppliedAlgorithm,
    QuicCongestionPacingProfileValidity Validity)
{
    internal const string CurrentObservationContractVersion =
        "quic-congestion-pacing-profile-observation-v1";

    public string AxisId => QuicCongestionPacingProfilePolicy.AxisId;

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string SnapshotVersion =>
        QuicCongestionPacingProfileConfiguredPolicySnapshot
            .CurrentSnapshotVersion;

    public string RuleVersion =>
        QuicCongestionPacingProfilePolicy.CurrentRuleVersion;

    public string ReasonVersion =>
        QuicCongestionPacingProfilePolicy.CurrentReasonVersion;

    public string ProvenanceVersion =>
        QuicCongestionPacingProfilePolicy.CurrentProvenanceVersion;
}

internal interface IQuicCongestionPacingProfileEvidenceSink
{
    bool TryPublish(in QuicCongestionPacingProfileDecision decision);
}

internal static class QuicCongestionPacingProfilePolicy
{
    internal const string AxisId = "congestion_pacing_profile";
    internal const string CurrentRuleVersion =
        "quic-congestion-pacing-profile-research-only-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-congestion-pacing-profile-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-congestion-pacing-profile-provenance-v1";

    internal static void ValidateValue(
        QuicCongestionPacingProfilePolicyValue value)
    {
        if (value is < QuicCongestionPacingProfilePolicyValue.LegacyCurrent
            or > QuicCongestionPacingProfilePolicyValue.Cubic)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicCongestionPacingProfileObservationMode mode)
    {
        if (mode
            is < QuicCongestionPacingProfileObservationMode.Disabled
            or > QuicCongestionPacingProfileObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicCongestionPacingProfileConfiguredPolicySnapshot
        CreateConfiguredSnapshot(
            QuicCongestionPacingProfileObservationMode mode,
            QuicCongestionPacingProfilePolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            return new(
                mode,
                HasForcedValue: true,
                forced,
                HasShadowRecommendation: mode
                    == QuicCongestionPacingProfileObservationMode.Shadow,
                ShadowRecommendation:
                    QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicCongestionPacingProfileSelectionSource.Forced,
                forced == QuicCongestionPacingProfilePolicyValue.Cubic
                    ? QuicCongestionPacingProfileReasonCode.ForcedCubic
                    : QuicCongestionPacingProfileReasonCode
                        .ForcedLegacyCurrent,
                QuicCongestionPacingProfileSafetyOverride.None,
                QuicCongestionPacingProfileDecisionBoundary
                    .ConnectionConstruction,
                QuicCongestionPacingProfileLatchLifetime
                    .ConnectionLifetime,
                FallbackApplied: false);
        }

        bool shadow =
            mode == QuicCongestionPacingProfileObservationMode.Shadow;
        return new(
            mode,
            HasForcedValue: false,
            ForcedValue:
                QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            HasShadowRecommendation: shadow,
            ShadowRecommendation:
                QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            SelectedValue:
                QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            AppliedValue:
                QuicCongestionPacingProfilePolicyValue.LegacyCurrent,
            shadow
                ? QuicCongestionPacingProfileSelectionSource.ShadowResearch
                : QuicCongestionPacingProfileSelectionSource.LegacyCurrent,
            mode switch
            {
                QuicCongestionPacingProfileObservationMode.ObserveOnly =>
                    QuicCongestionPacingProfileReasonCode.ObserveOnly,
                QuicCongestionPacingProfileObservationMode.Shadow =>
                    QuicCongestionPacingProfileReasonCode
                        .ShadowResearchOnly,
                _ => QuicCongestionPacingProfileReasonCode.LegacyCurrent,
            },
            QuicCongestionPacingProfileSafetyOverride.None,
            QuicCongestionPacingProfileDecisionBoundary
                .ConnectionConstruction,
            QuicCongestionPacingProfileLatchLifetime.ConnectionLifetime,
            FallbackApplied: false);
    }

    internal static QuicCongestionPacingProfileDecision Evaluate(
        QuicCongestionPacingProfileObservationMode mode,
        QuicCongestionPacingProfilePolicyValue? forcedValue,
        ulong connectionStartSequence,
        long captureTicks,
        ulong maximumDatagramSizeBytes =
            QuicCongestionControlState.MinimumMaxDatagramSizeBytes,
        bool lifecycleGuard = false,
        QuicCongestionPacingProfileValidity validity =
            QuicCongestionPacingProfileValidity.None)
    {
        QuicCongestionPacingProfileConfiguredPolicySnapshot configured =
            CreateConfiguredSnapshot(mode, forcedValue);
        if (connectionStartSequence == 0)
        {
            validity |=
                QuicCongestionPacingProfileValidity.MissingRequiredInput;
        }

        if (maximumDatagramSizeBytes
            < QuicCongestionControlState.MinimumMaxDatagramSizeBytes)
        {
            validity |=
                QuicCongestionPacingProfileValidity.OutOfDomain;
        }

        ulong safeMaximumDatagramSizeBytes = Math.Max(
            QuicCongestionControlState.MinimumMaxDatagramSizeBytes,
            maximumDatagramSizeBytes);
        QuicCongestionPacingProfileSafetyOverride safetyOverride;
        if (lifecycleGuard)
        {
            safetyOverride =
                QuicCongestionPacingProfileSafetyOverride.Lifecycle;
        }
        else if (validity != QuicCongestionPacingProfileValidity.None)
        {
            safetyOverride =
                QuicCongestionPacingProfileSafetyOverride
                    .InvalidObservation;
        }
        else
        {
            safetyOverride =
                QuicCongestionPacingProfileSafetyOverride.None;
        }
        bool fallbackApplied =
            safetyOverride
            != QuicCongestionPacingProfileSafetyOverride.None;
        QuicCongestionPacingProfilePolicyValue appliedValue =
            fallbackApplied
                ? QuicCongestionPacingProfilePolicyValue.LegacyCurrent
                : configured.AppliedValue;
        QuicCongestionControlAlgorithm algorithm =
            appliedValue == QuicCongestionPacingProfilePolicyValue.Cubic
                ? QuicCongestionControlAlgorithm.Cubic
                : QuicCongestionControlAlgorithm.NewReno;
        QuicCongestionPacingProfileReasonCode reasonCode;
        if (!fallbackApplied)
        {
            reasonCode = configured.ReasonCode;
        }
        else if (safetyOverride
            == QuicCongestionPacingProfileSafetyOverride.Lifecycle)
        {
            reasonCode =
                QuicCongestionPacingProfileReasonCode.LifecycleGuard;
        }
        else
        {
            reasonCode = GetValidityReason(validity);
        }

        return new(
            configured.Mode,
            configured.HasForcedValue,
            configured.ForcedValue,
            configured.HasShadowRecommendation,
            configured.ShadowRecommendation,
            configured.SelectedValue,
            appliedValue,
            fallbackApplied
                ? QuicCongestionPacingProfileSelectionSource.SafetyOverride
                : configured.SelectionSource,
            reasonCode,
            safetyOverride,
            configured.DecisionBoundary,
            configured.LatchLifetime,
            fallbackApplied,
            connectionStartSequence,
            captureTicks,
            safeMaximumDatagramSizeBytes,
            QuicCongestionControlState.ComputeInitialCongestionWindowBytes(
                safeMaximumDatagramSizeBytes),
            ulong.MaxValue,
            InitialBytesInFlight: 0,
            algorithm,
            validity);
    }

    private static QuicCongestionPacingProfileReasonCode GetValidityReason(
        QuicCongestionPacingProfileValidity validity)
    {
        if ((validity
            & QuicCongestionPacingProfileValidity.MissingRequiredInput) != 0)
        {
            return QuicCongestionPacingProfileReasonCode.MissingInput;
        }

        if ((validity
            & QuicCongestionPacingProfileValidity.StaleRequiredInput) != 0)
        {
            return QuicCongestionPacingProfileReasonCode.StaleInput;
        }

        if ((validity
            & QuicCongestionPacingProfileValidity.ArithmeticSaturated) != 0)
        {
            return QuicCongestionPacingProfileReasonCode
                .ArithmeticSaturated;
        }

        if ((validity
            & QuicCongestionPacingProfileValidity.Contradictory) != 0)
        {
            return QuicCongestionPacingProfileReasonCode.Contradictory;
        }

        if ((validity
            & QuicCongestionPacingProfileValidity.InvalidInput) != 0)
        {
            return QuicCongestionPacingProfileReasonCode.InvalidInput;
        }

        return QuicCongestionPacingProfileReasonCode.OutOfDomain;
    }
}
