// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicReceiveDeliveryQuantumObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

internal enum QuicReceiveDeliveryQuantumPolicyValue : byte
{
    LegacyCurrent = 0,
    SingleSegment = 1,
}

internal enum QuicReceiveDeliveryQuantumSelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowRule = 2,
    SafetyOverride = 3,
}

internal enum QuicReceiveDeliveryQuantumReasonCode : byte
{
    LegacyCurrent = 0,
    ObserveOnly = 1,
    ForcedSingleSegment = 2,
    ShadowSingleSegment = 3,
    LegacyAllAvailable = 4,
    SingleSegmentApplied = 5,
    MissingInput = 6,
    StaleInput = 7,
    ArithmeticSaturated = 8,
    Contradictory = 9,
    OutOfDomain = 10,
    InvalidInput = 11,
    LifecycleGuard = 12,
}

internal enum QuicReceiveDeliveryQuantumSafetyOverride : byte
{
    None = 0,
    InvalidObservation = 1,
    Lifecycle = 2,
}

internal enum QuicReceiveDeliveryQuantumDecisionBoundary : byte
{
    ProductiveApplicationRead = 0,
}

internal enum QuicReceiveDeliveryQuantumLatchLifetime : byte
{
    ApplicationReadCall = 0,
}

[Flags]
internal enum QuicReceiveDeliveryQuantumValidity : byte
{
    None = 0,
    MissingRequiredInput = 1 << 0,
    StaleRequiredInput = 1 << 1,
    ArithmeticSaturated = 1 << 2,
    Contradictory = 1 << 3,
    OutOfDomain = 1 << 4,
    InvalidInput = 1 << 5,
}

internal readonly record struct QuicReceiveDeliveryQuantumConfiguredPolicySnapshot(
    QuicReceiveDeliveryQuantumObservationMode Mode,
    bool HasForcedValue,
    QuicReceiveDeliveryQuantumPolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicReceiveDeliveryQuantumPolicyValue ShadowRecommendation,
    QuicReceiveDeliveryQuantumPolicyValue SelectedValue,
    QuicReceiveDeliveryQuantumPolicyValue AppliedValue,
    QuicReceiveDeliveryQuantumSelectionSource SelectionSource,
    QuicReceiveDeliveryQuantumReasonCode ReasonCode,
    QuicReceiveDeliveryQuantumSafetyOverride SafetyOverride,
    QuicReceiveDeliveryQuantumDecisionBoundary DecisionBoundary,
    QuicReceiveDeliveryQuantumLatchLifetime LatchLifetime,
    bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-receive-delivery-quantum-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct QuicReceiveDeliveryQuantumPolicyDecision(
    QuicReceiveDeliveryQuantumObservationMode Mode,
    bool HasForcedValue,
    QuicReceiveDeliveryQuantumPolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicReceiveDeliveryQuantumPolicyValue ShadowRecommendation,
    QuicReceiveDeliveryQuantumPolicyValue SelectedValue,
    QuicReceiveDeliveryQuantumPolicyValue AppliedValue,
    QuicReceiveDeliveryQuantumSelectionSource SelectionSource,
    QuicReceiveDeliveryQuantumReasonCode ReasonCode,
    QuicReceiveDeliveryQuantumSafetyOverride SafetyOverride,
    QuicReceiveDeliveryQuantumDecisionBoundary DecisionBoundary,
    QuicReceiveDeliveryQuantumLatchLifetime LatchLifetime,
    bool FallbackApplied,
    int MaximumSourceSegments,
    uint RequestedBufferLength,
    QuicReceiveDeliveryQuantumValidity Validity);

internal static class QuicReceiveDeliveryQuantumPolicy
{
    internal const string CurrentRuleVersion =
        "quic-receive-delivery-single-segment-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-receive-delivery-quantum-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-receive-delivery-quantum-provenance-v1";

    internal static void ValidateValue(
        QuicReceiveDeliveryQuantumPolicyValue value)
    {
        if (value is < QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent
            or > QuicReceiveDeliveryQuantumPolicyValue.SingleSegment)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicReceiveDeliveryQuantumObservationMode mode)
    {
        if (mode is < QuicReceiveDeliveryQuantumObservationMode.Disabled
            or > QuicReceiveDeliveryQuantumObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicReceiveDeliveryQuantumConfiguredPolicySnapshot
        CreateConfiguredSnapshot(
            QuicReceiveDeliveryQuantumObservationMode mode,
            QuicReceiveDeliveryQuantumPolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            bool shadow =
                mode == QuicReceiveDeliveryQuantumObservationMode.Shadow;
            return new(
                mode,
                HasForcedValue: true,
                forced,
                HasShadowRecommendation: shadow,
                ShadowRecommendation: shadow
                    ? QuicReceiveDeliveryQuantumPolicyValue.SingleSegment
                    : QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicReceiveDeliveryQuantumSelectionSource.Forced,
                forced == QuicReceiveDeliveryQuantumPolicyValue.SingleSegment
                    ? QuicReceiveDeliveryQuantumReasonCode.ForcedSingleSegment
                    : QuicReceiveDeliveryQuantumReasonCode.LegacyCurrent,
                QuicReceiveDeliveryQuantumSafetyOverride.None,
                QuicReceiveDeliveryQuantumDecisionBoundary
                    .ProductiveApplicationRead,
                QuicReceiveDeliveryQuantumLatchLifetime.ApplicationReadCall,
                FallbackApplied: false);
        }

        if (mode == QuicReceiveDeliveryQuantumObservationMode.Shadow)
        {
            return new(
                mode,
                HasForcedValue: false,
                ForcedValue:
                    QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
                HasShadowRecommendation: true,
                ShadowRecommendation:
                    QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                SelectedValue:
                    QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                AppliedValue:
                    QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
                QuicReceiveDeliveryQuantumSelectionSource.ShadowRule,
                QuicReceiveDeliveryQuantumReasonCode.ShadowSingleSegment,
                QuicReceiveDeliveryQuantumSafetyOverride.None,
                QuicReceiveDeliveryQuantumDecisionBoundary
                    .ProductiveApplicationRead,
                QuicReceiveDeliveryQuantumLatchLifetime.ApplicationReadCall,
                FallbackApplied: false);
        }

        return new(
            mode,
            HasForcedValue: false,
            ForcedValue:
                QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            HasShadowRecommendation: false,
            ShadowRecommendation:
                QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            SelectedValue:
                QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            AppliedValue:
                QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            QuicReceiveDeliveryQuantumSelectionSource.LegacyCurrent,
            mode == QuicReceiveDeliveryQuantumObservationMode.ObserveOnly
                ? QuicReceiveDeliveryQuantumReasonCode.ObserveOnly
                : QuicReceiveDeliveryQuantumReasonCode.LegacyCurrent,
            QuicReceiveDeliveryQuantumSafetyOverride.None,
            QuicReceiveDeliveryQuantumDecisionBoundary
                .ProductiveApplicationRead,
            QuicReceiveDeliveryQuantumLatchLifetime.ApplicationReadCall,
            FallbackApplied: false);
    }

    internal static QuicReceiveDeliveryQuantumPolicyDecision Evaluate(
        QuicReceiveDeliveryQuantumObservationMode mode,
        QuicReceiveDeliveryQuantumPolicyValue? forcedValue,
        int requestedBufferLength,
        bool lifecycleGuard,
        QuicReceiveDeliveryQuantumValidity validity =
            QuicReceiveDeliveryQuantumValidity.None)
    {
        QuicReceiveDeliveryQuantumConfiguredPolicySnapshot configured =
            CreateConfiguredSnapshot(mode, forcedValue);
        if (requestedBufferLength <= 0)
        {
            validity |= QuicReceiveDeliveryQuantumValidity.OutOfDomain;
        }

        QuicReceiveDeliveryQuantumSafetyOverride safetyOverride =
            QuicReceiveDeliveryQuantumSafetyOverride.None;
        if (lifecycleGuard)
        {
            safetyOverride =
                QuicReceiveDeliveryQuantumSafetyOverride.Lifecycle;
        }
        else if (validity != QuicReceiveDeliveryQuantumValidity.None)
        {
            safetyOverride =
                QuicReceiveDeliveryQuantumSafetyOverride
                    .InvalidObservation;
        }
        bool fallbackApplied =
            safetyOverride != QuicReceiveDeliveryQuantumSafetyOverride.None;
        QuicReceiveDeliveryQuantumPolicyValue appliedValue = fallbackApplied
            ? QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent
            : configured.AppliedValue;
        QuicReceiveDeliveryQuantumSelectionSource selectionSource =
            fallbackApplied
                ? QuicReceiveDeliveryQuantumSelectionSource.SafetyOverride
                : configured.SelectionSource;

        return new(
            mode,
            configured.HasForcedValue,
            configured.ForcedValue,
            configured.HasShadowRecommendation,
            configured.ShadowRecommendation,
            configured.SelectedValue,
            appliedValue,
            selectionSource,
            GetReasonCode(
                configured.ReasonCode,
                safetyOverride,
                validity,
                appliedValue),
            safetyOverride,
            configured.DecisionBoundary,
            configured.LatchLifetime,
            fallbackApplied,
            appliedValue
                == QuicReceiveDeliveryQuantumPolicyValue.SingleSegment
                    ? 1
                    : int.MaxValue,
            requestedBufferLength <= 0
                ? 0U
                : (uint)requestedBufferLength,
            validity);
    }

    private static QuicReceiveDeliveryQuantumReasonCode GetReasonCode(
        QuicReceiveDeliveryQuantumReasonCode configuredReason,
        QuicReceiveDeliveryQuantumSafetyOverride safetyOverride,
        QuicReceiveDeliveryQuantumValidity validity,
        QuicReceiveDeliveryQuantumPolicyValue appliedValue)
    {
        if (safetyOverride
            == QuicReceiveDeliveryQuantumSafetyOverride.Lifecycle)
        {
            return QuicReceiveDeliveryQuantumReasonCode.LifecycleGuard;
        }

        if ((validity
            & QuicReceiveDeliveryQuantumValidity.MissingRequiredInput) != 0)
        {
            return QuicReceiveDeliveryQuantumReasonCode.MissingInput;
        }

        if ((validity
            & QuicReceiveDeliveryQuantumValidity.StaleRequiredInput) != 0)
        {
            return QuicReceiveDeliveryQuantumReasonCode.StaleInput;
        }

        if ((validity
            & QuicReceiveDeliveryQuantumValidity.ArithmeticSaturated) != 0)
        {
            return QuicReceiveDeliveryQuantumReasonCode.ArithmeticSaturated;
        }

        if ((validity
            & QuicReceiveDeliveryQuantumValidity.Contradictory) != 0)
        {
            return QuicReceiveDeliveryQuantumReasonCode.Contradictory;
        }

        if ((validity
            & QuicReceiveDeliveryQuantumValidity.OutOfDomain) != 0)
        {
            return QuicReceiveDeliveryQuantumReasonCode.OutOfDomain;
        }

        if ((validity
            & QuicReceiveDeliveryQuantumValidity.InvalidInput) != 0)
        {
            return QuicReceiveDeliveryQuantumReasonCode.InvalidInput;
        }

        if (appliedValue
            == QuicReceiveDeliveryQuantumPolicyValue.SingleSegment)
        {
            return QuicReceiveDeliveryQuantumReasonCode
                .SingleSegmentApplied;
        }

        return configuredReason
            is QuicReceiveDeliveryQuantumReasonCode.ObserveOnly
                or QuicReceiveDeliveryQuantumReasonCode.ShadowSingleSegment
            ? configuredReason
            : QuicReceiveDeliveryQuantumReasonCode.LegacyAllAvailable;
    }
}

internal readonly record struct QuicReceiveDeliveryQuantumObservation(
    long OperationSequence,
    ulong StreamId,
    QuicReceiveDeliveryQuantumPolicyDecision Decision,
    uint DeliveredBytes,
    uint SourceSegmentsRead,
    bool Completed,
    bool BatchedReceiveCredit)
{
    internal const string CurrentObservationVersion =
        "quic-receive-delivery-quantum-observation-v1";

    public string AxisId => "receive_delivery_quantum";

    public string ObservationVersion => CurrentObservationVersion;

    public string RuleVersion =>
        QuicReceiveDeliveryQuantumPolicy.CurrentRuleVersion;

    public string SnapshotVersion =>
        QuicReceiveDeliveryQuantumConfiguredPolicySnapshot
            .CurrentSnapshotVersion;

    public string ReasonVersion =>
        QuicReceiveDeliveryQuantumPolicy.CurrentReasonVersion;

    public string ProvenanceVersion =>
        QuicReceiveDeliveryQuantumPolicy.CurrentProvenanceVersion;
}

internal interface IQuicReceiveDeliveryQuantumEvidenceSink
{
    bool TryPublish(
        in QuicReceiveDeliveryQuantumObservation observation);
}
