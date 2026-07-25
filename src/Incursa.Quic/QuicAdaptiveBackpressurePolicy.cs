// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicAdaptiveBackpressureObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

internal enum QuicAdaptiveBackpressurePolicyValue : byte
{
    LegacyCurrent = 0,
    EarlyDelay = 1,
}

internal enum QuicAdaptiveBackpressureSelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowRule = 2,
    SafetyOverride = 3,
}

internal enum QuicAdaptiveBackpressureReasonCode : byte
{
    LegacyCurrent = 0,
    ObserveOnly = 1,
    Forced = 2,
    ShadowEarlyDelay = 3,
    NoBacklog = 4,
    DelayAlreadyApplied = 5,
    MissingInput = 6,
    StaleInput = 7,
    ArithmeticSaturated = 8,
    Contradictory = 9,
    OutOfDomain = 10,
    InvalidInput = 11,
    LifecycleGuard = 12,
    ContinuationUnavailable = 13,
}

internal enum QuicAdaptiveBackpressureSafetyOverride : byte
{
    None = 0,
    InvalidObservation = 1,
    Lifecycle = 2,
    ContinuationUnavailable = 3,
}

internal enum QuicAdaptiveBackpressureDecisionBoundary : byte
{
    NewApplicationAdmission = 0,
}

internal enum QuicAdaptiveBackpressureLatchLifetime : byte
{
    ApplicationAdmission = 0,
}

[Flags]
internal enum QuicAdaptiveBackpressureValidity : byte
{
    None = 0,
    MissingRequiredInput = 1 << 0,
    StaleRequiredInput = 1 << 1,
    ArithmeticSaturated = 1 << 2,
    Contradictory = 1 << 3,
    OutOfDomain = 1 << 4,
    InvalidInput = 1 << 5,
}

internal readonly record struct QuicAdaptiveBackpressureConfiguredPolicySnapshot(
    QuicAdaptiveBackpressureObservationMode Mode,
    bool HasForcedValue,
    QuicAdaptiveBackpressurePolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicAdaptiveBackpressurePolicyValue ShadowRecommendation,
    QuicAdaptiveBackpressurePolicyValue SelectedValue,
    QuicAdaptiveBackpressurePolicyValue AppliedValue,
    QuicAdaptiveBackpressureSelectionSource SelectionSource,
    QuicAdaptiveBackpressureReasonCode ReasonCode,
    QuicAdaptiveBackpressureSafetyOverride SafetyOverride,
    QuicAdaptiveBackpressureDecisionBoundary DecisionBoundary,
    QuicAdaptiveBackpressureLatchLifetime LatchLifetime,
    bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-adaptive-backpressure-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct QuicAdaptiveBackpressurePolicyDecision(
    QuicAdaptiveBackpressureObservationMode Mode,
    bool HasForcedValue,
    QuicAdaptiveBackpressurePolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicAdaptiveBackpressurePolicyValue ShadowRecommendation,
    QuicAdaptiveBackpressurePolicyValue SelectedValue,
    QuicAdaptiveBackpressurePolicyValue AppliedValue,
    QuicAdaptiveBackpressureSelectionSource SelectionSource,
    QuicAdaptiveBackpressureReasonCode ReasonCode,
    QuicAdaptiveBackpressureSafetyOverride SafetyOverride,
    QuicAdaptiveBackpressureDecisionBoundary DecisionBoundary,
    QuicAdaptiveBackpressureLatchLifetime LatchLifetime,
    bool FallbackApplied,
    bool DelayApplied,
    uint QueuedOperationCount,
    ulong RetainedCapacityBytes,
    QuicAdaptiveBackpressureValidity Validity);

internal static class QuicAdaptiveBackpressurePolicy
{
    internal const string CurrentRuleVersion =
        "quic-adaptive-backpressure-early-delay-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-adaptive-backpressure-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-adaptive-backpressure-provenance-v1";

    internal static void ValidateValue(
        QuicAdaptiveBackpressurePolicyValue value)
    {
        if (value is < QuicAdaptiveBackpressurePolicyValue.LegacyCurrent
            or > QuicAdaptiveBackpressurePolicyValue.EarlyDelay)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicAdaptiveBackpressureObservationMode mode)
    {
        if (mode is < QuicAdaptiveBackpressureObservationMode.Disabled
            or > QuicAdaptiveBackpressureObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicAdaptiveBackpressureConfiguredPolicySnapshot
        CreateConfiguredSnapshot(
            QuicAdaptiveBackpressureObservationMode mode,
            QuicAdaptiveBackpressurePolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            bool shadow = mode
                == QuicAdaptiveBackpressureObservationMode.Shadow;
            return new(
                mode,
                HasForcedValue: true,
                forced,
                HasShadowRecommendation: shadow,
                ShadowRecommendation: shadow
                    ? QuicAdaptiveBackpressurePolicyValue.EarlyDelay
                    : QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicAdaptiveBackpressureSelectionSource.Forced,
                QuicAdaptiveBackpressureReasonCode.Forced,
                QuicAdaptiveBackpressureSafetyOverride.None,
                QuicAdaptiveBackpressureDecisionBoundary
                    .NewApplicationAdmission,
                QuicAdaptiveBackpressureLatchLifetime
                    .ApplicationAdmission,
                FallbackApplied: false);
        }

        if (mode == QuicAdaptiveBackpressureObservationMode.Shadow)
        {
            return new(
                mode,
                HasForcedValue: false,
                ForcedValue:
                    QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
                HasShadowRecommendation: true,
                ShadowRecommendation:
                    QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                SelectedValue:
                    QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                AppliedValue:
                    QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
                QuicAdaptiveBackpressureSelectionSource.ShadowRule,
                QuicAdaptiveBackpressureReasonCode.ShadowEarlyDelay,
                QuicAdaptiveBackpressureSafetyOverride.None,
                QuicAdaptiveBackpressureDecisionBoundary
                    .NewApplicationAdmission,
                QuicAdaptiveBackpressureLatchLifetime
                    .ApplicationAdmission,
                FallbackApplied: false);
        }

        return new(
            mode,
            HasForcedValue: false,
            ForcedValue:
                QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            HasShadowRecommendation: false,
            ShadowRecommendation:
                QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            SelectedValue:
                QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            AppliedValue:
                QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            QuicAdaptiveBackpressureSelectionSource.LegacyCurrent,
            mode == QuicAdaptiveBackpressureObservationMode.ObserveOnly
                ? QuicAdaptiveBackpressureReasonCode.ObserveOnly
                : QuicAdaptiveBackpressureReasonCode.LegacyCurrent,
            QuicAdaptiveBackpressureSafetyOverride.None,
            QuicAdaptiveBackpressureDecisionBoundary
                .NewApplicationAdmission,
            QuicAdaptiveBackpressureLatchLifetime.ApplicationAdmission,
            FallbackApplied: false);
    }

    internal static QuicAdaptiveBackpressurePolicyDecision Evaluate(
        QuicAdaptiveBackpressureObservationMode mode,
        QuicAdaptiveBackpressurePolicyValue? forcedValue,
        int queuedOperationCount,
        long retainedCapacityBytes,
        QuicAdaptiveBackpressureValidity validity,
        bool lifecycleGuard,
        bool continuationAvailable,
        bool admissionAlreadyEvaluated)
    {
        QuicAdaptiveBackpressureConfiguredPolicySnapshot configured =
            CreateConfiguredSnapshot(mode, forcedValue);
        if (queuedOperationCount < 0 || retainedCapacityBytes < 0)
        {
            validity |= QuicAdaptiveBackpressureValidity.OutOfDomain;
        }

        if (queuedOperationCount == 0 && retainedCapacityBytes > 0)
        {
            validity |= QuicAdaptiveBackpressureValidity.Contradictory;
        }

        QuicAdaptiveBackpressureSafetyOverride safetyOverride =
            GetSafetyOverride(
                configured.AppliedValue,
                queuedOperationCount,
                validity,
                lifecycleGuard,
                continuationAvailable);
        bool fallbackApplied =
            safetyOverride != QuicAdaptiveBackpressureSafetyOverride.None;
        QuicAdaptiveBackpressurePolicyValue appliedValue = fallbackApplied
            ? QuicAdaptiveBackpressurePolicyValue.LegacyCurrent
            : configured.AppliedValue;
        QuicAdaptiveBackpressureSelectionSource selectionSource =
            fallbackApplied
                ? QuicAdaptiveBackpressureSelectionSource.SafetyOverride
                : configured.SelectionSource;
        bool hasBacklog =
            queuedOperationCount > 0 || retainedCapacityBytes > 0;
        bool delayApplied =
            appliedValue == QuicAdaptiveBackpressurePolicyValue.EarlyDelay
            && hasBacklog
            && !admissionAlreadyEvaluated;
        QuicAdaptiveBackpressureReasonCode reasonCode =
            GetReasonCode(
                configured.ReasonCode,
                safetyOverride,
                validity,
                hasBacklog,
                admissionAlreadyEvaluated);

        return new(
            mode,
            configured.HasForcedValue,
            configured.ForcedValue,
            configured.HasShadowRecommendation,
            configured.ShadowRecommendation,
            configured.SelectedValue,
            appliedValue,
            selectionSource,
            reasonCode,
            safetyOverride,
            configured.DecisionBoundary,
            configured.LatchLifetime,
            fallbackApplied,
            delayApplied,
            queuedOperationCount < 0
                ? 0U
                : (uint)queuedOperationCount,
            retainedCapacityBytes < 0
                ? 0UL
                : (ulong)retainedCapacityBytes,
            validity);
    }

    private static QuicAdaptiveBackpressureSafetyOverride
        GetSafetyOverride(
            QuicAdaptiveBackpressurePolicyValue appliedValue,
            int queuedOperationCount,
            QuicAdaptiveBackpressureValidity validity,
            bool lifecycleGuard,
            bool continuationAvailable)
    {
        if (lifecycleGuard)
        {
            return QuicAdaptiveBackpressureSafetyOverride.Lifecycle;
        }

        if (validity != QuicAdaptiveBackpressureValidity.None)
        {
            return QuicAdaptiveBackpressureSafetyOverride
                .InvalidObservation;
        }

        if (appliedValue
                == QuicAdaptiveBackpressurePolicyValue.EarlyDelay
            && queuedOperationCount > 0
            && !continuationAvailable)
        {
            return QuicAdaptiveBackpressureSafetyOverride
                .ContinuationUnavailable;
        }

        return QuicAdaptiveBackpressureSafetyOverride.None;
    }

    private static QuicAdaptiveBackpressureReasonCode GetReasonCode(
        QuicAdaptiveBackpressureReasonCode configuredReason,
        QuicAdaptiveBackpressureSafetyOverride safetyOverride,
        QuicAdaptiveBackpressureValidity validity,
        bool hasBacklog,
        bool admissionAlreadyEvaluated)
    {
        if (safetyOverride
            == QuicAdaptiveBackpressureSafetyOverride.Lifecycle)
        {
            return QuicAdaptiveBackpressureReasonCode.LifecycleGuard;
        }

        if (safetyOverride
            == QuicAdaptiveBackpressureSafetyOverride
                .ContinuationUnavailable)
        {
            return QuicAdaptiveBackpressureReasonCode
                .ContinuationUnavailable;
        }

        if ((validity
            & QuicAdaptiveBackpressureValidity.MissingRequiredInput) != 0)
        {
            return QuicAdaptiveBackpressureReasonCode.MissingInput;
        }

        if ((validity
            & QuicAdaptiveBackpressureValidity.StaleRequiredInput) != 0)
        {
            return QuicAdaptiveBackpressureReasonCode.StaleInput;
        }

        if ((validity
            & QuicAdaptiveBackpressureValidity.ArithmeticSaturated) != 0)
        {
            return QuicAdaptiveBackpressureReasonCode
                .ArithmeticSaturated;
        }

        if ((validity
            & QuicAdaptiveBackpressureValidity.Contradictory) != 0)
        {
            return QuicAdaptiveBackpressureReasonCode.Contradictory;
        }

        if ((validity
            & QuicAdaptiveBackpressureValidity.OutOfDomain) != 0)
        {
            return QuicAdaptiveBackpressureReasonCode.OutOfDomain;
        }

        if ((validity
            & QuicAdaptiveBackpressureValidity.InvalidInput) != 0)
        {
            return QuicAdaptiveBackpressureReasonCode.InvalidInput;
        }

        if (admissionAlreadyEvaluated)
        {
            return QuicAdaptiveBackpressureReasonCode.DelayAlreadyApplied;
        }

        return hasBacklog
            ? configuredReason
            : QuicAdaptiveBackpressureReasonCode.NoBacklog;
    }
}

internal readonly record struct QuicAdaptiveBackpressureObservation(
    ulong OperationSequence,
    long RequestId,
    QuicAdaptiveBackpressureObservationMode Mode,
    QuicAdaptiveBackpressurePolicyValue? ForcedValue,
    QuicAdaptiveBackpressurePolicyValue? ShadowRecommendation,
    QuicAdaptiveBackpressurePolicyValue SelectedValue,
    QuicAdaptiveBackpressurePolicyValue AppliedValue,
    QuicAdaptiveBackpressureSelectionSource SelectionSource,
    QuicAdaptiveBackpressureReasonCode ReasonCode,
    QuicAdaptiveBackpressureSafetyOverride SafetyOverride,
    QuicAdaptiveBackpressureDecisionBoundary DecisionBoundary,
    QuicAdaptiveBackpressureLatchLifetime LatchLifetime,
    bool FallbackApplied,
    bool DelayApplied,
    uint QueuedOperationCount,
    ulong RetainedCapacityBytes,
    QuicConnectionPhase PhaseAfter,
    bool DisposalStarted,
    QuicAdaptiveBackpressureValidity Validity)
{
    internal const string AxisId = "adaptive_backpressure";
    internal const string CurrentObservationContractVersion =
        "quic-adaptive-backpressure-observation-v1";

    public string PolicyAxisId => AxisId;

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string RuleVersion =>
        QuicAdaptiveBackpressurePolicy.CurrentRuleVersion;

    public string SnapshotVersion =>
        QuicAdaptiveBackpressureConfiguredPolicySnapshot
            .CurrentSnapshotVersion;

    public string ReasonVersion =>
        QuicAdaptiveBackpressurePolicy.CurrentReasonVersion;

    public string ProvenanceVersion =>
        QuicAdaptiveBackpressurePolicy.CurrentProvenanceVersion;
}

internal interface IQuicAdaptiveBackpressureEvidenceSink
{
    bool TryPublish(
        in QuicAdaptiveBackpressureObservation observation);
}
