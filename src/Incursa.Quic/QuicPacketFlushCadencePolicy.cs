// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicPacketFlushCadenceObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

internal enum QuicPacketFlushCadencePolicyValue : byte
{
    LegacyCurrent = 0,
    Prompt = 1,
}

internal enum QuicPacketFlushCadenceSelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowRule = 2,
    SafetyOverride = 3,
}

internal enum QuicPacketFlushCadenceReasonCode : byte
{
    LegacyCurrent = 0,
    ObserveOnly = 1,
    ForcedPrompt = 2,
    ShadowPrompt = 3,
    NotDelayEligible = 4,
    LegacyDelay = 5,
    PromptFlush = 6,
    MissingInput = 7,
    StaleInput = 8,
    ArithmeticSaturated = 9,
    Contradictory = 10,
    OutOfDomain = 11,
    InvalidInput = 12,
    LifecycleGuard = 13,
    RetransmissionGuard = 14,
    AddressValidationGuard = 15,
}

internal enum QuicPacketFlushCadenceSafetyOverride : byte
{
    None = 0,
    InvalidObservation = 1,
    Lifecycle = 2,
    Retransmission = 3,
    AddressValidation = 4,
}

internal enum QuicPacketFlushCadenceDecisionBoundary : byte
{
    AuthorizedApplicationPacketConstruction = 0,
}

internal enum QuicPacketFlushCadenceLatchLifetime : byte
{
    LogicalWritePacketOpportunity = 0,
}

[Flags]
internal enum QuicPacketFlushCadenceValidity : byte
{
    None = 0,
    MissingRequiredInput = 1 << 0,
    StaleRequiredInput = 1 << 1,
    ArithmeticSaturated = 1 << 2,
    Contradictory = 1 << 3,
    OutOfDomain = 1 << 4,
    InvalidInput = 1 << 5,
}

internal readonly record struct QuicPacketFlushCadenceConfiguredPolicySnapshot(
    QuicPacketFlushCadenceObservationMode Mode,
    bool HasForcedValue,
    QuicPacketFlushCadencePolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicPacketFlushCadencePolicyValue ShadowRecommendation,
    QuicPacketFlushCadencePolicyValue SelectedValue,
    QuicPacketFlushCadencePolicyValue AppliedValue,
    QuicPacketFlushCadenceSelectionSource SelectionSource,
    QuicPacketFlushCadenceReasonCode ReasonCode,
    QuicPacketFlushCadenceSafetyOverride SafetyOverride,
    QuicPacketFlushCadenceDecisionBoundary DecisionBoundary,
    QuicPacketFlushCadenceLatchLifetime LatchLifetime,
    bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-packet-flush-cadence-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct QuicPacketFlushCadencePolicyDecision(
    QuicPacketFlushCadenceObservationMode Mode,
    bool HasForcedValue,
    QuicPacketFlushCadencePolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicPacketFlushCadencePolicyValue ShadowRecommendation,
    QuicPacketFlushCadencePolicyValue SelectedValue,
    QuicPacketFlushCadencePolicyValue AppliedValue,
    QuicPacketFlushCadenceSelectionSource SelectionSource,
    QuicPacketFlushCadenceReasonCode ReasonCode,
    QuicPacketFlushCadenceSafetyOverride SafetyOverride,
    QuicPacketFlushCadenceDecisionBoundary DecisionBoundary,
    QuicPacketFlushCadenceLatchLifetime LatchLifetime,
    bool FallbackApplied,
    bool LegacyDelayEligible,
    bool DelayApplied,
    bool PromptFlushApplied,
    uint StreamPayloadLength,
    uint QueuedWriteCount,
    bool FinishWrites,
    bool AddressValidated,
    bool RetransmissionPending,
    QuicPacketFlushCadenceValidity Validity);

internal static class QuicPacketFlushCadencePolicy
{
    internal const string CurrentRuleVersion =
        "quic-packet-flush-cadence-prompt-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-packet-flush-cadence-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-packet-flush-cadence-provenance-v1";

    internal static void ValidateValue(
        QuicPacketFlushCadencePolicyValue value)
    {
        if (value is < QuicPacketFlushCadencePolicyValue.LegacyCurrent
            or > QuicPacketFlushCadencePolicyValue.Prompt)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicPacketFlushCadenceObservationMode mode)
    {
        if (mode is < QuicPacketFlushCadenceObservationMode.Disabled
            or > QuicPacketFlushCadenceObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicPacketFlushCadenceConfiguredPolicySnapshot
        CreateConfiguredSnapshot(
            QuicPacketFlushCadenceObservationMode mode,
            QuicPacketFlushCadencePolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            bool shadow =
                mode == QuicPacketFlushCadenceObservationMode.Shadow;
            return new(
                mode,
                HasForcedValue: true,
                forced,
                HasShadowRecommendation: shadow,
                ShadowRecommendation: shadow
                    ? QuicPacketFlushCadencePolicyValue.Prompt
                    : QuicPacketFlushCadencePolicyValue.LegacyCurrent,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicPacketFlushCadenceSelectionSource.Forced,
                forced == QuicPacketFlushCadencePolicyValue.Prompt
                    ? QuicPacketFlushCadenceReasonCode.ForcedPrompt
                    : QuicPacketFlushCadenceReasonCode.LegacyCurrent,
                QuicPacketFlushCadenceSafetyOverride.None,
                QuicPacketFlushCadenceDecisionBoundary
                    .AuthorizedApplicationPacketConstruction,
                QuicPacketFlushCadenceLatchLifetime
                    .LogicalWritePacketOpportunity,
                FallbackApplied: false);
        }

        if (mode == QuicPacketFlushCadenceObservationMode.Shadow)
        {
            return new(
                mode,
                HasForcedValue: false,
                ForcedValue:
                    QuicPacketFlushCadencePolicyValue.LegacyCurrent,
                HasShadowRecommendation: true,
                ShadowRecommendation:
                    QuicPacketFlushCadencePolicyValue.Prompt,
                SelectedValue: QuicPacketFlushCadencePolicyValue.Prompt,
                AppliedValue:
                    QuicPacketFlushCadencePolicyValue.LegacyCurrent,
                QuicPacketFlushCadenceSelectionSource.ShadowRule,
                QuicPacketFlushCadenceReasonCode.ShadowPrompt,
                QuicPacketFlushCadenceSafetyOverride.None,
                QuicPacketFlushCadenceDecisionBoundary
                    .AuthorizedApplicationPacketConstruction,
                QuicPacketFlushCadenceLatchLifetime
                    .LogicalWritePacketOpportunity,
                FallbackApplied: false);
        }

        return new(
            mode,
            HasForcedValue: false,
            ForcedValue:
                QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            HasShadowRecommendation: false,
            ShadowRecommendation:
                QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            SelectedValue:
                QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            AppliedValue:
                QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            QuicPacketFlushCadenceSelectionSource.LegacyCurrent,
            mode == QuicPacketFlushCadenceObservationMode.ObserveOnly
                ? QuicPacketFlushCadenceReasonCode.ObserveOnly
                : QuicPacketFlushCadenceReasonCode.LegacyCurrent,
            QuicPacketFlushCadenceSafetyOverride.None,
            QuicPacketFlushCadenceDecisionBoundary
                .AuthorizedApplicationPacketConstruction,
            QuicPacketFlushCadenceLatchLifetime
                .LogicalWritePacketOpportunity,
            FallbackApplied: false);
    }

    internal static QuicPacketFlushCadencePolicyDecision Evaluate(
        QuicPacketFlushCadenceObservationMode mode,
        QuicPacketFlushCadencePolicyValue? forcedValue,
        int streamPayloadLength,
        int queuedWriteCount,
        bool finishWrites,
        bool addressValidated,
        bool retransmissionPending,
        bool lifecycleGuard,
        int legacyDelayThresholdBytes,
        QuicPacketFlushCadenceValidity validity =
            QuicPacketFlushCadenceValidity.None)
    {
        QuicPacketFlushCadenceConfiguredPolicySnapshot configured =
            CreateConfiguredSnapshot(mode, forcedValue);
        if (streamPayloadLength < 0
            || queuedWriteCount < 0
            || legacyDelayThresholdBytes <= 0)
        {
            validity |= QuicPacketFlushCadenceValidity.OutOfDomain;
        }

        if (finishWrites && streamPayloadLength == 0
            && queuedWriteCount > 0)
        {
            validity |= QuicPacketFlushCadenceValidity.Contradictory;
        }

        QuicPacketFlushCadenceSafetyOverride safetyOverride =
            GetSafetyOverride(
                configured.AppliedValue,
                validity,
                lifecycleGuard,
                retransmissionPending,
                addressValidated);
        bool fallbackApplied =
            safetyOverride != QuicPacketFlushCadenceSafetyOverride.None;
        QuicPacketFlushCadencePolicyValue appliedValue = fallbackApplied
            ? QuicPacketFlushCadencePolicyValue.LegacyCurrent
            : configured.AppliedValue;
        QuicPacketFlushCadenceSelectionSource selectionSource =
            fallbackApplied
                ? QuicPacketFlushCadenceSelectionSource.SafetyOverride
                : configured.SelectionSource;
        bool legacyDelayEligible =
            validity == QuicPacketFlushCadenceValidity.None
            && !lifecycleGuard
            && !retransmissionPending
            && !finishWrites
            && streamPayloadLength > 0
            && addressValidated
            && (queuedWriteCount > 0
                || streamPayloadLength < legacyDelayThresholdBytes);
        bool delayApplied =
            legacyDelayEligible
            && appliedValue
                == QuicPacketFlushCadencePolicyValue.LegacyCurrent;
        bool promptFlushApplied =
            legacyDelayEligible
            && appliedValue == QuicPacketFlushCadencePolicyValue.Prompt;
        QuicPacketFlushCadenceReasonCode reasonCode = GetReasonCode(
            configured.ReasonCode,
            safetyOverride,
            validity,
            legacyDelayEligible,
            delayApplied,
            promptFlushApplied);

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
            legacyDelayEligible,
            delayApplied,
            promptFlushApplied,
            streamPayloadLength < 0
                ? 0U
                : (uint)streamPayloadLength,
            queuedWriteCount < 0
                ? 0U
                : (uint)queuedWriteCount,
            finishWrites,
            addressValidated,
            retransmissionPending,
            validity);
    }

    private static QuicPacketFlushCadenceSafetyOverride
        GetSafetyOverride(
            QuicPacketFlushCadencePolicyValue appliedValue,
            QuicPacketFlushCadenceValidity validity,
            bool lifecycleGuard,
            bool retransmissionPending,
            bool addressValidated)
    {
        if (lifecycleGuard)
        {
            return QuicPacketFlushCadenceSafetyOverride.Lifecycle;
        }

        if (validity != QuicPacketFlushCadenceValidity.None)
        {
            return QuicPacketFlushCadenceSafetyOverride
                .InvalidObservation;
        }

        if (appliedValue == QuicPacketFlushCadencePolicyValue.Prompt
            && retransmissionPending)
        {
            return QuicPacketFlushCadenceSafetyOverride.Retransmission;
        }

        if (appliedValue == QuicPacketFlushCadencePolicyValue.Prompt
            && !addressValidated)
        {
            return QuicPacketFlushCadenceSafetyOverride
                .AddressValidation;
        }

        return QuicPacketFlushCadenceSafetyOverride.None;
    }

    private static QuicPacketFlushCadenceReasonCode GetReasonCode(
        QuicPacketFlushCadenceReasonCode configuredReason,
        QuicPacketFlushCadenceSafetyOverride safetyOverride,
        QuicPacketFlushCadenceValidity validity,
        bool legacyDelayEligible,
        bool delayApplied,
        bool promptFlushApplied)
    {
        if (safetyOverride
            == QuicPacketFlushCadenceSafetyOverride.Lifecycle)
        {
            return QuicPacketFlushCadenceReasonCode.LifecycleGuard;
        }

        if (safetyOverride
            == QuicPacketFlushCadenceSafetyOverride.Retransmission)
        {
            return QuicPacketFlushCadenceReasonCode
                .RetransmissionGuard;
        }

        if (safetyOverride
            == QuicPacketFlushCadenceSafetyOverride.AddressValidation)
        {
            return QuicPacketFlushCadenceReasonCode
                .AddressValidationGuard;
        }

        if ((validity
            & QuicPacketFlushCadenceValidity.MissingRequiredInput) != 0)
        {
            return QuicPacketFlushCadenceReasonCode.MissingInput;
        }

        if ((validity
            & QuicPacketFlushCadenceValidity.StaleRequiredInput) != 0)
        {
            return QuicPacketFlushCadenceReasonCode.StaleInput;
        }

        if ((validity
            & QuicPacketFlushCadenceValidity.ArithmeticSaturated) != 0)
        {
            return QuicPacketFlushCadenceReasonCode.ArithmeticSaturated;
        }

        if ((validity
            & QuicPacketFlushCadenceValidity.Contradictory) != 0)
        {
            return QuicPacketFlushCadenceReasonCode.Contradictory;
        }

        if ((validity
            & QuicPacketFlushCadenceValidity.OutOfDomain) != 0)
        {
            return QuicPacketFlushCadenceReasonCode.OutOfDomain;
        }

        if ((validity
            & QuicPacketFlushCadenceValidity.InvalidInput) != 0)
        {
            return QuicPacketFlushCadenceReasonCode.InvalidInput;
        }

        if (!legacyDelayEligible)
        {
            return QuicPacketFlushCadenceReasonCode.NotDelayEligible;
        }

        if (promptFlushApplied)
        {
            return QuicPacketFlushCadenceReasonCode.PromptFlush;
        }

        if (delayApplied)
        {
            return QuicPacketFlushCadenceReasonCode.LegacyDelay;
        }

        return configuredReason;
    }
}

internal readonly record struct QuicPacketFlushCadenceObservation(
    ulong OperationSequence,
    long RequestId,
    QuicPacketFlushCadenceObservationMode Mode,
    QuicPacketFlushCadencePolicyValue? ForcedValue,
    QuicPacketFlushCadencePolicyValue? ShadowRecommendation,
    QuicPacketFlushCadencePolicyValue SelectedValue,
    QuicPacketFlushCadencePolicyValue AppliedValue,
    QuicPacketFlushCadenceSelectionSource SelectionSource,
    QuicPacketFlushCadenceReasonCode ReasonCode,
    QuicPacketFlushCadenceSafetyOverride SafetyOverride,
    QuicPacketFlushCadenceDecisionBoundary DecisionBoundary,
    QuicPacketFlushCadenceLatchLifetime LatchLifetime,
    bool FallbackApplied,
    bool LegacyDelayEligible,
    bool DelayApplied,
    bool PromptFlushApplied,
    uint StreamPayloadLength,
    uint QueuedWriteCount,
    bool FinishWrites,
    bool AddressValidated,
    bool RetransmissionPending,
    QuicConnectionPhase PhaseAfter,
    bool DisposalStarted,
    QuicPacketFlushCadenceValidity Validity)
{
    internal const string AxisId = "packet_flush_cadence";
    internal const string CurrentObservationContractVersion =
        "quic-packet-flush-cadence-observation-v1";

    public string PolicyAxisId => AxisId;

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string RuleVersion =>
        QuicPacketFlushCadencePolicy.CurrentRuleVersion;

    public string SnapshotVersion =>
        QuicPacketFlushCadenceConfiguredPolicySnapshot
            .CurrentSnapshotVersion;

    public string ReasonVersion =>
        QuicPacketFlushCadencePolicy.CurrentReasonVersion;

    public string ProvenanceVersion =>
        QuicPacketFlushCadencePolicy.CurrentProvenanceVersion;
}

internal interface IQuicPacketFlushCadenceEvidenceSink
{
    bool TryPublish(
        in QuicPacketFlushCadenceObservation observation);
}
