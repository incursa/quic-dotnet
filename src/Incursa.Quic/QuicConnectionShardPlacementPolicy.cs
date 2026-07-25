// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicConnectionShardPlacementObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

internal enum QuicConnectionShardPlacementPolicyValue : byte
{
    LegacyCurrent = 0,
    BoundedPowerOfTwoChoices = 1,
}

internal enum QuicConnectionShardPlacementSelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowRule = 2,
    SafetyOverride = 3,
}

internal enum QuicConnectionShardPlacementReasonCode : byte
{
    LegacyCurrent = 0,
    ObserveOnly = 1,
    ForcedBoundedPowerOfTwoChoices = 2,
    ShadowBoundedPowerOfTwoChoices = 3,
    LegacyModuloApplied = 4,
    LowerActiveCountApplied = 5,
    LegacyTieBreakApplied = 6,
    SingleShardFallback = 7,
    MissingInput = 8,
    StaleInput = 9,
    ArithmeticSaturated = 10,
    Contradictory = 11,
    OutOfDomain = 12,
    InvalidInput = 13,
    LifecycleGuard = 14,
}

internal enum QuicConnectionShardPlacementSafetyOverride : byte
{
    None = 0,
    InvalidObservation = 1,
    Lifecycle = 2,
    SingleShard = 3,
}

internal enum QuicConnectionShardPlacementDecisionBoundary : byte
{
    ConnectionRegistration = 0,
}

internal enum QuicConnectionShardPlacementLatchLifetime : byte
{
    ConnectionLifetime = 0,
}

[Flags]
internal enum QuicConnectionShardPlacementValidity : byte
{
    None = 0,
    MissingRequiredInput = 1 << 0,
    StaleRequiredInput = 1 << 1,
    ArithmeticSaturated = 1 << 2,
    Contradictory = 1 << 3,
    OutOfDomain = 1 << 4,
    InvalidInput = 1 << 5,
}

internal readonly record struct
    QuicConnectionShardPlacementConfiguredPolicySnapshot(
        QuicConnectionShardPlacementObservationMode Mode,
        bool HasForcedValue,
        QuicConnectionShardPlacementPolicyValue ForcedValue,
        bool HasShadowRecommendation,
        QuicConnectionShardPlacementPolicyValue ShadowRecommendation,
        QuicConnectionShardPlacementPolicyValue SelectedValue,
        QuicConnectionShardPlacementPolicyValue AppliedValue,
        QuicConnectionShardPlacementSelectionSource SelectionSource,
        QuicConnectionShardPlacementReasonCode ReasonCode,
        QuicConnectionShardPlacementSafetyOverride SafetyOverride,
        QuicConnectionShardPlacementDecisionBoundary DecisionBoundary,
        QuicConnectionShardPlacementLatchLifetime LatchLifetime,
        bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-connection-shard-placement-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct QuicConnectionShardPlacementDecision(
    QuicConnectionShardPlacementObservationMode Mode,
    bool HasForcedValue,
    QuicConnectionShardPlacementPolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicConnectionShardPlacementPolicyValue ShadowRecommendation,
    QuicConnectionShardPlacementPolicyValue SelectedValue,
    QuicConnectionShardPlacementPolicyValue AppliedValue,
    QuicConnectionShardPlacementSelectionSource SelectionSource,
    QuicConnectionShardPlacementReasonCode ReasonCode,
    QuicConnectionShardPlacementSafetyOverride SafetyOverride,
    QuicConnectionShardPlacementDecisionBoundary DecisionBoundary,
    QuicConnectionShardPlacementLatchLifetime LatchLifetime,
    bool FallbackApplied,
    ulong ConnectionHandleValue,
    int ShardCount,
    int LegacyShardIndex,
    int AlternateShardIndex,
    int LegacyShardActiveConnections,
    int AlternateShardActiveConnections,
    int AppliedShardIndex,
    QuicConnectionShardPlacementValidity Validity)
{
    internal const string CurrentObservationContractVersion =
        "quic-connection-shard-placement-observation-v1";

    public string AxisId => "connection_shard_placement";

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string SnapshotVersion =>
        QuicConnectionShardPlacementConfiguredPolicySnapshot
            .CurrentSnapshotVersion;

    public string RuleVersion =>
        QuicConnectionShardPlacementPolicy.CurrentRuleVersion;

    public string ReasonVersion =>
        QuicConnectionShardPlacementPolicy.CurrentReasonVersion;

    public string ProvenanceVersion =>
        QuicConnectionShardPlacementPolicy.CurrentProvenanceVersion;
}

internal interface IQuicConnectionShardPlacementEvidenceSink
{
    bool TryPublish(in QuicConnectionShardPlacementDecision decision);
}

internal static class QuicConnectionShardPlacementPolicy
{
    private const int FirstMixShift = 30;
    private const int SecondMixShift = 27;
    private const int FinalMixShift = 31;
    private const ulong FirstMixMultiplier = 0xbf58476d1ce4e5b9UL;
    private const ulong SecondMixMultiplier = 0x94d049bb133111ebUL;
    internal const string AxisId = "connection_shard_placement";
    internal const string CurrentRuleVersion =
        "quic-connection-shard-placement-bounded-choice-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-connection-shard-placement-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-connection-shard-placement-provenance-v1";

    internal static void ValidateValue(
        QuicConnectionShardPlacementPolicyValue value)
    {
        if (value is < QuicConnectionShardPlacementPolicyValue.LegacyCurrent
            or > QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicConnectionShardPlacementObservationMode mode)
    {
        if (mode
            is < QuicConnectionShardPlacementObservationMode.Disabled
            or > QuicConnectionShardPlacementObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicConnectionShardPlacementConfiguredPolicySnapshot
        CreateConfiguredSnapshot(
            QuicConnectionShardPlacementObservationMode mode,
            QuicConnectionShardPlacementPolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            bool shadow =
                mode == QuicConnectionShardPlacementObservationMode.Shadow;
            return new(
                mode,
                HasForcedValue: true,
                forced,
                HasShadowRecommendation: shadow,
                ShadowRecommendation: shadow
                    ? QuicConnectionShardPlacementPolicyValue
                        .BoundedPowerOfTwoChoices
                    : QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicConnectionShardPlacementSelectionSource.Forced,
                forced == QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices
                    ? QuicConnectionShardPlacementReasonCode
                        .ForcedBoundedPowerOfTwoChoices
                    : QuicConnectionShardPlacementReasonCode.LegacyCurrent,
                QuicConnectionShardPlacementSafetyOverride.None,
                QuicConnectionShardPlacementDecisionBoundary
                    .ConnectionRegistration,
                QuicConnectionShardPlacementLatchLifetime
                    .ConnectionLifetime,
                FallbackApplied: false);
        }

        if (mode == QuicConnectionShardPlacementObservationMode.Shadow)
        {
            return new(
                mode,
                HasForcedValue: false,
                ForcedValue:
                    QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
                HasShadowRecommendation: true,
                ShadowRecommendation:
                    QuicConnectionShardPlacementPolicyValue
                        .BoundedPowerOfTwoChoices,
                SelectedValue:
                    QuicConnectionShardPlacementPolicyValue
                        .BoundedPowerOfTwoChoices,
                AppliedValue:
                    QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
                QuicConnectionShardPlacementSelectionSource.ShadowRule,
                QuicConnectionShardPlacementReasonCode
                    .ShadowBoundedPowerOfTwoChoices,
                QuicConnectionShardPlacementSafetyOverride.None,
                QuicConnectionShardPlacementDecisionBoundary
                    .ConnectionRegistration,
                QuicConnectionShardPlacementLatchLifetime
                    .ConnectionLifetime,
                FallbackApplied: false);
        }

        return new(
            mode,
            HasForcedValue: false,
            ForcedValue:
                QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            HasShadowRecommendation: false,
            ShadowRecommendation:
                QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            SelectedValue:
                QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            AppliedValue:
                QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            QuicConnectionShardPlacementSelectionSource.LegacyCurrent,
            mode == QuicConnectionShardPlacementObservationMode.ObserveOnly
                ? QuicConnectionShardPlacementReasonCode.ObserveOnly
                : QuicConnectionShardPlacementReasonCode.LegacyCurrent,
            QuicConnectionShardPlacementSafetyOverride.None,
            QuicConnectionShardPlacementDecisionBoundary
                .ConnectionRegistration,
            QuicConnectionShardPlacementLatchLifetime.ConnectionLifetime,
            FallbackApplied: false);
    }

    internal static QuicConnectionShardPlacementDecision Evaluate(
        QuicConnectionShardPlacementObservationMode mode,
        QuicConnectionShardPlacementPolicyValue? forcedValue,
        ulong connectionHandleValue,
        int shardCount,
        int legacyShardActiveConnections,
        int alternateShardActiveConnections,
        bool lifecycleGuard,
        QuicConnectionShardPlacementValidity validity =
            QuicConnectionShardPlacementValidity.None)
    {
        QuicConnectionShardPlacementConfiguredPolicySnapshot configured =
            CreateConfiguredSnapshot(mode, forcedValue);
        if (connectionHandleValue == 0)
        {
            validity |=
                QuicConnectionShardPlacementValidity.MissingRequiredInput;
        }

        if (shardCount <= 0
            || legacyShardActiveConnections < 0
            || alternateShardActiveConnections < 0)
        {
            validity |= QuicConnectionShardPlacementValidity.OutOfDomain;
        }

        int safeShardCount = Math.Max(1, shardCount);
        int legacyShardIndex =
            (int)(connectionHandleValue % (ulong)safeShardCount);
        int alternateShardIndex = SelectAlternateShardIndex(
            connectionHandleValue,
            safeShardCount,
            legacyShardIndex);

        QuicConnectionShardPlacementSafetyOverride safetyOverride =
            QuicConnectionShardPlacementSafetyOverride.None;
        if (lifecycleGuard)
        {
            safetyOverride =
                QuicConnectionShardPlacementSafetyOverride.Lifecycle;
        }
        else if (validity
            != QuicConnectionShardPlacementValidity.None)
        {
            safetyOverride =
                QuicConnectionShardPlacementSafetyOverride
                    .InvalidObservation;
        }
        else if (configured.AppliedValue
                == QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices
            && safeShardCount == 1)
        {
            safetyOverride =
                QuicConnectionShardPlacementSafetyOverride.SingleShard;
        }
        bool fallbackApplied =
            safetyOverride !=
            QuicConnectionShardPlacementSafetyOverride.None;
        QuicConnectionShardPlacementPolicyValue appliedValue =
            fallbackApplied
                ? QuicConnectionShardPlacementPolicyValue.LegacyCurrent
                : configured.AppliedValue;
        int appliedShardIndex = legacyShardIndex;
        QuicConnectionShardPlacementReasonCode reasonCode;
        if (fallbackApplied)
        {
            reasonCode = safetyOverride switch
            {
                QuicConnectionShardPlacementSafetyOverride.Lifecycle =>
                    QuicConnectionShardPlacementReasonCode.LifecycleGuard,
                QuicConnectionShardPlacementSafetyOverride.SingleShard =>
                    QuicConnectionShardPlacementReasonCode
                        .SingleShardFallback,
                _ => GetValidityReason(validity),
            };
        }
        else if (appliedValue
            == QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices)
        {
            if (alternateShardActiveConnections
                < legacyShardActiveConnections)
            {
                appliedShardIndex = alternateShardIndex;
                reasonCode = QuicConnectionShardPlacementReasonCode
                    .LowerActiveCountApplied;
            }
            else
            {
                reasonCode = QuicConnectionShardPlacementReasonCode
                    .LowerActiveCountApplied;
                if (legacyShardActiveConnections
                    == alternateShardActiveConnections)
                {
                    reasonCode = QuicConnectionShardPlacementReasonCode
                        .LegacyTieBreakApplied;
                }
            }
        }
        else
        {
            reasonCode =
                QuicConnectionShardPlacementReasonCode.LegacyModuloApplied;
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
                ? QuicConnectionShardPlacementSelectionSource.SafetyOverride
                : configured.SelectionSource,
            reasonCode,
            safetyOverride,
            configured.DecisionBoundary,
            configured.LatchLifetime,
            fallbackApplied,
            connectionHandleValue,
            shardCount,
            legacyShardIndex,
            alternateShardIndex,
            Math.Max(0, legacyShardActiveConnections),
            Math.Max(0, alternateShardActiveConnections),
            appliedShardIndex,
            validity);
    }

    private static int SelectAlternateShardIndex(
        ulong handleValue,
        int shardCount,
        int legacyShardIndex)
    {
        if (shardCount <= 1)
        {
            return legacyShardIndex;
        }

        ulong mixed = handleValue;
        mixed ^= mixed >> FirstMixShift;
        mixed *= FirstMixMultiplier;
        mixed ^= mixed >> SecondMixShift;
        mixed *= SecondMixMultiplier;
        mixed ^= mixed >> FinalMixShift;
        int alternate = (int)(mixed % (ulong)shardCount);
        return alternate == legacyShardIndex
            ? (legacyShardIndex + 1) % shardCount
            : alternate;
    }

    private static QuicConnectionShardPlacementReasonCode GetValidityReason(
        QuicConnectionShardPlacementValidity validity)
    {
        if ((validity
            & QuicConnectionShardPlacementValidity.MissingRequiredInput) != 0)
        {
            return QuicConnectionShardPlacementReasonCode.MissingInput;
        }

        if ((validity
            & QuicConnectionShardPlacementValidity.StaleRequiredInput) != 0)
        {
            return QuicConnectionShardPlacementReasonCode.StaleInput;
        }

        if ((validity
            & QuicConnectionShardPlacementValidity.ArithmeticSaturated) != 0)
        {
            return QuicConnectionShardPlacementReasonCode
                .ArithmeticSaturated;
        }

        if ((validity
            & QuicConnectionShardPlacementValidity.Contradictory) != 0)
        {
            return QuicConnectionShardPlacementReasonCode.Contradictory;
        }

        if ((validity
            & QuicConnectionShardPlacementValidity.OutOfDomain) != 0)
        {
            return QuicConnectionShardPlacementReasonCode.OutOfDomain;
        }

        return QuicConnectionShardPlacementReasonCode.InvalidInput;
    }
}
