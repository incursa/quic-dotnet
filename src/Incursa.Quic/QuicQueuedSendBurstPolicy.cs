// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicQueuedSendBurstPolicyMode : byte
{
    LegacyCurrent = 0,
    SingleDatagram = 1,
}

internal enum QuicQueuedSendBurstObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

[Flags]
internal enum QuicQueuedSendBurstSignalMask : ushort
{
    None = 0,
    QueuedApplicationWrites = 1 << 0,
    OutboundBacklogBytes = 1 << 1,
    DistinctQueuedStreams = 1 << 2,
    OldestQueuedSendAge = 1 << 3,
    QueueDelayEwma = 1 << 4,
    ActorServiceTimeEwma = 1 << 5,
    BurstLimitHits = 1 << 6,
    Congestion = 1 << 7,
    RetainedSendState = 1 << 8,
    Handshake = 1 << 9,
    LegalMaximumDatagrams = 1 << 10,
    Lifecycle = 1 << 11,
}

[Flags]
internal enum QuicQueuedSendBurstObservationCondition : byte
{
    None = 0,
    ArithmeticSaturated = 1 << 0,
    Contradictory = 1 << 1,
    OutOfDomain = 1 << 2,
    RecoveryUnstable = 1 << 3,
    ResourceConstrained = 1 << 4,
}

internal enum QuicQueuedSendBurstReason : ushort
{
    LegacyCurrent = 0,
    Forced = 1,
    ObserveOnly = 2,
    ShadowLegacyCurrent = 3,
    MissingSignal = 4,
    StaleSignal = 5,
    ArithmeticSaturated = 6,
    Contradictory = 7,
    OutOfDomain = 8,
    RecoveryGuard = 9,
    ResourceGuard = 10,
    TerminalGuard = 11,
    DisposalGuard = 12,
}

internal readonly record struct QuicQueuedSendBurstObservation(
    ulong TurnSequence,
    long CapturedAtTicks,
    string ObservationContractVersion,
    string RuleVersion,
    QuicQueuedSendBurstSignalMask MissingSignalMask,
    QuicQueuedSendBurstSignalMask StaleSignalMask,
    QuicQueuedSendBurstObservationCondition Conditions,
    QuicAdaptiveRuntimeLifecycle LifecycleFlags,
    uint QueuedApplicationWrites,
    ulong OutboundBacklogBytes,
    ushort DistinctQueuedStreams,
    ulong OldestQueuedSendAgeMicros,
    uint QueueDelayEwmaMicros,
    uint ActorServiceTimeEwmaMicros,
    uint BurstLimitHits,
    ulong BytesInFlight,
    ulong CongestionWindowBytes,
    uint RetainedSendBuffers,
    ulong RetainedSendBytes,
    bool HandshakeConfirmed,
    int LegalMaximumDatagrams,
    int ConfiguredMaximumDatagrams)
{
    internal const string CurrentObservationContractVersion =
        "adaptive-runtime-queued-send-burst-observation-v1";
    internal const string CurrentRuleVersion =
        "queued-send-burst-shadow-neutral-v1";
}

internal readonly record struct QuicQueuedSendBurstEvidence(
    QuicQueuedSendBurstObservationMode Mode,
    QuicQueuedSendBurstObservation Observation,
    QuicAdaptiveRuntimeStage1AxisDecision Decision,
    int LegalMaximumDatagrams,
    int AppliedMaximumDatagrams,
    int EmittedDatagrams,
    int QueuedWritesBefore,
    int QueuedWritesAfter,
    ulong QueuedBytesBefore,
    ulong QueuedBytesAfter,
    bool FollowOnWakeRequired,
    long? FollowOnWakeDueTicks,
    ulong FollowOnWakeGeneration,
    QuicApplicationSendRecoveryFlushOutcome Outcome,
    QuicSendPolicyBlockedReason BlockedReason)
{
    internal QuicQueuedSendBurstEvidence(
        QuicQueuedSendBurstObservationMode Mode,
        QuicQueuedSendBurstObservation Observation,
        QuicAdaptiveRuntimeStage1AxisDecision Decision,
        int LegalMaximumDatagrams,
        int AppliedMaximumDatagrams,
        int EmittedDatagrams,
        int QueuedWritesBefore,
        int QueuedWritesAfter,
        QuicApplicationSendRecoveryFlushOutcome Outcome,
        QuicSendPolicyBlockedReason BlockedReason)
        : this(
            Mode,
            Observation,
            Decision,
            LegalMaximumDatagrams,
            AppliedMaximumDatagrams,
            EmittedDatagrams,
            QueuedWritesBefore,
            QueuedWritesAfter,
            QueuedBytesBefore: Observation.OutboundBacklogBytes,
            QueuedBytesAfter: 0,
            FollowOnWakeRequired: false,
            FollowOnWakeDueTicks: null,
            FollowOnWakeGeneration: 0,
            Outcome,
            BlockedReason)
    {
    }
}

internal interface IQuicQueuedSendBurstEvidenceSink
{
    bool TryPublish(in QuicQueuedSendBurstEvidence evidence);
}

internal static class QuicQueuedSendBurstPolicy
{
    private const QuicQueuedSendBurstSignalMask RequiredSignalMask =
        QuicQueuedSendBurstSignalMask.QueuedApplicationWrites
        | QuicQueuedSendBurstSignalMask.OutboundBacklogBytes
        | QuicQueuedSendBurstSignalMask.DistinctQueuedStreams
        | QuicQueuedSendBurstSignalMask.OldestQueuedSendAge
        | QuicQueuedSendBurstSignalMask.QueueDelayEwma
        | QuicQueuedSendBurstSignalMask.ActorServiceTimeEwma
        | QuicQueuedSendBurstSignalMask.BurstLimitHits
        | QuicQueuedSendBurstSignalMask.Congestion
        | QuicQueuedSendBurstSignalMask.RetainedSendState
        | QuicQueuedSendBurstSignalMask.Handshake
        | QuicQueuedSendBurstSignalMask.LegalMaximumDatagrams
        | QuicQueuedSendBurstSignalMask.Lifecycle;

    internal const string CurrentSnapshotVersion =
        "adaptive-runtime-queued-send-burst-snapshot-v1";
    internal const string CurrentReasonVersion =
        "adaptive-runtime-queued-send-burst-reasons-v1";
    internal const string CurrentProvenanceVersion =
        "adaptive-runtime-queued-send-burst-provenance-v1";

    internal static QuicQueuedApplicationSendBudget Apply(
        QuicQueuedSendBurstPolicyMode mode,
        QuicQueuedApplicationSendBudget legalBudget)
    {
        ValidateMode(mode);
        if (!legalBudget.CanSendQueuedApplicationData)
        {
            return legalBudget;
        }

        int maximumDatagrams =
            mode == QuicQueuedSendBurstPolicyMode.SingleDatagram
                ? 1
                : legalBudget.MaxDatagrams;
        return QuicQueuedApplicationSendBudget.Allowed(
            Math.Min(legalBudget.MaxDatagrams, maximumDatagrams),
            legalBudget.MaxPayloadBytes);
    }

    internal static void ValidateMode(QuicQueuedSendBurstPolicyMode mode)
    {
        if (mode is < QuicQueuedSendBurstPolicyMode.LegacyCurrent
            or > QuicQueuedSendBurstPolicyMode.SingleDatagram)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicAdaptiveRuntimeStage1AxisDecision Evaluate(
        in QuicQueuedSendBurstObservation observation,
        QuicQueuedSendBurstObservationMode observationMode,
        bool hasForcedValue,
        QuicQueuedSendBurstPolicyMode forcedValue,
        in QuicQueuedApplicationSendBudget legalBudget)
    {
        if (observation.TurnSequence == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(observation),
                "Queued-send burst observations require a nonzero actor-turn sequence.");
        }

        if (observationMode is < QuicQueuedSendBurstObservationMode.Disabled
            or > QuicQueuedSendBurstObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(observationMode));
        }

        if (hasForcedValue)
        {
            ValidateMode(forcedValue);
        }

        QuicAdaptiveRuntimeStage1Validity validity = GetValidity(in observation);
        QuicQueuedSendBurstReason reason = GetReason(in observation, validity);
        QuicAdaptiveRuntimeStage1PolicyValue shadowRecommendation =
            validity == QuicAdaptiveRuntimeStage1Validity.None
                ? QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                : QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram;
        bool hasShadowRecommendation =
            observationMode == QuicQueuedSendBurstObservationMode.Shadow;
        QuicAdaptiveRuntimeStage1PolicyValue forcedStage1Value =
            ToStage1Value(forcedValue);
        QuicAdaptiveRuntimeStage1SafetyOverrideReason safetyOverrideReason =
            GetSafetyOverride(in observation, in legalBudget, hasForcedValue);

        QuicAdaptiveRuntimeStage1PolicyValue selectedValue;
        QuicAdaptiveRuntimeStage1PolicyValue appliedValue;
        QuicAdaptiveRuntimeStage1SelectionSource selectionSource;
        if (safetyOverrideReason != QuicAdaptiveRuntimeStage1SafetyOverrideReason.None)
        {
            selectedValue = forcedStage1Value;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride;
            reason = safetyOverrideReason switch
            {
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Disposal =>
                    QuicQueuedSendBurstReason.DisposalGuard,
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Terminal =>
                    QuicQueuedSendBurstReason.TerminalGuard,
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Recovery =>
                    QuicQueuedSendBurstReason.RecoveryGuard,
                _ => QuicQueuedSendBurstReason.ResourceGuard,
            };
        }
        else if (hasForcedValue)
        {
            selectedValue = forcedStage1Value;
            appliedValue = forcedStage1Value;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.Forced;
            reason = QuicQueuedSendBurstReason.Forced;
        }
        else if (hasShadowRecommendation)
        {
            selectedValue = shadowRecommendation;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule;
            if (validity == QuicAdaptiveRuntimeStage1Validity.None)
            {
                reason = QuicQueuedSendBurstReason.ShadowLegacyCurrent;
            }
        }
        else
        {
            selectedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.LegacySelector;
            reason = observationMode == QuicQueuedSendBurstObservationMode.ObserveOnly
                ? QuicQueuedSendBurstReason.ObserveOnly
                : QuicQueuedSendBurstReason.LegacyCurrent;
        }

        bool terminal =
            (observation.LifecycleFlags
                & (QuicAdaptiveRuntimeLifecycle.Terminal
                    | QuicAdaptiveRuntimeLifecycle.Disposed)) != 0;
        QuicAdaptiveRuntimeStage1LatchState latchState;
        QuicAdaptiveRuntimeStage1FallbackState fallbackState;
        if (terminal)
        {
            latchState = QuicAdaptiveRuntimeStage1LatchState.Terminal;
            fallbackState = QuicAdaptiveRuntimeStage1FallbackState.Terminal;
        }
        else if (validity == QuicAdaptiveRuntimeStage1Validity.None)
        {
            latchState = QuicAdaptiveRuntimeStage1LatchState.Completed;
            fallbackState = QuicAdaptiveRuntimeStage1FallbackState.NotRequired;
        }
        else
        {
            latchState = QuicAdaptiveRuntimeStage1LatchState.Fallback;
            fallbackState = QuicAdaptiveRuntimeStage1FallbackState.Applied;
        }

        return new QuicAdaptiveRuntimeStage1AxisDecision(
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
            observation.ObservationContractVersion,
            observation.RuleVersion,
            CurrentSnapshotVersion,
            CurrentReasonVersion,
            CurrentProvenanceVersion,
            validity,
            hasForcedValue,
            forcedStage1Value,
            hasShadowRecommendation,
            shadowRecommendation,
            selectedValue,
            appliedValue,
            selectionSource,
            (ushort)reason,
            safetyOverrideReason,
            QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
            QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn,
            latchState,
            fallbackState,
            observation.TurnSequence,
            observation.TurnSequence);
    }

    private static QuicAdaptiveRuntimeStage1PolicyValue ToStage1Value(
        QuicQueuedSendBurstPolicyMode mode)
        => mode switch
        {
            QuicQueuedSendBurstPolicyMode.LegacyCurrent =>
                QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            QuicQueuedSendBurstPolicyMode.SingleDatagram =>
                QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };

    private static QuicAdaptiveRuntimeStage1Validity GetValidity(
        in QuicQueuedSendBurstObservation observation)
    {
        QuicAdaptiveRuntimeStage1Validity validity = QuicAdaptiveRuntimeStage1Validity.None;
        if ((observation.MissingSignalMask & RequiredSignalMask) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Missing;
        }

        if ((observation.StaleSignalMask & RequiredSignalMask) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Stale;
        }

        if ((observation.Conditions
            & QuicQueuedSendBurstObservationCondition.ArithmeticSaturated) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Saturated;
        }

        if ((observation.Conditions
            & QuicQueuedSendBurstObservationCondition.Contradictory) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Contradictory;
        }

        if ((observation.Conditions
            & QuicQueuedSendBurstObservationCondition.OutOfDomain) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.OutOfDomain;
        }

        return validity;
    }

    private static QuicQueuedSendBurstReason GetReason(
        in QuicQueuedSendBurstObservation observation,
        QuicAdaptiveRuntimeStage1Validity validity)
    {
        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return QuicQueuedSendBurstReason.DisposalGuard;
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return QuicQueuedSendBurstReason.TerminalGuard;
        }

        if ((observation.Conditions
            & QuicQueuedSendBurstObservationCondition.RecoveryUnstable) != 0)
        {
            return QuicQueuedSendBurstReason.RecoveryGuard;
        }

        if ((observation.Conditions
            & QuicQueuedSendBurstObservationCondition.ResourceConstrained) != 0)
        {
            return QuicQueuedSendBurstReason.ResourceGuard;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Missing) != 0)
        {
            return QuicQueuedSendBurstReason.MissingSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Stale) != 0)
        {
            return QuicQueuedSendBurstReason.StaleSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Saturated) != 0)
        {
            return QuicQueuedSendBurstReason.ArithmeticSaturated;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Contradictory) != 0)
        {
            return QuicQueuedSendBurstReason.Contradictory;
        }

        return (validity & QuicAdaptiveRuntimeStage1Validity.OutOfDomain) != 0
            ? QuicQueuedSendBurstReason.OutOfDomain
            : QuicQueuedSendBurstReason.LegacyCurrent;
    }

    private static QuicAdaptiveRuntimeStage1SafetyOverrideReason GetSafetyOverride(
        in QuicQueuedSendBurstObservation observation,
        in QuicQueuedApplicationSendBudget legalBudget,
        bool hasForcedValue)
    {
        if (!hasForcedValue)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.None;
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.Disposal;
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.Terminal;
        }

        if (legalBudget.CanSendQueuedApplicationData)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.None;
        }

        return legalBudget.BlockedReason switch
        {
            QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending =>
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Recovery,
            QuicSendPolicyBlockedReason.CongestionLimited =>
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Congestion,
            QuicSendPolicyBlockedReason.OrdinaryPacketsUnavailable =>
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Pacing,
            _ => QuicAdaptiveRuntimeStage1SafetyOverrideReason.Resource,
        };
    }
}
