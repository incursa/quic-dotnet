// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicOversizedWriteAdmissionPolicyMode : byte
{
    LegacyCurrent = 0,
    SingleFragment = 1,
    BoundedMultiFragment = 2,
}

internal enum QuicOversizedWriteAdmissionObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

[Flags]
internal enum QuicOversizedWriteAdmissionSignalMask : ushort
{
    None = 0,
    LogicalWrite = 1 << 0,
    MaximumPayload = 1 << 1,
    MaximumFragment = 1 << 2,
    DistinctObservedStreams = 1 << 3,
    QueuedApplicationWrites = 1 << 4,
    QueueDelayEwma = 1 << 5,
    ActorServiceTimeEwma = 1 << 6,
    Congestion = 1 << 7,
    RetainedSendState = 1 << 8,
    ContinuationDispatcher = 1 << 9,
    LegacySelector = 1 << 10,
    LegalMaximumQuantum = 1 << 11,
    Lifecycle = 1 << 12,
}

[Flags]
internal enum QuicOversizedWriteAdmissionCondition : byte
{
    None = 0,
    ArithmeticSaturated = 1 << 0,
    Contradictory = 1 << 1,
    OutOfDomain = 1 << 2,
    RecoveryUnstable = 1 << 3,
    ResourceConstrained = 1 << 4,
}

internal enum QuicOversizedWriteAdmissionReason : ushort
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

internal enum QuicOversizedWriteOutcome : byte
{
    Completed = 0,
    Canceled = 1,
    Terminal = 2,
    Disposed = 3,
    Failed = 4,
    ContinuationPostFailed = 5,
}

internal readonly record struct QuicOversizedWriteAdmissionObservation(
    ulong LogicalWriteSequence,
    long CapturedAtTicks,
    string ObservationContractVersion,
    string RuleVersion,
    QuicOversizedWriteAdmissionSignalMask MissingSignalMask,
    QuicOversizedWriteAdmissionSignalMask StaleSignalMask,
    QuicOversizedWriteAdmissionCondition Conditions,
    QuicAdaptiveRuntimeLifecycle LifecycleFlags,
    int LogicalWriteBytes,
    int LogicalRemainingBytes,
    int MaximumApplicationPayloadBytes,
    int MaximumFragmentBytes,
    ushort DistinctObservedStreams,
    uint QueuedApplicationWrites,
    uint QueueDelayEwmaMicros,
    uint ActorServiceTimeEwmaMicros,
    ulong BytesInFlight,
    ulong CongestionWindowBytes,
    uint RetainedSendBuffers,
    ulong RetainedSendBytes,
    bool ContinuationDispatcherAvailable,
    int LegacySelectedChunkQuantum,
    int LegalMaximumChunkQuantum)
{
    internal const string CurrentObservationContractVersion =
        "adaptive-runtime-oversized-write-admission-observation-v1";
    internal const string CurrentRuleVersion =
        "oversized-write-admission-shadow-neutral-v1";
}

internal readonly record struct QuicOversizedWriteAdmissionResolution(
    QuicOversizedWriteAdmissionObservationMode Mode,
    QuicOversizedWriteAdmissionObservation Observation,
    QuicAdaptiveRuntimeStage1AxisDecision Decision,
    int AppliedChunkQuantum)
{
    internal bool UseMultiplexedPath => AppliedChunkQuantum > 1;
}

internal readonly record struct QuicOversizedWriteAdmissionEvidence(
    QuicOversizedWriteAdmissionObservationMode Mode,
    QuicOversizedWriteAdmissionObservation Observation,
    QuicAdaptiveRuntimeStage1AxisDecision Decision,
    int AppliedChunkQuantum,
    int CommittedFragments,
    int ContinuationPosts,
    ulong CommittedBytes,
    ulong CompletionLatencyMicros,
    QuicOversizedWriteOutcome Outcome);

internal interface IQuicOversizedWriteAdmissionEvidenceSink
{
    bool TryPublish(in QuicOversizedWriteAdmissionEvidence evidence);
}

internal static class QuicOversizedWriteAdmissionPolicy
{
    private const QuicOversizedWriteAdmissionSignalMask RequiredSignalMask =
        QuicOversizedWriteAdmissionSignalMask.LogicalWrite
        | QuicOversizedWriteAdmissionSignalMask.MaximumPayload
        | QuicOversizedWriteAdmissionSignalMask.MaximumFragment
        | QuicOversizedWriteAdmissionSignalMask.DistinctObservedStreams
        | QuicOversizedWriteAdmissionSignalMask.QueuedApplicationWrites
        | QuicOversizedWriteAdmissionSignalMask.QueueDelayEwma
        | QuicOversizedWriteAdmissionSignalMask.ActorServiceTimeEwma
        | QuicOversizedWriteAdmissionSignalMask.Congestion
        | QuicOversizedWriteAdmissionSignalMask.RetainedSendState
        | QuicOversizedWriteAdmissionSignalMask.ContinuationDispatcher
        | QuicOversizedWriteAdmissionSignalMask.LegacySelector
        | QuicOversizedWriteAdmissionSignalMask.LegalMaximumQuantum
        | QuicOversizedWriteAdmissionSignalMask.Lifecycle;

    internal const int SingleFragmentChunkQuantum = 1;
    internal const int BoundedMultiFragmentChunkQuantum = 2;
    internal const string CurrentSnapshotVersion =
        "adaptive-runtime-oversized-write-admission-snapshot-v1";
    internal const string CurrentReasonVersion =
        "adaptive-runtime-oversized-write-admission-reasons-v1";
    internal const string CurrentProvenanceVersion =
        "adaptive-runtime-oversized-write-admission-provenance-v1";

    internal static void ValidateMode(QuicOversizedWriteAdmissionPolicyMode mode)
    {
        if (mode is < QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent
            or > QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicOversizedWriteAdmissionResolution Resolve(
        in QuicOversizedWriteAdmissionObservation observation,
        QuicOversizedWriteAdmissionObservationMode observationMode,
        bool hasForcedValue,
        QuicOversizedWriteAdmissionPolicyMode forcedValue)
    {
        QuicAdaptiveRuntimeStage1AxisDecision decision = Evaluate(
            in observation,
            observationMode,
            hasForcedValue,
            forcedValue);
        int appliedChunkQuantum = decision.AppliedValue switch
        {
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent =>
                observation.LegacySelectedChunkQuantum,
            QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment =>
                SingleFragmentChunkQuantum,
            QuicAdaptiveRuntimeStage1PolicyValue.BoundedMultiFragment =>
                Math.Min(
                    BoundedMultiFragmentChunkQuantum,
                    observation.LegalMaximumChunkQuantum),
            _ => throw new InvalidOperationException(
                "The oversized-write policy resolved an unsupported Stage 1 value."),
        };

        return new QuicOversizedWriteAdmissionResolution(
            observationMode,
            observation,
            decision,
            appliedChunkQuantum);
    }

    internal static QuicAdaptiveRuntimeStage1AxisDecision Complete(
        in QuicAdaptiveRuntimeStage1AxisDecision decision,
        QuicOversizedWriteOutcome outcome)
    {
        if (decision.Axis != QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)
        {
            throw new ArgumentException(
                "Only an oversized-write admission decision can complete this latch.",
                nameof(decision));
        }

        bool terminal = outcome is QuicOversizedWriteOutcome.Terminal
            or QuicOversizedWriteOutcome.Disposed;
        return decision with
        {
            LatchState = terminal
                ? QuicAdaptiveRuntimeStage1LatchState.Terminal
                : QuicAdaptiveRuntimeStage1LatchState.Completed,
            FallbackState = terminal
                ? QuicAdaptiveRuntimeStage1FallbackState.Terminal
                : decision.FallbackState,
        };
    }

    private static QuicAdaptiveRuntimeStage1AxisDecision Evaluate(
        in QuicOversizedWriteAdmissionObservation observation,
        QuicOversizedWriteAdmissionObservationMode observationMode,
        bool hasForcedValue,
        QuicOversizedWriteAdmissionPolicyMode forcedValue)
    {
        if (observation.LogicalWriteSequence == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(observation),
                "Oversized-write observations require a nonzero logical-write sequence.");
        }

        if (observationMode is < QuicOversizedWriteAdmissionObservationMode.Disabled
            or > QuicOversizedWriteAdmissionObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(observationMode));
        }

        if (hasForcedValue)
        {
            ValidateMode(forcedValue);
        }

        ValidateQuantum(observation.LegacySelectedChunkQuantum, nameof(observation));
        ValidateQuantum(observation.LegalMaximumChunkQuantum, nameof(observation));

        QuicAdaptiveRuntimeStage1Validity validity = GetValidity(in observation);
        QuicOversizedWriteAdmissionReason reason = GetReason(in observation, validity);
        QuicAdaptiveRuntimeStage1PolicyValue shadowRecommendation =
            validity == QuicAdaptiveRuntimeStage1Validity.None
                ? QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                : QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment;
        bool hasShadowRecommendation =
            observationMode == QuicOversizedWriteAdmissionObservationMode.Shadow;
        QuicAdaptiveRuntimeStage1PolicyValue forcedStage1Value =
            ToStage1Value(forcedValue);
        QuicAdaptiveRuntimeStage1SafetyOverrideReason safetyOverrideReason =
            GetSafetyOverride(in observation, validity, hasForcedValue, forcedValue);

        QuicAdaptiveRuntimeStage1PolicyValue selectedValue;
        QuicAdaptiveRuntimeStage1PolicyValue appliedValue;
        QuicAdaptiveRuntimeStage1SelectionSource selectionSource;
        if (safetyOverrideReason != QuicAdaptiveRuntimeStage1SafetyOverrideReason.None)
        {
            selectedValue = forcedStage1Value;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride;
            reason = safetyOverrideReason switch
            {
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Disposal =>
                    QuicOversizedWriteAdmissionReason.DisposalGuard,
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Terminal =>
                    QuicOversizedWriteAdmissionReason.TerminalGuard,
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Recovery =>
                    QuicOversizedWriteAdmissionReason.RecoveryGuard,
                _ => QuicOversizedWriteAdmissionReason.ResourceGuard,
            };
        }
        else if (hasForcedValue)
        {
            selectedValue = forcedStage1Value;
            appliedValue = forcedStage1Value;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.Forced;
            reason = QuicOversizedWriteAdmissionReason.Forced;
        }
        else if (hasShadowRecommendation)
        {
            selectedValue = shadowRecommendation;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule;
            if (validity == QuicAdaptiveRuntimeStage1Validity.None)
            {
                reason = QuicOversizedWriteAdmissionReason.ShadowLegacyCurrent;
            }
        }
        else
        {
            selectedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.LegacySelector;
            reason = observationMode == QuicOversizedWriteAdmissionObservationMode.ObserveOnly
                ? QuicOversizedWriteAdmissionReason.ObserveOnly
                : QuicOversizedWriteAdmissionReason.LegacyCurrent;
        }

        QuicAdaptiveRuntimeStage1FallbackState fallbackState =
            validity == QuicAdaptiveRuntimeStage1Validity.None
                ? QuicAdaptiveRuntimeStage1FallbackState.NotRequired
                : QuicAdaptiveRuntimeStage1FallbackState.Eligible;
        if (safetyOverrideReason != QuicAdaptiveRuntimeStage1SafetyOverrideReason.None)
        {
            fallbackState = QuicAdaptiveRuntimeStage1FallbackState.Applied;
        }

        return new QuicAdaptiveRuntimeStage1AxisDecision(
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum,
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
            QuicAdaptiveRuntimeStage1DecisionBoundary.LogicalWriteAdmission,
            QuicAdaptiveRuntimeStage1LatchLifetime.LogicalWrite,
            QuicAdaptiveRuntimeStage1LatchState.Latched,
            fallbackState,
            observation.LogicalWriteSequence,
            observation.LogicalWriteSequence);
    }

    private static void ValidateQuantum(int quantum, string parameterName)
    {
        if (quantum is < SingleFragmentChunkQuantum
            or > BoundedMultiFragmentChunkQuantum)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                "Oversized-write chunk quantum must be one or two.");
        }
    }

    private static QuicAdaptiveRuntimeStage1PolicyValue ToStage1Value(
        QuicOversizedWriteAdmissionPolicyMode mode)
        => mode switch
        {
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent =>
                QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment =>
                QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment,
            QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment =>
                QuicAdaptiveRuntimeStage1PolicyValue.BoundedMultiFragment,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };

    private static QuicAdaptiveRuntimeStage1Validity GetValidity(
        in QuicOversizedWriteAdmissionObservation observation)
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
            & QuicOversizedWriteAdmissionCondition.ArithmeticSaturated) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Saturated;
        }

        if ((observation.Conditions
            & QuicOversizedWriteAdmissionCondition.Contradictory) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Contradictory;
        }

        if ((observation.Conditions
            & QuicOversizedWriteAdmissionCondition.OutOfDomain) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.OutOfDomain;
        }

        return validity;
    }

    private static QuicOversizedWriteAdmissionReason GetReason(
        in QuicOversizedWriteAdmissionObservation observation,
        QuicAdaptiveRuntimeStage1Validity validity)
    {
        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return QuicOversizedWriteAdmissionReason.DisposalGuard;
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return QuicOversizedWriteAdmissionReason.TerminalGuard;
        }

        if ((observation.Conditions & QuicOversizedWriteAdmissionCondition.RecoveryUnstable) != 0)
        {
            return QuicOversizedWriteAdmissionReason.RecoveryGuard;
        }

        if ((observation.Conditions & QuicOversizedWriteAdmissionCondition.ResourceConstrained) != 0)
        {
            return QuicOversizedWriteAdmissionReason.ResourceGuard;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Missing) != 0)
        {
            return QuicOversizedWriteAdmissionReason.MissingSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Stale) != 0)
        {
            return QuicOversizedWriteAdmissionReason.StaleSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Saturated) != 0)
        {
            return QuicOversizedWriteAdmissionReason.ArithmeticSaturated;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Contradictory) != 0)
        {
            return QuicOversizedWriteAdmissionReason.Contradictory;
        }

        return (validity & QuicAdaptiveRuntimeStage1Validity.OutOfDomain) != 0
            ? QuicOversizedWriteAdmissionReason.OutOfDomain
            : QuicOversizedWriteAdmissionReason.LegacyCurrent;
    }

    private static QuicAdaptiveRuntimeStage1SafetyOverrideReason GetSafetyOverride(
        in QuicOversizedWriteAdmissionObservation observation,
        QuicAdaptiveRuntimeStage1Validity validity,
        bool hasForcedValue,
        QuicOversizedWriteAdmissionPolicyMode forcedValue)
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

        if (forcedValue != QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.None;
        }

        if ((observation.Conditions & QuicOversizedWriteAdmissionCondition.ResourceConstrained) != 0
            || !observation.ContinuationDispatcherAvailable
            || observation.LegalMaximumChunkQuantum < BoundedMultiFragmentChunkQuantum)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.Resource;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Contradictory) != 0)
        {
            return QuicAdaptiveRuntimeStage1SafetyOverrideReason.Contradictory;
        }

        return (validity & QuicAdaptiveRuntimeStage1Validity.OutOfDomain) != 0
            ? QuicAdaptiveRuntimeStage1SafetyOverrideReason.OutOfDomain
            : QuicAdaptiveRuntimeStage1SafetyOverrideReason.None;
    }
}
