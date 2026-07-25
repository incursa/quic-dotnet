// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicApplicationSendBatchPolicyMode : byte
{
    LegacyCurrent = 0,
    SingleEligible = 1,
}

internal enum QuicApplicationSendBatchObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

[Flags]
internal enum QuicApplicationSendBatchSignalMask : ushort
{
    None = 0,
    MaximumPayloadBytes = 1 << 0,
    EligibleWriteCount = 1 << 1,
    EligibleWriteBytes = 1 << 2,
    QueuedApplicationWrites = 1 << 3,
    OutboundBacklogBytes = 1 << 4,
    DistinctQueuedStreams = 1 << 5,
    OldestQueuedSendAge = 1 << 6,
    QueueDelayEwma = 1 << 7,
    ActorServiceTimeEwma = 1 << 8,
    Congestion = 1 << 9,
    RetainedSendState = 1 << 10,
    Lifecycle = 1 << 11,
}

[Flags]
internal enum QuicApplicationSendBatchObservationCondition : byte
{
    None = 0,
    ArithmeticSaturated = 1 << 0,
    Contradictory = 1 << 1,
    OutOfDomain = 1 << 2,
}

internal enum QuicApplicationSendBatchReason : ushort
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
    TerminalGuard = 9,
    DisposalGuard = 10,
    ResourceGuard = 11,
}

internal readonly record struct QuicApplicationSendBatchObservation(
    ulong PlanSequence,
    long CapturedAtTicks,
    string ObservationContractVersion,
    string RuleVersion,
    QuicApplicationSendBatchSignalMask MissingSignalMask,
    QuicApplicationSendBatchSignalMask StaleSignalMask,
    QuicApplicationSendBatchObservationCondition Conditions,
    QuicAdaptiveRuntimeLifecycle LifecycleFlags,
    int MaximumPayloadBytes,
    int EligibleWriteCount,
    int EligibleWriteBytes,
    uint QueuedApplicationWrites,
    ulong OutboundBacklogBytes,
    ushort DistinctQueuedStreams,
    ulong OldestQueuedSendAgeMicros,
    uint QueueDelayEwmaMicros,
    uint ActorServiceTimeEwmaMicros,
    ulong BytesInFlight,
    ulong CongestionWindowBytes,
    uint RetainedSendBuffers,
    ulong RetainedSendBytes)
{
    internal const string CurrentObservationContractVersion =
        "adaptive-runtime-application-send-batch-observation-v1";
    internal const string CurrentRuleVersion =
        "application-send-batch-shadow-neutral-v1";
}

internal readonly record struct QuicApplicationSendBatchEvidence(
    QuicApplicationSendBatchObservationMode Mode,
    QuicApplicationSendBatchObservation Observation,
    QuicAdaptiveRuntimeStage1AxisDecision Decision,
    QuicApplicationSendBatchOperationEvidence OperationEvidence,
    QuicApplicationSendPlanKind PlanKind,
    int AppliedWriteCount,
    bool HasMoreQueuedData,
    QuicSendPolicyBlockedReason BlockedReason);

internal interface IQuicApplicationSendBatchEvidenceSink
{
    bool TryPublish(in QuicApplicationSendBatchEvidence evidence);
}

internal static class QuicApplicationSendBatchPolicy
{
    private const QuicApplicationSendBatchSignalMask RequiredSignalMask =
        QuicApplicationSendBatchSignalMask.MaximumPayloadBytes
        | QuicApplicationSendBatchSignalMask.EligibleWriteCount
        | QuicApplicationSendBatchSignalMask.EligibleWriteBytes
        | QuicApplicationSendBatchSignalMask.QueuedApplicationWrites
        | QuicApplicationSendBatchSignalMask.OutboundBacklogBytes
        | QuicApplicationSendBatchSignalMask.DistinctQueuedStreams
        | QuicApplicationSendBatchSignalMask.OldestQueuedSendAge
        | QuicApplicationSendBatchSignalMask.QueueDelayEwma
        | QuicApplicationSendBatchSignalMask.ActorServiceTimeEwma
        | QuicApplicationSendBatchSignalMask.Congestion
        | QuicApplicationSendBatchSignalMask.RetainedSendState
        | QuicApplicationSendBatchSignalMask.Lifecycle;

    internal const string CurrentSnapshotVersion =
        "adaptive-runtime-application-send-batch-snapshot-v1";
    internal const string CurrentReasonVersion =
        "adaptive-runtime-application-send-batch-reasons-v1";
    internal const string CurrentProvenanceVersion =
        "adaptive-runtime-application-send-batch-provenance-v2";

    internal static QuicApplicationSendBatchOperationEvidence
        CreateOperationEvidence(
            ulong epochSequence,
            in QuicApplicationSendBatchObservation observation,
            in QuicAdaptiveRuntimeStage1AxisDecision decision,
            in QuicApplicationSendPlan plan)
    {
        QuicAdaptiveRuntimeOperationEligibilityResult eligibilityResult =
            QuicAdaptiveRuntimeOperationEligibilityResult.Eligible;
        QuicAdaptiveRuntimeOperationEligibilityReason eligibilityReason =
            QuicAdaptiveRuntimeOperationEligibilityReason.Eligible;

        if (decision.SafetyOverrideApplied)
        {
            eligibilityResult =
                QuicAdaptiveRuntimeOperationEligibilityResult.Clamped;
            eligibilityReason = decision.SafetyOverrideReason switch
            {
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Terminal
                    or QuicAdaptiveRuntimeStage1SafetyOverrideReason.Disposal =>
                    QuicAdaptiveRuntimeOperationEligibilityReason.LifecycleGuard,
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.Resource =>
                    QuicAdaptiveRuntimeOperationEligibilityReason.ResourceGuard,
                _ => QuicAdaptiveRuntimeOperationEligibilityReason.SafetyOverride,
            };
        }
        else if (plan.Kind == QuicApplicationSendPlanKind.None)
        {
            eligibilityResult =
                QuicAdaptiveRuntimeOperationEligibilityResult.Ineligible;
            eligibilityReason =
                plan.BlockedReason
                    is QuicSendPolicyBlockedReason.InvalidPayloadBudget
                        or QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend
                    ? QuicAdaptiveRuntimeOperationEligibilityReason.InvalidInput
                    : QuicAdaptiveRuntimeOperationEligibilityReason.ResourceGuard;
        }
        else if (plan.EligibleWriteCount <= 1)
        {
            eligibilityReason =
                QuicAdaptiveRuntimeOperationEligibilityReason.StructurallyInactive;
        }

        QuicApplicationSendBatchMechanismEvent mechanismEvent =
            GetMechanismEvent(in decision, in plan);
        if (mechanismEvent == QuicApplicationSendBatchMechanismEvent.Unclassifiable)
        {
            eligibilityResult =
                QuicAdaptiveRuntimeOperationEligibilityResult.Ineligible;
            eligibilityReason =
                QuicAdaptiveRuntimeOperationEligibilityReason.UnclassifiableEvidence;
        }

        return new(
            epochSequence,
            observation.PlanSequence,
            observation.PlanSequence,
            decision.SelectedValue,
            eligibilityResult,
            eligibilityReason,
            mechanismEvent,
            ToUnsigned(plan.EligibleWriteCount),
            ToUnsigned(plan.SelectedWriteCount),
            ToUnsigned(plan.EligibleWriteBytes),
            ToUnsigned(plan.SelectedWriteBytes));
    }

    internal static int SelectWriteCount(
        QuicApplicationSendBatchPolicyMode mode,
        int legalEligibleWriteCount)
    {
        ValidateMode(mode);

        if (legalEligibleWriteCount <= 0)
        {
            return 0;
        }

        return mode == QuicApplicationSendBatchPolicyMode.SingleEligible
            ? 1
            : legalEligibleWriteCount;
    }

    private static QuicApplicationSendBatchMechanismEvent GetMechanismEvent(
        in QuicAdaptiveRuntimeStage1AxisDecision decision,
        in QuicApplicationSendPlan plan)
    {
        if (plan.Kind == QuicApplicationSendPlanKind.None)
        {
            return QuicApplicationSendBatchMechanismEvent.NoPacketPlan;
        }

        if (plan.SelectedWriteCount <= 0
            || plan.SelectedWriteCount > plan.EligibleWriteCount
            || plan.SelectedWriteBytes < 0
            || plan.SelectedWriteBytes > plan.EligibleWriteBytes)
        {
            return QuicApplicationSendBatchMechanismEvent.Unclassifiable;
        }

        if (plan.SelectedWriteCount == plan.EligibleWriteCount)
        {
            return QuicApplicationSendBatchMechanismEvent.LegalEligiblePrefixUsed;
        }

        return decision.AppliedValue
                    == QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible
                && plan.SelectedWriteCount == 1
                && plan.EligibleWriteCount > 1
            ? QuicApplicationSendBatchMechanismEvent.SingleEligiblePrefixUsed
            : QuicApplicationSendBatchMechanismEvent.Unclassifiable;
    }

    private static uint ToUnsigned(int value)
        => value <= 0 ? 0U : (uint)value;

    internal static void ValidateMode(QuicApplicationSendBatchPolicyMode mode)
    {
        if (mode is < QuicApplicationSendBatchPolicyMode.LegacyCurrent
            or > QuicApplicationSendBatchPolicyMode.SingleEligible)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicAdaptiveRuntimeStage1AxisDecision Evaluate(
        in QuicApplicationSendBatchObservation observation,
        QuicApplicationSendBatchObservationMode observationMode,
        bool hasForcedValue,
        QuicApplicationSendBatchPolicyMode forcedValue,
        in QuicApplicationSendPlan plan)
    {
        if (observation.PlanSequence == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(observation),
                "Application-send batch observations require a nonzero packet-plan sequence.");
        }

        if (observationMode is < QuicApplicationSendBatchObservationMode.Disabled
            or > QuicApplicationSendBatchObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(observationMode));
        }

        if (hasForcedValue)
        {
            _ = SelectWriteCount(forcedValue, Math.Max(1, observation.EligibleWriteCount));
        }

        QuicAdaptiveRuntimeStage1Validity validity = GetValidity(in observation);
        QuicApplicationSendBatchReason reason = GetReason(in observation, validity);
        QuicAdaptiveRuntimeStage1PolicyValue shadowRecommendation =
            validity == QuicAdaptiveRuntimeStage1Validity.None
                ? QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                : QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible;
        bool hasShadowRecommendation =
            observationMode == QuicApplicationSendBatchObservationMode.Shadow;

        QuicAdaptiveRuntimeStage1PolicyValue forcedStage1Value =
            ToStage1Value(forcedValue);
        QuicAdaptiveRuntimeStage1PolicyValue selectedValue;
        QuicAdaptiveRuntimeStage1PolicyValue appliedValue;
        QuicAdaptiveRuntimeStage1SelectionSource selectionSource;
        QuicAdaptiveRuntimeStage1SafetyOverrideReason safetyOverrideReason =
            GetSafetyOverride(in observation, in plan, hasForcedValue);

        if (safetyOverrideReason != QuicAdaptiveRuntimeStage1SafetyOverrideReason.None)
        {
            selectedValue = forcedStage1Value;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride;
            reason = plan.BlockedReason == QuicSendPolicyBlockedReason.None
                ? reason
                : QuicApplicationSendBatchReason.ResourceGuard;
        }
        else if (hasForcedValue)
        {
            selectedValue = forcedStage1Value;
            appliedValue = forcedStage1Value;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.Forced;
            reason = QuicApplicationSendBatchReason.Forced;
        }
        else if (hasShadowRecommendation)
        {
            selectedValue = shadowRecommendation;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule;
            if (validity == QuicAdaptiveRuntimeStage1Validity.None)
            {
                reason = QuicApplicationSendBatchReason.ShadowLegacyCurrent;
            }
        }
        else
        {
            selectedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.LegacySelector;
            reason = observationMode == QuicApplicationSendBatchObservationMode.ObserveOnly
                ? QuicApplicationSendBatchReason.ObserveOnly
                : QuicApplicationSendBatchReason.LegacyCurrent;
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
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
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
            QuicAdaptiveRuntimeStage1DecisionBoundary.PacketPlan,
            QuicAdaptiveRuntimeStage1LatchLifetime.PacketPlan,
            latchState,
            fallbackState,
            observation.PlanSequence,
            observation.PlanSequence);
    }

    private static QuicAdaptiveRuntimeStage1PolicyValue ToStage1Value(
        QuicApplicationSendBatchPolicyMode mode)
        => mode switch
        {
            QuicApplicationSendBatchPolicyMode.LegacyCurrent =>
                QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.SingleEligible =>
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };

    private static QuicAdaptiveRuntimeStage1Validity GetValidity(
        in QuicApplicationSendBatchObservation observation)
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
            & QuicApplicationSendBatchObservationCondition.ArithmeticSaturated) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Saturated;
        }

        if ((observation.Conditions
            & QuicApplicationSendBatchObservationCondition.Contradictory) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Contradictory;
        }

        if ((observation.Conditions
            & QuicApplicationSendBatchObservationCondition.OutOfDomain) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.OutOfDomain;
        }

        return validity;
    }

    private static QuicApplicationSendBatchReason GetReason(
        in QuicApplicationSendBatchObservation observation,
        QuicAdaptiveRuntimeStage1Validity validity)
    {
        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return QuicApplicationSendBatchReason.DisposalGuard;
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return QuicApplicationSendBatchReason.TerminalGuard;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Missing) != 0)
        {
            return QuicApplicationSendBatchReason.MissingSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Stale) != 0)
        {
            return QuicApplicationSendBatchReason.StaleSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Saturated) != 0)
        {
            return QuicApplicationSendBatchReason.ArithmeticSaturated;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Contradictory) != 0)
        {
            return QuicApplicationSendBatchReason.Contradictory;
        }

        return (validity & QuicAdaptiveRuntimeStage1Validity.OutOfDomain) != 0
            ? QuicApplicationSendBatchReason.OutOfDomain
            : QuicApplicationSendBatchReason.LegacyCurrent;
    }

    private static QuicAdaptiveRuntimeStage1SafetyOverrideReason GetSafetyOverride(
        in QuicApplicationSendBatchObservation observation,
        in QuicApplicationSendPlan plan,
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

        return plan.Kind == QuicApplicationSendPlanKind.None
            ? QuicAdaptiveRuntimeStage1SafetyOverrideReason.Resource
            : QuicAdaptiveRuntimeStage1SafetyOverrideReason.None;
    }
}
