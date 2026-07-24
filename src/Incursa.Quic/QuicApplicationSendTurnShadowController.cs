// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

[Flags]
internal enum QuicApplicationSendTurnSignalMask : ushort
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
    Lifecycle = 1 << 9,
    Recovery = 1 << 10,
    Resource = 1 << 11,
}

[Flags]
internal enum QuicApplicationSendTurnObservationCondition : byte
{
    None = 0,
    ArithmeticSaturated = 1 << 0,
    Contradictory = 1 << 1,
    OutOfDomain = 1 << 2,
    RecoveryUnstable = 1 << 3,
    ResourceConstrained = 1 << 4,
}

internal enum QuicApplicationSendTurnShadowState : byte
{
    LegacyCurrent = 0,
    Fallback = 1,
    Terminal = 2,
}

internal enum QuicApplicationSendTurnShadowReason : byte
{
    LegacyCurrent = 0,
    MissingSignal = 1,
    StaleSignal = 2,
    ContradictorySignals = 3,
    OutOfDomain = 4,
    RuleVersionMismatch = 5,
    ArithmeticSaturated = 6,
    TerminalStarted = 7,
    ResourceGuard = 8,
    RecoveryGuard = 9,
    CancellationOrDisposal = 10,
}

internal readonly record struct QuicApplicationSendTurnObservation(
    ulong TurnSequence,
    long CapturedAtTicks,
    string ObservationContractVersion,
    string PolicyRuleVersion,
    QuicApplicationSendTurnSignalMask MissingSignalMask,
    QuicApplicationSendTurnSignalMask StaleSignalMask,
    QuicApplicationSendTurnObservationCondition Conditions,
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
    ulong RetainedSendBytes)
{
    internal const string CurrentObservationContractVersion =
        "adaptive-runtime-application-send-turn-observation-v1";
    internal const string CurrentPolicyRuleVersion =
        "application-send-turn-shadow-neutral-v1";
}

internal readonly record struct QuicApplicationSendTurnPolicySnapshot(
    ulong SnapshotSequence,
    string SnapshotContractVersion,
    string ObservationContractVersion,
    string RuleVersion,
    string ReasonVersion,
    string ProvenanceVersion,
    string AxisId,
    ulong TurnSequence,
    QuicApplicationSendTurnShadowState PreviousState,
    QuicApplicationSendTurnShadowState State,
    bool Transitioned,
    QuicApplicationSendTurnPolicyMode AppliedPolicy,
    QuicApplicationSendTurnPolicyMode RecommendedPolicy,
    QuicApplicationSendTurnShadowReason Reason)
{
    internal const string CurrentSnapshotContractVersion =
        "adaptive-runtime-application-send-turn-snapshot-v1";
    internal const string CurrentReasonVersion =
        "adaptive-runtime-application-send-turn-reasons-v1";
    internal const string CurrentProvenanceVersion =
        "adaptive-runtime-application-send-turn-shadow-provenance-v1";
    internal const string CurrentAxisId = "application_send_turn_planning";
}

internal struct QuicApplicationSendTurnShadowController
{
    private const QuicApplicationSendTurnSignalMask RequiredSignalMask =
        QuicApplicationSendTurnSignalMask.QueuedApplicationWrites
        | QuicApplicationSendTurnSignalMask.OutboundBacklogBytes
        | QuicApplicationSendTurnSignalMask.DistinctQueuedStreams
        | QuicApplicationSendTurnSignalMask.OldestQueuedSendAge
        | QuicApplicationSendTurnSignalMask.QueueDelayEwma
        | QuicApplicationSendTurnSignalMask.ActorServiceTimeEwma
        | QuicApplicationSendTurnSignalMask.BurstLimitHits
        | QuicApplicationSendTurnSignalMask.Congestion
        | QuicApplicationSendTurnSignalMask.RetainedSendState
        | QuicApplicationSendTurnSignalMask.Lifecycle
        | QuicApplicationSendTurnSignalMask.Recovery
        | QuicApplicationSendTurnSignalMask.Resource;
    private const QuicAdaptiveRuntimeLifecycle PhaseMask =
        QuicAdaptiveRuntimeLifecycle.Establishing
        | QuicAdaptiveRuntimeLifecycle.Active
        | QuicAdaptiveRuntimeLifecycle.Closing
        | QuicAdaptiveRuntimeLifecycle.Draining
        | QuicAdaptiveRuntimeLifecycle.Discarded;

    private ulong lastTurnSequence;
    private ulong snapshotSequence;
    private QuicApplicationSendTurnShadowState state;

    internal bool TryEvaluate(
        in QuicApplicationSendTurnObservation observation,
        out QuicApplicationSendTurnPolicySnapshot snapshot)
    {
        snapshot = default;
        if (observation.TurnSequence == 0
            || observation.TurnSequence <= lastTurnSequence
            || snapshotSequence == ulong.MaxValue)
        {
            return false;
        }

        lastTurnSequence = observation.TurnSequence;

        if (state == QuicApplicationSendTurnShadowState.Terminal)
        {
            return Publish(
                in observation,
                QuicApplicationSendTurnShadowState.Terminal,
                QuicApplicationSendTurnPolicyMode.Conservative,
                QuicApplicationSendTurnShadowReason.TerminalStarted,
                out snapshot);
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return Publish(
                in observation,
                QuicApplicationSendTurnShadowState.Terminal,
                QuicApplicationSendTurnPolicyMode.Conservative,
                QuicApplicationSendTurnShadowReason.CancellationOrDisposal,
                out snapshot);
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return Publish(
                in observation,
                QuicApplicationSendTurnShadowState.Terminal,
                QuicApplicationSendTurnPolicyMode.Conservative,
                QuicApplicationSendTurnShadowReason.TerminalStarted,
                out snapshot);
        }

        if (!string.Equals(
                observation.ObservationContractVersion,
                QuicApplicationSendTurnObservation.CurrentObservationContractVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                observation.PolicyRuleVersion,
                QuicApplicationSendTurnObservation.CurrentPolicyRuleVersion,
                StringComparison.Ordinal))
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.RuleVersionMismatch,
                out snapshot);
        }

        if ((observation.MissingSignalMask & RequiredSignalMask) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.MissingSignal,
                out snapshot);
        }

        if ((observation.StaleSignalMask & RequiredSignalMask) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.StaleSignal,
                out snapshot);
        }

        if ((observation.Conditions & QuicApplicationSendTurnObservationCondition.ArithmeticSaturated) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.ArithmeticSaturated,
                out snapshot);
        }

        if ((observation.Conditions & QuicApplicationSendTurnObservationCondition.Contradictory) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.ContradictorySignals,
                out snapshot);
        }

        if ((observation.Conditions & QuicApplicationSendTurnObservationCondition.OutOfDomain) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.OutOfDomain,
                out snapshot);
        }

        QuicAdaptiveRuntimeLifecycle phase = observation.LifecycleFlags & PhaseMask;
        byte phaseValue = (byte)phase;
        if (phaseValue == 0 || (phaseValue & (phaseValue - 1)) != 0)
        {
            return PublishFallback(
                in observation,
                phaseValue == 0
                    ? QuicApplicationSendTurnShadowReason.OutOfDomain
                    : QuicApplicationSendTurnShadowReason.ContradictorySignals,
                out snapshot);
        }

        if ((observation.Conditions & QuicApplicationSendTurnObservationCondition.RecoveryUnstable) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.RecoveryGuard,
                out snapshot);
        }

        if ((observation.Conditions & QuicApplicationSendTurnObservationCondition.ResourceConstrained) != 0)
        {
            return PublishFallback(
                in observation,
                QuicApplicationSendTurnShadowReason.ResourceGuard,
                out snapshot);
        }

        return Publish(
            in observation,
            QuicApplicationSendTurnShadowState.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnShadowReason.LegacyCurrent,
            out snapshot);
    }

    private bool PublishFallback(
        in QuicApplicationSendTurnObservation observation,
        QuicApplicationSendTurnShadowReason reason,
        out QuicApplicationSendTurnPolicySnapshot snapshot)
        => Publish(
            in observation,
            QuicApplicationSendTurnShadowState.Fallback,
            QuicApplicationSendTurnPolicyMode.Conservative,
            reason,
            out snapshot);

    private bool Publish(
        in QuicApplicationSendTurnObservation observation,
        QuicApplicationSendTurnShadowState nextState,
        QuicApplicationSendTurnPolicyMode recommendedPolicy,
        QuicApplicationSendTurnShadowReason reason,
        out QuicApplicationSendTurnPolicySnapshot snapshot)
    {
        QuicApplicationSendTurnShadowState previousState = state;
        state = nextState;
        snapshotSequence++;
        snapshot = new QuicApplicationSendTurnPolicySnapshot(
            snapshotSequence,
            QuicApplicationSendTurnPolicySnapshot.CurrentSnapshotContractVersion,
            observation.ObservationContractVersion,
            QuicApplicationSendTurnObservation.CurrentPolicyRuleVersion,
            QuicApplicationSendTurnPolicySnapshot.CurrentReasonVersion,
            QuicApplicationSendTurnPolicySnapshot.CurrentProvenanceVersion,
            QuicApplicationSendTurnPolicySnapshot.CurrentAxisId,
            observation.TurnSequence,
            previousState,
            nextState,
            previousState != nextState,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            recommendedPolicy,
            reason);
        return true;
    }
}
