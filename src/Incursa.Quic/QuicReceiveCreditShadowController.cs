// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicAdaptiveRuntimePolicyState : byte
{
    Conservative = 0,
    Candidate = 1,
    Fallback = 2,
    Terminal = 3,
}

internal enum QuicAdaptiveRuntimePolicyReason : byte
{
    LegacyImmediate = 0,
    LegacyReadDominantBatch = 1,
    MissingSignal = 2,
    StaleSignal = 3,
    ContradictorySignals = 4,
    OutOfDomain = 5,
    RuleVersionMismatch = 6,
    ArithmeticSaturated = 7,
    TerminalStarted = 8,
    ResourceGuard = 9,
    RecoveryGuard = 10,
    FlowProgressGuard = 11,
    CancellationOrDisposal = 12,
    Shutdown = 13,
}

internal readonly record struct QuicReceiveCreditPolicySnapshot(
    ulong SnapshotVersion,
    string RuleVersion,
    QuicAdaptiveRuntimePolicyState State,
    ulong EpochSequence,
    QuicReceiveCreditPolicyMode AppliedPolicy,
    QuicReceiveCreditPolicyMode ProposedPolicy,
    QuicAdaptiveRuntimePolicyReason Reason,
    bool HasIssuedApplicationData);

internal struct QuicReceiveCreditShadowController
{
    private const QuicAdaptiveRuntimeSignalMask RequiredSignalMask =
        QuicAdaptiveRuntimeSignalMask.HasIssuedApplicationData
        | QuicAdaptiveRuntimeSignalMask.LiveObserverStreams
        | QuicAdaptiveRuntimeSignalMask.Lifecycle;
    private const QuicAdaptiveRuntimeLifecycle PhaseMask =
        QuicAdaptiveRuntimeLifecycle.Establishing
        | QuicAdaptiveRuntimeLifecycle.Active
        | QuicAdaptiveRuntimeLifecycle.Closing
        | QuicAdaptiveRuntimeLifecycle.Draining
        | QuicAdaptiveRuntimeLifecycle.Discarded;

    private ulong lastEpochSequence;
    private ulong snapshotVersion;
    private bool hasIssuedApplicationData;
    private QuicAdaptiveRuntimePolicyState state;

    internal bool TryEvaluate(
        in QuicAdaptiveRuntimeConnectionObservation observation,
        out QuicReceiveCreditPolicySnapshot snapshot)
    {
        snapshot = default;
        if (observation.ConnectionEpochSequence == 0
            || observation.ConnectionEpochSequence <= lastEpochSequence
            || snapshotVersion == ulong.MaxValue)
        {
            return false;
        }

        lastEpochSequence = observation.ConnectionEpochSequence;
        hasIssuedApplicationData |= observation.HasIssuedApplicationData;

        if (state == QuicAdaptiveRuntimePolicyState.Terminal)
        {
            return Publish(
                in observation,
                QuicAdaptiveRuntimePolicyState.Terminal,
                QuicReceiveCreditPolicyMode.Immediate,
                QuicAdaptiveRuntimePolicyReason.TerminalStarted,
                out snapshot);
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return Publish(
                in observation,
                QuicAdaptiveRuntimePolicyState.Terminal,
                QuicReceiveCreditPolicyMode.Immediate,
                QuicAdaptiveRuntimePolicyReason.CancellationOrDisposal,
                out snapshot);
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return Publish(
                in observation,
                QuicAdaptiveRuntimePolicyState.Terminal,
                QuicReceiveCreditPolicyMode.Immediate,
                QuicAdaptiveRuntimePolicyReason.TerminalStarted,
                out snapshot);
        }

        if (!string.Equals(
                observation.ObservationContractVersion,
                QuicAdaptiveRuntimeConnectionObservation.CurrentObservationContractVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                observation.PolicyRuleVersion,
                QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
                StringComparison.Ordinal))
        {
            return PublishFallback(
                in observation,
                QuicAdaptiveRuntimePolicyReason.RuleVersionMismatch,
                out snapshot);
        }

        if ((observation.MissingSignalMask & RequiredSignalMask) != 0)
        {
            return PublishFallback(
                in observation,
                QuicAdaptiveRuntimePolicyReason.MissingSignal,
                out snapshot);
        }

        if ((observation.StaleSignalMask & RequiredSignalMask) != 0)
        {
            return PublishFallback(
                in observation,
                QuicAdaptiveRuntimePolicyReason.StaleSignal,
                out snapshot);
        }

        QuicAdaptiveRuntimeLifecycle phase = observation.LifecycleFlags & PhaseMask;
        byte phaseValue = (byte)phase;
        if (phaseValue == 0 || (phaseValue & (phaseValue - 1)) != 0)
        {
            return PublishFallback(
                in observation,
                phaseValue == 0
                    ? QuicAdaptiveRuntimePolicyReason.OutOfDomain
                    : QuicAdaptiveRuntimePolicyReason.ContradictorySignals,
                out snapshot);
        }

        if (observation.LiveObserverStreams == ushort.MaxValue)
        {
            return PublishFallback(
                in observation,
                QuicAdaptiveRuntimePolicyReason.ArithmeticSaturated,
                out snapshot);
        }

        bool useBatchedReceiveCredit = observation.LiveObserverStreams
            >= QuicReceiveCreditPolicy.ReadDominantMinimumLiveObserverStreams
            && !hasIssuedApplicationData;
        return Publish(
            in observation,
            useBatchedReceiveCredit
                ? QuicAdaptiveRuntimePolicyState.Candidate
                : QuicAdaptiveRuntimePolicyState.Conservative,
            useBatchedReceiveCredit
                ? QuicReceiveCreditPolicyMode.ReadDominantBatch
                : QuicReceiveCreditPolicyMode.Immediate,
            useBatchedReceiveCredit
                ? QuicAdaptiveRuntimePolicyReason.LegacyReadDominantBatch
                : QuicAdaptiveRuntimePolicyReason.LegacyImmediate,
            out snapshot);
    }

    private bool PublishFallback(
        in QuicAdaptiveRuntimeConnectionObservation observation,
        QuicAdaptiveRuntimePolicyReason reason,
        out QuicReceiveCreditPolicySnapshot snapshot)
        => Publish(
            in observation,
            QuicAdaptiveRuntimePolicyState.Fallback,
            QuicReceiveCreditPolicyMode.Immediate,
            reason,
            out snapshot);

    private bool Publish(
        in QuicAdaptiveRuntimeConnectionObservation observation,
        QuicAdaptiveRuntimePolicyState nextState,
        QuicReceiveCreditPolicyMode proposedPolicy,
        QuicAdaptiveRuntimePolicyReason reason,
        out QuicReceiveCreditPolicySnapshot snapshot)
    {
        state = nextState;
        snapshotVersion++;
        snapshot = new QuicReceiveCreditPolicySnapshot(
            snapshotVersion,
            QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
            state,
            observation.ConnectionEpochSequence,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            proposedPolicy,
            reason,
            hasIssuedApplicationData);
        return true;
    }
}
