// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicActorServiceEpochSummary(
    bool HasObservation,
    ulong FirstServiceSequence,
    ulong LastServiceSequence,
    ulong ActorTurnCount,
    ulong CompletedTurnCount,
    ulong SkippedTurnCount,
    ulong FaultedTurnCount,
    ulong ConnectionEventCount,
    ulong TimerCount,
    ulong PacketReceivedCount,
    ulong StreamCapacityReleaseCount,
    ulong FlowControlCreditUpdateCount,
    ulong StreamOpenCount,
    ulong StreamWriteCount,
    ulong ObservedWakeCount,
    uint MaximumWakePosition,
    ulong TotalServiceTimeMicros,
    ulong MaximumServiceTimeMicros,
    ulong ServiceTimeEwmaMicros,
    ulong QueueDelayObservationCount,
    ulong TotalQueueDelayMicros,
    ulong MaximumQueueDelayMicros,
    ulong QueueDelayEwmaMicros,
    ulong MaximumPendingWorkItemsAfterDequeue,
    ulong TotalEffectCount,
    ulong ApplicationSendFollowOnCount,
    ulong FlowControlFollowOnCount,
    ulong StreamCapacityFollowOnCount,
    QuicActorServiceValidity Validity,
    ulong InterServiceGapObservationCount,
    ulong TotalInterServiceGapMicros,
    ulong MaximumInterServiceGapMicros,
    ulong InterServiceGapEwmaMicros,
    ulong DeadlineLatenessObservationCount,
    ulong TotalDeadlineLatenessMicros,
    ulong MaximumDeadlineLatenessMicros,
    ulong DeadlineLatenessEwmaMicros,
    ulong ServiceContenderObservationCount = 0,
    ulong MaximumServiceContenderCount = 0,
    ulong ContendedTurnCount = 0,
    ulong AcceptedConnectionWorkObservationCount = 0,
    ulong TotalAcceptedConnectionWorkItemsAfterCurrent = 0,
    ulong MaximumAcceptedConnectionWorkItemsAfterCurrent = 0,
    ulong TurnsWithAcceptedConnectionWorkRemaining = 0,
    ulong CompleteContinuationAssessmentTurnCount = 0,
    ulong ApplicationSendContinuationObservationCount = 0,
    ulong ApplicationSendContinuationDrainedTurnCount = 0,
    ulong ApplicationSendContinuationScheduledTurnCount = 0,
    ulong ApplicationSendContinuationBlockedTurnCount = 0,
    ulong ApplicationSendContinuationReadyTurnCount = 0,
    ulong MaximumApplicationSendContinuationRemainingCount = 0,
    ulong FlowControlContinuationObservationCount = 0,
    ulong FlowControlContinuationDrainedTurnCount = 0,
    ulong FlowControlContinuationScheduledTurnCount = 0,
    ulong FlowControlContinuationBlockedTurnCount = 0,
    ulong FlowControlContinuationReadyTurnCount = 0,
    ulong MaximumFlowControlContinuationRemainingCount = 0,
    ulong StreamCapacityContinuationObservationCount = 0,
    ulong StreamCapacityContinuationDrainedTurnCount = 0,
    ulong StreamCapacityContinuationScheduledTurnCount = 0,
    ulong StreamCapacityContinuationBlockedTurnCount = 0,
    ulong StreamCapacityContinuationReadyTurnCount = 0,
    ulong MaximumStreamCapacityContinuationRemainingCount = 0)
{
    internal const string CurrentEpochContractVersion =
        "quic-actor-service-epoch-v5";

    public string EpochContractVersion => CurrentEpochContractVersion;
}

internal sealed class QuicActorServiceEpochAccumulator :
    IQuicActorServiceEvidenceSink
{
    private const int EwmaShift = 3;
    private readonly object gate = new();

    private QuicActorServiceValidity validity;
    private bool hasObservation;
    private ulong firstServiceSequence;
    private ulong lastServiceSequence;
    private ulong actorTurnCount;
    private ulong completedTurnCount;
    private ulong skippedTurnCount;
    private ulong faultedTurnCount;
    private ulong connectionEventCount;
    private ulong timerCount;
    private ulong packetReceivedCount;
    private ulong streamCapacityReleaseCount;
    private ulong flowControlCreditUpdateCount;
    private ulong streamOpenCount;
    private ulong streamWriteCount;
    private ulong observedWakeCount;
    private ulong lastWakeSequence;
    private uint maximumWakePosition;
    private ulong totalServiceTimeMicros;
    private ulong maximumServiceTimeMicros;
    private ulong serviceTimeEwmaMicros;
    private ulong queueDelayObservationCount;
    private ulong totalQueueDelayMicros;
    private ulong maximumQueueDelayMicros;
    private ulong queueDelayEwmaMicros;
    private ulong maximumPendingWorkItemsAfterDequeue;
    private ulong totalEffectCount;
    private ulong applicationSendFollowOnCount;
    private ulong flowControlFollowOnCount;
    private ulong streamCapacityFollowOnCount;
    private ulong interServiceGapObservationCount;
    private ulong totalInterServiceGapMicros;
    private ulong maximumInterServiceGapMicros;
    private ulong interServiceGapEwmaMicros;
    private ulong deadlineLatenessObservationCount;
    private ulong totalDeadlineLatenessMicros;
    private ulong maximumDeadlineLatenessMicros;
    private ulong deadlineLatenessEwmaMicros;
    private ulong serviceContenderObservationCount;
    private ulong maximumServiceContenderCount;
    private ulong contendedTurnCount;
    private ulong acceptedConnectionWorkObservationCount;
    private ulong totalAcceptedConnectionWorkItemsAfterCurrent;
    private ulong maximumAcceptedConnectionWorkItemsAfterCurrent;
    private ulong turnsWithAcceptedConnectionWorkRemaining;
    private ulong completeContinuationAssessmentTurnCount;
    private ulong applicationSendContinuationObservationCount;
    private ulong applicationSendContinuationDrainedTurnCount;
    private ulong applicationSendContinuationScheduledTurnCount;
    private ulong applicationSendContinuationBlockedTurnCount;
    private ulong applicationSendContinuationReadyTurnCount;
    private ulong maximumApplicationSendContinuationRemainingCount;
    private ulong flowControlContinuationObservationCount;
    private ulong flowControlContinuationDrainedTurnCount;
    private ulong flowControlContinuationScheduledTurnCount;
    private ulong flowControlContinuationBlockedTurnCount;
    private ulong flowControlContinuationReadyTurnCount;
    private ulong maximumFlowControlContinuationRemainingCount;
    private ulong streamCapacityContinuationObservationCount;
    private ulong streamCapacityContinuationDrainedTurnCount;
    private ulong streamCapacityContinuationScheduledTurnCount;
    private ulong streamCapacityContinuationBlockedTurnCount;
    private ulong streamCapacityContinuationReadyTurnCount;
    private ulong maximumStreamCapacityContinuationRemainingCount;

    public bool TryPublish(in QuicActorServiceObservation observation)
    {
        lock (gate)
        {
            if (!hasObservation)
            {
                hasObservation = true;
                firstServiceSequence = observation.ServiceSequence;
            }

            lastServiceSequence = observation.ServiceSequence;
            AddSaturating(ref actorTurnCount, 1);
            switch (observation.Disposition)
            {
                case QuicActorServiceDisposition.Completed:
                    AddSaturating(ref completedTurnCount, 1);
                    break;
                case QuicActorServiceDisposition.Faulted:
                    AddSaturating(ref faultedTurnCount, 1);
                    break;
                default:
                    AddSaturating(ref skippedTurnCount, 1);
                    break;
            }

            AddWorkKind(observation.WorkKind);
            if (observedWakeCount == 0
                || observation.WakeSequence != lastWakeSequence)
            {
                AddSaturating(ref observedWakeCount, 1);
                lastWakeSequence = observation.WakeSequence;
            }

            maximumWakePosition = Math.Max(
                maximumWakePosition,
                observation.WakePosition);
            AddSaturating(
                ref totalServiceTimeMicros,
                observation.ServiceTimeMicros);
            maximumServiceTimeMicros = Math.Max(
                maximumServiceTimeMicros,
                observation.ServiceTimeMicros);
            serviceTimeEwmaMicros = UpdateEwma(
                serviceTimeEwmaMicros,
                observation.ServiceTimeMicros,
                actorTurnCount == 1);

            if (observation.QueueDelayMicros is { } queueDelayMicros)
            {
                AddSaturating(ref queueDelayObservationCount, 1);
                AddSaturating(ref totalQueueDelayMicros, queueDelayMicros);
                maximumQueueDelayMicros = Math.Max(
                    maximumQueueDelayMicros,
                    queueDelayMicros);
                queueDelayEwmaMicros = UpdateEwma(
                    queueDelayEwmaMicros,
                    queueDelayMicros,
                    queueDelayObservationCount == 1);
            }

            maximumPendingWorkItemsAfterDequeue = Math.Max(
                maximumPendingWorkItemsAfterDequeue,
                observation.PendingWorkItemsAfterDequeue);
            AddSaturating(ref totalEffectCount, observation.EffectCount);
            AddSaturating(
                ref applicationSendFollowOnCount,
                observation.ApplicationSendFollowOnCount);
            AddSaturating(
                ref flowControlFollowOnCount,
                observation.FlowControlFollowOnCount);
            AddSaturating(
                ref streamCapacityFollowOnCount,
                observation.StreamCapacityFollowOnCount);
            if (observation.InterServiceGapMicros is { } interServiceGapMicros)
            {
                AddSaturating(ref interServiceGapObservationCount, 1);
                AddSaturating(
                    ref totalInterServiceGapMicros,
                    interServiceGapMicros);
                maximumInterServiceGapMicros = Math.Max(
                    maximumInterServiceGapMicros,
                    interServiceGapMicros);
                interServiceGapEwmaMicros = UpdateEwma(
                    interServiceGapEwmaMicros,
                    interServiceGapMicros,
                    interServiceGapObservationCount == 1);
            }

            if (observation.DeadlineLatenessMicros
                is { } deadlineLatenessMicros)
            {
                AddSaturating(ref deadlineLatenessObservationCount, 1);
                AddSaturating(
                    ref totalDeadlineLatenessMicros,
                    deadlineLatenessMicros);
                maximumDeadlineLatenessMicros = Math.Max(
                    maximumDeadlineLatenessMicros,
                    deadlineLatenessMicros);
                deadlineLatenessEwmaMicros = UpdateEwma(
                    deadlineLatenessEwmaMicros,
                    deadlineLatenessMicros,
                    deadlineLatenessObservationCount == 1);
            }

            if (observation.ServiceContenderCountAtStart
                is { } serviceContenderCount)
            {
                AddSaturating(ref serviceContenderObservationCount, 1);
                maximumServiceContenderCount = Math.Max(
                    maximumServiceContenderCount,
                    serviceContenderCount);
                if (serviceContenderCount > 1)
                {
                    AddSaturating(ref contendedTurnCount, 1);
                }
            }

            if (observation.AcceptedConnectionWorkItemsAfterCurrent
                is { } acceptedWorkItemsAfterCurrent)
            {
                AddSaturating(
                    ref acceptedConnectionWorkObservationCount,
                    1);
                AddSaturating(
                    ref totalAcceptedConnectionWorkItemsAfterCurrent,
                    acceptedWorkItemsAfterCurrent);
                maximumAcceptedConnectionWorkItemsAfterCurrent = Math.Max(
                    maximumAcceptedConnectionWorkItemsAfterCurrent,
                    acceptedWorkItemsAfterCurrent);
                if (acceptedWorkItemsAfterCurrent > 0)
                {
                    AddSaturating(
                        ref turnsWithAcceptedConnectionWorkRemaining,
                        1);
                }
            }

            QuicActorContinuationAssessment continuation =
                observation.ContinuationAssessment;
            if (continuation.IsComplete)
            {
                AddSaturating(
                    ref completeContinuationAssessmentTurnCount,
                    1);
            }

            ObserveContinuationProducer(
                continuation.ApplicationSendState,
                continuation.ApplicationSendRemainingCount,
                ref applicationSendContinuationObservationCount,
                ref applicationSendContinuationDrainedTurnCount,
                ref applicationSendContinuationScheduledTurnCount,
                ref applicationSendContinuationBlockedTurnCount,
                ref applicationSendContinuationReadyTurnCount,
                ref maximumApplicationSendContinuationRemainingCount);
            ObserveContinuationProducer(
                continuation.FlowControlState,
                continuation.FlowControlRemainingCount,
                ref flowControlContinuationObservationCount,
                ref flowControlContinuationDrainedTurnCount,
                ref flowControlContinuationScheduledTurnCount,
                ref flowControlContinuationBlockedTurnCount,
                ref flowControlContinuationReadyTurnCount,
                ref maximumFlowControlContinuationRemainingCount);
            ObserveContinuationProducer(
                continuation.StreamCapacityState,
                continuation.StreamCapacityRemainingCount,
                ref streamCapacityContinuationObservationCount,
                ref streamCapacityContinuationDrainedTurnCount,
                ref streamCapacityContinuationScheduledTurnCount,
                ref streamCapacityContinuationBlockedTurnCount,
                ref streamCapacityContinuationReadyTurnCount,
                ref maximumStreamCapacityContinuationRemainingCount);

            validity |= observation.Validity;
        }

        return true;
    }

    internal QuicActorServiceEpochSummary CaptureAndReset()
    {
        lock (gate)
        {
            QuicActorServiceEpochSummary summary = new(
                hasObservation,
                firstServiceSequence,
                lastServiceSequence,
                actorTurnCount,
                completedTurnCount,
                skippedTurnCount,
                faultedTurnCount,
                connectionEventCount,
                timerCount,
                packetReceivedCount,
                streamCapacityReleaseCount,
                flowControlCreditUpdateCount,
                streamOpenCount,
                streamWriteCount,
                observedWakeCount,
                maximumWakePosition,
                totalServiceTimeMicros,
                maximumServiceTimeMicros,
                serviceTimeEwmaMicros,
                queueDelayObservationCount,
                totalQueueDelayMicros,
                maximumQueueDelayMicros,
                queueDelayEwmaMicros,
                maximumPendingWorkItemsAfterDequeue,
                totalEffectCount,
                applicationSendFollowOnCount,
                flowControlFollowOnCount,
                streamCapacityFollowOnCount,
                validity,
                interServiceGapObservationCount,
                totalInterServiceGapMicros,
                maximumInterServiceGapMicros,
                interServiceGapEwmaMicros,
                deadlineLatenessObservationCount,
                totalDeadlineLatenessMicros,
                maximumDeadlineLatenessMicros,
                deadlineLatenessEwmaMicros,
                serviceContenderObservationCount,
                maximumServiceContenderCount,
                contendedTurnCount,
                acceptedConnectionWorkObservationCount,
                totalAcceptedConnectionWorkItemsAfterCurrent,
                maximumAcceptedConnectionWorkItemsAfterCurrent,
                turnsWithAcceptedConnectionWorkRemaining,
                completeContinuationAssessmentTurnCount,
                applicationSendContinuationObservationCount,
                applicationSendContinuationDrainedTurnCount,
                applicationSendContinuationScheduledTurnCount,
                applicationSendContinuationBlockedTurnCount,
                applicationSendContinuationReadyTurnCount,
                maximumApplicationSendContinuationRemainingCount,
                flowControlContinuationObservationCount,
                flowControlContinuationDrainedTurnCount,
                flowControlContinuationScheduledTurnCount,
                flowControlContinuationBlockedTurnCount,
                flowControlContinuationReadyTurnCount,
                maximumFlowControlContinuationRemainingCount,
                streamCapacityContinuationObservationCount,
                streamCapacityContinuationDrainedTurnCount,
                streamCapacityContinuationScheduledTurnCount,
                streamCapacityContinuationBlockedTurnCount,
                streamCapacityContinuationReadyTurnCount,
                maximumStreamCapacityContinuationRemainingCount);
            Reset();
            return summary;
        }
    }

    private void AddWorkKind(QuicActorWorkKind workKind)
    {
        switch (workKind)
        {
            case QuicActorWorkKind.ConnectionEvent:
                AddSaturating(ref connectionEventCount, 1);
                break;
            case QuicActorWorkKind.Timer:
                AddSaturating(ref timerCount, 1);
                break;
            case QuicActorWorkKind.PacketReceived:
                AddSaturating(ref packetReceivedCount, 1);
                break;
            case QuicActorWorkKind.StreamCapacityRelease:
                AddSaturating(ref streamCapacityReleaseCount, 1);
                break;
            case QuicActorWorkKind.FlowControlCreditUpdate:
                AddSaturating(ref flowControlCreditUpdateCount, 1);
                break;
            case QuicActorWorkKind.StreamOpen:
                AddSaturating(ref streamOpenCount, 1);
                break;
            case QuicActorWorkKind.StreamWrite:
                AddSaturating(ref streamWriteCount, 1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(workKind));
        }
    }

    private void AddSaturating(ref ulong target, ulong value)
    {
        if (ulong.MaxValue - target < value)
        {
            target = ulong.MaxValue;
            validity |= QuicActorServiceValidity.ArithmeticSaturated;
            return;
        }

        target += value;
    }

    private static ulong UpdateEwma(
        ulong current,
        ulong sample,
        bool initialize)
    {
        if (initialize)
        {
            return sample;
        }

        return sample >= current
            ? current + ((sample - current) >> EwmaShift)
            : current - ((current - sample) >> EwmaShift);
    }

    private void Reset()
    {
        validity = QuicActorServiceValidity.None;
        hasObservation = false;
        firstServiceSequence = 0;
        lastServiceSequence = 0;
        actorTurnCount = 0;
        completedTurnCount = 0;
        skippedTurnCount = 0;
        faultedTurnCount = 0;
        connectionEventCount = 0;
        timerCount = 0;
        packetReceivedCount = 0;
        streamCapacityReleaseCount = 0;
        flowControlCreditUpdateCount = 0;
        streamOpenCount = 0;
        streamWriteCount = 0;
        observedWakeCount = 0;
        lastWakeSequence = 0;
        maximumWakePosition = 0;
        totalServiceTimeMicros = 0;
        maximumServiceTimeMicros = 0;
        serviceTimeEwmaMicros = 0;
        queueDelayObservationCount = 0;
        totalQueueDelayMicros = 0;
        maximumQueueDelayMicros = 0;
        queueDelayEwmaMicros = 0;
        maximumPendingWorkItemsAfterDequeue = 0;
        totalEffectCount = 0;
        applicationSendFollowOnCount = 0;
        flowControlFollowOnCount = 0;
        streamCapacityFollowOnCount = 0;
        interServiceGapObservationCount = 0;
        totalInterServiceGapMicros = 0;
        maximumInterServiceGapMicros = 0;
        interServiceGapEwmaMicros = 0;
        deadlineLatenessObservationCount = 0;
        totalDeadlineLatenessMicros = 0;
        maximumDeadlineLatenessMicros = 0;
        deadlineLatenessEwmaMicros = 0;
        serviceContenderObservationCount = 0;
        maximumServiceContenderCount = 0;
        contendedTurnCount = 0;
        acceptedConnectionWorkObservationCount = 0;
        totalAcceptedConnectionWorkItemsAfterCurrent = 0;
        maximumAcceptedConnectionWorkItemsAfterCurrent = 0;
        turnsWithAcceptedConnectionWorkRemaining = 0;
        completeContinuationAssessmentTurnCount = 0;
        applicationSendContinuationObservationCount = 0;
        applicationSendContinuationDrainedTurnCount = 0;
        applicationSendContinuationScheduledTurnCount = 0;
        applicationSendContinuationBlockedTurnCount = 0;
        applicationSendContinuationReadyTurnCount = 0;
        maximumApplicationSendContinuationRemainingCount = 0;
        flowControlContinuationObservationCount = 0;
        flowControlContinuationDrainedTurnCount = 0;
        flowControlContinuationScheduledTurnCount = 0;
        flowControlContinuationBlockedTurnCount = 0;
        flowControlContinuationReadyTurnCount = 0;
        maximumFlowControlContinuationRemainingCount = 0;
        streamCapacityContinuationObservationCount = 0;
        streamCapacityContinuationDrainedTurnCount = 0;
        streamCapacityContinuationScheduledTurnCount = 0;
        streamCapacityContinuationBlockedTurnCount = 0;
        streamCapacityContinuationReadyTurnCount = 0;
        maximumStreamCapacityContinuationRemainingCount = 0;
    }

    private void ObserveContinuationProducer(
        QuicActorContinuationAssessmentState state,
        uint? remainingCount,
        ref ulong observationCount,
        ref ulong drainedTurnCount,
        ref ulong scheduledTurnCount,
        ref ulong blockedTurnCount,
        ref ulong readyTurnCount,
        ref ulong maximumRemainingCount)
    {
        if (!QuicActorContinuationAssessment.IsConsistent(
                state,
                remainingCount)
            || state is (
                QuicActorContinuationAssessmentState.NotAssessed
                or QuicActorContinuationAssessmentState.Invalid))
        {
            return;
        }

        AddSaturating(ref observationCount, 1);
        maximumRemainingCount = Math.Max(
            maximumRemainingCount,
            remainingCount.GetValueOrDefault());
        switch (state)
        {
            case QuicActorContinuationAssessmentState.Drained:
                AddSaturating(ref drainedTurnCount, 1);
                break;
            case QuicActorContinuationAssessmentState.Scheduled:
                AddSaturating(ref scheduledTurnCount, 1);
                break;
            case QuicActorContinuationAssessmentState.Blocked:
                AddSaturating(ref blockedTurnCount, 1);
                break;
            case QuicActorContinuationAssessmentState
                    .ReadyAfterCooperativeYield:
                AddSaturating(ref readyTurnCount, 1);
                break;
        }
    }
}
