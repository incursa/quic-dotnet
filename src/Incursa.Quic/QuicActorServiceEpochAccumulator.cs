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
    QuicActorServiceValidity Validity)
{
    internal const string CurrentEpochContractVersion =
        "quic-actor-service-epoch-v1";

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
                validity);
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
    }
}
