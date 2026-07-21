// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicApplicationSendPressureMode
{
    Sparse,
    Cooperative,
    Saturated,
}

internal readonly record struct QuicApplicationSendPressureObservation(
    QuicApplicationSendPressureMode Mode,
    QuicApplicationSendPressureMode PreviousMode,
    int QueueDelayEwmaMicros,
    int DistinctQueuedStreamCount,
    bool BurstLimitReached)
{
    internal bool ModeChanged => Mode != PreviousMode;
}

/// <summary>
/// Classifies connection-local application-send pressure without selecting or scheduling work.
/// </summary>
internal struct QuicApplicationSendPressureClassifier
{
    internal const int MaximumObservedDistinctStreamCount = 12;
    internal const int CooperativeQueueDelayMicros = 2_000;
    internal const int SaturatedQueueDelayMicros = 20_000;
    internal const int PressureStreamCount = 8;

    private const int RequiredEntryObservations = 2;
    private const int RequiredSparseReliefObservations = 4;
    private const int RequiredSaturatedReliefObservations = 8;
    private const int EwmaShift = 2;

    private int queueDelayEwmaMicros;
    private int candidateObservationCount;
    private QuicApplicationSendPressureMode candidateMode;
    private bool hasQueueDelay;

    internal QuicApplicationSendPressureMode Mode { get; private set; }

    internal int QueueDelayEwmaMicros => queueDelayEwmaMicros;

    internal bool HasQueueDelay => hasQueueDelay;

    internal void ObserveQueueDelay(double queueDelayMilliseconds)
    {
        if (!double.IsFinite(queueDelayMilliseconds) || queueDelayMilliseconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(queueDelayMilliseconds));
        }

        int observedMicros = queueDelayMilliseconds >= int.MaxValue / 1_000.0
            ? int.MaxValue
            : (int)Math.Round(queueDelayMilliseconds * 1_000.0, MidpointRounding.AwayFromZero);
        if (!hasQueueDelay)
        {
            queueDelayEwmaMicros = observedMicros;
            hasQueueDelay = true;
            return;
        }

        long delta = (long)observedMicros - queueDelayEwmaMicros;
        queueDelayEwmaMicros = (int)Math.Clamp(
            queueDelayEwmaMicros + (delta >> EwmaShift),
            0,
            int.MaxValue);
    }

    internal QuicApplicationSendPressureObservation ObserveTurn(
        int distinctQueuedStreamCount,
        bool burstLimitReached)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(distinctQueuedStreamCount);

        QuicApplicationSendPressureMode previousMode = Mode;
        QuicApplicationSendPressureMode observedMode = ClassifyObservedMode(
            distinctQueuedStreamCount,
            burstLimitReached);
        if (observedMode == Mode)
        {
            candidateMode = Mode;
            candidateObservationCount = 0;
        }
        else
        {
            if (candidateMode != observedMode)
            {
                candidateMode = observedMode;
                candidateObservationCount = 1;
            }
            else
            {
                candidateObservationCount++;
            }

            if (candidateObservationCount >= GetRequiredObservationCount(Mode, observedMode))
            {
                Mode = observedMode;
                candidateMode = Mode;
                candidateObservationCount = 0;
            }
        }

        return new QuicApplicationSendPressureObservation(
            Mode,
            previousMode,
            queueDelayEwmaMicros,
            Math.Min(distinctQueuedStreamCount, MaximumObservedDistinctStreamCount),
            burstLimitReached);
    }

    private QuicApplicationSendPressureMode ClassifyObservedMode(
        int distinctQueuedStreamCount,
        bool burstLimitReached)
    {
        if (!hasQueueDelay)
        {
            return QuicApplicationSendPressureMode.Sparse;
        }

        if (queueDelayEwmaMicros >= SaturatedQueueDelayMicros)
        {
            return QuicApplicationSendPressureMode.Saturated;
        }

        bool hasRunnablePressure = burstLimitReached
            || distinctQueuedStreamCount >= PressureStreamCount;
        return hasRunnablePressure && queueDelayEwmaMicros >= CooperativeQueueDelayMicros
            ? QuicApplicationSendPressureMode.Cooperative
            : QuicApplicationSendPressureMode.Sparse;
    }

    private static int GetRequiredObservationCount(
        QuicApplicationSendPressureMode currentMode,
        QuicApplicationSendPressureMode observedMode)
    {
        if (currentMode == QuicApplicationSendPressureMode.Saturated)
        {
            return RequiredSaturatedReliefObservations;
        }

        return observedMode == QuicApplicationSendPressureMode.Sparse
            ? RequiredSparseReliefObservations
            : RequiredEntryObservations;
    }
}
