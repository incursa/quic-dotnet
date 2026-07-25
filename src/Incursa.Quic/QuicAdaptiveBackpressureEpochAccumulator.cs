// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicAdaptiveBackpressureEpochSummary(
    QuicAdaptiveBackpressureConfiguredPolicySnapshot PolicySnapshot,
    bool HasObservation,
    ulong FirstOperationSequence,
    ulong LastOperationSequence,
    ulong OperationCount,
    ulong DelayAppliedCount,
    ulong SafetyOverrideCount,
    ulong FallbackCount,
    ulong MaximumQueuedOperationCount,
    ulong MaximumRetainedCapacityBytes,
    QuicAdaptiveBackpressureValidity Validity)
{
    internal const string CurrentEpochContractVersion =
        "quic-adaptive-backpressure-epoch-v1";

    public string EpochContractVersion => CurrentEpochContractVersion;
}

internal sealed class QuicAdaptiveBackpressureEpochAccumulator :
    IQuicAdaptiveBackpressureEvidenceSink
{
    private readonly object gate = new();
    private readonly QuicAdaptiveBackpressureConfiguredPolicySnapshot
        policySnapshot;
    private bool hasObservation;
    private ulong firstOperationSequence;
    private ulong lastOperationSequence;
    private ulong operationCount;
    private ulong delayAppliedCount;
    private ulong safetyOverrideCount;
    private ulong fallbackCount;
    private ulong maximumQueuedOperationCount;
    private ulong maximumRetainedCapacityBytes;
    private QuicAdaptiveBackpressureValidity validity;

    internal QuicAdaptiveBackpressureEpochAccumulator()
        : this(QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
            QuicAdaptiveBackpressureObservationMode.Disabled,
            forcedValue: null))
    {
    }

    internal QuicAdaptiveBackpressureEpochAccumulator(
        in QuicAdaptiveBackpressureConfiguredPolicySnapshot policySnapshot)
    {
        this.policySnapshot = policySnapshot;
    }

    public bool TryPublish(
        in QuicAdaptiveBackpressureObservation observation)
    {
        lock (gate)
        {
            if (!hasObservation)
            {
                hasObservation = true;
                firstOperationSequence = observation.OperationSequence;
            }

            lastOperationSequence = observation.OperationSequence;
            AddSaturating(ref operationCount);
            if (observation.DelayApplied)
            {
                AddSaturating(ref delayAppliedCount);
            }

            if (observation.SafetyOverride
                != QuicAdaptiveBackpressureSafetyOverride.None)
            {
                AddSaturating(ref safetyOverrideCount);
            }

            if (observation.FallbackApplied)
            {
                AddSaturating(ref fallbackCount);
            }

            maximumQueuedOperationCount = Math.Max(
                maximumQueuedOperationCount,
                observation.QueuedOperationCount);
            maximumRetainedCapacityBytes = Math.Max(
                maximumRetainedCapacityBytes,
                observation.RetainedCapacityBytes);
            validity |= observation.Validity;
        }

        return true;
    }

    internal QuicAdaptiveBackpressureEpochSummary CaptureAndReset()
    {
        lock (gate)
        {
            QuicAdaptiveBackpressureEpochSummary summary = new(
                policySnapshot,
                hasObservation,
                firstOperationSequence,
                lastOperationSequence,
                operationCount,
                delayAppliedCount,
                safetyOverrideCount,
                fallbackCount,
                maximumQueuedOperationCount,
                maximumRetainedCapacityBytes,
                validity);
            hasObservation = false;
            firstOperationSequence = 0;
            lastOperationSequence = 0;
            operationCount = 0;
            delayAppliedCount = 0;
            safetyOverrideCount = 0;
            fallbackCount = 0;
            maximumQueuedOperationCount = 0;
            maximumRetainedCapacityBytes = 0;
            validity = QuicAdaptiveBackpressureValidity.None;
            return summary;
        }
    }

    private static void AddSaturating(ref ulong value)
    {
        if (value != ulong.MaxValue)
        {
            value++;
        }
    }
}
