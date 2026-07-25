// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicPacketFlushCadenceEpochSummary(
    QuicPacketFlushCadenceConfiguredPolicySnapshot PolicySnapshot,
    bool HasObservation,
    ulong FirstOperationSequence,
    ulong LastOperationSequence,
    ulong OperationCount,
    ulong EligibleCount,
    ulong DelayAppliedCount,
    ulong PromptFlushAppliedCount,
    ulong SafetyOverrideCount,
    ulong FallbackCount,
    ulong MaximumStreamPayloadLength,
    ulong MaximumQueuedWriteCount,
    QuicPacketFlushCadenceValidity Validity)
{
    internal const string CurrentEpochContractVersion =
        "quic-packet-flush-cadence-epoch-v1";

    public string EpochContractVersion => CurrentEpochContractVersion;
}

internal sealed class QuicPacketFlushCadenceEpochAccumulator :
    IQuicPacketFlushCadenceEvidenceSink
{
    private readonly object gate = new();
    private readonly QuicPacketFlushCadenceConfiguredPolicySnapshot
        policySnapshot;
    private bool hasObservation;
    private ulong firstOperationSequence;
    private ulong lastOperationSequence;
    private ulong operationCount;
    private ulong eligibleCount;
    private ulong delayAppliedCount;
    private ulong promptFlushAppliedCount;
    private ulong safetyOverrideCount;
    private ulong fallbackCount;
    private ulong maximumStreamPayloadLength;
    private ulong maximumQueuedWriteCount;
    private QuicPacketFlushCadenceValidity validity;

    internal QuicPacketFlushCadenceEpochAccumulator()
        : this(QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
            QuicPacketFlushCadenceObservationMode.Disabled,
            forcedValue: null))
    {
    }

    internal QuicPacketFlushCadenceEpochAccumulator(
        in QuicPacketFlushCadenceConfiguredPolicySnapshot policySnapshot)
    {
        this.policySnapshot = policySnapshot;
    }

    public bool TryPublish(
        in QuicPacketFlushCadenceObservation observation)
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
            if (observation.LegacyDelayEligible)
            {
                AddSaturating(ref eligibleCount);
            }

            if (observation.DelayApplied)
            {
                AddSaturating(ref delayAppliedCount);
            }

            if (observation.PromptFlushApplied)
            {
                AddSaturating(ref promptFlushAppliedCount);
            }

            if (observation.SafetyOverride
                != QuicPacketFlushCadenceSafetyOverride.None)
            {
                AddSaturating(ref safetyOverrideCount);
            }

            if (observation.FallbackApplied)
            {
                AddSaturating(ref fallbackCount);
            }

            maximumStreamPayloadLength = Math.Max(
                maximumStreamPayloadLength,
                observation.StreamPayloadLength);
            maximumQueuedWriteCount = Math.Max(
                maximumQueuedWriteCount,
                observation.QueuedWriteCount);
            validity |= observation.Validity;
        }

        return true;
    }

    internal QuicPacketFlushCadenceEpochSummary CaptureAndReset()
    {
        lock (gate)
        {
            QuicPacketFlushCadenceEpochSummary summary = new(
                policySnapshot,
                hasObservation,
                firstOperationSequence,
                lastOperationSequence,
                operationCount,
                eligibleCount,
                delayAppliedCount,
                promptFlushAppliedCount,
                safetyOverrideCount,
                fallbackCount,
                maximumStreamPayloadLength,
                maximumQueuedWriteCount,
                validity);
            hasObservation = false;
            firstOperationSequence = 0;
            lastOperationSequence = 0;
            operationCount = 0;
            eligibleCount = 0;
            delayAppliedCount = 0;
            promptFlushAppliedCount = 0;
            safetyOverrideCount = 0;
            fallbackCount = 0;
            maximumStreamPayloadLength = 0;
            maximumQueuedWriteCount = 0;
            validity = QuicPacketFlushCadenceValidity.None;
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
