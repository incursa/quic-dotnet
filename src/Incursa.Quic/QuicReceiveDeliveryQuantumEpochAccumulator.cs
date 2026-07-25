// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicReceiveDeliveryQuantumEpochSummary(
    QuicReceiveDeliveryQuantumConfiguredPolicySnapshot PolicySnapshot,
    bool HasObservation,
    ulong FirstOperationSequence,
    ulong LastOperationSequence,
    uint OperationCount,
    uint SingleSegmentOperationCount,
    uint CompletedOperationCount,
    uint BatchedReceiveCreditOperationCount,
    uint SafetyOverrideCount,
    uint FallbackCount,
    ulong DeliveredBytes,
    ulong SourceSegmentsRead,
    uint MaximumRequestedBufferLength,
    uint MaximumDeliveredBytes,
    uint MaximumSourceSegmentsRead,
    QuicReceiveDeliveryQuantumValidity Validity)
{
    internal const string CurrentEpochContractVersion =
        "quic-receive-delivery-quantum-epoch-v1";

    public string AxisId => "receive_delivery_quantum";

    public string EpochContractVersion => CurrentEpochContractVersion;
}

internal sealed class QuicReceiveDeliveryQuantumEpochAccumulator :
    IQuicReceiveDeliveryQuantumEvidenceSink
{
    private readonly object syncRoot = new();
    private readonly QuicReceiveDeliveryQuantumConfiguredPolicySnapshot
        policySnapshot;
    private ulong firstOperationSequence;
    private ulong lastOperationSequence;
    private uint operationCount;
    private uint singleSegmentOperationCount;
    private uint completedOperationCount;
    private uint batchedReceiveCreditOperationCount;
    private uint safetyOverrideCount;
    private uint fallbackCount;
    private ulong deliveredBytes;
    private ulong sourceSegmentsRead;
    private uint maximumRequestedBufferLength;
    private uint maximumDeliveredBytes;
    private uint maximumSourceSegmentsRead;
    private QuicReceiveDeliveryQuantumValidity validity;

    internal QuicReceiveDeliveryQuantumEpochAccumulator()
        : this(QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
            QuicReceiveDeliveryQuantumObservationMode.Disabled,
            forcedValue: null))
    {
    }

    internal QuicReceiveDeliveryQuantumEpochAccumulator(
        in QuicReceiveDeliveryQuantumConfiguredPolicySnapshot policySnapshot)
    {
        this.policySnapshot = policySnapshot;
    }

    public bool TryPublish(
        in QuicReceiveDeliveryQuantumObservation observation)
    {
        lock (syncRoot)
        {
            ulong sequence = unchecked((ulong)observation.OperationSequence);
            if (operationCount == 0)
            {
                firstOperationSequence = sequence;
            }
            else if (sequence <= lastOperationSequence)
            {
                validity |=
                    QuicReceiveDeliveryQuantumValidity.Contradictory;
            }

            lastOperationSequence = sequence;
            operationCount = SaturatingIncrement(operationCount);
            if (observation.Decision.AppliedValue
                == QuicReceiveDeliveryQuantumPolicyValue.SingleSegment)
            {
                singleSegmentOperationCount =
                    SaturatingIncrement(singleSegmentOperationCount);
            }

            if (observation.Completed)
            {
                completedOperationCount =
                    SaturatingIncrement(completedOperationCount);
            }

            if (observation.BatchedReceiveCredit)
            {
                batchedReceiveCreditOperationCount =
                    SaturatingIncrement(
                        batchedReceiveCreditOperationCount);
            }

            if (observation.Decision.SafetyOverride
                != QuicReceiveDeliveryQuantumSafetyOverride.None)
            {
                safetyOverrideCount =
                    SaturatingIncrement(safetyOverrideCount);
            }

            if (observation.Decision.FallbackApplied)
            {
                fallbackCount = SaturatingIncrement(fallbackCount);
            }

            deliveredBytes = SaturatingAdd(
                deliveredBytes,
                observation.DeliveredBytes);
            sourceSegmentsRead = SaturatingAdd(
                sourceSegmentsRead,
                observation.SourceSegmentsRead);
            maximumRequestedBufferLength = Math.Max(
                maximumRequestedBufferLength,
                observation.Decision.RequestedBufferLength);
            maximumDeliveredBytes = Math.Max(
                maximumDeliveredBytes,
                observation.DeliveredBytes);
            maximumSourceSegmentsRead = Math.Max(
                maximumSourceSegmentsRead,
                observation.SourceSegmentsRead);
            validity |= observation.Decision.Validity;
            return true;
        }
    }

    internal QuicReceiveDeliveryQuantumEpochSummary CaptureAndReset()
    {
        lock (syncRoot)
        {
            QuicReceiveDeliveryQuantumEpochSummary summary = new(
                policySnapshot,
                operationCount > 0,
                firstOperationSequence,
                lastOperationSequence,
                operationCount,
                singleSegmentOperationCount,
                completedOperationCount,
                batchedReceiveCreditOperationCount,
                safetyOverrideCount,
                fallbackCount,
                deliveredBytes,
                sourceSegmentsRead,
                maximumRequestedBufferLength,
                maximumDeliveredBytes,
                maximumSourceSegmentsRead,
                validity);
            firstOperationSequence = 0;
            lastOperationSequence = 0;
            operationCount = 0;
            singleSegmentOperationCount = 0;
            completedOperationCount = 0;
            batchedReceiveCreditOperationCount = 0;
            safetyOverrideCount = 0;
            fallbackCount = 0;
            deliveredBytes = 0;
            sourceSegmentsRead = 0;
            maximumRequestedBufferLength = 0;
            maximumDeliveredBytes = 0;
            maximumSourceSegmentsRead = 0;
            validity = QuicReceiveDeliveryQuantumValidity.None;
            return summary;
        }
    }

    private static uint SaturatingIncrement(uint value)
        => value == uint.MaxValue ? uint.MaxValue : value + 1;

    private static ulong SaturatingAdd(ulong value, uint addition)
        => ulong.MaxValue - value < addition
            ? ulong.MaxValue
            : value + addition;
}
