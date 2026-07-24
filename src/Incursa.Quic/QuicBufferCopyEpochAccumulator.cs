// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicBufferCopyEpochSummary(
    bool HasObservation,
    ulong FirstOperationSequence,
    ulong LastOperationSequence,
    ulong OperationCount,
    ulong ApplicationWriteRequestCount,
    ulong OversizedRawQueueCount,
    ulong FormattedStreamPayloadCount,
    ulong CombinedApplicationSendCount,
    ulong SentPacketPlaintextRetentionCount,
    ulong RetransmissionCloneCount,
    ulong ReceiveSegmentCount,
    ulong OutboundPacketProtectionCount,
    ulong CopyCount,
    ulong ReuseAndCopyCount,
    ulong FormatCount,
    ulong CombineCount,
    ulong RetainCount,
    ulong CloneCount,
    ulong ProtectCount,
    ulong TotalLogicalBytes,
    ulong TotalCopiedBytes,
    ulong MaximumCopiedBytes,
    ulong TotalRequestedCapacityBytes,
    ulong TotalRetainedCapacityBytes,
    ulong MaximumRetainedCapacityBytes,
    QuicBufferCopyValidity Validity)
{
    internal const string CurrentEpochContractVersion =
        "quic-buffer-copy-epoch-v3";

    public string EpochContractVersion => CurrentEpochContractVersion;
}

internal sealed class QuicBufferCopyEpochAccumulator :
    IQuicBufferCopyEvidenceSink
{
    private readonly object gate = new();
    private bool hasObservation;
    private ulong firstOperationSequence;
    private ulong lastOperationSequence;
    private ulong operationCount;
    private ulong applicationWriteRequestCount;
    private ulong oversizedRawQueueCount;
    private ulong formattedStreamPayloadCount;
    private ulong combinedApplicationSendCount;
    private ulong sentPacketPlaintextRetentionCount;
    private ulong retransmissionCloneCount;
    private ulong receiveSegmentCount;
    private ulong outboundPacketProtectionCount;
    private ulong copyCount;
    private ulong reuseAndCopyCount;
    private ulong formatCount;
    private ulong combineCount;
    private ulong retainCount;
    private ulong cloneCount;
    private ulong protectCount;
    private ulong totalLogicalBytes;
    private ulong totalCopiedBytes;
    private ulong maximumCopiedBytes;
    private ulong totalRequestedCapacityBytes;
    private ulong totalRetainedCapacityBytes;
    private ulong maximumRetainedCapacityBytes;
    private QuicBufferCopyValidity validity;

    public bool TryPublish(in QuicBufferCopyObservation observation)
    {
        lock (gate)
        {
            if (!hasObservation)
            {
                hasObservation = true;
                firstOperationSequence = observation.OperationSequence;
            }

            lastOperationSequence = observation.OperationSequence;
            AddSaturating(ref operationCount, 1);
            AddPath(observation.Path);
            AddOperation(observation.Operation);
            AddSaturating(ref totalLogicalBytes, observation.LogicalBytes);
            AddSaturating(ref totalCopiedBytes, observation.CopiedBytes);
            maximumCopiedBytes = Math.Max(
                maximumCopiedBytes,
                observation.CopiedBytes);
            AddSaturating(
                ref totalRequestedCapacityBytes,
                observation.RequestedCapacityBytes);
            AddSaturating(
                ref totalRetainedCapacityBytes,
                observation.RetainedCapacityBytes);
            maximumRetainedCapacityBytes = Math.Max(
                maximumRetainedCapacityBytes,
                observation.RetainedCapacityBytes);
            validity |= observation.Validity;
        }

        return true;
    }

    internal QuicBufferCopyEpochSummary CaptureAndReset()
    {
        lock (gate)
        {
            QuicBufferCopyEpochSummary summary = new(
                hasObservation,
                firstOperationSequence,
                lastOperationSequence,
                operationCount,
                applicationWriteRequestCount,
                oversizedRawQueueCount,
                formattedStreamPayloadCount,
                combinedApplicationSendCount,
                sentPacketPlaintextRetentionCount,
                retransmissionCloneCount,
                receiveSegmentCount,
                outboundPacketProtectionCount,
                copyCount,
                reuseAndCopyCount,
                formatCount,
                combineCount,
                retainCount,
                cloneCount,
                protectCount,
                totalLogicalBytes,
                totalCopiedBytes,
                maximumCopiedBytes,
                totalRequestedCapacityBytes,
                totalRetainedCapacityBytes,
                maximumRetainedCapacityBytes,
                validity);
            Reset();
            return summary;
        }
    }

    private void AddPath(QuicBufferCopyPath path)
    {
        switch (path)
        {
            case QuicBufferCopyPath.ApplicationWriteRequest:
                AddSaturating(ref applicationWriteRequestCount, 1);
                break;
            case QuicBufferCopyPath.OversizedRawQueue:
                AddSaturating(ref oversizedRawQueueCount, 1);
                break;
            case QuicBufferCopyPath.FormattedStreamPayload:
                AddSaturating(ref formattedStreamPayloadCount, 1);
                break;
            case QuicBufferCopyPath.CombinedApplicationSend:
                AddSaturating(ref combinedApplicationSendCount, 1);
                break;
            case QuicBufferCopyPath.SentPacketPlaintextRetention:
                AddSaturating(
                    ref sentPacketPlaintextRetentionCount,
                    1);
                break;
            case QuicBufferCopyPath.RetransmissionClone:
                AddSaturating(ref retransmissionCloneCount, 1);
                break;
            case QuicBufferCopyPath.ReceiveSegment:
                AddSaturating(ref receiveSegmentCount, 1);
                break;
            case QuicBufferCopyPath.OutboundPacketProtection:
                AddSaturating(ref outboundPacketProtectionCount, 1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(path));
        }
    }

    private void AddOperation(QuicBufferCopyOperation operation)
    {
        switch (operation)
        {
            case QuicBufferCopyOperation.Copy:
                AddSaturating(ref copyCount, 1);
                break;
            case QuicBufferCopyOperation.ReuseAndCopy:
                AddSaturating(ref reuseAndCopyCount, 1);
                break;
            case QuicBufferCopyOperation.Format:
                AddSaturating(ref formatCount, 1);
                break;
            case QuicBufferCopyOperation.Combine:
                AddSaturating(ref combineCount, 1);
                break;
            case QuicBufferCopyOperation.Retain:
                AddSaturating(ref retainCount, 1);
                break;
            case QuicBufferCopyOperation.Clone:
                AddSaturating(ref cloneCount, 1);
                break;
            case QuicBufferCopyOperation.Protect:
                AddSaturating(ref protectCount, 1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private void AddSaturating(ref ulong target, ulong value)
    {
        if (ulong.MaxValue - target < value)
        {
            target = ulong.MaxValue;
            validity |= QuicBufferCopyValidity.ArithmeticSaturated;
            return;
        }

        target += value;
    }

    private void Reset()
    {
        hasObservation = false;
        firstOperationSequence = 0;
        lastOperationSequence = 0;
        operationCount = 0;
        applicationWriteRequestCount = 0;
        oversizedRawQueueCount = 0;
        formattedStreamPayloadCount = 0;
        combinedApplicationSendCount = 0;
        sentPacketPlaintextRetentionCount = 0;
        retransmissionCloneCount = 0;
        receiveSegmentCount = 0;
        outboundPacketProtectionCount = 0;
        copyCount = 0;
        reuseAndCopyCount = 0;
        formatCount = 0;
        combineCount = 0;
        retainCount = 0;
        cloneCount = 0;
        protectCount = 0;
        totalLogicalBytes = 0;
        totalCopiedBytes = 0;
        maximumCopiedBytes = 0;
        totalRequestedCapacityBytes = 0;
        totalRetainedCapacityBytes = 0;
        maximumRetainedCapacityBytes = 0;
        validity = QuicBufferCopyValidity.None;
    }
}
