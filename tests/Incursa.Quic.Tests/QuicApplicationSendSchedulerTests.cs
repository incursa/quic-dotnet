// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationSendSchedulerTests
{
    [Fact]
    public void SelectQueuedApplicationSendPlan_SelectsNoWorkWhenBudgetIsZero()
    {
        PendingApplicationSendRequest[] queuedWrites = [CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 16)];

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.CongestionLimited),
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.None, plan.Kind);
        Assert.Equal(0, plan.SelectedWriteCount);
        Assert.Equal(QuicSendPolicyBlockedReason.CongestionLimited, plan.BlockedReason);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_SelectsPayloadBoundedBatch()
    {
        PendingApplicationSendRequest first = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8);
        PendingApplicationSendRequest second = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8);
        PendingApplicationSendRequest third = CreateQueuedWrite(sequence: 2, streamId: 12, dataLength: 8);
        PendingApplicationSendRequest[] queuedWrites = [first, second, third];
        int maximumPayloadBytes = first.StreamPayloadLength + second.StreamPayloadLength;

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maximumPayloadBytes),
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Batch, plan.Kind);
        Assert.Equal(2, plan.SelectedWriteCount);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal([4UL, 8UL], queuedWrites[..plan.SelectedWriteCount].Select(write => write.StreamId));
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_FragmentsOversizedQueuedWriteWithoutDrainingIt()
    {
        PendingApplicationSendRequest queuedWrite = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 96);

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            [queuedWrite],
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 40),
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Fragment, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.InRange(plan.FragmentDataLength, 1, 95);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal(4UL, plan.FirstStreamId);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_PreservesPriorityAndSequenceOrderProvidedByQueue()
    {
        QuicApplicationSendQueue queue = new();
        byte[] lowPriorityPayload = CreateQueuedWritePayload(streamId: 4, dataLength: 4);
        byte[] firstHighPriorityPayload = CreateQueuedWritePayload(streamId: 8, dataLength: 4);
        byte[] secondHighPriorityPayload = CreateQueuedWritePayload(streamId: 12, dataLength: 4);
        queue.Enqueue(4, priority: 0, lowPriorityPayload, lowPriorityPayload.Length);
        queue.Enqueue(8, priority: 5, firstHighPriorityPayload, firstHighPriorityPayload.Length);
        queue.Enqueue(12, priority: 5, secondHighPriorityPayload, secondHighPriorityPayload.Length);

        PendingApplicationSendRequest[] sortedQueuedWrites = queue.RentSortedQueuedWrites(out int queuedWriteCount);
        try
        {
            QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                sortedQueuedWrites.AsSpan(0, queuedWriteCount),
                QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 64),
                out Exception? exception);

            Assert.Null(exception);
            Assert.Equal(QuicApplicationSendPlanKind.Batch, plan.Kind);
            Assert.Equal(3, plan.SelectedWriteCount);
            Assert.Equal([8UL, 12UL, 4UL], sortedQueuedWrites.AsSpan(0, plan.SelectedWriteCount).ToArray().Select(write => write.StreamId));
            Assert.Equal([5, 5, 0], sortedQueuedWrites.AsSpan(0, plan.SelectedWriteCount).ToArray().Select(write => write.Priority));
            Assert.Equal([1L, 2L, 0L], sortedQueuedWrites.AsSpan(0, plan.SelectedWriteCount).ToArray().Select(write => write.Sequence));
        }
        finally
        {
            QuicApplicationSendQueue.ReturnRentedQueuedWrites(sortedQueuedWrites);
        }
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_ReportsMoreWorkWhenQueueIsNotDrained()
    {
        PendingApplicationSendRequest first = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 4);
        PendingApplicationSendRequest second = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 4);
        PendingApplicationSendRequest third = CreateQueuedWrite(sequence: 2, streamId: 12, dataLength: 4);
        PendingApplicationSendRequest[] queuedWrites = [first, second, third];
        int maximumPayloadBytes = first.StreamPayloadLength + second.StreamPayloadLength;

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maximumPayloadBytes),
            out Exception? exception);

        Assert.Null(exception);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal(2, plan.SelectedWriteCount);
    }

    private static PendingApplicationSendRequest CreateQueuedWrite(long sequence, ulong streamId, int dataLength)
    {
        byte[] streamPayload = CreateQueuedWritePayload(streamId, dataLength);
        return new PendingApplicationSendRequest(
            sequence,
            streamId,
            Priority: 0,
            streamPayload,
            streamPayload.Length);
    }

    private static byte[] CreateQueuedWritePayload(ulong streamId, int dataLength)
    {
        byte[] streamData = Enumerable.Range(0, dataLength).Select(value => (byte)value).ToArray();
        byte[] streamPayload = new byte[dataLength + 32];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId,
            offset: 0,
            streamData,
            streamPayload,
            out int streamPayloadLength));

        return streamPayload[..streamPayloadLength];
    }
}
