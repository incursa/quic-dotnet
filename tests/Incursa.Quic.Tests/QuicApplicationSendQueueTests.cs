// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationSendQueueTests
{
    [Fact]
    public void RentSortedQueuedWrites_SortsByPriorityDescendingAndPreservesFifoForEqualPriority()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(1, priority: 0, [0x10], 1);
        queue.Enqueue(2, priority: 5, [0x20], 1);
        queue.Enqueue(3, priority: 5, [0x30], 1);
        queue.Enqueue(4, priority: 1, [0x40], 1);

        PendingApplicationSendRequest[] queuedWrites = CopySortedQueuedWrites(queue);

        Assert.Equal(new[] { 2UL, 3UL, 4UL, 1UL }, queuedWrites.Select(queuedWrite => queuedWrite.StreamId));
        Assert.Equal(new[] { 5, 5, 1, 0 }, queuedWrites.Select(queuedWrite => queuedWrite.Priority));
        Assert.Equal(new[] { 1L, 2L, 3L, 0L }, queuedWrites.Select(queuedWrite => queuedWrite.Sequence));
    }

    [Fact]
    public void TryGetLatestQueuedWriteForStream_ReturnsTheMostRecentQueuedWriteForThatStream()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(7, priority: 0, [0x10], 1);
        queue.Enqueue(8, priority: 1, [0x20], 1);
        queue.Enqueue(7, priority: 2, [0x30], 1);

        Assert.True(queue.TryGetLatestQueuedWriteForStream(7, out PendingApplicationSendRequest queuedWrite));
        Assert.Equal(7UL, queuedWrite.StreamId);
        Assert.Equal(2, queuedWrite.Priority);
        Assert.Equal(2L, queuedWrite.Sequence);
        Assert.Equal([0x30], queuedWrite.StreamPayload);
    }

    [Fact]
    public void SelectQueuedApplicationSendBatchCount_AlwaysIncludesTheFirstQueuedWrite()
    {
        PendingApplicationSendRequest[] queuedWrites =
        [
            new PendingApplicationSendRequest(0, 1, 0, new byte[9], 9),
            new PendingApplicationSendRequest(1, 2, 0, new byte[1], 1),
        ];

        int selectedCount = QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount(queuedWrites, maximumPayloadBytes: 8);

        Assert.Equal(1, selectedCount);
    }

    [Fact]
    public void BuildDistinctStreamIds_ReturnsFirstOccurrencesInOrder()
    {
        PendingApplicationSendRequest[] queuedWrites =
        [
            new PendingApplicationSendRequest(0, 7, 0, [0x10], 1),
            new PendingApplicationSendRequest(1, 3, 0, [0x20], 1),
            new PendingApplicationSendRequest(2, 7, 0, [0x30], 1),
            new PendingApplicationSendRequest(3, 5, 0, [0x40], 1),
            new PendingApplicationSendRequest(4, 3, 0, [0x50], 1),
        ];

        ulong[] streamIds = QuicApplicationSendQueue.BuildDistinctStreamIds(queuedWrites);

        Assert.Equal([7UL, 3UL, 5UL], streamIds);
    }

    [Fact]
    public void BuildDistinctStreamIds_PreservesFirstOccurrencesInOrderForLargeBatches()
    {
        PendingApplicationSendRequest[] queuedWrites = new PendingApplicationSendRequest[40];
        for (int index = 0; index < queuedWrites.Length; index++)
        {
            ulong streamId = (ulong)(index % 10) * 4;
            queuedWrites[index] = new PendingApplicationSendRequest(index, streamId, 0, [0x10], 1);
        }

        ulong[] streamIds = QuicApplicationSendQueue.BuildDistinctStreamIds(queuedWrites);

        Assert.Equal([0UL, 4UL, 8UL, 12UL, 16UL, 20UL, 24UL, 28UL, 32UL, 36UL], streamIds);
    }

    [Fact]
    public void TryRemoveQueuedWritesForStream_RemovesOnlyMatchingStreamWrites()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(7, priority: 0, [0x10], 1);
        queue.Enqueue(8, priority: 0, [0x20], 1);
        queue.Enqueue(7, priority: 0, [0x30], 1);

        Assert.True(queue.TryRemoveQueuedWritesForStream(7));
        Assert.Equal(1, queue.Count);
        Assert.False(queue.HasPendingWritesForStream(7));
        Assert.True(queue.HasPendingWritesForStream(8));

        PendingApplicationSendRequest[] remaining = CopySortedQueuedWrites(queue);

        Assert.Single(remaining);
        Assert.Equal(8UL, remaining[0].StreamId);
    }

    [Fact]
    public void TryRemoveQueuedWrite_RemovesOnlyTheMatchingSequence()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(7, priority: 0, [0x10], 1);
        queue.Enqueue(8, priority: 0, [0x20], 1);
        queue.Enqueue(7, priority: 0, [0x30], 1);

        Assert.True(queue.TryRemoveQueuedWrite(1));
        Assert.Equal(2, queue.Count);
        Assert.False(queue.TryRemoveQueuedWrite(99));

        PendingApplicationSendRequest[] remaining = CopySortedQueuedWrites(queue);

        Assert.Equal(new[] { 0L, 2L }, remaining.Select(request => request.Sequence));
        Assert.Equal(new[] { 7UL, 7UL }, remaining.Select(request => request.StreamId));
    }

    [Fact]
    public void TryReplaceQueuedWritePayload_ReplacesTheMatchingQueuedRequestWithoutChangingSequence()
    {
        QuicApplicationSendQueue queue = new();
        byte[] firstPayload = QuicBufferPool.RentBytes(1);
        byte[] secondPayload = QuicBufferPool.RentBytes(1);
        byte[] replacementPayload = QuicBufferPool.RentBytes(2);
        firstPayload[0] = 0x10;
        secondPayload[0] = 0x20;
        replacementPayload[0] = 0xAA;
        replacementPayload[1] = 0xBB;

        try
        {
            queue.Enqueue(7, priority: 0, firstPayload, 1);
            queue.Enqueue(7, priority: 1, secondPayload, 1);

            Assert.True(queue.TryGetLatestQueuedWriteForStream(7, out PendingApplicationSendRequest queuedWrite));
            Assert.True(queue.TryReplaceQueuedWritePayload(queuedWrite.Sequence, replacementPayload, 2));

            PendingApplicationSendRequest[] queuedWrites = CopySortedQueuedWrites(queue);

            Assert.Equal(2, queuedWrites.Length);
            Assert.Equal(new byte[] { 0xAA, 0xBB }, queuedWrites[0].StreamPayload[..2].ToArray());
            Assert.Equal(queuedWrite.Sequence, queuedWrites[0].Sequence);
        }
        finally
        {
            queue.Clear();
        }
    }

    [Fact]
    public void TryGetFragmentDataLength_FindsAPacketSizedPrefixForLargeQueuedStreamPayload()
    {
        byte[] streamData = Enumerable.Range(0, 96).Select(value => (byte)value).ToArray();
        byte[] queuedPayload = new byte[128];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId: 7,
            offset: 0,
            streamData,
            queuedPayload,
            out int queuedPayloadLength));

        Assert.True(QuicStreamPayloadSizer.TryGetFragmentDataLength(
            queuedPayload.AsSpan(0, queuedPayloadLength),
            maximumPayloadBytes: 40,
            out int fragmentDataLength));

        Assert.InRange(fragmentDataLength, 1, streamData.Length - 1);

        byte[] fragmentPayload = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId: 7,
            offset: 0,
            streamData.AsSpan(0, fragmentDataLength),
            fragmentPayload,
            out int fragmentPayloadLength));
        Assert.True(fragmentPayloadLength <= 40);
    }

    [Fact]
    public void TryGetFragmentDataLength_ReturnsTheWholeFrameWhenItAlreadyFits()
    {
        byte[] streamData = Enumerable.Range(0, 24).Select(value => (byte)value).ToArray();
        byte[] queuedPayload = new byte[128];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId: 7,
            offset: 0,
            streamData,
            queuedPayload,
            out int queuedPayloadLength));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            queuedPayload.AsSpan(0, queuedPayloadLength),
            out QuicStreamFrame queuedFrame));

        Assert.True(QuicStreamPayloadSizer.TryGetFragmentDataLength(
            queuedFrame,
            maximumPayloadBytes: 64,
            out int fragmentDataLength));

        Assert.Equal(streamData.Length, fragmentDataLength);
    }

    [Fact]
    public void TryGetFragmentDataLength_SplitsProtocolLab64KbQueuedStreamPayload()
    {
        byte[] streamData = Enumerable.Range(0, 65_536).Select(value => (byte)value).ToArray();
        byte[] queuedPayload = new byte[streamData.Length + 32];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId: 7,
            offset: 0,
            streamData,
            queuedPayload,
            out int queuedPayloadLength));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            queuedPayload.AsSpan(0, queuedPayloadLength),
            out QuicStreamFrame queuedFrame));

        const int MaximumPayloadBytes = 1_150;
        Assert.True(QuicStreamPayloadSizer.TryGetFragmentDataLength(
            queuedFrame,
            MaximumPayloadBytes,
            out int fragmentDataLength));

        Assert.InRange(fragmentDataLength, 1, streamData.Length - 1);

        byte[] fragmentPayload = new byte[MaximumPayloadBytes + 16];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId: 7,
            offset: 0,
            streamData.AsSpan(0, fragmentDataLength),
            fragmentPayload,
            out int fragmentPayloadLength));

        Assert.True(fragmentPayloadLength <= MaximumPayloadBytes);
        Assert.Equal(streamData.Length, fragmentDataLength + queuedFrame.StreamData[fragmentDataLength..].Length);
    }

    private static PendingApplicationSendRequest[] CopySortedQueuedWrites(QuicApplicationSendQueue queue)
    {
        PendingApplicationSendRequest[] rentedWrites = queue.RentSortedQueuedWrites(out int queuedWriteCount);
        try
        {
            return rentedWrites.AsSpan(0, queuedWriteCount).ToArray();
        }
        finally
        {
            QuicApplicationSendQueue.ReturnRentedQueuedWrites(rentedWrites);
        }
    }
}
