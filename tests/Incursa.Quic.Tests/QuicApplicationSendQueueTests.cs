// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationSendQueueTests
{
    [Fact]
    public void GetSortedQueuedWrites_SortsByPriorityDescendingAndPreservesFifoForEqualPriority()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(1, priority: 0, [0x10], 1);
        queue.Enqueue(2, priority: 5, [0x20], 1);
        queue.Enqueue(3, priority: 5, [0x30], 1);
        queue.Enqueue(4, priority: 1, [0x40], 1);

        PendingApplicationSendRequest[] queuedWrites = queue.GetSortedQueuedWrites();

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

        PendingApplicationSendRequest[] remaining = queue.GetSortedQueuedWrites();

        Assert.Single(remaining);
        Assert.Equal(8UL, remaining[0].StreamId);
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

            PendingApplicationSendRequest[] queuedWrites = queue.GetSortedQueuedWrites();

            Assert.Equal(2, queuedWrites.Length);
            Assert.Equal(new byte[] { 0xAA, 0xBB }, queuedWrites[0].StreamPayload[..2].ToArray());
            Assert.Equal(queuedWrite.Sequence, queuedWrites[0].Sequence);
        }
        finally
        {
            queue.Clear();
        }
    }
}
