// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationSendQueueTests
{
    [Fact]
    public void CaptureRetentionSnapshotCountsActualPayloadOwnerCapacity()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(1, priority: 0, new byte[16], streamPayloadLength: 3);
        queue.Enqueue(2, priority: 0, new byte[64], streamPayloadLength: 5);

        QuicRetentionSnapshot snapshot = queue.CaptureRetentionSnapshot();

        Assert.Equal(2, snapshot.RetainedBufferCount);
        Assert.Equal(80, snapshot.RetainedByteCount);
        Assert.Null(snapshot.OldestAgeMilliseconds);
    }

    [Fact]
    public void CaptureRetentionSnapshotFiltersCauseAndReportsFirstEnqueueAge()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(
            1,
            priority: 0,
            new byte[16],
            streamPayloadLength: 3,
            firstEnqueuedAtMicros: 100,
            QuicApplicationSendQueueCause.SmallWriteDelay);
        queue.Enqueue(
            2,
            priority: 0,
            new byte[64],
            streamPayloadLength: 5,
            firstEnqueuedAtMicros: 175,
            QuicApplicationSendQueueCause.DirectSendBlocked);

        QuicRetentionSnapshot smallWrite = queue.CaptureRetentionSnapshot(
            nowMicros: 350,
            QuicApplicationSendQueueCause.SmallWriteDelay);
        QuicRetentionSnapshot blocked = queue.CaptureRetentionSnapshot(
            nowMicros: 350,
            QuicApplicationSendQueueCause.DirectSendBlocked);
        QuicRetentionSnapshot absent = queue.CaptureRetentionSnapshot(
            nowMicros: 350,
            QuicApplicationSendQueueCause.PendingRetransmission);

        Assert.Equal(new QuicRetentionSnapshot(1, 16, 0.25), smallWrite);
        Assert.Equal(new QuicRetentionSnapshot(1, 64, 0.175), blocked);
        Assert.Equal(new QuicRetentionSnapshot(0, 0, null), absent);
    }

    [Fact]
    public void CaptureRetentionSnapshotsBuildsAggregateAndCauseBreakdownInOnePass()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(1, 0, new byte[16], 3, 100, QuicApplicationSendQueueCause.OversizedWrite);
        queue.Enqueue(2, 0, new byte[64], 5, 175, QuicApplicationSendQueueCause.DirectSendBlocked);
        queue.Enqueue(3, 0, new byte[32], 7, 200, QuicApplicationSendQueueCause.OversizedWrite);
        Span<QuicRetentionSnapshot> causeSnapshots =
            stackalloc QuicRetentionSnapshot[QuicApplicationSendQueue.QueueCauseCount];

        QuicRetentionSnapshot aggregate = queue.CaptureRetentionSnapshots(350, causeSnapshots);

        Assert.Equal(new QuicRetentionSnapshot(3, 112, 0.25), aggregate);
        Assert.Equal(new QuicRetentionSnapshot(0, 0, null), causeSnapshots[(int)QuicApplicationSendQueueCause.PendingRetransmission]);
        Assert.Equal(new QuicRetentionSnapshot(2, 48, 0.25), causeSnapshots[(int)QuicApplicationSendQueueCause.OversizedWrite]);
        Assert.Equal(new QuicRetentionSnapshot(0, 0, null), causeSnapshots[(int)QuicApplicationSendQueueCause.SmallWriteDelay]);
        Assert.Equal(new QuicRetentionSnapshot(1, 64, 0.175), causeSnapshots[(int)QuicApplicationSendQueueCause.DirectSendBlocked]);
    }

    [Fact]
    public void ReplacingPayloadPreservesFirstEnqueueTimeAndCause()
    {
        QuicApplicationSendQueue queue = new();
        byte[] originalPayload = QuicBufferPool.RentBytes(1);
        originalPayload[0] = 0x10;
        byte[] replacementPayload = QuicBufferPool.RentBytes(2);
        replacementPayload[0] = 0x20;
        replacementPayload[1] = 0x21;
        queue.Enqueue(
            7,
            priority: 2,
            originalPayload,
            streamPayloadLength: 1,
            firstEnqueuedAtMicros: 125,
            QuicApplicationSendQueueCause.OversizedWrite);
        Assert.True(queue.TryGetLatestQueuedWriteForStream(7, out PendingApplicationSendRequest before));

        Assert.True(queue.TryReplaceQueuedWritePayload(before.Sequence, replacementPayload, 2));
        Assert.True(queue.TryGetLatestQueuedWriteForStream(7, out PendingApplicationSendRequest after));

        Assert.Equal(125UL, after.FirstEnqueuedAtMicros);
        Assert.Equal(QuicApplicationSendQueueCause.OversizedWrite, after.QueueCause);
        Assert.Equal([0x20, 0x21], after.StreamPayload.AsSpan(0, 2).ToArray());
        Assert.Equal(2, after.StreamPayloadLength);
        queue.Clear();
    }

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
    public void RentSortedQueuedWrites_MatchesReferenceOrderForLargeMixedQueue()
    {
        QuicApplicationSendQueue queue = new();
        Random random = new(0x51A7);
        List<(long Sequence, int Priority)> expected = [];

        for (int index = 0; index < 1_000; index++)
        {
            int priority = random.Next(-8, 9);
            queue.Enqueue((ulong)index * 4, priority, [0x10], 1);
            expected.Add((index, priority));
        }

        PendingApplicationSendRequest[] actual = CopySortedQueuedWrites(queue);
        (long Sequence, int Priority)[] expectedOrder = expected
            .OrderByDescending(item => item.Priority)
            .ThenBy(item => item.Sequence)
            .ToArray();

        Assert.Equal(
            expectedOrder,
            actual.Select(item => (item.Sequence, item.Priority)).ToArray());
    }

    [Fact]
    public void RentSortedQueuedWrites_FallsBackForExtremePriorityRange()
    {
        QuicApplicationSendQueue queue = new();
        for (int index = 0; index < 40; index++)
        {
            int priority = index switch
            {
                0 => int.MinValue,
                1 => int.MaxValue,
                _ => index % 3,
            };
            queue.Enqueue((ulong)index * 4, priority, [0x10], 1);
        }

        PendingApplicationSendRequest[] actual = CopySortedQueuedWrites(queue);

        Assert.Equal(int.MaxValue, actual[0].Priority);
        Assert.Equal(int.MinValue, actual[^1].Priority);
        Assert.Equal(
            Enumerable.Range(0, 40)
                .Select(index => (Sequence: (long)index, Priority: index switch
                {
                    0 => int.MinValue,
                    1 => int.MaxValue,
                    _ => index % 3,
                }))
                .OrderByDescending(item => item.Priority)
                .ThenBy(item => item.Sequence),
            actual.Select(item => (item.Sequence, item.Priority)));
    }

    [Fact]
    public void RentSortedQueuedWrites_PreservesOrderAfterUnorderedQueueMutations()
    {
        QuicApplicationSendQueue queue = new();
        try
        {
            for (int index = 0; index < 48; index++)
            {
                byte[] payload = QuicBufferPool.RentBytes(1);
                payload[0] = (byte)index;
                queue.Enqueue((ulong)index * 4, index % 5, payload, 1);
            }

            Assert.True(queue.TryRemoveQueuedWrite(sequence: 7, returnPayloads: true));
            Assert.True(queue.TryRemoveQueuedWritesForStream(streamId: 80, returnPayloads: true));

            byte[] replacementPayload = QuicBufferPool.RentBytes(2);
            replacementPayload[0] = 0xAA;
            replacementPayload[1] = 0xBB;
            Assert.True(queue.TryReplaceQueuedWritePayload(sequence: 33, replacementPayload, 2));

            byte[] appendedPayload = QuicBufferPool.RentBytes(1);
            appendedPayload[0] = 0xCC;
            queue.Enqueue(streamId: 400, priority: 4, appendedPayload, 1);

            PendingApplicationSendRequest[] actual = CopySortedQueuedWrites(queue);

            Assert.Equal(
                actual.OrderByDescending(item => item.Priority).ThenBy(item => item.Sequence),
                actual);
            Assert.DoesNotContain(actual, item => item.Sequence is 7 or 20);
            PendingApplicationSendRequest replaced = Assert.Single(actual, item => item.Sequence == 33);
            Assert.Equal([0xAA, 0xBB], replaced.StreamPayload[..replaced.StreamPayloadLength]);
            Assert.Equal(
                [4, 9, 14, 19, 24, 29, 34, 39, 44, 48],
                actual.Where(item => item.Priority == 4).Select(item => item.Sequence));
        }
        finally
        {
            queue.Clear();
        }
    }

    [Fact]
    public void Enqueue_RejectsSequenceExhaustionBeforeOrderingCanWrap()
    {
        QuicApplicationSendQueue queue = new(initialSequence: long.MaxValue);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => queue.Enqueue(4, priority: 0, [0x10], 1));

        Assert.Contains("sequence space is exhausted", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, queue.Count);
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
    public void TryGetNextQueuedWrite_ReturnsHighestPriorityWriteWithoutRemovingIt()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(4, priority: 0, [0x10], 1);
        queue.Enqueue(8, priority: 5, [0x20], 1);
        queue.Enqueue(12, priority: 5, [0x30], 1);
        queue.Enqueue(16, priority: 1, [0x40], 1);

        Assert.True(queue.TryGetNextQueuedWrite(out PendingApplicationSendRequest queuedWrite));

        Assert.Equal(8UL, queuedWrite.StreamId);
        Assert.Equal(5, queuedWrite.Priority);
        Assert.Equal(1L, queuedWrite.Sequence);
        Assert.Equal(4, queue.Count);
    }

    [Fact]
    public void TryGetNextQueuedWrite_PreservesFifoForEqualPriorityWrites()
    {
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(4, priority: 3, [0x10], 1);
        queue.Enqueue(8, priority: 3, [0x20], 1);
        queue.Enqueue(12, priority: 3, [0x30], 1);

        Assert.True(queue.TryGetNextQueuedWrite(out PendingApplicationSendRequest queuedWrite));

        Assert.Equal(4UL, queuedWrite.StreamId);
        Assert.Equal(0L, queuedWrite.Sequence);
    }

    [Fact]
    public void TryGetNextQueuedWrite_ReturnsFalseForEmptyQueue()
    {
        QuicApplicationSendQueue queue = new();

        Assert.False(queue.TryGetNextQueuedWrite(out PendingApplicationSendRequest queuedWrite));
        Assert.Equal(default, queuedWrite);
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
    public void BuildDistinctStreamIds_ReturnsSingleIdForSingleStreamBatch()
    {
        PendingApplicationSendRequest[] queuedWrites =
        [
            new PendingApplicationSendRequest(0, 7, 0, [0x10], 1),
            new PendingApplicationSendRequest(1, 7, 0, [0x20], 1),
            new PendingApplicationSendRequest(2, 7, 0, [0x30], 1),
        ];

        ulong[] streamIds = QuicApplicationSendQueue.BuildDistinctStreamIds(queuedWrites);

        Assert.Equal([7UL], streamIds);
    }

    [Fact]
    public void TryGetOnlyDistinctStreamId_IdentifiesOnlySameStreamBatches()
    {
        PendingApplicationSendRequest[] sameStreamWrites =
        [
            new PendingApplicationSendRequest(0, 7, 0, [0x10], 1),
            new PendingApplicationSendRequest(1, 7, 1, [0x20], 1),
        ];
        PendingApplicationSendRequest[] mixedStreamWrites =
        [
            sameStreamWrites[0],
            new PendingApplicationSendRequest(2, 11, 0, [0x30], 1),
        ];

        Assert.True(QuicApplicationSendQueue.TryGetOnlyDistinctStreamId(sameStreamWrites, out ulong streamId));
        Assert.Equal(7UL, streamId);
        Assert.False(QuicApplicationSendQueue.TryGetOnlyDistinctStreamId(mixedStreamWrites, out _));
        Assert.False(QuicApplicationSendQueue.TryGetOnlyDistinctStreamId([], out _));
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
    public void TryUpdateQueuedWritePayloadSlice_PreservesOwnerAndQueueMetadata()
    {
        QuicApplicationSendQueue queue = new();
        byte[] payload = QuicBufferPool.RentBytes(16);
        payload.AsSpan(4, 3).Fill(0x5A);

        try
        {
            queue.Enqueue(
                streamId: 7,
                priority: 3,
                payload,
                streamPayloadLength: 16,
                firstEnqueuedAtMicros: 123,
                QuicApplicationSendQueueCause.OversizedWrite);
            Assert.True(queue.TryGetOnlyQueuedWrite(out PendingApplicationSendRequest before));

            Assert.True(queue.TryUpdateQueuedWritePayloadSlice(before.Sequence, payload, 4, 3));
            Assert.True(queue.TryGetOnlyQueuedWrite(out PendingApplicationSendRequest after));

            Assert.Same(payload, after.StreamPayload);
            Assert.Equal(4, after.StreamPayloadOffset);
            Assert.Equal(3, after.StreamPayloadLength);
            Assert.Equal(before.Sequence, after.Sequence);
            Assert.Equal(before.Priority, after.Priority);
            Assert.Equal(before.FirstEnqueuedAtMicros, after.FirstEnqueuedAtMicros);
            Assert.Equal(before.QueueCause, after.QueueCause);
        }
        finally
        {
            queue.Clear();
        }
    }

    [Fact]
    public void TryUpdateQueuedWritePayloadSlice_RejectsWrongOwnerAndInvalidRangeWithoutChangingQueue()
    {
        QuicApplicationSendQueue queue = new();
        byte[] payload = QuicBufferPool.RentBytes(16);

        try
        {
            queue.Enqueue(streamId: 7, priority: 3, payload, streamPayloadLength: 16);
            Assert.True(queue.TryGetOnlyQueuedWrite(out PendingApplicationSendRequest before));

            Assert.False(queue.TryUpdateQueuedWritePayloadSlice(before.Sequence, new byte[16], 4, 3));
            Assert.False(queue.TryUpdateQueuedWritePayloadSlice(before.Sequence, payload, 15, 2));
            Assert.True(queue.TryGetOnlyQueuedWrite(out PendingApplicationSendRequest after));
            Assert.Equal(before, after);
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
    public void TryGetFragmentDataLength_AcceptsAStandaloneFinFrame()
    {
        byte[] queuedPayload = new byte[32];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum
                | QuicStreamFrameBits.OffsetBitMask
                | QuicStreamFrameBits.LengthBitMask
                | QuicStreamFrameBits.FinBitMask),
            streamId: 7,
            offset: 24,
            streamData: [],
            queuedPayload,
            out int queuedPayloadLength));

        Assert.True(QuicStreamPayloadSizer.TryGetFragmentDataLength(
            queuedPayload.AsSpan(0, queuedPayloadLength),
            maximumPayloadBytes: 32,
            out int fragmentDataLength));

        Assert.Equal(0, fragmentDataLength);
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

    [Fact]
    public void RemainderLayout_AdvancesProtocolLabPayloadWithoutMovingStreamData()
    {
        byte[] streamData = Enumerable.Range(0, 65_536).Select(value => (byte)value).ToArray();
        byte[] queuedPayload = new byte[streamData.Length + 64];
        const byte FrameType = QuicStreamFrameBits.StreamFrameTypeMinimum
            | QuicStreamFrameBits.LengthBitMask
            | QuicStreamFrameBits.FinBitMask;

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            FrameType,
            streamId: 7,
            offset: 0,
            streamData,
            queuedPayload,
            out int queuedPayloadLength));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            queuedPayload.AsSpan(0, queuedPayloadLength),
            out QuicStreamFrame queuedFrame));
        int originalHeaderLength = queuedFrame.ConsumedLength - queuedFrame.StreamDataLength;

        Assert.True(QuicStreamPayloadSizer.TryGetFragmentDataLength(
            queuedFrame,
            maximumPayloadBytes: 1_150,
            out int fragmentDataLength));
        Assert.True(QuicStreamPayloadSizer.TryCreateRemainderLayout(
            queuedFrame,
            currentPayloadOffset: 0,
            fragmentDataLength,
            minimumPayloadLength: 20,
            queuedPayload.Length,
            out QuicStreamPayloadRemainderLayout layout));

        Assert.Equal(originalHeaderLength + fragmentDataLength, layout.StreamDataOffset);
        Assert.Equal(layout.StreamDataOffset, layout.PayloadOffset + layout.HeaderLength);

        QuicStreamPayloadSizer.ApplyRemainderLayout(queuedPayload, layout);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            queuedPayload.AsSpan(layout.PayloadOffset, layout.PayloadLength),
            out QuicStreamFrame remainderFrame));
        Assert.Equal((ulong)fragmentDataLength, remainderFrame.Offset);
        Assert.True(remainderFrame.IsFin);
        Assert.Equal(streamData.AsSpan(fragmentDataLength).ToArray(), remainderFrame.StreamData.ToArray());
    }

    [Fact]
    public void RemainderLayout_RepeatedlyAdvancesTheSamePayloadOwner()
    {
        byte[] streamData = Enumerable.Range(0, 8_192).Select(value => (byte)value).ToArray();
        byte[] queuedPayload = new byte[streamData.Length + 64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum
                | QuicStreamFrameBits.LengthBitMask
                | QuicStreamFrameBits.FinBitMask),
            streamId: 11,
            offset: 0,
            streamData,
            queuedPayload,
            out int payloadLength));

        int payloadOffset = 0;
        int consumedDataLength = 0;
        for (int iteration = 0; iteration < 4; iteration++)
        {
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                queuedPayload.AsSpan(payloadOffset, payloadLength),
                out QuicStreamFrame frame));
            Assert.True(QuicStreamPayloadSizer.TryGetFragmentDataLength(
                frame,
                maximumPayloadBytes: 1_150,
                out int fragmentDataLength));
            Assert.True(QuicStreamPayloadSizer.TryCreateRemainderLayout(
                frame,
                payloadOffset,
                fragmentDataLength,
                minimumPayloadLength: 20,
                queuedPayload.Length,
                out QuicStreamPayloadRemainderLayout layout));

            consumedDataLength += fragmentDataLength;
            QuicStreamPayloadSizer.ApplyRemainderLayout(queuedPayload, layout);
            payloadOffset = layout.PayloadOffset;
            payloadLength = layout.PayloadLength;

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                queuedPayload.AsSpan(payloadOffset, payloadLength),
                out QuicStreamFrame remainderFrame));
            Assert.Equal((ulong)consumedDataLength, remainderFrame.Offset);
            Assert.True(remainderFrame.IsFin);
            Assert.Equal(streamData.AsSpan(consumedDataLength).ToArray(), remainderFrame.StreamData.ToArray());
        }
    }

    [Fact]
    public void RemainderLayout_RejectsInsufficientCapacityAndOffsetOverflow()
    {
        byte[] streamData = new byte[4_096];
        byte[] queuedPayload = new byte[streamData.Length + 64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask),
            streamId: 11,
            offset: 0,
            streamData,
            queuedPayload,
            out int payloadLength));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            queuedPayload.AsSpan(0, payloadLength),
            out QuicStreamFrame frame));

        Assert.False(QuicStreamPayloadSizer.TryCreateRemainderLayout(
            frame,
            currentPayloadOffset: 0,
            fragmentDataLength: 1_140,
            minimumPayloadLength: queuedPayload.Length + 1,
            queuedPayload.Length,
            out _));
        Assert.False(QuicStreamPayloadSizer.TryCreateRemainderLayout(
            frame,
            currentPayloadOffset: int.MaxValue,
            fragmentDataLength: 1_140,
            minimumPayloadLength: 20,
            bufferCapacity: int.MaxValue,
            out _));
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
