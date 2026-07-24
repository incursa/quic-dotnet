// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;

namespace Incursa.Quic;

internal readonly record struct PendingApplicationSendRequest(
    long Sequence,
    ulong StreamId,
    int Priority,
    byte[] StreamPayload,
    int StreamPayloadLength,
    ulong FirstEnqueuedAtMicros = 0,
    QuicApplicationSendQueueCause QueueCause = QuicApplicationSendQueueCause.SmallWriteDelay,
    int StreamPayloadOffset = 0,
    bool ContainsRawStreamData = false,
    ulong StreamOffset = 0,
    bool IsFinal = false,
    QuicBufferCopyLifetimeToken LifetimeToken = default)
{
    internal bool TryGetStreamFrame(out QuicStreamFrame frame)
    {
        ReadOnlySpan<byte> payload = StreamPayload.AsSpan(StreamPayloadOffset, StreamPayloadLength);
        if (!ContainsRawStreamData)
        {
            return QuicStreamParser.TryParseStreamFrame(payload, out frame);
        }

        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (StreamOffset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (IsFinal)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        if (!QuicStreamPayloadSizer.TryGetOutboundStreamFrameLength(
                frameType,
                StreamId,
                StreamOffset,
                payload.Length,
                out int frameLength))
        {
            frame = default;
            return false;
        }

        frame = new QuicStreamFrame(
            frameType,
            new QuicStreamId(StreamId),
            hasOffset: StreamOffset != 0,
            StreamOffset,
            hasLength: true,
            length: checked((ulong)payload.Length),
            IsFinal,
            payload,
            frameLength);
        return true;
    }
}

internal enum QuicApplicationSendQueueCause
{
    PendingRetransmission,
    OversizedWrite,
    SmallWriteDelay,
    DirectSendBlocked,
}

/// <summary>
/// Owns the pending application-send queue and its selection/bookkeeping rules.
/// </summary>
internal sealed class QuicApplicationSendQueue
{
    internal const int QueueCauseCount = 4;

    // CONTEXT: distinct stream-id selection hot path
    // SEE: code:src/Incursa.Quic/QuicApplicationSendQueue.cs#BuildDistinctStreamIds
    // SEE: code:src/Incursa.Quic/QuicApplicationSendQueue.cs#GetDistinctStreamIdSetCapacity
    // SEE: code:src/Incursa.Quic/QuicApplicationSendQueue.cs#MixStreamIdHash
    // This path intentionally switches from a linear scan to a pooled
    // open-addressed set only after small batches stop being cheaper. The
    // threshold and hash constants are tuned for the send hot path and should
    // not be replaced with a general-purpose collection without re-benchmarking.
    private const int LinearDistinctStreamIdThreshold = 16;
    private const int MaintainedOrderThreshold = 32;
    private const int MaximumDistributedPriorityRange = 64;
    private const int PooledDistinctStreamIdSetMinimumCapacity = 32;
    private const int StreamIdHashShift = 33;
    private const ulong StreamIdHashMultiplier = 0xff51afd7ed558ccdUL;

    private readonly List<PendingApplicationSendRequest> pendingRequests = [];
    private long nextSequence;
    private long retainedCapacityBytes;
    private ulong? oldestEnqueuedAtMicros;
    private bool pendingRequestsOrdered = true;
    private IQuicBufferCopyOperationObserver? bufferCopyOperationObserver;

    internal QuicApplicationSendQueue(long initialSequence = 0)
    {
        nextSequence = initialSequence;
    }

    public int Count => pendingRequests.Count;

    internal void ConfigureBufferCopyOperationObserver(
        IQuicBufferCopyOperationObserver observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        if (Interlocked.CompareExchange(
                ref bufferCopyOperationObserver,
                observer,
                comparand: null) is not null)
        {
            throw new InvalidOperationException(
                "The application-send queue buffer-copy observer has already been configured.");
        }
    }

    internal QuicRetentionSnapshot CaptureRetentionSnapshot(
        ulong? nowMicros = null,
        QuicApplicationSendQueueCause? queueCause = null)
    {
        if (!queueCause.HasValue)
        {
            return new QuicRetentionSnapshot(
                pendingRequests.Count,
                retainedCapacityBytes,
                nowMicros.HasValue
                    ? QuicRetentionSnapshot.GetOldestAgeMilliseconds(
                        nowMicros.Value,
                        oldestEnqueuedAtMicros)
                    : null);
        }

        long retainedBytes = 0;
        long retainedBuffers = 0;
        ulong? causeOldestEnqueuedAtMicros = null;
        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            if (pendingRequest.QueueCause != queueCause.Value)
            {
                continue;
            }

            retainedBuffers++;
            retainedBytes += pendingRequest.StreamPayload.Length;
            causeOldestEnqueuedAtMicros =
                !causeOldestEnqueuedAtMicros.HasValue
                || pendingRequest.FirstEnqueuedAtMicros
                    < causeOldestEnqueuedAtMicros.Value
                ? pendingRequest.FirstEnqueuedAtMicros
                : causeOldestEnqueuedAtMicros;
        }

        return new QuicRetentionSnapshot(
            retainedBuffers,
            retainedBytes,
            nowMicros.HasValue
                ? QuicRetentionSnapshot.GetOldestAgeMilliseconds(
                    nowMicros.Value,
                    causeOldestEnqueuedAtMicros)
                : null);
    }

    internal QuicRetentionSnapshot CaptureRetentionSnapshots(
        ulong nowMicros,
        Span<QuicRetentionSnapshot> causeSnapshots)
    {
        if (causeSnapshots.Length < QueueCauseCount)
        {
            throw new ArgumentException("A snapshot slot is required for every queue cause.", nameof(causeSnapshots));
        }

        Span<long> retainedBuffersByCause = stackalloc long[QueueCauseCount];
        Span<long> retainedBytesByCause = stackalloc long[QueueCauseCount];
        Span<ulong> oldestEnqueuedAtMicrosByCause = stackalloc ulong[QueueCauseCount];
        Span<bool> hasOldestEnqueuedAtMicrosByCause = stackalloc bool[QueueCauseCount];

        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            int causeIndex = (int)pendingRequest.QueueCause;
            if ((uint)causeIndex >= QueueCauseCount)
            {
                throw new InvalidOperationException($"Unknown application-send queue cause: {pendingRequest.QueueCause}.");
            }

            retainedBuffersByCause[causeIndex]++;
            retainedBytesByCause[causeIndex] += pendingRequest.StreamPayload.Length;
            if (!hasOldestEnqueuedAtMicrosByCause[causeIndex]
                || pendingRequest.FirstEnqueuedAtMicros < oldestEnqueuedAtMicrosByCause[causeIndex])
            {
                oldestEnqueuedAtMicrosByCause[causeIndex] = pendingRequest.FirstEnqueuedAtMicros;
                hasOldestEnqueuedAtMicrosByCause[causeIndex] = true;
            }
        }

        for (int causeIndex = 0; causeIndex < QueueCauseCount; causeIndex++)
        {
            causeSnapshots[causeIndex] = new QuicRetentionSnapshot(
                retainedBuffersByCause[causeIndex],
                retainedBytesByCause[causeIndex],
                hasOldestEnqueuedAtMicrosByCause[causeIndex]
                    ? QuicRetentionSnapshot.GetOldestAgeMilliseconds(
                        nowMicros,
                        oldestEnqueuedAtMicrosByCause[causeIndex])
                    : null);
        }

        return new QuicRetentionSnapshot(
            pendingRequests.Count,
            retainedCapacityBytes,
            QuicRetentionSnapshot.GetOldestAgeMilliseconds(
                nowMicros,
                this.oldestEnqueuedAtMicros));
    }

    public bool HasPendingWritesForStream(ulong streamId)
    {
        foreach (PendingApplicationSendRequest pendingWrite in pendingRequests)
        {
            if (pendingWrite.StreamId == streamId)
            {
                return true;
            }
        }

        return false;
    }

    internal int CountDistinctStreamIdsUpTo(Span<ulong> distinctStreamIds)
    {
        if (distinctStreamIds.IsEmpty)
        {
            return 0;
        }

        int distinctStreamCount = 0;
        foreach (PendingApplicationSendRequest pendingWrite in pendingRequests)
        {
            if (distinctStreamIds[..distinctStreamCount].Contains(pendingWrite.StreamId))
            {
                continue;
            }

            distinctStreamIds[distinctStreamCount++] = pendingWrite.StreamId;
            if (distinctStreamCount == distinctStreamIds.Length)
            {
                break;
            }
        }

        return distinctStreamCount;
    }

    internal QuicApplicationSendTurnQueueSnapshot CaptureBoundedTurnSnapshot(
        ulong nowMicros,
        int maximumObservedWrites,
        int maximumObservedDistinctStreams)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumObservedWrites);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumObservedDistinctStreams);

        int queuedWriteCount = pendingRequests.Count;
        int observedWriteCount = Math.Min(queuedWriteCount, maximumObservedWrites);
        Span<ulong> distinctStreamIds = maximumObservedDistinctStreams <= 64
            ? stackalloc ulong[maximumObservedDistinctStreams]
            : throw new ArgumentOutOfRangeException(nameof(maximumObservedDistinctStreams));
        int distinctStreamCount = 0;
        ulong logicalBacklogBytes = 0;
        ulong retainedBytes = 0;
        ulong boundedOldestEnqueuedAtMicros = 0;
        bool hasBoundedOldestEnqueuedAtMicros = false;
        bool complete = queuedWriteCount <= maximumObservedWrites;

        for (int index = 0; index < observedWriteCount; index++)
        {
            PendingApplicationSendRequest pendingWrite = pendingRequests[index];
            if (!pendingWrite.TryGetStreamFrame(out QuicStreamFrame streamFrame))
            {
                complete = false;
            }
            else if (ulong.MaxValue - logicalBacklogBytes < (ulong)streamFrame.StreamDataLength)
            {
                logicalBacklogBytes = ulong.MaxValue;
                complete = false;
            }
            else
            {
                logicalBacklogBytes += (ulong)streamFrame.StreamDataLength;
            }

            uint retainedBufferLength = (uint)pendingWrite.StreamPayload.Length;
            if (ulong.MaxValue - retainedBytes < retainedBufferLength)
            {
                retainedBytes = ulong.MaxValue;
                complete = false;
            }
            else
            {
                retainedBytes += retainedBufferLength;
            }

            if (!hasBoundedOldestEnqueuedAtMicros
                || pendingWrite.FirstEnqueuedAtMicros
                    < boundedOldestEnqueuedAtMicros)
            {
                boundedOldestEnqueuedAtMicros =
                    pendingWrite.FirstEnqueuedAtMicros;
                hasBoundedOldestEnqueuedAtMicros = true;
            }

            if (distinctStreamIds[..distinctStreamCount].Contains(pendingWrite.StreamId))
            {
                continue;
            }

            if (distinctStreamCount == distinctStreamIds.Length)
            {
                complete = false;
                continue;
            }

            distinctStreamIds[distinctStreamCount++] = pendingWrite.StreamId;
        }

        ulong oldestAgeMicros =
            hasBoundedOldestEnqueuedAtMicros
            && nowMicros >= boundedOldestEnqueuedAtMicros
            ? nowMicros - boundedOldestEnqueuedAtMicros
            : 0;
        return new QuicApplicationSendTurnQueueSnapshot(
            (uint)queuedWriteCount,
            logicalBacklogBytes,
            (ushort)distinctStreamCount,
            oldestAgeMicros,
            (uint)queuedWriteCount,
            retainedBytes,
            complete);
    }

    public void Enqueue(
        ulong streamId,
        int priority,
        byte[] streamPayload,
        int streamPayloadLength,
        ulong firstEnqueuedAtMicros = 0,
        QuicApplicationSendQueueCause queueCause = QuicApplicationSendQueueCause.SmallWriteDelay,
        QuicBufferCopyLifetimeToken lifetimeToken = default)
    {
        PendingApplicationSendRequest request = new(
            TakeNextSequence(),
            streamId,
            priority,
            streamPayload,
            streamPayloadLength,
            firstEnqueuedAtMicros,
            queueCause,
            LifetimeToken: lifetimeToken);

        if (pendingRequestsOrdered && pendingRequests.Count < MaintainedOrderThreshold)
        {
            pendingRequests.Insert(FindInsertionIndex(request), request);
        }
        else
        {
            pendingRequests.Add(request);
            pendingRequestsOrdered = false;
        }

        RecordEnqueue(request);
    }

    public void EnqueueRawStreamData(
        ulong streamId,
        int priority,
        byte[] streamData,
        int streamDataLength,
        ulong streamOffset,
        bool isFinal,
        ulong firstEnqueuedAtMicros = 0,
        QuicApplicationSendQueueCause queueCause = QuicApplicationSendQueueCause.OversizedWrite,
        QuicBufferCopyLifetimeToken lifetimeToken = default)
    {
        PendingApplicationSendRequest request = new(
            TakeNextSequence(),
            streamId,
            priority,
            streamData,
            streamDataLength,
            firstEnqueuedAtMicros,
            queueCause,
            StreamPayloadOffset: 0,
            ContainsRawStreamData: true,
            StreamOffset: streamOffset,
            IsFinal: isFinal,
            LifetimeToken: lifetimeToken);

        if (pendingRequestsOrdered && pendingRequests.Count < MaintainedOrderThreshold)
        {
            pendingRequests.Insert(FindInsertionIndex(request), request);
        }
        else
        {
            pendingRequests.Add(request);
            pendingRequestsOrdered = false;
        }

        RecordEnqueue(request);
    }

    public bool TryGetLatestQueuedWriteForStream(ulong streamId, out PendingApplicationSendRequest queuedWrite)
    {
        queuedWrite = default;
        bool found = false;
        foreach (PendingApplicationSendRequest pendingWrite in pendingRequests)
        {
            if (pendingWrite.StreamId == streamId
                && (!found || pendingWrite.Sequence > queuedWrite.Sequence))
            {
                queuedWrite = pendingWrite;
                found = true;
            }
        }

        return found;
    }

    internal bool TryGetOnlyQueuedWrite(out PendingApplicationSendRequest queuedWrite)
    {
        if (pendingRequests.Count == 1)
        {
            queuedWrite = pendingRequests[0];
            return true;
        }

        queuedWrite = default;
        return false;
    }

    internal bool TryGetNextQueuedWrite(out PendingApplicationSendRequest queuedWrite)
    {
        if (pendingRequests.Count == 0)
        {
            queuedWrite = default;
            return false;
        }

        queuedWrite = pendingRequests[0];
        if (!pendingRequestsOrdered)
        {
            for (int index = 1; index < pendingRequests.Count; index++)
            {
                PendingApplicationSendRequest candidate = pendingRequests[index];
                if (ComparePendingApplicationSendRequests(candidate, queuedWrite) < 0)
                {
                    queuedWrite = candidate;
                }
            }
        }

        return true;
    }

    public bool TryReplaceQueuedWritePayload(
        long sequence,
        byte[] streamPayload,
        int streamPayloadLength,
        QuicBufferCopyLifetimeToken lifetimeToken = default)
    {
        for (int index = 0; index < pendingRequests.Count; index++)
        {
            PendingApplicationSendRequest queuedWrite = pendingRequests[index];
            if (queuedWrite.Sequence != sequence)
            {
                continue;
            }

            ReleasePayload(
                in queuedWrite,
                QuicBufferReleaseReason.Replaced);
            pendingRequests[index] = queuedWrite with
            {
                StreamPayload = streamPayload,
                StreamPayloadLength = streamPayloadLength,
                StreamPayloadOffset = 0,
                LifetimeToken = lifetimeToken,
            };
            retainedCapacityBytes +=
                streamPayload.Length - queuedWrite.StreamPayload.Length;
            return true;
        }

        return false;
    }

    public bool TryUpdateQueuedWritePayloadSlice(
        long sequence,
        byte[] expectedStreamPayload,
        int streamPayloadOffset,
        int streamPayloadLength)
    {
        if (streamPayloadOffset < 0
            || streamPayloadLength < 0
            || streamPayloadOffset > expectedStreamPayload.Length - streamPayloadLength)
        {
            return false;
        }

        for (int index = 0; index < pendingRequests.Count; index++)
        {
            PendingApplicationSendRequest queuedWrite = pendingRequests[index];
            if (queuedWrite.Sequence != sequence
                || !ReferenceEquals(queuedWrite.StreamPayload, expectedStreamPayload))
            {
                continue;
            }

            pendingRequests[index] = queuedWrite with
            {
                StreamPayloadOffset = streamPayloadOffset,
                StreamPayloadLength = streamPayloadLength,
            };
            return true;
        }

        return false;
    }

    public bool TryAdvanceQueuedRawStreamData(
        long sequence,
        byte[] expectedStreamData,
        int consumedDataLength)
    {
        if (consumedDataLength <= 0)
        {
            return false;
        }

        for (int index = 0; index < pendingRequests.Count; index++)
        {
            PendingApplicationSendRequest queuedWrite = pendingRequests[index];
            if (queuedWrite.Sequence != sequence
                || !queuedWrite.ContainsRawStreamData
                || !ReferenceEquals(queuedWrite.StreamPayload, expectedStreamData)
                || consumedDataLength >= queuedWrite.StreamPayloadLength)
            {
                continue;
            }

            pendingRequests[index] = queuedWrite with
            {
                StreamPayloadOffset = checked(queuedWrite.StreamPayloadOffset + consumedDataLength),
                StreamPayloadLength = queuedWrite.StreamPayloadLength - consumedDataLength,
                StreamOffset = checked(queuedWrite.StreamOffset + (ulong)consumedDataLength),
            };
            return true;
        }

        return false;
    }

    public bool TryMarkQueuedWriteFinal(long sequence)
    {
        for (int index = 0; index < pendingRequests.Count; index++)
        {
            PendingApplicationSendRequest queuedWrite = pendingRequests[index];
            if (queuedWrite.Sequence != sequence || !queuedWrite.ContainsRawStreamData)
            {
                continue;
            }

            pendingRequests[index] = queuedWrite with { IsFinal = true };
            return true;
        }

        return false;
    }

    public PendingApplicationSendRequest[] RentSortedQueuedWrites(out int queuedWriteCount)
    {
        queuedWriteCount = pendingRequests.Count;
        if (queuedWriteCount == 0)
        {
            return [];
        }

        PendingApplicationSendRequest[] queuedWrites =
            ArrayPool<PendingApplicationSendRequest>.Shared.Rent(queuedWriteCount);

        if (pendingRequestsOrdered)
        {
            pendingRequests.CopyTo(queuedWrites);
        }
        else if (!TryCopyInPriorityOrder(queuedWrites))
        {
            pendingRequests.CopyTo(queuedWrites);
            Array.Sort(
                queuedWrites,
                index: 0,
                length: queuedWriteCount,
                PendingApplicationSendRequestComparer.Instance);
        }

        return queuedWrites;
    }

    private bool TryCopyInPriorityOrder(PendingApplicationSendRequest[] destination)
    {
        int minimumPriority = pendingRequests[0].Priority;
        int maximumPriority = minimumPriority;
        for (int index = 1; index < pendingRequests.Count; index++)
        {
            int priority = pendingRequests[index].Priority;
            minimumPriority = Math.Min(minimumPriority, priority);
            maximumPriority = Math.Max(maximumPriority, priority);
        }

        long priorityRange = (long)maximumPriority - minimumPriority + 1;
        if (priorityRange > MaximumDistributedPriorityRange)
        {
            return false;
        }

        Span<int> nextIndexes = stackalloc int[(int)priorityRange];
        nextIndexes.Clear();
        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            nextIndexes[pendingRequest.Priority - minimumPriority]++;
        }

        int nextIndex = 0;
        for (int priorityOffset = nextIndexes.Length - 1; priorityOffset >= 0; priorityOffset--)
        {
            int count = nextIndexes[priorityOffset];
            nextIndexes[priorityOffset] = nextIndex;
            nextIndex += count;
        }

        // The queue preserves sequence order within each priority while ordered,
        // after it switches to append-only insertion, and through removals.
        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            int priorityOffset = pendingRequest.Priority - minimumPriority;
            destination[nextIndexes[priorityOffset]++] = pendingRequest;
        }

        return true;
    }

    public static void ReturnRentedQueuedWrites(PendingApplicationSendRequest[] queuedWrites)
    {
        if (queuedWrites.Length != 0)
        {
            ArrayPool<PendingApplicationSendRequest>.Shared.Return(queuedWrites, clearArray: true);
        }
    }

    public bool TryRemoveQueuedWritesForStream(ulong streamId)
        => TryRemoveQueuedWritesForStream(streamId, returnPayloads: false);

    public bool TryRemoveQueuedWritesForStream(
        ulong streamId,
        bool returnPayloads,
        QuicBufferReleaseReason releaseReason =
            QuicBufferReleaseReason.Canceled)
    {
        bool removedAny = false;
        bool removedOldest = false;
        for (int index = pendingRequests.Count - 1; index >= 0; index--)
        {
            if (pendingRequests[index].StreamId != streamId)
            {
                continue;
            }

            if (returnPayloads)
            {
                PendingApplicationSendRequest pendingWrite =
                    pendingRequests[index];
                ReleasePayload(
                    in pendingWrite,
                    releaseReason);
            }

            RecordRemoval(
                pendingRequests[index],
                ref removedOldest);
            pendingRequests.RemoveAt(index);
            ResetOrderWhenEmpty();
            removedAny = true;
        }

        if (removedOldest)
        {
            RecomputeOldestEnqueuedAtMicros();
        }

        return removedAny;
    }

    public bool TryRemoveQueuedWrite(
        long sequence,
        bool returnPayloads = false,
        QuicBufferReleaseReason releaseReason =
            QuicBufferReleaseReason.Completed)
    {
        for (int index = 0; index < pendingRequests.Count; index++)
        {
            PendingApplicationSendRequest pendingWrite = pendingRequests[index];
            if (pendingWrite.Sequence != sequence)
            {
                continue;
            }

            if (returnPayloads)
            {
                ReleasePayload(
                    in pendingWrite,
                    releaseReason);
            }

            bool removedOldest = false;
            RecordRemoval(pendingWrite, ref removedOldest);
            pendingRequests.RemoveAt(index);
            ResetOrderWhenEmpty();
            if (removedOldest)
            {
                RecomputeOldestEnqueuedAtMicros();
            }

            return true;
        }

        return false;
    }

    public bool TryRemoveQueuedWrites(
        ReadOnlySpan<PendingApplicationSendRequest> selectedWrites,
        bool returnPayloads = false,
        QuicBufferReleaseReason releaseReason =
            QuicBufferReleaseReason.Completed)
    {
        bool removedAny = false;
        bool removedOldest = false;
        foreach (PendingApplicationSendRequest selectedWrite in selectedWrites)
        {
            for (int index = 0; index < pendingRequests.Count; index++)
            {
                if (pendingRequests[index].Sequence != selectedWrite.Sequence)
                {
                    continue;
                }

                if (returnPayloads)
                {
                    PendingApplicationSendRequest pendingWrite =
                        pendingRequests[index];
                    ReleasePayload(
                        in pendingWrite,
                        releaseReason);
                }

                RecordRemoval(
                    pendingRequests[index],
                    ref removedOldest);
                pendingRequests.RemoveAt(index);
                ResetOrderWhenEmpty();
                removedAny = true;
                break;
            }
        }

        if (removedOldest)
        {
            RecomputeOldestEnqueuedAtMicros();
        }

        return removedAny;
    }

    public void Clear(
        QuicBufferReleaseReason releaseReason =
            QuicBufferReleaseReason.Terminal)
    {
        foreach (PendingApplicationSendRequest pendingWrite in pendingRequests)
        {
            ReleasePayload(
                in pendingWrite,
                releaseReason);
        }

        pendingRequests.Clear();
        retainedCapacityBytes = 0;
        oldestEnqueuedAtMicros = null;
        pendingRequestsOrdered = true;
    }

    private void ReleasePayload(
        in PendingApplicationSendRequest pendingWrite,
        QuicBufferReleaseReason reason)
    {
        QuicBufferPool.ReturnBytes(pendingWrite.StreamPayload);
        IQuicBufferCopyOperationObserver? observer =
            bufferCopyOperationObserver;
        if (observer is null || pendingWrite.LifetimeToken.IsEmpty)
        {
            return;
        }

        try
        {
            QuicBufferCopyLifetimeToken token =
                pendingWrite.LifetimeToken;
            observer.ObserveBufferRelease(
                in token,
                reason,
                pendingWrite.StreamPayload.Length);
        }
        catch (Exception)
        {
            // Release evidence follows the authoritative pool return and
            // cannot change queue ownership or send progress.
        }
    }

    private void RecordEnqueue(
        in PendingApplicationSendRequest pendingRequest)
    {
        retainedCapacityBytes += pendingRequest.StreamPayload.Length;
        if (!oldestEnqueuedAtMicros.HasValue
            || pendingRequest.FirstEnqueuedAtMicros
                < oldestEnqueuedAtMicros.Value)
        {
            oldestEnqueuedAtMicros =
                pendingRequest.FirstEnqueuedAtMicros;
        }
    }

    private void RecordRemoval(
        in PendingApplicationSendRequest pendingRequest,
        ref bool removedOldest)
    {
        retainedCapacityBytes -= pendingRequest.StreamPayload.Length;
        removedOldest |= oldestEnqueuedAtMicros.HasValue
            && pendingRequest.FirstEnqueuedAtMicros
                == oldestEnqueuedAtMicros.Value;
    }

    private void RecomputeOldestEnqueuedAtMicros()
    {
        ulong? oldest = null;
        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            if (!oldest.HasValue
                || pendingRequest.FirstEnqueuedAtMicros < oldest.Value)
            {
                oldest = pendingRequest.FirstEnqueuedAtMicros;
            }
        }

        oldestEnqueuedAtMicros = oldest;
    }

    internal static int SelectQueuedApplicationSendBatchCount(
        ReadOnlySpan<PendingApplicationSendRequest> queuedWrites,
        int maximumPayloadBytes)
        => SelectQueuedApplicationSendBatchCount(
            queuedWrites,
            maximumPayloadBytes,
            out _);

    internal static int SelectQueuedApplicationSendBatchCount(
        ReadOnlySpan<PendingApplicationSendRequest> queuedWrites,
        int maximumPayloadBytes,
        out int selectedBytes)
    {
        int selectedCount = 0;
        selectedBytes = 0;
        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            int nextSelectedBytes = checked(selectedBytes + queuedWrite.StreamPayloadLength);
            if (selectedCount > 0 && nextSelectedBytes > maximumPayloadBytes)
            {
                break;
            }

            selectedBytes = nextSelectedBytes;
            selectedCount++;
        }

        return selectedCount;
    }

    internal static ulong[] BuildDistinctStreamIds(ReadOnlySpan<PendingApplicationSendRequest> queuedWrites)
    {
        if (queuedWrites.IsEmpty)
        {
            return [];
        }

        if (TryGetOnlyDistinctStreamId(queuedWrites, out ulong onlyStreamId))
        {
            return [onlyStreamId];
        }

        if (queuedWrites.Length <= LinearDistinctStreamIdThreshold)
        {
            return BuildDistinctStreamIdsByLinearScan(queuedWrites);
        }

        ulong[] streamIds = new ulong[queuedWrites.Length];
        int setCapacity = GetDistinctStreamIdSetCapacity(queuedWrites.Length);
        ulong[] setSlots = ArrayPool<ulong>.Shared.Rent(setCapacity);
        bool[] occupiedSlots = ArrayPool<bool>.Shared.Rent(setCapacity);
        int uniqueCount = 0;

        Array.Clear(occupiedSlots, 0, setCapacity);

        try
        {
            int setMask = setCapacity - 1;
            foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
            {
                if (TryAddDistinctStreamId(setSlots, occupiedSlots, setMask, queuedWrite.StreamId))
                {
                    streamIds[uniqueCount++] = queuedWrite.StreamId;
                }
            }
        }
        finally
        {
            ArrayPool<bool>.Shared.Return(occupiedSlots);
            ArrayPool<ulong>.Shared.Return(setSlots);
        }

        if (uniqueCount != streamIds.Length)
        {
            Array.Resize(ref streamIds, uniqueCount);
        }

        return streamIds;
    }

    internal static bool TryGetOnlyDistinctStreamId(
        ReadOnlySpan<PendingApplicationSendRequest> queuedWrites,
        out ulong streamId)
    {
        if (queuedWrites.IsEmpty)
        {
            streamId = default;
            return false;
        }

        streamId = queuedWrites[0].StreamId;
        return HasOnlyStreamId(queuedWrites, streamId);
    }

    private static bool HasOnlyStreamId(ReadOnlySpan<PendingApplicationSendRequest> queuedWrites, ulong streamId)
    {
        for (int index = 1; index < queuedWrites.Length; index++)
        {
            if (queuedWrites[index].StreamId != streamId)
            {
                return false;
            }
        }

        return true;
    }

    private static int GetDistinctStreamIdSetCapacity(int itemCount)
    {
        int capacity = PooledDistinctStreamIdSetMinimumCapacity;
        int minimumCapacity = itemCount * 2;
        while (capacity < minimumCapacity)
        {
            capacity <<= 1;
        }

        return capacity;
    }

    private static bool TryAddDistinctStreamId(
        ulong[] setSlots,
        bool[] occupiedSlots,
        int setMask,
        ulong streamId)
    {
        int index = MixStreamIdHash(streamId) & setMask;
        while (occupiedSlots[index])
        {
            if (setSlots[index] == streamId)
            {
                return false;
            }

            index = (index + 1) & setMask;
        }

        occupiedSlots[index] = true;
        setSlots[index] = streamId;
        return true;
    }

    private static int MixStreamIdHash(ulong streamId)
    {
        unchecked
        {
            streamId ^= streamId >> StreamIdHashShift;
            streamId *= StreamIdHashMultiplier;
            streamId ^= streamId >> StreamIdHashShift;
            return (int)streamId;
        }
    }

    private static ulong[] BuildDistinctStreamIdsByLinearScan(ReadOnlySpan<PendingApplicationSendRequest> queuedWrites)
    {
        ulong[] streamIds = new ulong[queuedWrites.Length];
        int uniqueCount = 0;

        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            bool alreadyPresent = false;
            for (int index = 0; index < uniqueCount; index++)
            {
                if (streamIds[index] == queuedWrite.StreamId)
                {
                    alreadyPresent = true;
                    break;
                }
            }

            if (!alreadyPresent)
            {
                streamIds[uniqueCount++] = queuedWrite.StreamId;
            }
        }

        if (uniqueCount != streamIds.Length)
        {
            Array.Resize(ref streamIds, uniqueCount);
        }

        return streamIds;
    }

    internal static int ComparePendingApplicationSendRequests(
        PendingApplicationSendRequest left,
        PendingApplicationSendRequest right)
    {
        int priorityComparison = right.Priority.CompareTo(left.Priority);
        if (priorityComparison != 0)
        {
            return priorityComparison;
        }

        return left.Sequence.CompareTo(right.Sequence);
    }

    private int FindInsertionIndex(PendingApplicationSendRequest request)
    {
        int lower = 0;
        int upper = pendingRequests.Count;
        while (lower < upper)
        {
            int middle = lower + ((upper - lower) / 2);
            if (ComparePendingApplicationSendRequests(request, pendingRequests[middle]) < 0)
            {
                upper = middle;
            }
            else
            {
                lower = middle + 1;
            }
        }

        return lower;
    }

    private long TakeNextSequence()
    {
        if (nextSequence == long.MaxValue)
        {
            throw new InvalidOperationException("The application-send sequence space is exhausted.");
        }

        return nextSequence++;
    }

    private void ResetOrderWhenEmpty()
    {
        if (pendingRequests.Count == 0)
        {
            pendingRequestsOrdered = true;
        }
    }

    private sealed class PendingApplicationSendRequestComparer : IComparer<PendingApplicationSendRequest>
    {
        public static readonly PendingApplicationSendRequestComparer Instance = new();

        private PendingApplicationSendRequestComparer()
        {
        }

        public int Compare(PendingApplicationSendRequest left, PendingApplicationSendRequest right)
            => ComparePendingApplicationSendRequests(left, right);
    }
}
