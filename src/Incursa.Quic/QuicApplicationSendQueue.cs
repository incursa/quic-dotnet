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
    QuicApplicationSendQueueCause QueueCause = QuicApplicationSendQueueCause.SmallWriteDelay);

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
    private const int PooledDistinctStreamIdSetMinimumCapacity = 32;
    private const int StreamIdHashShift = 33;
    private const ulong StreamIdHashMultiplier = 0xff51afd7ed558ccdUL;

    private readonly List<PendingApplicationSendRequest> pendingRequests = [];
    private long nextSequence;
    private bool pendingRequestsOrdered = true;

    internal QuicApplicationSendQueue(long initialSequence = 0)
    {
        nextSequence = initialSequence;
    }

    public int Count => pendingRequests.Count;

    internal QuicRetentionSnapshot CaptureRetentionSnapshot(
        ulong? nowMicros = null,
        QuicApplicationSendQueueCause? queueCause = null)
    {
        long retainedBytes = 0;
        long retainedBuffers = 0;
        ulong? oldestEnqueuedAtMicros = null;
        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            if (queueCause.HasValue && pendingRequest.QueueCause != queueCause.Value)
            {
                continue;
            }

            retainedBuffers++;
            retainedBytes += pendingRequest.StreamPayload.Length;
            oldestEnqueuedAtMicros = !oldestEnqueuedAtMicros.HasValue
                || pendingRequest.FirstEnqueuedAtMicros < oldestEnqueuedAtMicros.Value
                ? pendingRequest.FirstEnqueuedAtMicros
                : oldestEnqueuedAtMicros;
        }

        return new QuicRetentionSnapshot(
            retainedBuffers,
            retainedBytes,
            nowMicros.HasValue
                ? QuicRetentionSnapshot.GetOldestAgeMilliseconds(nowMicros.Value, oldestEnqueuedAtMicros)
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
        long retainedBuffers = 0;
        long retainedBytes = 0;
        ulong? oldestEnqueuedAtMicros = null;

        foreach (PendingApplicationSendRequest pendingRequest in pendingRequests)
        {
            int causeIndex = (int)pendingRequest.QueueCause;
            if ((uint)causeIndex >= QueueCauseCount)
            {
                throw new InvalidOperationException($"Unknown application-send queue cause: {pendingRequest.QueueCause}.");
            }

            retainedBuffers++;
            retainedBytes += pendingRequest.StreamPayload.Length;
            oldestEnqueuedAtMicros = !oldestEnqueuedAtMicros.HasValue
                || pendingRequest.FirstEnqueuedAtMicros < oldestEnqueuedAtMicros.Value
                ? pendingRequest.FirstEnqueuedAtMicros
                : oldestEnqueuedAtMicros;

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
            retainedBuffers,
            retainedBytes,
            QuicRetentionSnapshot.GetOldestAgeMilliseconds(nowMicros, oldestEnqueuedAtMicros));
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

    public void Enqueue(
        ulong streamId,
        int priority,
        byte[] streamPayload,
        int streamPayloadLength,
        ulong firstEnqueuedAtMicros = 0,
        QuicApplicationSendQueueCause queueCause = QuicApplicationSendQueueCause.SmallWriteDelay)
    {
        PendingApplicationSendRequest request = new(
            TakeNextSequence(),
            streamId,
            priority,
            streamPayload,
            streamPayloadLength,
            firstEnqueuedAtMicros,
            queueCause);

        if (pendingRequestsOrdered && pendingRequests.Count < MaintainedOrderThreshold)
        {
            pendingRequests.Insert(FindInsertionIndex(request), request);
        }
        else
        {
            pendingRequests.Add(request);
            pendingRequestsOrdered = false;
        }
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

    public bool TryReplaceQueuedWritePayload(long sequence, byte[] streamPayload, int streamPayloadLength)
    {
        for (int index = 0; index < pendingRequests.Count; index++)
        {
            PendingApplicationSendRequest queuedWrite = pendingRequests[index];
            if (queuedWrite.Sequence != sequence)
            {
                continue;
            }

            QuicBufferPool.ReturnBytes(queuedWrite.StreamPayload);
            pendingRequests[index] = queuedWrite with
            {
                StreamPayload = streamPayload,
                StreamPayloadLength = streamPayloadLength,
            };
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

        pendingRequests.CopyTo(queuedWrites);
        if (!pendingRequestsOrdered)
        {
            Array.Sort(
                queuedWrites,
                index: 0,
                length: queuedWriteCount,
                PendingApplicationSendRequestComparer.Instance);
        }

        return queuedWrites;
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

    public bool TryRemoveQueuedWritesForStream(ulong streamId, bool returnPayloads)
    {
        bool removedAny = false;
        for (int index = pendingRequests.Count - 1; index >= 0; index--)
        {
            if (pendingRequests[index].StreamId != streamId)
            {
                continue;
            }

            if (returnPayloads)
            {
                QuicBufferPool.ReturnBytes(pendingRequests[index].StreamPayload);
            }

            pendingRequests.RemoveAt(index);
            ResetOrderWhenEmpty();
            removedAny = true;
        }

        return removedAny;
    }

    public bool TryRemoveQueuedWrite(long sequence, bool returnPayloads = false)
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
                QuicBufferPool.ReturnBytes(pendingWrite.StreamPayload);
            }

            pendingRequests.RemoveAt(index);
            ResetOrderWhenEmpty();
            return true;
        }

        return false;
    }

    public bool TryRemoveQueuedWrites(
        ReadOnlySpan<PendingApplicationSendRequest> selectedWrites,
        bool returnPayloads = false)
    {
        bool removedAny = false;
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
                    QuicBufferPool.ReturnBytes(pendingRequests[index].StreamPayload);
                }

                pendingRequests.RemoveAt(index);
                ResetOrderWhenEmpty();
                removedAny = true;
                break;
            }
        }

        return removedAny;
    }

    public void Clear()
    {
        foreach (PendingApplicationSendRequest pendingWrite in pendingRequests)
        {
            QuicBufferPool.ReturnBytes(pendingWrite.StreamPayload);
        }

        pendingRequests.Clear();
        pendingRequestsOrdered = true;
    }

    internal static int SelectQueuedApplicationSendBatchCount(
        ReadOnlySpan<PendingApplicationSendRequest> queuedWrites,
        int maximumPayloadBytes)
    {
        int selectedCount = 0;
        int selectedBytes = 0;
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
