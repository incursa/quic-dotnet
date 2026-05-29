// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct PendingApplicationSendRequest(
    long Sequence,
    ulong StreamId,
    int Priority,
    byte[] StreamPayload,
    int StreamPayloadLength);

/// <summary>
/// Owns the pending application-send queue and its selection/bookkeeping rules.
/// </summary>
internal sealed class QuicApplicationSendQueue
{
    private readonly List<PendingApplicationSendRequest> pendingRequests = [];
    private long nextSequence;

    public int Count => pendingRequests.Count;

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

    public void Enqueue(ulong streamId, int priority, byte[] streamPayload, int streamPayloadLength)
    {
        pendingRequests.Add(new PendingApplicationSendRequest(
            nextSequence++,
            streamId,
            priority,
            streamPayload,
            streamPayloadLength));
    }

    public bool TryGetLatestQueuedWriteForStream(ulong streamId, out PendingApplicationSendRequest queuedWrite)
    {
        for (int index = pendingRequests.Count - 1; index >= 0; index--)
        {
            queuedWrite = pendingRequests[index];
            if (queuedWrite.StreamId == streamId)
            {
                return true;
            }
        }

        queuedWrite = default;
        return false;
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

    public PendingApplicationSendRequest[] GetSortedQueuedWrites()
    {
        if (pendingRequests.Count == 0)
        {
            return [];
        }

        PendingApplicationSendRequest[] queuedWrites = pendingRequests.ToArray();
        Array.Sort(queuedWrites, ComparePendingApplicationSendRequests);
        return queuedWrites;
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
            removedAny = true;
        }

        return removedAny;
    }

    public bool TryRemoveQueuedWrites(ReadOnlySpan<PendingApplicationSendRequest> selectedWrites)
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

                pendingRequests.RemoveAt(index);
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
}
