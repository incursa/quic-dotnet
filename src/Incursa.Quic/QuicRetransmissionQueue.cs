// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Owns the pending retransmission queue and the queue-local bookkeeping rules around it.
/// </summary>
internal sealed class QuicRetransmissionQueue
{
    private readonly Queue<QuicConnectionRetransmissionPlan> pendingRetransmissions = [];
    private long retainedBufferCount;
    private long retainedByteCount;
    private ulong? oldestSentAtMicros;

    public int Count => pendingRetransmissions.Count;

    internal QuicRetentionSnapshot CaptureRetentionSnapshot(ulong nowMicros)
    {
        return new QuicRetentionSnapshot(
            retainedBufferCount,
            retainedByteCount,
            QuicRetentionSnapshot.GetOldestAgeMilliseconds(nowMicros, oldestSentAtMicros));
    }

    public bool HasPendingRetransmission(QuicPacketNumberSpace packetNumberSpace)
    {
        foreach (QuicConnectionRetransmissionPlan retransmission in pendingRetransmissions)
        {
            if (retransmission.PacketNumberSpace == packetNumberSpace)
            {
                return true;
            }
        }

        return false;
    }

    public ulong? GetLargestTrackedPacketNumber(QuicPacketNumberSpace packetNumberSpace)
    {
        ulong largestPacketNumber = default;
        bool found = false;

        foreach (QuicConnectionRetransmissionPlan retransmission in pendingRetransmissions)
        {
            if (retransmission.PacketNumberSpace != packetNumberSpace)
            {
                continue;
            }

            largestPacketNumber = found
                ? Math.Max(largestPacketNumber, retransmission.PacketNumber)
                : retransmission.PacketNumber;
            found = true;
        }

        return found ? largestPacketNumber : null;
    }

    public void QueueRetransmission(QuicConnectionRetransmissionPlan retransmission)
    {
        pendingRetransmissions.Enqueue(retransmission);
        RecordEnqueue(retransmission);
    }

    // CONTEXT: retransmission scans preserve queue order
    // SEE: code:src/Incursa.Quic/QuicRetransmissionQueue.cs#TryDiscardPacketNumberSpace
    // SEE: code:src/Incursa.Quic/QuicRetransmissionQueue.cs#TryDiscardPacketProtectionLevel
    // SEE: code:src/Incursa.Quic/QuicRetransmissionQueue.cs#TrySuppressResetStreamRetransmissionForStream
    // The queue is walked by dequeue/re-enqueue so unmatched plans keep their
    // original FIFO order while matched plans release resources immediately.
    // Do not replace this with a filtering copy unless the ordering and
    // lifetime behavior are revalidated.
    public bool TryRemovePendingRetransmission(QuicConnectionSentPacketKey key)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool removed = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketNumberSpace == key.PacketNumberSpace
                && retransmission.PacketNumber == key.PacketNumber)
            {
                removedOldest |= RecordRemoval(retransmission);
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                removed = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return removed;
    }

    public bool TryDiscardPacketNumberSpace(QuicPacketNumberSpace packetNumberSpace)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketNumberSpace == packetNumberSpace)
            {
                removedOldest |= RecordRemoval(retransmission);
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketProtectionLevel == packetProtectionLevel)
            {
                removedOldest |= RecordRemoval(retransmission);
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TryDiscardOneRttKeyPhase(ulong keyPhase)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                && retransmission.OneRttKeyPhase == keyPhase)
            {
                removedOldest |= RecordRemoval(retransmission);
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TryDiscardPendingRetransmissionsOlderThan(ulong discardBeforeSentAtMicros)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.SentAtMicros < discardBeforeSentAtMicros)
            {
                removedOldest |= RecordRemoval(retransmission);
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TrySuppressRetransmissionForStream(ulong streamId)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.StreamId != streamId
                && (retransmission.StreamIds is null
                    || retransmission.StreamIds.Length != 1
                    || retransmission.StreamIds[0] != streamId))
            {
                pendingRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
            removedOldest |= RecordRemoval(retransmission);
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TrySuppressStopSendingRetransmissionForStream(ulong streamId)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (!QuicFramePayloadInspector.ContainsStopSendingFrameForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                pendingRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
            removedOldest |= RecordRemoval(retransmission);
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TrySuppressResetStreamRetransmissionForStream(ulong streamId)
    {
        int pendingCount = pendingRetransmissions.Count;
        if (pendingCount == 0)
        {
            return false;
        }

        bool updated = false;
        bool removedOldest = false;
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (!QuicFramePayloadInspector.ContainsResetStreamFrameForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                pendingRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
            removedOldest |= RecordRemoval(retransmission);
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
        }

        RefreshOldestSentAtMicros(removedOldest);
        return updated;
    }

    public bool TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission)
    {
        if (pendingRetransmissions.Count == 0)
        {
            retransmission = default;
            return false;
        }

        retransmission = pendingRetransmissions.Dequeue();
        RefreshOldestSentAtMicros(RecordRemoval(retransmission));
        return true;
    }

    private void RecordEnqueue(QuicConnectionRetransmissionPlan retransmission)
    {
        QuicRetentionSnapshot.AddOwners(
            retransmission.PlaintextPayloadOwner,
            retransmission.PacketBytesOwner,
            ref retainedBufferCount,
            ref retainedByteCount);
        if (!oldestSentAtMicros.HasValue
            || retransmission.SentAtMicros < oldestSentAtMicros.Value)
        {
            oldestSentAtMicros = retransmission.SentAtMicros;
        }
    }

    private bool RecordRemoval(QuicConnectionRetransmissionPlan retransmission)
    {
        if (retransmission.PlaintextPayloadOwner is not null)
        {
            retainedBufferCount--;
            retainedByteCount -= retransmission.PlaintextPayloadOwner.Length;
        }

        if (retransmission.PacketBytesOwner is not null
            && !ReferenceEquals(
                retransmission.PlaintextPayloadOwner,
                retransmission.PacketBytesOwner))
        {
            retainedBufferCount--;
            retainedByteCount -= retransmission.PacketBytesOwner.Length;
        }

        return oldestSentAtMicros == retransmission.SentAtMicros;
    }

    private void RefreshOldestSentAtMicros(bool removedOldest)
    {
        if (!removedOldest)
        {
            return;
        }

        oldestSentAtMicros = null;
        foreach (QuicConnectionRetransmissionPlan retained in pendingRetransmissions)
        {
            if (!oldestSentAtMicros.HasValue
                || retained.SentAtMicros < oldestSentAtMicros.Value)
            {
                oldestSentAtMicros = retained.SentAtMicros;
            }
        }
    }

    internal void CaptureBuildableApplicationRetransmissions(
        Dictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket>.ValueCollection sentPackets,
        ref List<QuicConnectionRetransmissionPlan>? retainedRetransmissions)
    {
        foreach (QuicConnectionSentPacket packet in sentPackets)
        {
            if (packet.PacketNumberSpace != QuicPacketNumberSpace.ApplicationData
                || !packet.Retransmittable
                || packet.PlaintextPayload.IsEmpty)
            {
                continue;
            }

            QuicConnectionRetransmissionPlan retained = new(
                packet.PacketNumberSpace,
                packet.PacketNumber,
                packet.PayloadBytes,
                packet.SentAtMicros,
                packet.ProbePacket,
                packet.CryptoMetadata,
                default,
                packet.PacketProtectionLevel,
                packet.StreamId,
                packet.StreamIds,
                packet.PlaintextPayload,
                packet.OneRttKeyPhase,
                PlaintextPayloadOwner: packet.PlaintextPayloadOwner,
                PacketBytesOwner: packet.PacketBytesOwner);
            AddClonedRetainedPlan(retained, ref retainedRetransmissions);
        }

        foreach (QuicConnectionRetransmissionPlan retransmission in pendingRetransmissions)
        {
            if (retransmission.PacketNumberSpace != QuicPacketNumberSpace.ApplicationData
                || retransmission.PlaintextPayload.IsEmpty)
            {
                continue;
            }

            AddClonedRetainedPlan(retransmission, ref retainedRetransmissions);
        }
    }

    private static void AddClonedRetainedPlan(
        QuicConnectionRetransmissionPlan retransmission,
        ref List<QuicConnectionRetransmissionPlan>? retainedRetransmissions)
    {
        retainedRetransmissions ??= [];
        QuicConnectionRetransmissionPlan retained = CloneOwnedPlaintext(retransmission);
        try
        {
            retainedRetransmissions.Add(retained);
        }
        catch
        {
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retained);
            throw;
        }
    }

    private static QuicConnectionRetransmissionPlan CloneOwnedPlaintext(
        QuicConnectionRetransmissionPlan retransmission)
    {
        if (retransmission.PlaintextPayloadOwner is null
            && retransmission.PacketBytesOwner is null)
        {
            return retransmission with
            {
                PacketBytes = default,
                PacketBytesOwner = null,
            };
        }

        int payloadLength = retransmission.PlaintextPayload.Length;
        byte[] payloadOwner = QuicBufferPool.RentBytes(
            payloadLength,
            QuicBufferPoolOwner.Retransmission);
        retransmission.PlaintextPayload.CopyTo(payloadOwner);
        return retransmission with
        {
            PacketBytes = default,
            PlaintextPayload = payloadOwner.AsMemory(0, payloadLength),
            PlaintextPayloadOwner = payloadOwner,
            PacketBytesOwner = null,
        };
    }

    internal bool ContainsStreamDataForStream(ulong streamId)
    {
        foreach (QuicConnectionRetransmissionPlan retransmission in pendingRetransmissions)
        {
            if (QuicFramePayloadInspector.ContainsStreamDataForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                return true;
            }
        }

        return false;
    }
}
