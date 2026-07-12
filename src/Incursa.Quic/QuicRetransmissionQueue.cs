// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Owns the pending retransmission queue and the queue-local bookkeeping rules around it.
/// </summary>
internal sealed class QuicRetransmissionQueue
{
    private readonly Queue<QuicConnectionRetransmissionPlan> pendingRetransmissions = [];

    public int Count => pendingRetransmissions.Count;

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketNumberSpace == key.PacketNumberSpace
                && retransmission.PacketNumber == key.PacketNumber)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                removed = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketNumberSpace == packetNumberSpace)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketProtectionLevel == packetProtectionLevel)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                && retransmission.OneRttKeyPhase == keyPhase)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.SentAtMicros < discardBeforeSentAtMicros)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                updated = true;
                continue;
            }

            pendingRetransmissions.Enqueue(retransmission);
        }

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
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
        }

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (!QuicFramePayloadInspector.ContainsStopSendingFrameForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                pendingRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
        }

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
        for (int index = 0; index < pendingCount; index++)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (!QuicFramePayloadInspector.ContainsResetStreamFrameForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                pendingRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
            QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
        }

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
        return true;
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
        byte[] payloadOwner = QuicBufferPool.RentBytes(payloadLength);
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
