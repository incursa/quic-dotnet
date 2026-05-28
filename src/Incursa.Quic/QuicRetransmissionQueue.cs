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

    public bool TryRemovePendingRetransmission(QuicConnectionSentPacketKey key)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool removed = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketNumberSpace == key.PacketNumberSpace
                && retransmission.PacketNumber == key.PacketNumber)
            {
                removed = true;
                continue;
            }

            retainedRetransmissions.Enqueue(retransmission);
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return removed;
    }

    public bool TryDiscardPacketNumberSpace(QuicPacketNumberSpace packetNumberSpace)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketNumberSpace == packetNumberSpace)
            {
                updated = true;
                continue;
            }

            retainedRetransmissions.Enqueue(retransmission);
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return updated;
    }

    public bool TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketProtectionLevel == packetProtectionLevel)
            {
                updated = true;
                continue;
            }

            retainedRetransmissions.Enqueue(retransmission);
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return updated;
    }

    public bool TryDiscardOneRttKeyPhase(ulong keyPhase)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                && retransmission.OneRttKeyPhase == keyPhase)
            {
                updated = true;
                continue;
            }

            retainedRetransmissions.Enqueue(retransmission);
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return updated;
    }

    public bool TryDiscardPendingRetransmissionsOlderThan(ulong discardBeforeSentAtMicros)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.SentAtMicros < discardBeforeSentAtMicros)
            {
                updated = true;
                continue;
            }

            retainedRetransmissions.Enqueue(retransmission);
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return updated;
    }

    public bool TrySuppressRetransmissionForStream(ulong streamId)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (retransmission.StreamIds is null
                || retransmission.StreamIds.Length != 1
                || retransmission.StreamIds[0] != streamId)
            {
                retainedRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return updated;
    }

    public bool TrySuppressStopSendingRetransmissionForStream(ulong streamId)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (!QuicFramePayloadInspector.ContainsStopSendingFrameForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                retainedRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
        }

        return updated;
    }

    public bool TrySuppressResetStreamRetransmissionForStream(ulong streamId)
    {
        if (pendingRetransmissions.Count == 0)
        {
            return false;
        }

        bool updated = false;
        Queue<QuicConnectionRetransmissionPlan> retainedRetransmissions = [];
        while (pendingRetransmissions.Count > 0)
        {
            QuicConnectionRetransmissionPlan retransmission = pendingRetransmissions.Dequeue();
            if (!QuicFramePayloadInspector.ContainsResetStreamFrameForStream(retransmission.PlaintextPayload.Span, streamId))
            {
                retainedRetransmissions.Enqueue(retransmission);
                continue;
            }

            updated = true;
        }

        while (retainedRetransmissions.Count > 0)
        {
            pendingRetransmissions.Enqueue(retainedRetransmissions.Dequeue());
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

            (retainedRetransmissions ??= []).Add(new QuicConnectionRetransmissionPlan(
                packet.PacketNumberSpace,
                packet.PacketNumber,
                packet.PayloadBytes,
                packet.SentAtMicros,
                packet.ProbePacket,
                packet.CryptoMetadata,
                default,
                packet.PacketProtectionLevel,
                packet.StreamIds,
                packet.PlaintextPayload,
                packet.OneRttKeyPhase));
        }

        foreach (QuicConnectionRetransmissionPlan retransmission in pendingRetransmissions)
        {
            if (retransmission.PacketNumberSpace != QuicPacketNumberSpace.ApplicationData
                || retransmission.PlaintextPayload.IsEmpty)
            {
                continue;
            }

            (retainedRetransmissions ??= []).Add(retransmission with { PacketBytes = default });
        }
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
