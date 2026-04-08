namespace Incursa.Quic;

internal readonly record struct QuicConnectionSentPacketKey(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber);

internal readonly record struct QuicConnectionSentPacket(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber,
    ulong PayloadBytes,
    ulong SentAtMicros,
    bool AckEliciting = true,
    bool AckOnlyPacket = false,
    bool ProbePacket = false,
    bool Retransmittable = true);

internal readonly record struct QuicConnectionRetransmissionPlan(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber,
    ulong PayloadBytes,
    ulong SentAtMicros);

/// <summary>
/// Owns connection-scoped send state, PTO bookkeeping, and retransmission planning.
/// </summary>
internal sealed class QuicConnectionSendRuntime
{
    private readonly Dictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPackets = [];
    private readonly Queue<QuicConnectionRetransmissionPlan> pendingRetransmissions = [];
    private readonly QuicSenderFlowController flowController;

    public QuicConnectionSendRuntime(QuicSenderFlowController? flowController = null)
    {
        this.flowController = flowController ?? new QuicSenderFlowController();
    }

    public QuicSenderFlowController FlowController => flowController;

    public IReadOnlyDictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> SentPackets => sentPackets;

    public ulong? LossDetectionDeadlineMicros { get; private set; }

    public int ProbeTimeoutCount { get; private set; }

    public int PendingRetransmissionCount => pendingRetransmissions.Count;

    public void TrackSentPacket(QuicConnectionSentPacket packet)
    {
        QuicConnectionSentPacketKey key = new(packet.PacketNumberSpace, packet.PacketNumber);
        sentPackets[key] = packet;
        flowController.RecordPacketSent(
            packet.PacketNumberSpace,
            packet.PacketNumber,
            packet.PayloadBytes,
            packet.SentAtMicros,
            packet.AckEliciting,
            packet.AckOnlyPacket,
            packet.ProbePacket);
    }

    public bool TryAcknowledgePacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool handshakeConfirmed = false)
    {
        QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);
        if (!sentPackets.Remove(key))
        {
            return false;
        }

        ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ProbeTimeoutCount,
            acknowledgmentReceived: true,
            acknowledgmentPacketNumberSpace: packetNumberSpace,
            handshakeConfirmed: handshakeConfirmed);

        if (sentPackets.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    public bool TryRegisterLoss(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool handshakeConfirmed = false,
        bool scheduleRetransmission = true)
    {
        QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);
        if (!sentPackets.Remove(key, out QuicConnectionSentPacket packet))
        {
            return false;
        }

        _ = flowController.TryRegisterLoss(
            packet.PacketNumberSpace,
            packet.PacketNumber,
            packet.SentAtMicros,
            allowAckOnlyLossSignal: packet.AckOnlyPacket);

        if (scheduleRetransmission && packet.Retransmittable)
        {
            pendingRetransmissions.Enqueue(new QuicConnectionRetransmissionPlan(
                packet.PacketNumberSpace,
                packet.PacketNumber,
                packet.PayloadBytes,
                packet.SentAtMicros));
        }

        ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ProbeTimeoutCount,
            acknowledgmentPacketNumberSpace: packet.PacketNumberSpace,
            handshakeConfirmed: handshakeConfirmed);

        if (sentPackets.Count == 0 && pendingRetransmissions.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    public bool TryArmProbeTimeout(
        QuicPacketNumberSpace packetNumberSpace,
        ulong nowMicros,
        ulong smoothedRttMicros,
        ulong rttVarMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed)
    {
        if (!QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            packetNumberSpace,
            smoothedRttMicros,
            rttVarMicros,
            maxAckDelayMicros,
            handshakeConfirmed,
            out ulong probeTimeoutMicros))
        {
            return false;
        }

        ulong backedOffProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros,
            ProbeTimeoutCount);

        LossDetectionDeadlineMicros = SaturatingAdd(nowMicros, backedOffProbeTimeoutMicros);
        ProbeTimeoutCount++;
        return true;
    }

    public bool TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission)
    {
        if (pendingRetransmissions.Count == 0)
        {
            retransmission = default;
            return false;
        }

        retransmission = pendingRetransmissions.Dequeue();
        if (pendingRetransmissions.Count == 0 && sentPackets.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    public void ClearLossDetectionDeadline()
    {
        LossDetectionDeadlineMicros = null;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }
}
