namespace Incursa.Quic;

internal readonly record struct QuicSenderPacketRecord(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber,
    ulong SentBytes,
    ulong SentAtMicros,
    bool AckEliciting,
    bool IsProbePacket);

/// <summary>
/// Owns packet-sent tracking and recovery timing for a connection.
/// </summary>
internal sealed class QuicSenderRecoveryRuntime
{
    private readonly Dictionary<QuicPacketNumberSpace, SortedDictionary<ulong, QuicSenderPacketRecord>> sentPacketsBySpace = [];

    /// <summary>
    /// Initializes a new sender/recovery runtime owner.
    /// </summary>
    public QuicSenderRecoveryRuntime(
        ulong maxDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
        ulong initialRttMicros = QuicRttEstimator.DefaultInitialRttMicros,
        int maximumRetainedAckRanges = 32,
        int minimumAckElicitingPacketsBeforeDelayedAck = 2)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        SenderFlowController = new QuicSenderFlowController(
            maxDatagramSizeBytes,
            maximumRetainedAckRanges,
            minimumAckElicitingPacketsBeforeDelayedAck);
        RecoveryController = new QuicRecoveryController(initialRttMicros);
    }

    /// <summary>
    /// Gets the sender-facing flow controller.
    /// </summary>
    public QuicSenderFlowController SenderFlowController { get; }

    /// <summary>
    /// Gets the recovery controller that owns PTO and loss timing.
    /// </summary>
    public QuicRecoveryController RecoveryController { get; }

    /// <summary>
    /// Gets the number of packet records currently retained for retransmission planning.
    /// </summary>
    public int PendingSentPacketCount
    {
        get
        {
            int count = 0;
            foreach (SortedDictionary<ulong, QuicSenderPacketRecord> sentPackets in sentPacketsBySpace.Values)
            {
                count += sentPackets.Count;
            }

            return count;
        }
    }

    /// <summary>
    /// Gets whether any ack-eliciting packet remains in flight.
    /// </summary>
    public bool HasAckElicitingPacketsInFlight => RecoveryController.HasAnyAckElicitingPacketsInFlight;

    /// <summary>
    /// Gets the current PTO backoff count.
    /// </summary>
    public int ProbeTimeoutBackoffCount => RecoveryController.ProbeTimeoutBackoffCount;

    /// <summary>
    /// Records a sent packet in the sender/recovery owner.
    /// </summary>
    public void RecordPacketSent(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentBytes,
        ulong sentAtMicros,
        bool ackEliciting,
        bool isAckOnlyPacket = false,
        bool isProbePacket = false)
    {
        SenderFlowController.RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            sentBytes,
            sentAtMicros,
            ackEliciting,
            isAckOnlyPacket,
            isProbePacket);

        RecoveryController.RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            sentAtMicros,
            ackEliciting && !isAckOnlyPacket);

        if (isAckOnlyPacket)
        {
            return;
        }

        SortedDictionary<ulong, QuicSenderPacketRecord> sentPackets = GetOrCreateSentPackets(packetNumberSpace);
        sentPackets[packetNumber] = new QuicSenderPacketRecord(
            packetNumberSpace,
            packetNumber,
            sentBytes,
            sentAtMicros,
            ackEliciting,
            isProbePacket);
    }

    /// <summary>
    /// Detects lost packets and updates the retransmission plan.
    /// </summary>
    public IReadOnlyList<QuicLostPacket> DetectLostPackets(
        ulong nowMicros,
        out ulong? earliestLossDetectionTimeMicros,
        out QuicPacketNumberSpace earliestLossPacketNumberSpace)
    {
        IReadOnlyList<QuicLostPacket> lostPackets = RecoveryController.DetectLostPackets(
            nowMicros,
            out earliestLossDetectionTimeMicros,
            out earliestLossPacketNumberSpace);

        if (lostPackets.Count == 0)
        {
            return lostPackets;
        }

        foreach (QuicLostPacket lostPacket in lostPackets)
        {
            if (!sentPacketsBySpace.TryGetValue(lostPacket.PacketNumberSpace, out SortedDictionary<ulong, QuicSenderPacketRecord>? sentPackets))
            {
                continue;
            }

            sentPackets.Remove(lostPacket.PacketNumber);
            if (sentPackets.Count == 0)
            {
                sentPacketsBySpace.Remove(lostPacket.PacketNumberSpace);
            }
        }

        return lostPackets;
    }

    /// <summary>
    /// Computes the next loss-detection or PTO deadline.
    /// </summary>
    public bool TrySelectLossDetectionTimer(
        ulong nowMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed,
        bool serverAtAntiAmplificationLimit,
        bool peerAddressValidationComplete,
        bool handshakeKeysAvailable,
        out ulong selectedRecoveryTimerMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        return RecoveryController.TrySelectLossDetectionTimer(
            nowMicros,
            maxAckDelayMicros,
            handshakeConfirmed,
            serverAtAntiAmplificationLimit,
            peerAddressValidationComplete,
            handshakeKeysAvailable,
            out selectedRecoveryTimerMicros,
            out selectedPacketNumberSpace);
    }

    /// <summary>
    /// Advances the PTO backoff count after a PTO fires.
    /// </summary>
    public void RecordProbeTimeoutExpired()
    {
        RecoveryController.RecordProbeTimeoutExpired();
    }

    /// <summary>
    /// Looks up a retained packet record.
    /// </summary>
    public bool TryGetSentPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        out QuicSenderPacketRecord packetRecord)
    {
        packetRecord = default;

        if (!sentPacketsBySpace.TryGetValue(packetNumberSpace, out SortedDictionary<ulong, QuicSenderPacketRecord>? sentPackets))
        {
            return false;
        }

        return sentPackets.TryGetValue(packetNumber, out packetRecord);
    }

    private SortedDictionary<ulong, QuicSenderPacketRecord> GetOrCreateSentPackets(QuicPacketNumberSpace packetNumberSpace)
    {
        if (!sentPacketsBySpace.TryGetValue(packetNumberSpace, out SortedDictionary<ulong, QuicSenderPacketRecord>? sentPackets))
        {
            sentPackets = [];
            sentPacketsBySpace[packetNumberSpace] = sentPackets;
        }

        return sentPackets;
    }
}
