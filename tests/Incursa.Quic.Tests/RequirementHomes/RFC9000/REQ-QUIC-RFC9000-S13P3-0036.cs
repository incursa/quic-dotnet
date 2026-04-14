namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0036">A sender SHOULD avoid retransmitting information from packets once they are acknowledged.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0036")]
public sealed class REQ_QUIC_RFC9000_S13P3_0036
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgePacket_RemovesQueuedRetransmissionForAnAcknowledgedLostPacket()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_LeavesAnUnrelatedQueuedRetransmissionIntact()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            9,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
        Assert.Equal(1_200UL, retransmission.PayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcknowledgePacket_PreservesLaterQueuedRetransmissionsWhenRemovingAnAckedPacket()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 125,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            8,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(8UL, retransmission.PacketNumber);
        Assert.Equal(900UL, retransmission.PayloadBytes);
    }
}
