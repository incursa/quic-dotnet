namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP5-0001">When a packet is sent, the sender MUST store its packet number, send time, ack-eliciting flag, in_flight flag, and sent_bytes in sent_packets[pn_space][packet_number].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP5-0001")]
public sealed class REQ_QUIC_RFC9002_SAP5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicPersistentCongestionPacket_PreservesTheSendMetadataNeededForPacketTracking()
    {
        QuicPersistentCongestionPacket packet = new(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_234,
            sentBytes: 1_200,
            ackEliciting: true,
            inFlight: true,
            acknowledged: false,
            lost: false);

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packet.PacketNumberSpace);
        Assert.Equal(1_234UL, packet.SentAtMicros);
        Assert.Equal(1_200UL, packet.SentBytes);
        Assert.True(packet.AckEliciting);
        Assert.True(packet.InFlight);
        Assert.False(packet.Acknowledged);
        Assert.False(packet.Lost);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void QuicPersistentCongestionPacket_CanRepresentNonInFlightOrNonAckElicitingPackets()
    {
        QuicPersistentCongestionPacket packet = new(
            QuicPacketNumberSpace.Handshake,
            sentAtMicros: 4_567,
            sentBytes: 0,
            ackEliciting: false,
            inFlight: false,
            acknowledged: true,
            lost: true);

        Assert.Equal(QuicPacketNumberSpace.Handshake, packet.PacketNumberSpace);
        Assert.Equal(4_567UL, packet.SentAtMicros);
        Assert.Equal(0UL, packet.SentBytes);
        Assert.False(packet.AckEliciting);
        Assert.False(packet.InFlight);
        Assert.True(packet.Acknowledged);
        Assert.True(packet.Lost);
    }
}
