namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP1P1-0004")]
public sealed class REQ_QUIC_RFC9002_SAP1P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordSentBytes_PreservesThePacketSizeInThePacketRecord()
    {
        QuicPersistentCongestionPacket initialPacket = new(
            QuicPacketNumberSpace.Initial,
            sentAtMicros: 2_000,
            sentBytes: 1_200,
            ackEliciting: true,
            inFlight: true,
            acknowledged: false,
            lost: true);

        QuicPersistentCongestionPacket handshakePacket = new(
            QuicPacketNumberSpace.Handshake,
            sentAtMicros: 4_000,
            sentBytes: 64,
            ackEliciting: true,
            inFlight: false,
            acknowledged: true,
            lost: false);

        Assert.Equal(1_200UL, initialPacket.SentBytes);
        Assert.Equal(64UL, handshakePacket.SentBytes);
    }
}
