namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0003")]
public sealed class REQ_QUIC_RFC9000_S5P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_RecognizesHandshakePacketsThatCanBeAssociatedWithConnections()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.LongPacketTypeBits);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }
}
