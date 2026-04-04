namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsHandshakePacketsThatUseLongHeaderTypeTwo()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_DoesNotTreatRetryPacketsAsHandshakePackets()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0xAA]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsTheShortestValidHandshakePacket()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            protectedPayload: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }
}
