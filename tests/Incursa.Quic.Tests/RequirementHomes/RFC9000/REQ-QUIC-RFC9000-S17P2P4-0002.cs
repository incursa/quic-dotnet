namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesHandshakeReservedAndPacketNumberLengthBitsFromByteZero()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 2,
            reservedBits: 0x02);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.ReservedBits);
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsHandshakePacketsWhoseLengthFieldIsShorterThanTheEncodedPacketNumber()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: QuicHandshakePacketRequirementTestData.BuildHandshakeHeaderControlBits(
                packetNumberLength: 4,
                reservedBits: 0x01),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x03, 0x01, 0x02, 0x03]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsHandshakePacketsWhenBothBitFieldsUseTheirLargestEncodings()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 4,
            reservedBits: 0x03,
            protectedPayload: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.ReservedBits);
        Assert.Equal((byte)0x03, header.PacketNumberLengthBits);
    }
}
