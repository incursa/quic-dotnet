namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheInitialPacketNumberLengthBits()
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(packetNumberLength: 3);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsInitialPacketsWhoseLengthFieldIsShorterThanTheEncodedPacketNumber()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: []);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            QuicS17P2P2TestSupport.BuildInitialHeaderControlBits(packetNumberLength: 4),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(1, (byte)0x00)]
    [InlineData(4, (byte)0x03)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsInitialPacketNumberLengthBitBoundaries(
        int packetNumberLength,
        byte expectedPacketNumberLengthBits)
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(expectedPacketNumberLengthBits, header.PacketNumberLengthBits);
    }
}
