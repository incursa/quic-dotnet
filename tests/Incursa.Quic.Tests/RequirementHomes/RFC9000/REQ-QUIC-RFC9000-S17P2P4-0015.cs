namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0015")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsANormalOneBytePacketNumberField()
    {
        byte[] packet = BuildInitialPacket(packetNumberLength: 1, protectedPayloadLength: 1);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.PacketNumberLengthBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsWhosePayloadIsShorterThanThePacketNumberField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x43,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x00, 0x03, 0xAA, 0xBB, 0xCC]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsTheMinimumAndMaximumPacketNumberFieldLengths(int packetNumberLength)
    {
        byte[] packet = BuildInitialPacket(packetNumberLength, protectedPayloadLength: packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
    }

    private static byte[] BuildInitialPacket(int packetNumberLength, int protectedPayloadLength)
    {
        byte[] packetNumber = new byte[packetNumberLength];
        byte[] protectedPayload = new byte[protectedPayloadLength];

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(0x40 | (packetNumberLength - 1)),
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], packetNumber, protectedPayload));
    }
}
