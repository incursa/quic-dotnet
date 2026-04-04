namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2_0004
{
    [Theory]
    [InlineData((byte)0x40, (byte)0x00, (byte)0x00)]
    [InlineData((byte)0x45, (byte)0x05, (byte)0x01)]
    [InlineData((byte)0x4A, (byte)0x0A, (byte)0x02)]
    [InlineData((byte)0x4F, (byte)0x0F, (byte)0x03)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0004")]
    public void TryParseLongHeader_ExposesTheFourBitTypeSpecificField(
        byte headerControlBits,
        byte expectedTypeSpecificBits,
        byte expectedReservedBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 0,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(expectedTypeSpecificBits, header.TypeSpecificBits);
        Assert.Equal(expectedReservedBits, header.ReservedBits);
    }
}
