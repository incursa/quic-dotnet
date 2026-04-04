namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0007")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0007")]
    public void TryParseLongHeader_ReportsTheReservedBitsWhenTheyAreSet()
    {
        byte[] packet = BuildVersion1InitialPacket(reservedBits: 1);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)1, header.ReservedBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0007")]
    public void TryParseLongHeader_RejectsShortHeadersForTheReservedBitsField()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x00,
            remainder: [0x01, 0x02, 0x03]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0007")]
    public void TryParseLongHeader_PreservesTheBoundaryReservedBits(byte reservedBits)
    {
        byte[] packet = BuildVersion1InitialPacket(reservedBits);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(reservedBits, header.ReservedBits);
    }

    private static byte[] BuildVersion1InitialPacket(byte reservedBits)
    {
        byte headerControlBits = (byte)(0x40 | 0x20 | (reservedBits << 2));
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                packetNumber: [0x01],
                protectedPayload: [0xAA]));
    }
}
