namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0011")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesAFullySizedDestinationConnectionId()
    {
        byte[] packet = BuildInitialPacket(destinationConnectionIdLength: 8);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(8, header.DestinationConnectionIdLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsDestinationConnectionIdsLongerThanTwentyBytes()
    {
        byte[] packet = BuildInitialPacket(destinationConnectionIdLength: 21);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsDestinationConnectionIdLengthBoundaries(int destinationConnectionIdLength)
    {
        byte[] packet = BuildInitialPacket(destinationConnectionIdLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
    }

    private static byte[] BuildInitialPacket(int destinationConnectionIdLength)
    {
        byte[] destinationConnectionId = new byte[destinationConnectionIdLength];

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: [0x01],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], [0xAA]));
    }
}
