namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0013")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesAFullySizedSourceConnectionId()
    {
        byte[] packet = BuildInitialPacket(sourceConnectionIdLength: 8);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(8, header.SourceConnectionIdLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsSourceConnectionIdsLongerThanTwentyBytes()
    {
        byte[] packet = BuildInitialPacket(sourceConnectionIdLength: 21);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsSourceConnectionIdLengthBoundaries(int sourceConnectionIdLength)
    {
        byte[] packet = BuildInitialPacket(sourceConnectionIdLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
    }

    private static byte[] BuildInitialPacket(int sourceConnectionIdLength)
    {
        byte[] sourceConnectionId = new byte[sourceConnectionIdLength];

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x01],
            sourceConnectionId: sourceConnectionId,
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], [0xAA]));
    }
}
