namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0012")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheSourceConnectionIdLengthByte()
    {
        byte[] packet = BuildInitialPacket(destinationConnectionIdLength: 1, sourceConnectionIdLength: 20, protectedPayloadLength: 1);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(20, header.SourceConnectionIdLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsWithoutTheSourceConnectionIdLengthByte()
    {
        byte[] packet = BuildInitialPacket(destinationConnectionIdLength: 1, sourceConnectionIdLength: 1, protectedPayloadLength: 1);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..7], out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_HandlesBoundarySourceConnectionIdLengths(int sourceConnectionIdLength)
    {
        byte[] packet = BuildInitialPacket(destinationConnectionIdLength: 1, sourceConnectionIdLength, protectedPayloadLength: 1);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
    }

    private static byte[] BuildInitialPacket(int destinationConnectionIdLength, int sourceConnectionIdLength, int protectedPayloadLength)
    {
        byte[] destinationConnectionId = new byte[destinationConnectionIdLength];
        byte[] sourceConnectionId = new byte[sourceConnectionIdLength];
        byte[] protectedPayload = new byte[protectedPayloadLength];

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: sourceConnectionId,
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], protectedPayload));
    }
}
