namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0007")]
public sealed class REQ_QUIC_RFC9000_S17P2_0007
{
    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0007")]
    public void TryParseLongHeader_PreservesTheDestinationConnectionIdLengthInVersion1Packets(
        int destinationConnectionIdLength)
    {
        byte[] destinationConnectionId = new byte[destinationConnectionIdLength];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId,
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xAA],
                packetNumber: [0x01],
                protectedPayload: [0xBB]));

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0007")]
    public void TryParseLongHeader_RejectsVersion1DestinationConnectionIdsLongerThan20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: Enumerable.Repeat((byte)0xDA, 21).ToArray(),
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xAA],
                packetNumber: [0x01],
                protectedPayload: [0xBB]));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}
