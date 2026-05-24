namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0258")]
public sealed class REQ_QUIC_RFC9000_0258
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsValidInitialPacketWithPacketNumberSpace()
    {
        byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0x01],
                packetNumber: [0x02],
                protectedPayload: [0xAA, 0xBB]));

        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsWeaklyProtectedInvalidPackets()
    {
        byte[] truncatedInitialPacket = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([0x01], [0x02], [0xAA]),
            truncateBy: 1);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.False(QuicPacketParser.TryParseLongHeader(truncatedInitialPacket, out _));
        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal((byte)0x03, retryHeader.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }
}
