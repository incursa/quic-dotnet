namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P2-0003")]
public sealed class REQ_QUIC_RFC9000_S12P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsAPacketWithALengthFieldToBeFollowedByAnotherPacketInTheSameDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xAA],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xBB]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] secondPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0x30, 0x31, 0x32]);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.Equal(firstPacket.Length + secondPacket.Length, datagram.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..firstPacket.Length], out QuicLongHeaderPacket header));
        Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
        Assert.True(QuicPacketParser.TryParseShortHeader(datagram.AsSpan(firstPacket.Length), out QuicShortHeaderPacket trailingHeader));
        Assert.Equal(secondPacket.Length - 1, trailingHeader.Remainder.Length);
        Assert.True(secondPacket.AsSpan(1).SequenceEqual(trailingHeader.Remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsACoalescedDatagramWhenTheFirstPacketIsTruncatedBeforeItsLengthDelimitedPayloadCompletes()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xAA],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xBB]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] truncatedFirstPacket = firstPacket[..^2];
        byte[] secondPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0x30, 0x31, 0x32]);
        byte[] datagram = [.. truncatedFirstPacket, .. secondPacket];

        Assert.False(QuicPacketParser.TryParseLongHeader(datagram[..truncatedFirstPacket.Length], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AllowsTheShortestValidCoalescedDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01, 0x02, 0x03],
            protectedPayload: []);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [],
            sourceConnectionId: [],
            firstVersionSpecificData);
        byte[] secondPacket = QuicHeaderTestData.BuildShortHeader(0x24, []);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.Equal(firstPacket.Length + secondPacket.Length, datagram.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..firstPacket.Length], out QuicLongHeaderPacket header));
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
        Assert.True(QuicPacketParser.TryParseShortHeader(datagram.AsSpan(firstPacket.Length), out QuicShortHeaderPacket trailingHeader));
        Assert.True(trailingHeader.Remainder.IsEmpty);
    }
}
