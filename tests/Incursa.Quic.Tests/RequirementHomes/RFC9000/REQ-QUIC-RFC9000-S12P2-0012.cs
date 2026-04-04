namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P2-0012")]
public sealed class REQ_QUIC_RFC9000_S12P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_IndividuallyExposesEveryPacketInACoalescedDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA1],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB1]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x02, 0x03],
            protectedPayload: [0xB2]);
        byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x62,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            secondVersionSpecificData);
        byte[] thirdPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xC0, 0xC1, 0xC2]);
        byte[] datagram = [.. firstPacket, .. secondPacket, .. thirdPacket];

        Assert.Equal(firstPacket.Length + secondPacket.Length + thirdPacket.Length, datagram.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..firstPacket.Length], out QuicLongHeaderPacket firstHeader));
        Assert.Equal(firstPacket.Length, 1 + 4 + 1 + firstHeader.DestinationConnectionIdLength + 1 + firstHeader.SourceConnectionIdLength + firstHeader.VersionSpecificData.Length);
        Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(firstHeader.VersionSpecificData));

        Assert.True(QuicPacketParser.TryParseLongHeader(datagram.AsSpan(firstPacket.Length, secondPacket.Length), out QuicLongHeaderPacket secondHeader));
        Assert.Equal(secondPacket.Length, 1 + 4 + 1 + secondHeader.DestinationConnectionIdLength + 1 + secondHeader.SourceConnectionIdLength + secondHeader.VersionSpecificData.Length);
        Assert.True(secondVersionSpecificData.AsSpan().SequenceEqual(secondHeader.VersionSpecificData));

        Assert.True(QuicPacketParser.TryParseShortHeader(datagram.AsSpan(firstPacket.Length + secondPacket.Length, thirdPacket.Length), out QuicShortHeaderPacket thirdHeader));
        Assert.True(thirdPacket.AsSpan(1).SequenceEqual(thirdHeader.Remainder));
    }
}
