namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P2-0005")]
public sealed class REQ_QUIC_RFC9000_S12P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_TreatsEverythingAfterTheFirstByteAsPartOfThePacket()
    {
        byte[] leadingPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] trailingPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xDD],
                packetNumber: [0x01, 0x02],
                protectedPayload: [0xEE]));
        byte[] datagram = [.. leadingPacket, .. trailingPacket];

        Assert.True(QuicPacketParser.TryParseShortHeader(datagram, out QuicShortHeaderPacket header));
        Assert.Equal(datagram.Length - 1, header.Remainder.Length);
        Assert.True(header.Remainder.Slice(leadingPacket.Length - 1).SequenceEqual(trailingPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_AcceptsAShortHeaderPacketWhenItIsLastInTheDatagram()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(3, header.Remainder.Length);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }
}
