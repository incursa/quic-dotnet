namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0014")]
public sealed class REQ_QUIC_RFC9000_S17P2_0014
{
    [Theory]
    [InlineData((byte)0x40)]
    [InlineData((byte)0x50)]
    [InlineData((byte)0x60)]
    [InlineData((byte)0x70)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_RequiresTheFixedBitForVersionedLongHeaders(byte headerControlBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: BuildVersion1VersionSpecificData(headerControlBits));

        Assert.Equal(0x40, packet[0] & 0x40);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(header.FixedBit);
    }

    private static byte[] BuildVersion1VersionSpecificData(byte headerControlBits)
    {
        int packetNumberLength = (headerControlBits & 0x03) + 1;
        byte[] packetNumber = Enumerable.Range(1, packetNumberLength).Select(static value => (byte)value).ToArray();
        byte[] protectedPayload = [0xAA];
        byte longPacketTypeBits = (byte)(headerControlBits & 0x30);

        return longPacketTypeBits switch
        {
            0x00 => QuicHeaderTestData.BuildInitialVersionSpecificData([], packetNumber, protectedPayload),
            0x10 or 0x20 => QuicHeaderTestData.BuildZeroRttVersionSpecificData(packetNumber, protectedPayload),
            _ => [0xAA, 0xBB, 0xCC],
        };
    }
}
