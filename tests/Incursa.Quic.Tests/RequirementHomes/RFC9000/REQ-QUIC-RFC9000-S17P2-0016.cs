namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0016")]
public sealed class REQ_QUIC_RFC9000_S17P2_0016
{
    [Theory]
    [InlineData((byte)0x40, (byte)0x00)]
    [InlineData((byte)0x50, (byte)0x01)]
    [InlineData((byte)0x60, (byte)0x02)]
    [InlineData((byte)0x70, (byte)0x03)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesThePacketTypeBitsFromByteZero(
        byte headerControlBits,
        byte expectedLongPacketTypeBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: BuildVersion1VersionSpecificData(headerControlBits));

        Assert.Equal(expectedLongPacketTypeBits, (packet[0] & 0x30) >> 4);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(expectedLongPacketTypeBits, header.LongPacketTypeBits);
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
