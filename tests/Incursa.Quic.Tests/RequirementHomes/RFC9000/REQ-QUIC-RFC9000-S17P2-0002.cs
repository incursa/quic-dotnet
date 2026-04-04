namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2_0002
{
    [Theory]
    [InlineData((byte)0x40, (byte)0x00)]
    [InlineData((byte)0x50, (byte)0x01)]
    [InlineData((byte)0x60, (byte)0x02)]
    [InlineData((byte)0x70, (byte)0x03)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0002")]
    public void TryParseLongHeader_RequiresTheFixedBitForVersionedLongHeaders(
        byte headerControlBits,
        byte expectedLongPacketTypeBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: BuildVersion1VersionSpecificData(headerControlBits));

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(header.FixedBit);
        Assert.Equal(expectedLongPacketTypeBits, header.LongPacketTypeBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0002")]
    public void TryParseLongHeader_RejectsVersionedLongHeadersWithTheFixedBitClear()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x12,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: BuildVersion1VersionSpecificData(0x12));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    private static byte[] BuildVersion1VersionSpecificData(byte headerControlBits)
    {
        return (headerControlBits & 0x30) switch
        {
            0x00 => QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA]),
            0x10 or 0x20 => QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                packetNumber: [0x01],
                protectedPayload: [0xAA]),
            _ => [0xAA],
        };
    }
}
