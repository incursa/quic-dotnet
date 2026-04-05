namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ExposesTheFixedBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xAA, 0xBB]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x40, (byte)(header.HeaderControlBits & 0x40));
    }
}
