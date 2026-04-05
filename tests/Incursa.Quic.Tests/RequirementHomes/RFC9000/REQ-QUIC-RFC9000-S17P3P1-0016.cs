namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesTheZeroValueBeforeProtection()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xA1]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)0x00, (byte)(header.HeaderControlBits & 0x3F));
        Assert.Equal((byte)0x00, header.ReservedBits);
    }
}
