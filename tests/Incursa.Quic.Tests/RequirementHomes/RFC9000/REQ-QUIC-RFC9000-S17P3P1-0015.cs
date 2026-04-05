namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0015")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesReservedBitsAsZero()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xA1, 0xA2]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)0x00, header.ReservedBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsPacketsWithReservedBitsSet()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x18, [0xA1, 0xA2]);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }
}
