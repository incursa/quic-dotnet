namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0014")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_RejectsPacketsWithAZeroFixedBit()
    {
        byte[] packet = [0x3D, 0xA1];

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RecognizesPacketsWithTheFixedBitSet()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xA1]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.FixedBit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseShortHeader_RejectsTheShortestPacketWithAZeroFixedBit()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([0x3D], out _));
    }
}
