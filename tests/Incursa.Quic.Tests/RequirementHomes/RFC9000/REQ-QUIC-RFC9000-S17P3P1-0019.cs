namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ExposesTheKeyPhaseBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x04, [0xA1, 0xA2]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.KeyPhase);
    }
}
