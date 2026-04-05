namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryClassifyHeaderForm_RecognizesShortHeadersByTheHighBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xAA, 0xBB]);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Short, headerForm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryClassifyHeaderForm_RecognizesLongHeadersByTheHighBit()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33]);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Long, headerForm);
    }
}
