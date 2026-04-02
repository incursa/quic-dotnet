namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryClassifyHeaderForm_UsesTheFirstByteHighBit()
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(
            QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x4A,
                version: 0x11223344,
                destinationConnectionId: [0x11],
                sourceConnectionId: [0x22],
                versionSpecificData: [0x33]),
            out QuicHeaderForm longHeaderForm));
        Assert.Equal(QuicHeaderForm.Long, longHeaderForm);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(
            QuicHeaderTestData.BuildShortHeader(
                headerControlBits: 0x24,
                remainder: [0xAA, 0xBB]),
            out QuicHeaderForm shortHeaderForm));
        Assert.Equal(QuicHeaderForm.Short, shortHeaderForm);
    }
}
