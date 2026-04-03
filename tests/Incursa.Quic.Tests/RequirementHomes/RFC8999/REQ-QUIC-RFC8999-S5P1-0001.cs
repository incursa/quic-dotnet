namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
public sealed class REQ_QUIC_RFC8999_S5P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    public void TryClassifyHeaderForm_RecognizesLongHeadersByTheHighBit()
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(
            QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x4A,
                version: 0x11223344,
                destinationConnectionId: [0x11],
                sourceConnectionId: [0x22],
                versionSpecificData: [0x33]),
            out QuicHeaderForm headerForm));

        Assert.Equal(QuicHeaderForm.Long, headerForm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    public void TryClassifyHeaderForm_RecognizesShortHeadersByTheHighBit()
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(
            QuicHeaderTestData.BuildShortHeader(
                headerControlBits: 0x24,
                remainder: [0xAA, 0xBB]),
            out QuicHeaderForm headerForm));

        Assert.Equal(QuicHeaderForm.Short, headerForm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    public void TryClassifyHeaderForm_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryClassifyHeaderForm([], out _));
    }
}
