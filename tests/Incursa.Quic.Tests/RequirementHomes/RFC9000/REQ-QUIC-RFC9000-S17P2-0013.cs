namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0013")]
public sealed class REQ_QUIC_RFC9000_S17P2_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ClassifiesPacketsWithTheHighBitSetAsLongHeaders()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA]));

        Assert.Equal(0x80, packet[0] & 0x80);
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Long, headerForm);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsWhenTheHighBitIsNotSet()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x00,
            remainder: [0x01, 0x02, 0x03, 0x04]);

        Assert.Equal(0x00, packet[0] & 0x80);
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Short, headerForm);
        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsTheSmallestLongHeaderMarkerByte()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x00,
            version: 0,
            destinationConnectionId: [],
            sourceConnectionId: [],
            versionSpecificData: [0x00, 0x00, 0x00, 0x01]);

        Assert.Equal(0x80, packet[0]);
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Long, headerForm);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}
