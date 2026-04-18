namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3-0001">This version of QUIC defines a single packet type that MUST use the short packet header.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3-0001")]
public sealed class REQ_QUIC_RFC9000_S17P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3-0001">This version of QUIC defines a single packet type that MUST use the short packet header.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P3-0001")]
    public void TryParseShortHeader_RecognizesThe1RttPacketType()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB]);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Short, headerForm);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket shortHeader));
        Assert.Equal(QuicHeaderForm.Short, shortHeader.HeaderForm);
        Assert.True(shortHeader.FixedBit);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3-0001">This version of QUIC defines a single packet type that MUST use the short packet header.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P3-0001")]
    public void TryParseShortHeader_RejectsVersion1LongHeaders()
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

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Long, headerForm);
        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }
}
