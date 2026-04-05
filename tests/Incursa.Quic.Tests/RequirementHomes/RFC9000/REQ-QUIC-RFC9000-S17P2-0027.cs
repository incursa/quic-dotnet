namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0027">Two bits (those with a mask of 0x0c) of byte 0 MUST be reserved across multiple packet types.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0027")]
public sealed class REQ_QUIC_RFC9000_S17P2_0027
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0027">Two bits (those with a mask of 0x0c) of byte 0 MUST be reserved across multiple packet types.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0027")]
    public void TryParseHeaders_ExposeReservedBitsAsZeroBeforeProtection()
    {
        byte[] longHeader = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA]));

        Assert.True(QuicPacketParser.TryParseLongHeader(longHeader, out QuicLongHeaderPacket parsedLongHeader));
        Assert.Equal((byte)0x00, parsedLongHeader.ReservedBits);

        byte[] shortHeader = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x00,
            remainder: [0xAA, 0xBB]);

        Assert.True(QuicPacketParser.TryParseShortHeader(shortHeader, out QuicShortHeaderPacket parsedShortHeader));
        Assert.Equal((byte)0x00, parsedShortHeader.ReservedBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0027">Two bits (those with a mask of 0x0c) of byte 0 MUST be reserved across multiple packet types.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0027")]
    public void TryParseShortHeader_RejectsReservedBitsWhenTheyAreNonZero()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x18,
            remainder: [0xAA, 0xBB]);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }
}
