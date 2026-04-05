namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0030">Discarding such a packet after only removing header protection MAY expose the endpoint to attacks; see Section 9.5 of [QUIC-TLS].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0030")]
public sealed class REQ_QUIC_RFC9000_S17P2_0030
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0030">Discarding such a packet after only removing header protection MAY expose the endpoint to attacks; see Section 9.5 of [QUIC-TLS].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0030")]
    public void TryParseLongHeader_PreservesNonZeroReservedBitsForValidation()
    {
        byte[] packet = BuildVersion1InitialPacket(1);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x01, header.ReservedBits);
    }

    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x03)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0030">Discarding such a packet after only removing header protection MAY expose the endpoint to attacks; see Section 9.5 of [QUIC-TLS].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0030")]
    public void TryParseLongHeader_PreservesBoundaryReservedBits(byte reservedBits)
    {
        byte[] packet = BuildVersion1InitialPacket(reservedBits);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(reservedBits, header.ReservedBits);
    }

    private static byte[] BuildVersion1InitialPacket(byte reservedBits)
    {
        byte headerControlBits = (byte)(0x40 | (reservedBits << 2) | 0x02);
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01, 0x02],
                protectedPayload: [0xAA]));
    }
}
