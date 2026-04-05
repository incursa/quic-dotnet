namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0028">The value included prior to protection MUST be set to 0.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0028")]
public sealed class REQ_QUIC_RFC9000_S17P2_0028
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0028">The value included prior to protection MUST be set to 0.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0028")]
    public void TryParseLongHeader_ExposesZeroReservedBitsBeforeProtection()
    {
        byte[] packet = BuildVersion1InitialPacket(0);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.ReservedBits);
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
