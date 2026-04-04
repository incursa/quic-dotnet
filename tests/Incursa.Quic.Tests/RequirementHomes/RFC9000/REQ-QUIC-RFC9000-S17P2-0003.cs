namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0003">The Long Packet Type field MUST be 2 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2_0003
{
    [Theory]
    [InlineData((byte)0x40, (byte)0x00)]
    [InlineData((byte)0x50, (byte)0x01)]
    [InlineData((byte)0x60, (byte)0x02)]
    [InlineData((byte)0x70, (byte)0x03)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0003">The Long Packet Type field MUST be 2 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0003")]
    public void TryParseLongHeader_ExposesTheTwoBitLongPacketTypeField(
        byte headerControlBits,
        byte expectedLongPacketTypeBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 0,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(expectedLongPacketTypeBits, header.LongPacketTypeBits);
    }
}
