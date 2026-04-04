namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0006">The Long Packet Type field MUST be 2 bits long with value 2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P4-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0006">The Long Packet Type field MUST be 2 bits long with value 2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0006")]
    public void TryGetPacketNumberSpace_MapsHandshakePacketsToTheHandshakeSpace()
    {
        byte[] packet = BuildVersion1LongHeader(0x02);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0006">The Long Packet Type field MUST be 2 bits long with value 2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0006")]
    public void TryGetPacketNumberSpace_DoesNotMapInitialPacketsToTheHandshakeSpace()
    {
        byte[] packet = BuildVersion1LongHeader(0x00);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0006">The Long Packet Type field MUST be 2 bits long with value 2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0006")]
    public void TryParseLongHeader_ExposesTheFullTwoBitLongPacketTypeRange()
    {
        byte[] packet = BuildVersion1LongHeader(0x03);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }

    private static byte[] BuildVersion1LongHeader(byte longPacketTypeBits)
    {
        byte headerControlBits = (byte)(0x40 | (longPacketTypeBits << 4));
        byte[] versionSpecificData = longPacketTypeBits == 0x00
            ? QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA])
            : QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                packetNumber: [0x01],
                protectedPayload: [0xAA]);

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);
    }
}
