namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0009">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0009")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesThePacketNumberLengthBits()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x55,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsZeroRttPacketsWithPacketNumberLengthMismatch()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: QuicS17P2P3TestSupport.BuildZeroRttHeaderControlBits(packetNumberLength: 4),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x03, 0x01, 0x02, 0x03]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(1, 0x00)]
    [InlineData(4, 0x03)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsZeroRttPacketNumberLengthBoundaries(int packetNumberLength, byte expectedPacketNumberLengthBits)
    {
        byte[] packet = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            packetNumberLength,
            protectedPayload: [0xAA]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(expectedPacketNumberLengthBits, header.PacketNumberLengthBits);
    }
}
