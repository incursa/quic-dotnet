namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0002">The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheReservedAndPacketNumberLengthBits()
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
        Assert.Equal((byte)0x01, header.ReservedBits);
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsZeroRttPacketsWhoseLengthFieldIsShorterThanTheEncodedPacketNumber()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: QuicS17P2P3TestSupport.BuildZeroRttHeaderControlBits(packetNumberLength: 4),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x01, 0xAA]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsZeroRttPacketsWhenBothBitFieldsUseTheirLargestEncodings()
    {
        byte[] packet = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            packetNumberLength: 4,
            reservedBits: 0x03,
            protectedPayload: [0xAA]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.ReservedBits);
        Assert.Equal((byte)0x03, header.PacketNumberLengthBits);
    }
}
