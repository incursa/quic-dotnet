namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0011">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheDestinationConnectionIdLengthField()
    {
        byte[] destinationConnectionId =
        [
            0x10, 0x11, 0x12,
        ];

        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x55,
            version: 1,
            destinationConnectionId,
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsZeroRttPacketsMissingTheDestinationConnectionIdLengthByte()
    {
        byte[] packet = [0xD0, 0x00, 0x00, 0x00, 0x01];

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_ExposesZeroRttDestinationConnectionIdLengthBoundaries(int destinationConnectionIdLength)
    {
        byte[] packet = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            destinationConnectionId: new byte[destinationConnectionIdLength],
            sourceConnectionId: [0x20]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
    }
}
