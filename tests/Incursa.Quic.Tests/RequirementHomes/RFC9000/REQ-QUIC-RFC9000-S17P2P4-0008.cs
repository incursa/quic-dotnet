namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P4-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0008
{
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0008")]
    public void TryParseLongHeader_ExposesThePacketNumberLengthBitsForBoundaryPacketNumberLengths(int packetNumberLength)
    {
        (byte[] packet, byte[] versionSpecificData) = BuildInitialPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0008")]
    public void TryParseLongHeader_RejectsPacketsWhenThePayloadIsShorterThanThePacketNumberField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x43,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x00, 0x01, 0x01, 0x02, 0x03, 0x04]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0008")]
    public void TryParseLongHeader_AllowsTheShortestAndLongestPacketNumberLengths(int packetNumberLength)
    {
        (byte[] packet, byte[] versionSpecificData) = BuildInitialPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    private static (byte[] Packet, byte[] VersionSpecificData) BuildInitialPacket(int packetNumberLength)
    {
        byte[] packetNumber = Enumerable.Range(0, packetNumberLength)
            .Select(index => (byte)(index + 1))
            .ToArray();
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber,
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(0x40 | (packetNumberLength - 1)),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);

        return (packet, versionSpecificData);
    }
}
