namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0016">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0016
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0016">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsZeroRttPacketNumberLengthsWithinTheRange()
    {
        byte[] packetNumber = [0x01, 0x02, 0x03, 0x04];
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber,
            protectedPayload: [0xDD]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x53,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsZeroRttPacketsWhenLengthCannotContainTheEncodedPacketNumber()
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
    [InlineData(1)]
    [InlineData(4)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AllowsZeroRttPacketNumberLengthBoundaries(int packetNumberLength)
    {
        byte[] packetNumber = QuicS17P2P3TestSupport.CreatePacketNumber(packetNumberLength);
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber,
            protectedPayload: [0xDD]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: QuicS17P2P3TestSupport.BuildZeroRttHeaderControlBits(packetNumberLength),
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(packetNumberLength - 1, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
