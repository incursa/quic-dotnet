namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0012
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0012">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsZeroRttDestinationConnectionIdsAt20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: new byte[20],
            sourceConnectionId: [0x5C],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x01], [0xAA]));

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(20, header.DestinationConnectionIdLength);
        Assert.Equal(1, header.SourceConnectionIdLength);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0012">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsZeroRttDestinationConnectionIdsLongerThan20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: new byte[21],
            sourceConnectionId: [0x5C],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x01], [0xAA]));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}
