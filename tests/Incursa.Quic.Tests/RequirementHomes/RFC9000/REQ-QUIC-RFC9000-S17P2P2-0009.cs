namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0009
{
    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    public void TryParseLongHeader_PreservesDestinationConnectionIdRange(int destinationConnectionIdLength)
    {
        byte[] destinationConnectionId = new byte[destinationConnectionIdLength];
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: [0xAA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId,
            sourceConnectionId: [0x5C],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    public void TryParseLongHeader_RejectsInitialDestinationConnectionIdsLongerThan20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: new byte[21],
            sourceConnectionId: [0x5C],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA]));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}
