namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0005
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0005">The Version field MUST be 32 bits long with value 0.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_ExposesZeroVersionAsVersionNegotiationState()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x2C,
            version: 0,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02, 0x03],
            versionSpecificData: [0x04, 0x05, 0x06, 0x07]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)0, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.False(header.FixedBit);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0005">The Version field MUST be 32 bits long with value 0.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseVersionNegotiation_RejectsOrdinaryLongHeaders()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x21,
            version: 0x01020304,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33, 0x44, 0x55, 0x66]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet, out _));
    }
}
