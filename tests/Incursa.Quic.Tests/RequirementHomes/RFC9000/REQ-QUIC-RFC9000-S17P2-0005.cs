namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0005">The Version field MUST be 32 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2_0005
{
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(0x11223344u)]
    [InlineData(uint.MaxValue)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0005">The Version field MUST be 32 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0005")]
    public void TryParseLongHeader_ExposesThe32BitVersionField(uint version)
    {
        byte[] versionSpecificData = version == 1
            ? QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA])
            : [0x30];

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(version, header.Version);
        Assert.Equal(version == 0, header.IsVersionNegotiation);
    }
}
