namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0017">This field MUST indicate the version of QUIC that is in use and determines how the rest of the protocol fields are interpreted.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0017")]
public sealed class REQ_QUIC_RFC9000_S17P2_0017
{
    [Theory]
    [InlineData(0u, true)]
    [InlineData(1u, false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0017">This field MUST indicate the version of QUIC that is in use and determines how the rest of the protocol fields are interpreted.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0017")]
    public void TryParseLongHeader_InterpretsTheVersionField(uint version, bool expectedVersionNegotiation)
    {
        byte[] packet = version == 0
            ? QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x00,
                version,
                destinationConnectionId: [0x11],
                sourceConnectionId: [0x22],
                versionSpecificData: [0x33, 0x34, 0x35, 0x36])
            : QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version,
                destinationConnectionId: [0x11],
                sourceConnectionId: [0x22],
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                    token: [0xAA],
                    packetNumber: [0x01],
                    protectedPayload: [0xBB]));

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(version, header.Version);
        Assert.Equal(expectedVersionNegotiation, header.IsVersionNegotiation);
        int versionSpecificDataOffset = 6 + header.DestinationConnectionIdLength + 1 + header.SourceConnectionIdLength;
        Assert.True(packet.AsSpan(versionSpecificDataOffset).SequenceEqual(header.VersionSpecificData));
    }
}
