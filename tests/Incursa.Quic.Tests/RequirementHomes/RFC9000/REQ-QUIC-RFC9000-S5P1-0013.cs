namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1-0013")]
public sealed class REQ_QUIC_RFC9000_S5P1_0013
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0013">A zero-length connection ID MAY be used when a connection ID is not needed to route to the correct endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsZeroLengthConnectionIds()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: [0xAA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [],
            sourceConnectionId: [],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
