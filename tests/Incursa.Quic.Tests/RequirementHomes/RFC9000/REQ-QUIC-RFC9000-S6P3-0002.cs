namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S6P3-0002")]
public sealed class REQ_QUIC_RFC9000_S6P3_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0002">Endpoints MAY send packets with a reserved version to test that a peer correctly discards the packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P3-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseVersionNegotiation_RejectsPacketsWithReservedVersions()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: reservedVersion,
            destinationConnectionId: [0x01, 0x02],
            sourceConnectionId: [0x03],
            versionSpecificData: [0x04, 0x05]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(reservedVersion, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet, out _));
    }
}
