namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0010">The value in the Unused field MUST be set to an arbitrary value by the server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0010")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0010">The value in the Unused field MUST be set to an arbitrary value by the server.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0010")]
    public void TryFormatVersionNegotiationResponse_UsesTheUnusedFieldValueOnTheWire()
    {
        byte[] destination = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0x11223344,
            clientDestinationConnectionId: [0x01, 0x02],
            clientSourceConnectionId: [0x03, 0x04, 0x05],
            serverSupportedVersions: [QuicVersionNegotiation.Version1, 0xAABBCCDD],
            destination,
            out int bytesWritten));

        Assert.Equal((byte)0xC0, destination[0]);
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.Equal((byte)0x40, packet.HeaderControlBits);
        Assert.Equal(2, packet.SupportedVersionCount);
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
        Assert.True(packet.ContainsSupportedVersion(0xAABBCCDD));
    }
}
