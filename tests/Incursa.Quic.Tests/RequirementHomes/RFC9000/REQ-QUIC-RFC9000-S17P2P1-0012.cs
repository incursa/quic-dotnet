namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0012">Where QUIC might be multiplexed with other protocols (see [RFC7983]), servers SHOULD set the most significant bit of this field (0x40) to 1 so that Version Negotiation packets appear to have the Fixed Bit field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0012")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0012">Where QUIC might be multiplexed with other protocols (see [RFC7983]), servers SHOULD set the most significant bit of this field (0x40) to 1 so that Version Negotiation packets appear to have the Fixed Bit field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0012")]
    public void TryFormatVersionNegotiationResponse_SetsTheMostSignificantUnusedBit()
    {
        byte[] destination = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0x11223344,
            clientDestinationConnectionId: [0x01],
            clientSourceConnectionId: [0x02],
            serverSupportedVersions: [0xAABBCCDD],
            destination,
            out int bytesWritten));

        Assert.Equal((byte)0xC0, destination[0]);
        Assert.NotEqual(0, destination[0] & 0x40);
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.Equal((byte)0x40, packet.HeaderControlBits);
    }
}
