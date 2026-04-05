namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0014">The server MUST include the value from the Source Connection ID field of the packet it receives in the Destination Connection ID field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0014")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0014">The server MUST include the value from the Source Connection ID field of the packet it receives in the Destination Connection ID field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0014")]
    public void TryFormatVersionNegotiationResponse_EchoesTheClientSourceConnectionIdIntoTheDestinationField()
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            [QuicVersionNegotiation.Version1],
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
    }
}
