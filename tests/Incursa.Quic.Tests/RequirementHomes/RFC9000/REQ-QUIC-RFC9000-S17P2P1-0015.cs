namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0015">The value for Source Connection ID MUST be copied from the Destination Connection ID of the received packet, which is initially randomly selected by a client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0015")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0015">The value for Source Connection ID MUST be copied from the Destination Connection ID of the received packet, which is initially randomly selected by a client.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0015")]
    public void TryFormatVersionNegotiationResponse_EchoesTheClientDestinationConnectionIdIntoTheSourceField()
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
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
    }
}
