namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0004">Each endpoint MUST select connection IDs using an implementation-specific method that allows packets with that connection ID to be routed back to the endpoint and to be identified by the endpoint upon receipt.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0004")]
public sealed class REQ_QUIC_RFC9000_S5P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0004">Each endpoint MUST select connection IDs using an implementation-specific method that allows packets with that connection ID to be routed back to the endpoint and to be identified by the endpoint upon receipt.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0004")]
    public void TryFormatVersionNegotiationResponse_EchoesTheClientConnectionIds()
    {
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];
        uint[] serverSupportedVersions = [0x00000001, 0x11223344];
        Span<byte> destination = stackalloc byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0x0A0B0C0D,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions,
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(destination[..bytesWritten], out QuicVersionNegotiationPacket packet));
        Assert.Equal(clientSourceConnectionId.Length, packet.DestinationConnectionIdLength);
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.Equal(clientDestinationConnectionId.Length, packet.SourceConnectionIdLength);
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(2, packet.SupportedVersionCount);
        Assert.Equal((uint)0x00000001, packet.GetSupportedVersion(0));
        Assert.Equal((uint)0x11223344, packet.GetSupportedVersion(1));
    }
}
