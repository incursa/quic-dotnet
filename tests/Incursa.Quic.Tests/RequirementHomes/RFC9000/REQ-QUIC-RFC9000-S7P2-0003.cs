namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0003">Copy the peer Source Connection ID into subsequent packets</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S7P2-0003")]
public sealed class REQ_QUIC_RFC9000_S7P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0003">Copy the peer Source Connection ID into subsequent packets</workbench-requirement>
    /// </workbench-requirements>
    public void TryFormatVersionNegotiationResponse_EchoesTheClientConnectionIds()
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];
        uint[] serverSupportedVersions = [QuicVersionNegotiation.Version1, 0x11223344];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions,
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
        Assert.True(packet.ContainsSupportedVersion(0x11223344));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0003">Copy the peer Source Connection ID into subsequent packets</workbench-requirement>
    /// </workbench-requirements>
    public void TryFormatVersionNegotiationResponse_RejectsInsufficientDestinationSpace()
    {
        byte[] destination = new byte[8];

        Assert.False(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId: [0x01, 0x02],
            clientSourceConnectionId: [0x03, 0x04, 0x05],
            serverSupportedVersions: [QuicVersionNegotiation.Version1],
            destination,
            out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0003">Copy the peer Source Connection ID into subsequent packets</workbench-requirement>
    /// </workbench-requirements>
    public void TryFormatVersionNegotiationResponse_AllowsBoundaryConnectionIdLengths(int connectionIdLength)
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId = connectionIdLength == 0 ? [] : [0x01];
        byte[] clientSourceConnectionId = connectionIdLength == 0 ? [] : [0x03];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions: [QuicVersionNegotiation.Version1],
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        if (connectionIdLength == 0)
        {
            Assert.True(packet.DestinationConnectionId.IsEmpty);
            Assert.True(packet.SourceConnectionId.IsEmpty);
        }
        else
        {
            Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
            Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        }
        Assert.Equal(1, packet.SupportedVersionCount);
        Assert.Equal(QuicVersionNegotiation.Version1, packet.GetSupportedVersion(0));
    }
}
