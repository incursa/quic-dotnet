namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0285">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0285")]
public sealed class REQ_QUIC_RFC9000_0285
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0285">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0285")]
    public void TryFormatVersionNegotiationResponse_FormatsAResponseForAnUnsupportedClientVersion()
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
    [Requirement("REQ-QUIC-RFC9000-0285")]
    public void TryFormatVersionNegotiationResponse_RejectsTheVersionNegotiationSentinelAsTheSelectedVersion()
    {
        byte[] destination = new byte[64];

        Assert.False(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            QuicVersionNegotiation.VersionNegotiationVersion,
            clientDestinationConnectionId: [0x01, 0x02],
            clientSourceConnectionId: [0x03],
            serverSupportedVersions: [QuicVersionNegotiation.Version1],
            destination,
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }
}
