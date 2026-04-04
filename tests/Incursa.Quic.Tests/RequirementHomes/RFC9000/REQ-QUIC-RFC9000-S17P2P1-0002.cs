namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P1-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0002")]
    public void TryFormatVersionNegotiationResponse_FormatsAResponseFromTheServer()
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            [QuicVersionNegotiation.Version1, 0x11223344],
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.Equal(QuicVersionNegotiation.VersionNegotiationVersion, packet.Version);
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
        Assert.True(packet.ContainsSupportedVersion(0x11223344));
    }
}
