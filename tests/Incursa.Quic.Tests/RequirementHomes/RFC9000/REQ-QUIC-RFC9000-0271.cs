namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0271")]
public sealed class REQ_QUIC_RFC9000_0271
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerHostProceedsWithHandshakeForAConformingInitialPacket()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        ];
        byte[] clientSourceConnectionId =
        [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        ];
        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        byte[] serverResponse = await QuicS5P2P2ServerPreAcceptanceTestSupport
            .SendConformingInitialAndReceiveServerInitialAsync(clientInitialPacket, clientSourceConnectionId);

        Assert.True(serverResponse.Length > 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClassifyUnroutedDatagram_DoesNotAdmitUndersizedInitialPackets()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1InitialDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.SendProtocolViolationClose, action);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClassifyUnroutedDatagram_AdmitsInitialPacketsAtTheMinimumDatagramSize()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1InitialDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.AdmitInitial, action);
    }
}
