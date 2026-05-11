namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P2-0001")]
public sealed class REQ_QUIC_RFC9000_S7P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7-0004")]
    [Trait("Category", "Positive")]
    public void HandshakePacketsUseLongHeadersToEstablishBothConnectionIds()
    {
        byte[] originalDestinationConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId;
        byte[] clientInitialSourceConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId;
        byte[] serverSourceConnectionId = [0x30, 0x31, 0x32];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientInitialSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(
                clientRuntime,
                clientInitialSourceConnectionId);

        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientInitialSourceConnectionId,
            serverSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x51),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.HandshakePacket,
            observedAtTicks: 2).StateChanged);
        Assert.True(clientRuntime.TlsState.PeerCertificatePolicyAccepted);
        Assert.True(clientRuntime.TlsState.PeerFinishedVerified);
        Assert.True(clientRuntime.TlsState.HandshakeKeysAvailable);
        Assert.True(clientRuntime.TlsState.OneRttKeysAvailable);

        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            clientInitialDatagrams[0].Datagram.Span,
            originalDestinationConnectionId,
            clientInitialSourceConnectionId);
        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.InitialPacket,
            clientInitialSourceConnectionId,
            serverSourceConnectionId);
        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.HandshakePacket,
            clientInitialSourceConnectionId,
            serverSourceConnectionId);
    }
}
