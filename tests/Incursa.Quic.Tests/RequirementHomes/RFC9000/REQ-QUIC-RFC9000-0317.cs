namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0317")]
public sealed class REQ_QUIC_RFC9000_0317
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientContinuesTheConnectionForSubsequentInitialPacketsWithTheSameServerSourceConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] clientSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] serverSourceConnectionId = [0x31, 0x32, 0x33, 0x34];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);
        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x21),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 2);

        Assert.Equal(serverSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted);
        Assert.Null(clientRuntime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDiscardsSubsequentInitialPacketsWithADifferentServerSourceConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] clientSourceConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] firstServerSourceConnectionId = [0x61, 0x62, 0x63, 0x64];
        byte[] replacementServerSourceConnectionId = [0x71, 0x72, 0x73, 0x74];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);
        ServerHandshakeFlight firstFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            firstServerSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x31),
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            replacementServerSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x32),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            firstFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial firstHandshakeMaterial));

        _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            replacementFlight.InitialPacket,
            observedAtTicks: 2);

        Assert.Equal(firstServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial retainedHandshakeMaterial));
        Assert.True(firstHandshakeMaterial.Matches(retainedHandshakeMaterial));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientDoesNotBufferSubsequentHandshakePacketsWithADifferentServerSourceConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] clientSourceConnectionId = [0x91, 0x92, 0x93, 0x94];
        byte[] firstServerSourceConnectionId = [0xA1, 0xA2, 0xA3, 0xA4];
        byte[] replacementServerSourceConnectionId = [0xB1, 0xB2, 0xB3, 0xB4];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);
        ServerHandshakeFlight firstFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            firstServerSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x41),
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            replacementServerSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x42),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            firstFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            replacementFlight.HandshakePacket,
            observedAtTicks: 2);

        Assert.Equal(0, QuicS7P2ServerConnectionIdTestSupport.GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.Equal(firstServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted);
    }
}
