namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P2-0009")]
public sealed class REQ_QUIC_RFC9000_S7P2_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientAdoptsTheFirstServerInitialSourceConnectionIdForSubsequentDestinations()
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

        QuicConnectionTransitionResult result = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(serverSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotReplaceTheFirstServerInitialSourceConnectionIdWithALaterRetry()
    {
        byte[] originalDestinationConnectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] clientSourceConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] serverSourceConnectionId = [0x61, 0x62, 0x63, 0x64];
        byte[] lateRetrySourceConnectionId = [0x71, 0x72, 0x73, 0x74];

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
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x22),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 2,
                RetrySourceConnectionId: lateRetrySourceConnectionId,
                RetryToken: new byte[] { 0x01, 0x02, 0x03 }),
            nowTicks: 2);

        Assert.False(retryResult.StateChanged);
        Assert.Equal(serverSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ZeroRttPacketAfterServerInitialUsesTheAdoptedServerSourceConnectionId()
    {
        byte[] initialDestinationConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] clientSourceConnectionId = [0x91, 0x92, 0x93, 0x94];
        byte[] serverSourceConnectionId = [0xA1, 0xA2, 0xA3, 0xA4];

        byte[] zeroRttPacket = QuicS7P2ServerConnectionIdTestSupport.BuildZeroRttPacketAfterServerSourceConnectionIdAdoption(
            initialDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId);

        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            zeroRttPacket,
            serverSourceConnectionId,
            clientSourceConnectionId);
    }
}
