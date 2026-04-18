namespace Incursa.Quic.Tests;

internal static class QuicS17P2P5P2TestSupport
{
    internal static readonly byte[] OriginalDestinationConnectionId = QuicS17P2P2TestSupport.InitialDestinationConnectionId;

    internal static readonly byte[] InitialSourceConnectionId = QuicS17P2P2TestSupport.InitialSourceConnectionId;

    internal static readonly byte[] RetrySourceConnectionId =
    [
        0x31, 0x32, 0x33,
    ];

    internal static readonly byte[] RetryToken =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    internal static QuicConnectionRuntime CreateClientRuntime()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client);

        Assert.True(runtime.TryConfigureInitialPacketProtection(OriginalDestinationConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));
        return runtime;
    }

    internal static QuicConnectionRuntime CreateBootstrappedClientRuntime()
    {
        QuicConnectionRuntime runtime = CreateClientRuntime();

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId)),
            nowTicks: 0);

        Assert.True(bootstrapResult.StateChanged);
        Assert.Contains(bootstrapResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        return runtime;
    }

    internal static QuicHandshakeFlowCoordinator CreateClientCoordinator()
    {
        return new(OriginalDestinationConnectionId, InitialSourceConnectionId);
    }

    internal static QuicConnectionRetryReceivedEvent CreateRetryReceivedEvent(long observedAtTicks)
    {
        byte[] retryPacket = CreateRetryPacket();
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            OriginalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));

        return new QuicConnectionRetryReceivedEvent(
            observedAtTicks,
            retryMetadata.RetrySourceConnectionId,
            retryMetadata.RetryToken,
            retryPacket);
    }

    internal static byte[] CreateRetryPacket()
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            OriginalDestinationConnectionId,
            InitialSourceConnectionId,
            RetrySourceConnectionId,
            RetryToken,
            out byte[] retryPacket));

        return retryPacket;
    }
}
