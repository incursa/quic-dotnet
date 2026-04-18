namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeDiscardsARetryReplayThatCarriesADifferentClientHello()
    {
        using QuicConnectionRuntime serverRuntime = CreateServerRuntime(QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId);
        using QuicConnectionRuntime bootstrapRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        byte[] bootstrapClientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(bootstrapRuntime);
        byte[] differentClientHelloBytes = new byte[bootstrapClientHelloBytes.Length];
        bootstrapClientHelloBytes.CopyTo(differentClientHelloBytes, 0);
        Assert.True(differentClientHelloBytes.Length > 38);
        differentClientHelloBytes[38] = 0xFF;

        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = new(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            QuicS17P2P5P2TestSupport.InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            differentClientHelloBytes,
            cryptoPayloadOffset: 0,
            retryReceivedEvent.RetrySourceConnectionId.Span,
            retryReceivedEvent.RetryToken.Span,
            clientProtection,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                new QuicConnectionPathIdentity("203.0.113.10", "198.51.100.20", 443, 12345),
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Null(serverRuntime.TerminalState);
        Assert.Empty(result.Effects);
    }

    private static QuicConnectionRuntime CreateServerRuntime(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        return runtime;
    }
}
