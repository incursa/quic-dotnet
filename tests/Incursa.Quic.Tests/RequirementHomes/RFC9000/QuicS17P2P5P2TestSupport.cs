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

    internal static readonly byte[] MaximumLengthRetrySourceConnectionId =
    [
        0x51, 0x52, 0x53, 0x54, 0x55,
        0x56, 0x57, 0x58, 0x59, 0x5A,
        0x61, 0x62, 0x63, 0x64, 0x65,
        0x66, 0x67, 0x68, 0x69, 0x6A,
    ];

    internal static readonly byte[] SingleByteRetryToken = [0x7F];

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
        return CreateRetryReceivedEvent(
            observedAtTicks,
            RetrySourceConnectionId,
            RetryToken);
    }

    internal static QuicConnectionRetryReceivedEvent CreateRetryReceivedEvent(
        long observedAtTicks,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> retryToken)
    {
        byte[] retryPacket = CreateRetryPacket();
        if (!retrySourceConnectionId.SequenceEqual(RetrySourceConnectionId)
            || !retryToken.SequenceEqual(RetryToken))
        {
            retryPacket = CreateRetryPacket(retrySourceConnectionId, retryToken);
        }

        return new QuicConnectionRetryReceivedEvent(
            observedAtTicks,
            retrySourceConnectionId.ToArray(),
            retryToken.ToArray(),
            retryPacket);
    }

    internal static byte[] CreateRetryPacket()
    {
        return CreateRetryPacket(RetrySourceConnectionId, RetryToken);
    }

    internal static byte[] CreateRetryPacket(
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> retryToken)
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            OriginalDestinationConnectionId,
            InitialSourceConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));

        return retryPacket;
    }

    internal static QuicS17P2P5P3TestSupport.RetryReplayInitialPacket ReadSingleRetryReplayInitialPacket(
        QuicConnectionTransitionResult retryResult)
    {
        return ReadSingleRetryReplayInitialPacket(
            retryResult,
            RetrySourceConnectionId);
    }

    internal static QuicS17P2P5P3TestSupport.RetryReplayInitialPacket ReadSingleRetryReplayInitialPacket(
        QuicConnectionTransitionResult retryResult,
        ReadOnlySpan<byte> retrySourceConnectionId)
    {
        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection(retrySourceConnectionId));

        return Assert.Single(replayPackets);
    }

    internal static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        return needle.IsEmpty || haystack.IndexOf(needle) >= 0;
    }

    internal static byte[] GetOriginalClientHelloBytes()
    {
        using QuicConnectionRuntime runtime = CreateBootstrappedClientRuntime();
        return QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(runtime);
    }
}
