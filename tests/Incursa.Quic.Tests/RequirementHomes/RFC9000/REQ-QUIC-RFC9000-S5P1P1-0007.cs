namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0007")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FirstClientSelectedDestinationConnectionIdCanBeIssuedLaterWithASequenceNumber()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] firstClientSelectedDestinationConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] peerInitialSourceConnectionId = [0x61, 0x62, 0x63, 0x64];
        QuicNewConnectionIdFrame frame = new(
            1UL,
            0UL,
            firstClientSelectedDestinationConnectionId,
            QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70));

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            peerInitialSourceConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(1UL, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal(firstClientSelectedDestinationConnectionId, state.CurrentDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetryProvidedConnectionIdCanBeUsedByPreferredAddressSequenceOneAfterServerInitialSourceIsObserved()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] clientSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] retrySourceConnectionId = [0x31, 0x32, 0x33, 0x34];
        byte[] serverInitialSourceConnectionId = [0x41, 0x42, 0x43, 0x44];

        using QuicConnectionRuntime clientRuntime = CreateRetryRuntimeWithObservedServerInitial(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId);

        QuicConnectionTransitionResult result = CommitPeerParametersWithPreferredAddress(
            clientRuntime,
            originalDestinationConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId,
            preferredAddressConnectionId: retrySourceConnectionId);

        Assert.True(result.StateChanged);
        Assert.Null(clientRuntime.TerminalState);
        Assert.True(clientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.Equal(serverInitialSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ObservedServerInitialSourceConnectionIdCannotBeReusedByPreferredAddressSequenceOneAfterRetry()
    {
        byte[] originalDestinationConnectionId = [0x61, 0x62, 0x63, 0x64];
        byte[] clientSourceConnectionId = [0x71, 0x72, 0x73, 0x74];
        byte[] retrySourceConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] serverInitialSourceConnectionId = [0x91, 0x92, 0x93, 0x94];

        using QuicConnectionRuntime clientRuntime = CreateRetryRuntimeWithObservedServerInitial(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId);

        QuicConnectionTransitionResult result = CommitPeerParametersWithPreferredAddress(
            clientRuntime,
            originalDestinationConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId,
            preferredAddressConnectionId: serverInitialSourceConnectionId);

        Assert.True(result.StateChanged);
        Assert.NotNull(clientRuntime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.TransportParameterError, clientRuntime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void MaximumLengthRetryProvidedConnectionIdStillDoesNotConsumeASequenceNumber()
    {
        byte[] originalDestinationConnectionId = [0xA1, 0xA2, 0xA3, 0xA4];
        byte[] clientSourceConnectionId = [0xB1, 0xB2, 0xB3, 0xB4];
        byte[] retrySourceConnectionId =
        [
            0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
            0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
            0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4,
        ];
        byte[] serverInitialSourceConnectionId = [0xE1, 0xE2, 0xE3, 0xE4];

        using QuicConnectionRuntime clientRuntime = CreateRetryRuntimeWithObservedServerInitial(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId);

        QuicConnectionTransitionResult result = CommitPeerParametersWithPreferredAddress(
            clientRuntime,
            originalDestinationConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId,
            preferredAddressConnectionId: retrySourceConnectionId);

        Assert.True(result.StateChanged);
        Assert.Null(clientRuntime.TerminalState);
        Assert.True(clientRuntime.TlsState.PeerTransportParametersCommitted);
    }

    private static QuicConnectionRuntime CreateRetryRuntimeWithObservedServerInitial(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> clientSourceConnectionId,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> serverInitialSourceConnectionId)
    {
        QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        _ = QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                RetrySourceConnectionId: retrySourceConnectionId.ToArray(),
                RetryToken: new byte[] { 0x01, 0x02, 0x03 }),
            nowTicks: 1);
        QuicConnectionSendDatagramEffect[] retryReplayDatagrams = retryResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(retryReplayDatagrams);
        Assert.Equal(retrySourceConnectionId.ToArray(), clientRuntime.CurrentPeerDestinationConnectionId.ToArray());

        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlightAfterRetry(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x51),
            retryReplayDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 2).StateChanged);
        Assert.Equal(retrySourceConnectionId.ToArray(), clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
        return clientRuntime;
    }

    private static QuicConnectionTransitionResult CommitPeerParametersWithPreferredAddress(
        QuicConnectionRuntime clientRuntime,
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> serverInitialSourceConnectionId,
        ReadOnlySpan<byte> preferredAddressConnectionId)
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray(),
            InitialSourceConnectionId = serverInitialSourceConnectionId.ToArray(),
            RetrySourceConnectionId = retrySourceConnectionId.ToArray(),
            InitialMaxData = 64,
            InitialMaxStreamDataBidiLocal = 64,
            InitialMaxStreamDataBidiRemote = 64,
            InitialMaxStreamDataUni = 64,
            InitialMaxStreamsBidi = 8,
            InitialMaxStreamsUni = 8,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [203, 0, 113, 7],
                IPv4Port = 9443,
                ConnectionId = preferredAddressConnectionId.ToArray(),
                StatelessResetToken = QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xA0),
            },
        };

        return QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
            clientRuntime,
            peerParameters);
    }
}
