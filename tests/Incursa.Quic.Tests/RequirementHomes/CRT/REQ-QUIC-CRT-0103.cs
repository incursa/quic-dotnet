namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0103")]
public sealed class REQ_QUIC_CRT_0103
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TlsBridgeStateSnapshotsTransportParametersAndTracksKeyLifecycleOutputs()
    {
        QuicTransportParameters localParameters = new()
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };

        QuicTransportParameters peerSeedParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                IPv6Port = 8443,
                ConnectionId = [0x10, 0x11],
                StatelessResetToken = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
            },
            ActiveConnectionIdLimit = 4,
        };

        Span<byte> encodedPeerParameters = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            peerSeedParameters,
            QuicTransportParameterRole.Server,
            encodedPeerParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedPeerParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedPeerParameters));

        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: parsedPeerParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Initial)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeyUpdateInstalled,
            KeyPhase: 2)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysDiscarded,
            QuicTlsEncryptionLevel.Initial)));

        localParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedPeerParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedPeerParameters.PreferredAddress!.ConnectionId[0] = 0x99;
        parsedPeerParameters.PreferredAddress.StatelessResetToken[0] = 0x98;

        Assert.NotSame(localParameters, bridge.LocalTransportParameters);
        Assert.NotSame(parsedPeerParameters, bridge.PeerTransportParameters);
        Assert.Equal(15UL, bridge.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, bridge.LocalTransportParameters.InitialSourceConnectionId);
        Assert.Equal(30UL, bridge.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.PeerTransportParametersAuthenticated);
        Assert.False(bridge.InitialKeysAvailable);
        Assert.True(bridge.HandshakeKeysAvailable);
        Assert.True(bridge.OneRttKeysAvailable);
        Assert.True(bridge.HandshakeConfirmed);
        Assert.True(bridge.KeyUpdateInstalled);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.Equal(2U, bridge.CurrentOneRttKeyPhase);
        Assert.True(bridge.HasAnyAvailableKeys);
        Assert.False(bridge.IsTerminal);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bridge.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x10, 0x11 }, bridge.PeerTransportParameters.PreferredAddress!.ConnectionId);
        Assert.Equal(new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F }, bridge.PeerTransportParameters.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProhibitedKeyUpdatesMarkTheBridgeTerminal()
    {
        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation)));

        Assert.True(bridge.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, bridge.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", bridge.FatalAlertDescription);
        Assert.False(bridge.HasAnyAvailableKeys);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverConsumesBufferedInboundCryptoBytes()
    {
        QuicTlsTransportBridgeDriver driver = new();
        byte[] inboundCrypto = [0x10, 0x11, 0x12, 0x13];

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            offset: 0,
            inboundCrypto,
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);

        inboundCrypto[0] = 0xFF;

        Span<byte> dequeuedCrypto = stackalloc byte[4];
        Assert.True(driver.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCrypto,
            out int bytesWritten));

        Assert.Equal(4, bytesWritten);
        Assert.True(new byte[] { 0x10, 0x11, 0x12, 0x13 }.AsSpan().SequenceEqual(dequeuedCrypto[..bytesWritten]));
        Assert.False(driver.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCrypto,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverQueuesOutboundCryptoBytes()
    {
        QuicTlsTransportBridgeDriver driver = new();
        byte[] outboundCrypto = [0x20, 0x21, 0x22];

        Assert.True(driver.TryBufferOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            offset: 0,
            outboundCrypto,
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);

        outboundCrypto[0] = 0xEE;

        Span<byte> dequeuedCrypto = stackalloc byte[3];
        Assert.True(driver.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCrypto,
            out int bytesWritten));

        Assert.Equal(3, bytesWritten);
        Assert.True(new byte[] { 0x20, 0x21, 0x22 }.AsSpan().SequenceEqual(dequeuedCrypto[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsAuthenticatedPeerTransportParameters()
    {
        QuicTransportParameters peerParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
        };

        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.PublishAuthenticatedPeerTransportParameters(peerParameters);

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersAuthenticated, updates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersAuthenticated);

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                updates[0]),
            nowTicks: 11).StateChanged);

        peerParameters.InitialSourceConnectionId![0] = 0xFF;

        Assert.NotSame(peerParameters, driver.State.PeerTransportParameters);
        Assert.Equal(30UL, driver.State.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(driver.State.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, driver.State.PeerTransportParameters.InitialSourceConnectionId);
        Assert.True(runtime.TlsState.PeerTransportParametersAuthenticated);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.Equal(30UL, runtime.PeerMaxIdleTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsHandshakeConfirmedUpdates()
    {
        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.PublishHandshakeConfirmed();

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.HandshakeConfirmed, updates[0].Kind);
        Assert.True(driver.State.HandshakeConfirmed);

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                updates[0]),
            nowTicks: 12).StateChanged);

        Assert.True(runtime.TlsState.HandshakeConfirmed);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsKeyDiscardUpdates()
    {
        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> availableUpdates = driver.PublishKeysAvailable(QuicTlsEncryptionLevel.Handshake);
        Assert.Single(availableUpdates);
        Assert.True(driver.State.HandshakeKeysAvailable);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.PublishKeyDiscard(QuicTlsEncryptionLevel.Handshake);
        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.KeysDiscarded, updates[0].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[0].EncryptionLevel);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.OldKeysDiscarded);

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 20,
                availableUpdates[0]),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 21,
                updates[0]),
            nowTicks: 21).StateChanged);

        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FatalAlertBridgeUpdatesRouteThroughTheExistingRuntimeSeam()
    {
        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.PublishFatalAlert(alertDescription: 0x0017);

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0017, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);

        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 40,
                updates[0]),
            nowTicks: 40);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal("TLS alert 23.", runtime.TerminalState?.Close.ReasonPhrase);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 0).StateChanged);

        return runtime;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
