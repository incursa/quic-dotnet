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
            QuicTlsUpdateKind.TranscriptProgressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
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
    public void BridgeDriverConsumesDeterministicHandshakeTranscriptBytesIncrementally()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();
        byte[] peerHandshakeTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
            peerParameters,
            QuicTransportParameterRole.Server));

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript[..5]);

        Assert.Empty(firstUpdates);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, driver.State.HandshakeTranscriptPhase);
        Assert.False(driver.State.PeerTransportParametersAuthenticated);
        Assert.False(driver.State.HandshakeConfirmed);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript[5..]);

        Assert.Equal(4, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersAuthenticated, updates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeConfirmed, updates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[3].Kind);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, updates[3].TranscriptPhase);
        Assert.True(driver.State.PeerTransportParametersAuthenticated);
        Assert.True(driver.State.HandshakeConfirmed);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, driver.State.HandshakeTranscriptPhase);
        Assert.NotSame(peerParameters, driver.State.PeerTransportParameters);
        Assert.Equal(30UL, driver.State.PeerTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, driver.State.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(0, driver.State.HandshakeIngressCryptoBuffer.BufferedBytes);

        Span<byte> drainedInboundCrypto = stackalloc byte[1];
        Assert.False(driver.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            drainedInboundCrypto,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BridgeDriverRejectsRepeatedHandshakeTranscriptProgressionDeterministically()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();
        byte[] peerHandshakeTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
            peerParameters,
            QuicTransportParameterRole.Server));

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript);

        Assert.Equal(4, firstUpdates.Count);
        Assert.True(driver.State.HandshakeConfirmed);

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript);

        Assert.Single(repeatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, repeatedUpdates[0].Kind);
        Assert.Equal((ushort)0x0010, repeatedUpdates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BridgeDriverDoesNotAuthenticateRawTransportParameterBlobsByConstruction()
    {
        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(CreateBootstrapLocalTransportParameters()));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(driver.State.PeerTransportParametersAuthenticated);
        Assert.False(driver.State.HandshakeConfirmed);
        Assert.True(driver.State.IsTerminal);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, driver.State.HandshakeTranscriptPhase);
        Assert.Empty(driver.PublishAuthenticatedPeerTransportParameters(CreatePeerTransportParameters()));
        Assert.Empty(driver.PublishHandshakeConfirmed());
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
        IReadOnlyList<QuicTlsStateUpdate> stageUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.PeerTransportParametersStaged);
        Assert.Single(stageUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, stageUpdates[0].Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, stageUpdates[0].TranscriptPhase);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.PublishAuthenticatedPeerTransportParameters(peerParameters);

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersAuthenticated, updates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersAuthenticated);

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                stageUpdates[0]),
            nowTicks: 11).StateChanged);
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
    public void BridgeDriverStartHandshakePublishesLocalTransportParameters()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        byte[] expectedHandshakeTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                localParameters,
                QuicTransportParameterRole.Client));

        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(localParameters);

        Assert.Equal(3, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.LocalTransportParametersReady, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[1].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[2].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[2].EncryptionLevel);
        Assert.Equal(0UL, updates[2].CryptoDataOffset);
        Assert.Same(localParameters, updates[0].TransportParameters);
        Assert.NotSame(localParameters, driver.State.LocalTransportParameters);
        Assert.Equal(15UL, driver.State.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, driver.State.LocalTransportParameters.InitialSourceConnectionId);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.HandshakeEgressCryptoBuffer.BufferedBytes > 0);

        Span<byte> surfacedHandshakeTranscript = stackalloc byte[expectedHandshakeTranscript.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            surfacedHandshakeTranscript,
            out ulong offset,
            out int bytesWritten));

        Assert.Equal(0UL, offset);
        Assert.Equal(expectedHandshakeTranscript.Length, bytesWritten);
        Assert.True(expectedHandshakeTranscript.AsSpan().SequenceEqual(surfacedHandshakeTranscript[..bytesWritten]));

        localParameters.InitialSourceConnectionId![0] = 0xFF;

        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, driver.State.LocalTransportParameters.InitialSourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesHandshakeBootstrapUpdatesThroughTheExistingTlsReducer()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: localParameters),
            nowTicks: 10);

        Assert.True(bootstrapResult.StateChanged);
        Assert.Equal(QuicConnectionEventKind.HandshakeBootstrapRequested, bootstrapResult.EventKind);
        Assert.NotSame(localParameters, runtime.TlsState.LocalTransportParameters);
        Assert.Equal(15UL, runtime.TlsState.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(15UL, runtime.LocalMaxIdleTimeoutMicros);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes > 0);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.HandshakeConfirmed);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 11).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
                    TransportParameters: CreatePeerTransportParameters())),
            nowTicks: 11).StateChanged);

        QuicConnectionTransitionResult handshakeConfirmedResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)),
            nowTicks: 11);

        Assert.True(handshakeConfirmedResult.StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.TlsState.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeBootstrapRejectsRepeatedRequests()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult firstBootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10);

        QuicConnectionTransitionResult repeatedBootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 11,
                LocalTransportParameters: new QuicTransportParameters
                {
                    MaxIdleTimeout = 20,
                }),
            nowTicks: 11);

        Assert.True(firstBootstrapResult.StateChanged);
        Assert.False(repeatedBootstrapResult.StateChanged);
        Assert.Equal(15UL, runtime.LocalMaxIdleTimeoutMicros);
        Assert.NotNull(runtime.TlsState.LocalTransportParameters);
        Assert.Equal(15UL, runtime.TlsState.LocalTransportParameters!.MaxIdleTimeout);
        Assert.False(runtime.HandshakeConfirmed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeBootstrapRejectsInvalidTransportParameters()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 12,
                LocalTransportParameters: null),
            nowTicks: 12);

        Assert.False(result.StateChanged);
        Assert.Equal(QuicConnectionEventKind.HandshakeBootstrapRequested, result.EventKind);
        Assert.Null(runtime.TlsState.LocalTransportParameters);
        Assert.Null(runtime.LocalMaxIdleTimeoutMicros);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsHandshakeConfirmedUpdates()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateEncryptedExtensionsTranscript(
                CreateFormattedTransportParameters(peerParameters, QuicTransportParameterRole.Server)));

        Assert.Equal(4, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersAuthenticated, updates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeConfirmed, updates[2].Kind);
        Assert.True(driver.State.HandshakeConfirmed);

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                updates[0]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                updates[1]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                updates[2]),
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
        Assert.NotEmpty(driver.StartHandshake(CreateBootstrapLocalTransportParameters()));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateMalformedHandshakeTranscriptBytes());

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
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
        Assert.Equal("TLS alert 50.", runtime.TerminalState?.Close.ReasonPhrase);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
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
    }

    private static byte[] CreateFormattedTransportParameters(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int bytesWritten));

        return encodedTransportParameters[..bytesWritten];
    }

    private static byte[] CreateEncryptedExtensionsTranscript(ReadOnlySpan<byte> encodedTransportParameters)
    {
        QuicTransportParameters parameters = new();
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out parameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicTransportParametersMessage(
            parameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        Array.Resize(ref transcript, bytesWritten);
        return transcript;
    }

    private static byte[] CreateMalformedHandshakeTranscriptBytes()
    {
        return [0x08, 0x00, 0x00, 0x03, 0x00, 0x02, 0x12];
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
