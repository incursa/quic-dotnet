namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0106")]
public sealed class REQ_QUIC_CRT_0106
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverHandshakeConfirmationUpdatesTheRuntimePhase()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.TlsState.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverHandshakeKeyDiscardFlowsThroughTheRuntimeAndClearsHandshakeSendState()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 10).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 10).StateChanged);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 7,
            PayloadBytes: 128,
            SentAtMicros: 0,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake)));

        Assert.Single(runtime.SendRuntime.SentPackets);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out _));
        Assert.Empty(runtime.SendRuntime.SentPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeExecutesTheDeterministicHandshakeSmokePathFromBootstrapToHandshakeConfirmation()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 10);

        Assert.True(bootstrapResult.StateChanged);
        Assert.NotSame(localTransportParameters, runtime.TlsState.LocalTransportParameters);
        Assert.Equal(15UL, runtime.TlsState.LocalTransportParameters!.MaxIdleTimeout);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Equal(0, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);

        QuicConnectionSendDatagramEffect outboundHandshake = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(
                bootstrapResult.Effects,
                effect => effect is QuicConnectionSendDatagramEffect));
        Assert.Equal(path, outboundHandshake.PathIdentity);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenHandshakePacket(
            outboundHandshake.Datagram.Span,
            material,
            out byte[] openedOutboundPacket,
            out int outboundPayloadOffset,
            out int outboundPayloadLength));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedOutboundPacket.AsSpan(outboundPayloadOffset, outboundPayloadLength),
            out QuicCryptoFrame outboundCryptoFrame,
            out int outboundBytesConsumed));
        Assert.True(outboundBytesConsumed > 0);
        Assert.True(outboundBytesConsumed <= outboundPayloadLength);
        Assert.Equal(0UL, outboundCryptoFrame.Offset);
        Assert.True(
            CreateEncryptedExtensionsTranscript(
                CreateFormattedTransportParameters(
                    localTransportParameters,
                    QuicTransportParameterRole.Client)).AsSpan().SequenceEqual(outboundCryptoFrame.CryptoData));

        byte[] peerTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
            peerTransportParameters,
            QuicTransportParameterRole.Server));
        byte[] protectedPeerPacket = BuildProtectedHandshakePacket(material, peerTranscript);

        QuicConnectionTransitionResult inboundResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                path,
                protectedPeerPacket),
            nowTicks: 11);

        Assert.True(inboundResult.StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersAuthenticated);
        Assert.Equal(30UL, runtime.TlsState.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(runtime.TlsState.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, runtime.TlsState.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(0, runtime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
        Assert.True(runtime.TlsState.HandshakeConfirmed);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 7,
            PayloadBytes: 128,
            SentAtMicros: 0,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake)));
        Assert.Single(runtime.SendRuntime.SentPackets);

        QuicConnectionTransitionResult discardResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 12);

        Assert.True(discardResult.StateChanged);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out _));
        Assert.Empty(runtime.SendRuntime.SentPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsTamperedHandshakePacketsWithoutAdvancingTheTranscript()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        byte[] peerTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
            CreatePeerTransportParameters(),
            QuicTransportParameterRole.Server));
        byte[] tamperedPeerPacket = BuildProtectedHandshakePacket(material, peerTranscript);
        tamperedPeerPacket[^1] ^= 0x80;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                path,
                tamperedPeerPacket),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.False(runtime.TlsState.PeerTransportParametersAuthenticated);
        Assert.False(runtime.TlsState.HandshakeConfirmed);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0, runtime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesDeterministicHandshakeTranscriptThroughTheExistingTlsReducer()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        byte[] peerTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        byte[] protectedHandshakePacket = BuildProtectedHandshakePacket(
            material,
            peerTranscript);

        QuicConnectionTransitionResult transcriptResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                protectedHandshakePacket),
            nowTicks: 11);

        Assert.True(transcriptResult.StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersAuthenticated);
        Assert.Equal(30UL, runtime.TlsState.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(runtime.TlsState.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, runtime.TlsState.PeerTransportParameters.InitialSourceConnectionId);
        Assert.True(runtime.TlsState.HandshakeConfirmed);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.False(runtime.TlsState.OneRttKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeAccumulatesFragmentedHandshakeCryptoAcrossMultiplePacketsBeforeConfirming()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        byte[] peerTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        byte[] firstPacket = BuildProtectedHandshakePacket(material, peerTranscript.AsSpan(0, 5), cryptoOffset: 0);
        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                firstPacket),
            nowTicks: 11);

        Assert.True(firstResult.StateChanged);
        Assert.False(runtime.TlsState.PeerTransportParametersAuthenticated);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);

        byte[] secondPacket = BuildProtectedHandshakePacket(material, peerTranscript.AsSpan(5), cryptoOffset: 5);
        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 12,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                secondPacket),
            nowTicks: 12);

        Assert.True(secondResult.StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersAuthenticated);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedPeerHandshakeBlobRoutesFatalAlertThroughTheRuntimeCoordinator()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            CreateMalformedHandshakeTranscriptBytes(),
            cryptoPayloadOffset: 0,
            material,
            out byte[] malformedHandshakePacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                malformedHandshakePacket),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TlsState.FatalAlertCode);
        Assert.Equal("TLS alert 50.", runtime.TlsState.FatalAlertDescription);
        Assert.True(runtime.TlsState.IsTerminal);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.False(runtime.HandshakeConfirmed);
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
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parameters));

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
        return
        [
            0x08, 0x00, 0x00, 0x03,
            0x00, 0x02, 0x12,
        ];
    }

    private static byte[] BuildProtectedHandshakePacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoOffset = 0)
    {
        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoOffset,
            material,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
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
