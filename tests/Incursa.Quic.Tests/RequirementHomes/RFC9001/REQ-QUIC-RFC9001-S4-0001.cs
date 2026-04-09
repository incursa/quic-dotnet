namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0001")]
public sealed class REQ_QUIC_RFC9001_S4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeCarriesDeterministicHandshakeDataThroughCryptoFramesFromBootstrapToConfirmation()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 4).StateChanged);

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 5,
                LocalTransportParameters: CreateLocalTransportParameters()),
            nowTicks: 5);

        Assert.True(bootstrapResult.StateChanged);
        QuicConnectionSendDatagramEffect outboundHandshake = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(
                bootstrapResult.Effects,
                effect => effect is QuicConnectionSendDatagramEffect sendEffect
                    && sendEffect.PathIdentity == runtime.ActivePath!.Value.Identity
                    && !sendEffect.Datagram.IsEmpty));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenHandshakePacket(
            outboundHandshake.Datagram.Span,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame localCryptoFrame,
            out int localBytesConsumed));
        Assert.True(localBytesConsumed > 0);
        Assert.True(localBytesConsumed <= payloadLength);
        Assert.Equal(0UL, localCryptoFrame.Offset);
        Assert.True(openedPacket
            .AsSpan(payloadOffset + localBytesConsumed, payloadLength - localBytesConsumed)
            .IndexOfAnyExcept((byte)0) < 0);

        byte[] expectedLocalTranscript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                CreateLocalTransportParameters(),
                QuicTransportParameterRole.Client));
        Assert.True(expectedLocalTranscript.AsSpan().SequenceEqual(localCryptoFrame.CryptoData));

        byte[] inboundHandshakePacket = BuildProtectedHandshakePacket(
            material,
            CreateEncryptedExtensionsTranscript(
                CreateFormattedTransportParameters(
                    CreatePeerTransportParameters(),
                    QuicTransportParameterRole.Server)));

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 6,
                runtime.ActivePath!.Value.Identity,
                inboundHandshakePacket),
            nowTicks: 6);

        Assert.True(receiveResult.StateChanged);
        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Null(runtime.TlsState.PeerTransportParameters);
        Assert.Null(runtime.TlsState.StagedPeerTransportParameters);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TlsState.FatalAlertCode);
        Assert.Equal("TLS alert 50.", runtime.TlsState.FatalAlertDescription);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.False(runtime.TlsState.OneRttKeysAvailable);
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 0).StateChanged);

        return runtime;
    }

    private static QuicTransportParameters CreateLocalTransportParameters()
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

    private static byte[] BuildProtectedHandshakePacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> cryptoPayload)
    {
        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
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
