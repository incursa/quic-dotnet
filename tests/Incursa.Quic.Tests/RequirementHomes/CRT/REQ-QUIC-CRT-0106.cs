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

        byte[] protectedHandshakePacket = BuildProtectedHandshakePacket(
            material,
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

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

    private static byte[] BuildProtectedHandshakePacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> cryptoPayload)
    {
        Span<byte> cryptoFrameBuffer = stackalloc byte[256];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(0, cryptoPayload),
            cryptoFrameBuffer,
            out int cryptoFrameBytesWritten));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId: [],
            sourceConnectionId: [],
            packetNumber: [0x01, 0x02, 0x03, 0x04],
            plaintextPayload: cryptoFrameBuffer[..cryptoFrameBytesWritten]);

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);
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
