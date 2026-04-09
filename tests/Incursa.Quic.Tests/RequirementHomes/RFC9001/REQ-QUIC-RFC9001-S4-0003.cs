namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0003")]
public sealed class REQ_QUIC_RFC9001_S4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeFormatsOutboundHandshakeCryptoBytesIntoProtectedHandshakePackets()
    {
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 5).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 5).StateChanged);

        byte[] outboundCrypto = CreateSequentialBytes(0x50, 24);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 6,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: outboundCrypto)),
            nowTicks: 6);

        Assert.True(result.StateChanged);
        Assert.Equal(0, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);
        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(
                result.Effects,
                effect => effect is QuicConnectionSendDatagramEffect sendEffect
                    && sendEffect.PathIdentity == path
                    && !sendEffect.Datagram.IsEmpty));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenHandshakePacket(
            send.Datagram.Span,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame cryptoFrame, out int bytesConsumed));
        Assert.Equal(payloadLength, bytesConsumed);
        Assert.Equal(0UL, cryptoFrame.Offset);
        Assert.True(outboundCrypto.AsSpan().SequenceEqual(cryptoFrame.CryptoData));
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
