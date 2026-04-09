namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0005")]
public sealed class REQ_QUIC_RFC9001_S4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeOpensHandshakePacketsAndFeedsTheBridgeDriverWithCryptoBytes()
    {
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();
        QuicConnectionRuntime runtime = CreateRuntime();

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

        byte[] cryptoData = CreateSequentialBytes(0x40, 24);
        Span<byte> cryptoFrameBuffer = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(0, cryptoData),
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

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 6,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                protectedPacket),
            nowTicks: 6);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.True(runtime.ActivePath.HasValue);
        Span<byte> surfacedCryptoBytes = stackalloc byte[24];
        Assert.True(runtime.TlsState.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            surfacedCryptoBytes,
            out ulong offset,
            out int bytesWritten));

        Assert.Equal(0UL, offset);
        Assert.Equal(24, bytesWritten);
        Assert.True(cryptoData.AsSpan().SequenceEqual(surfacedCryptoBytes[..bytesWritten]));
        Assert.False(runtime.HandshakeConfirmed);
        Assert.False(runtime.TlsState.HandshakeConfirmed);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
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
