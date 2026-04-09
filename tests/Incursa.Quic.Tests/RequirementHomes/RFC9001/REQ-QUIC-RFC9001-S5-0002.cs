namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0002")]
public sealed class REQ_QUIC_RFC9001_S5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesTlsNegotiatedPacketProtectionMaterialUpdates()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        byte[] aeadKey = CreateSequentialBytes(0x11, 16);
        byte[] aeadIv = CreateSequentialBytes(0x21, 12);
        byte[] headerProtectionKey = CreateSequentialBytes(0x31, 16);

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Ccm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(32, 64),
            out QuicTlsPacketProtectionMaterial material));

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 10).StateChanged);

        aeadKey[0] = 0xFF;
        aeadIv[0] = 0xEE;
        headerProtectionKey[0] = 0xDD;

        Assert.True(runtime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial storedMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, storedMaterial.EncryptionLevel);
        Assert.Equal(QuicAeadAlgorithm.Aes128Ccm, storedMaterial.Algorithm);
        Assert.Equal(32d, storedMaterial.UsageLimits.ConfidentialityLimitPackets);
        Assert.Equal(64d, storedMaterial.UsageLimits.IntegrityLimitPackets);
        Assert.Equal(16, storedMaterial.AeadKey.Length);
        Assert.Equal(12, storedMaterial.AeadIv.Length);
        Assert.Equal(16, storedMaterial.HeaderProtectionKey.Length);
        Assert.True(CreateSequentialBytes(0x11, 16).AsSpan().SequenceEqual(storedMaterial.AeadKey));
        Assert.True(CreateSequentialBytes(0x21, 12).AsSpan().SequenceEqual(storedMaterial.AeadIv));
        Assert.True(CreateSequentialBytes(0x31, 16).AsSpan().SequenceEqual(storedMaterial.HeaderProtectionKey));
        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreate_RejectsUnsupportedAeadAlgorithms()
    {
        Assert.False(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            (QuicAeadAlgorithm)999,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(32, 64),
            out _));

        Assert.False(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Ccm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(double.NaN, 64),
            out _));
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
